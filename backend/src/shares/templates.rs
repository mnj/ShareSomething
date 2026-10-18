//! Named, reusable access policies ("Home IP only", "acme.com via Google", ...).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{handlers::validate_policy, policy::PolicyRule};
use crate::{
    app::AppState,
    audit::Action,
    auth::users::CurrentUser,
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    util::now,
};

#[derive(Serialize, ToSchema)]
pub struct PolicyTemplate {
    pub id: String,
    pub name: String,
    pub policy: Vec<PolicyRule>,
    pub created_at: i64,
    /// Shared with the whole organisation (managed by admins).
    pub org: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct SaveTemplate {
    pub name: String,
    pub policy: Vec<PolicyRule>,
    /// Admins: save for everyone in the organisation.
    #[serde(default)]
    pub org: bool,
}

/// Org-wide templates are stored under this owner id.
const ORG_OWNER: i64 = 0;

/// Saved access policies.
#[utoipa::path(get, path = "/policy-templates", tag = "templates", operation_id = "template_list",
    responses((status = 200, body = Vec<PolicyTemplate>)))]
async fn list(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<Vec<PolicyTemplate>>> {
    let rows: Vec<(String, String, String, i64, i64)> =
        sqlx::query_as("SELECT id, name, rules, created_at, owner_id FROM policy_templates WHERE owner_id IN (?, 0) ORDER BY owner_id != 0, name COLLATE NOCASE")
            .bind(user.id)
            .fetch_all(&state.db)
            .await?;
    Ok(Json(
        rows.into_iter()
            .filter_map(|(id, name, rules, created_at, owner)| {
                serde_json::from_str(&rules).ok().map(|policy| PolicyTemplate {
                    id,
                    name,
                    policy,
                    created_at,
                    org: owner == ORG_OWNER,
                })
            })
            .collect(),
    ))
}

/// Save a policy under a name; saving an existing name replaces it.
#[utoipa::path(post, path = "/policy-templates", tag = "templates", operation_id = "template_save", request_body = SaveTemplate,
    responses((status = 200, body = PolicyTemplate), (status = 400, body = crate::error::ErrorBody)))]
async fn save(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Json(req): Json<SaveTemplate>,
) -> AppResult<Json<PolicyTemplate>> {
    user.ensure_can_share(&state).await?;
    let name = req.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(AppError::BadRequest("template name must be 1-80 characters".into()));
    }
    let policy = validate_policy(&state, req.policy)?;
    super::handlers::validate_references(&state, &policy).await?;
    crate::org::settings::load(&state)
        .await?
        .enforce(&crate::org::settings::ShareParams {
            enc_mode: None,
            expires_at: None,
            max_views: None,
            policy: Some(&policy),
            slug_generator: None,
        })?;
    if req.org && !user.is_admin() {
        return Err(AppError::Forbidden("only admins can save organisation-wide policies".into()));
    }
    let owner = if req.org { ORG_OWNER } else { user.id };
    let rules = serde_json::to_string(&policy).map_err(anyhow::Error::from)?;
    let (id, created_at): (String, i64) = sqlx::query_as(
        "INSERT INTO policy_templates (id, owner_id, name, rules, created_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(owner_id, name) DO UPDATE SET rules = excluded.rules
         RETURNING id, created_at",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(owner)
    .bind(&name)
    .bind(rules)
    .bind(now())
    .fetch_one(&state.db)
    .await?;
    state
        .audit
        .record(
            user.event(Action::TemplateSaved)
                .client(&client)
                .target("template", &id, Some(name.clone()))
                .detail("policy", &policy)
                .detail("org", req.org),
        )
        .await?;
    Ok(Json(PolicyTemplate {
        id,
        name,
        policy,
        created_at,
        org: req.org,
    }))
}

/// Delete a saved policy (shares that used it keep their own copy of the rules).
#[utoipa::path(delete, path = "/policy-templates/{id}", tag = "templates", operation_id = "template_delete", params(("id" = String, Path)),
    responses((status = 204), (status = 404, body = crate::error::ErrorBody)))]
async fn delete(State(state): State<AppState>, client: ClientInfo, user: CurrentUser, Path(id): Path<String>) -> AppResult<StatusCode> {
    let res = sqlx::query("DELETE FROM policy_templates WHERE id = ? AND (owner_id = ? OR (owner_id = 0 AND ?))")
        .bind(&id)
        .bind(user.id)
        .bind(user.is_admin())
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    state
        .audit
        .record(user.event(Action::TemplateDeleted).client(&client).target("template", &id, None))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list, save)).routes(routes!(delete))
}
