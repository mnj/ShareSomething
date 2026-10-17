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
    auth::owner::Owner,
    error::{AppError, AppResult},
    util::now,
};

#[derive(Serialize, ToSchema)]
pub struct PolicyTemplate {
    pub id: String,
    pub name: String,
    pub policy: Vec<PolicyRule>,
    pub created_at: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct SaveTemplate {
    pub name: String,
    pub policy: Vec<PolicyRule>,
}

/// Saved access policies.
#[utoipa::path(get, path = "/policy-templates", tag = "templates", operation_id = "template_list",
    responses((status = 200, body = Vec<PolicyTemplate>)))]
async fn list(State(state): State<AppState>, _owner: Owner) -> AppResult<Json<Vec<PolicyTemplate>>> {
    let rows: Vec<(String, String, String, i64)> =
        sqlx::query_as("SELECT id, name, rules, created_at FROM policy_templates ORDER BY name COLLATE NOCASE")
            .fetch_all(&state.db)
            .await?;
    Ok(Json(
        rows.into_iter()
            .filter_map(|(id, name, rules, created_at)| {
                serde_json::from_str(&rules).ok().map(|policy| PolicyTemplate {
                    id,
                    name,
                    policy,
                    created_at,
                })
            })
            .collect(),
    ))
}

/// Save a policy under a name; saving an existing name replaces it.
#[utoipa::path(post, path = "/policy-templates", tag = "templates", operation_id = "template_save", request_body = SaveTemplate,
    responses((status = 200, body = PolicyTemplate), (status = 400, body = crate::error::ErrorBody)))]
async fn save(State(state): State<AppState>, _owner: Owner, Json(req): Json<SaveTemplate>) -> AppResult<Json<PolicyTemplate>> {
    let name = req.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(AppError::BadRequest("template name must be 1-80 characters".into()));
    }
    let policy = validate_policy(&state, req.policy)?;
    let rules = serde_json::to_string(&policy).map_err(anyhow::Error::from)?;
    let (id, created_at): (String, i64) = sqlx::query_as(
        "INSERT INTO policy_templates (id, name, rules, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET rules = excluded.rules
         RETURNING id, created_at",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&name)
    .bind(rules)
    .bind(now())
    .fetch_one(&state.db)
    .await?;
    Ok(Json(PolicyTemplate {
        id,
        name,
        policy,
        created_at,
    }))
}

/// Delete a saved policy (shares that used it keep their own copy of the rules).
#[utoipa::path(delete, path = "/policy-templates/{id}", tag = "templates", operation_id = "template_delete", params(("id" = String, Path)),
    responses((status = 204), (status = 404, body = crate::error::ErrorBody)))]
async fn delete(State(state): State<AppState>, _owner: Owner, Path(id): Path<String>) -> AppResult<StatusCode> {
    let res = sqlx::query("DELETE FROM policy_templates WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list, save)).routes(routes!(delete))
}
