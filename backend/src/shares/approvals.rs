//! Owner approval: each open of a `require_approval` share waits for the owner to say yes.
//!
//! Flow: the visitor passes the policy and passphrase checks, then `POST /open` creates a pending
//! approval and answers 403 `need_approval` with an id and a secret. The browser keeps retrying
//! `/open` with both. The owner approves or denies in the dashboard (with fresh MFA). An approval is
//! single-use: it's consumed in the same transaction that spends the view.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, Transaction};
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{model::OpenRequest, store::ShareRow};
use crate::{
    app::AppState,
    audit::{Action, Event},
    auth::users::{CurrentUser, require_fresh_mfa},
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    notify,
    util::{now, random_token, sha256},
};

/// How long a request waits for the owner.
const PENDING_TTL_SECS: i64 = 15 * 60;
/// How long an approved request can be used.
const APPROVED_TTL_SECS: i64 = 10 * 60;
/// Pending requests per share (stops a visitor from flooding the owner).
const MAX_PENDING: i64 = 10;

/// Returns the approval id to consume if this open is approved; otherwise the `need_approval`
/// (or `approval_denied`) error to send back. `event` is a pre-attributed visitor audit event.
pub async fn gate(
    state: &AppState,
    row: &ShareRow,
    req: &OpenRequest,
    client: &ClientInfo,
    visitor: Option<String>,
    event: Event,
) -> AppResult<String> {
    if let (Some(id), Some(secret)) = (&req.approval_id, &req.approval_secret) {
        let found: Option<(String, i64, Vec<u8>)> =
            sqlx::query_as("SELECT status, expires_at, secret_hash FROM approvals WHERE id = ? AND share_id = ?")
                .bind(id)
                .bind(&row.id)
                .fetch_optional(&state.db)
                .await?;
        if let Some((status, expires_at, hash)) = found
            && bool::from(sha256(secret.as_bytes()).ct_eq(&hash))
        {
            let live = expires_at > now();
            match status.as_str() {
                "approved" if live => return Ok(id.clone()),
                "pending" if live => {
                    return Err(AppError::NeedApproval {
                        id: id.clone(),
                        secret: None,
                    });
                }
                "denied" => return Err(AppError::Access("approval_denied", "the owner declined this request".into())),
                _ => {} // used or expired: ask again
            }
        }
    }
    let pending: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM approvals WHERE share_id = ? AND status = 'pending' AND expires_at > ?")
        .bind(&row.id)
        .bind(now())
        .fetch_one(&state.db)
        .await?;
    if pending.0 >= MAX_PENDING {
        return Err(AppError::TooManyRequests);
    }
    let (id, secret) = (uuid::Uuid::new_v4().to_string(), random_token());
    sqlx::query(
        "INSERT INTO approvals (id, share_id, secret_hash, requester_label, ip, country, user_agent, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&row.id)
    .bind(sha256(secret.as_bytes()))
    .bind(&visitor)
    .bind(client.ip.to_string())
    .bind(&client.country)
    .bind(&client.user_agent)
    .bind(now())
    .bind(now() + PENDING_TTL_SECS)
    .execute(&state.db)
    .await?;
    state.audit.record(event.detail("approval_id", &id)).await?;
    let who = visitor.unwrap_or_else(|| "Someone".into());
    let place = client
        .country
        .as_ref()
        .map(|c| format!("{} ({c})", client.ip))
        .unwrap_or_else(|| client.ip.to_string());
    notify::notify(
        state,
        row.owner_id,
        notify::Kind::ApprovalRequested,
        Some(&row.id),
        Some(&id),
        &format!("Approve opening \"{}\"?", row.audit_label()),
        &format!(
            "{who} wants to open \"{}\" from {place}. Approve or deny it in ShareSomething within 15 minutes.",
            row.audit_label()
        ),
    )
    .await?;
    Err(AppError::NeedApproval { id, secret: Some(secret) })
}

/// Marks an approval used; false if it was already used, denied or has expired meanwhile.
pub async fn consume(tx: &mut Transaction<'_, Sqlite>, id: &str) -> sqlx::Result<bool> {
    let res = sqlx::query("UPDATE approvals SET status = 'used' WHERE id = ? AND status = 'approved' AND expires_at > ?")
        .bind(id)
        .bind(now())
        .execute(&mut **tx)
        .await?;
    Ok(res.rows_affected() == 1)
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct PendingApproval {
    pub id: String,
    pub share_id: String,
    pub share_label: String,
    pub requester_label: Option<String>,
    pub ip: String,
    pub country: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Pending open requests for your shares.
#[utoipa::path(get, path = "/approvals", tag = "approvals", operation_id = "approvals_list",
    responses((status = 200, body = Vec<PendingApproval>)))]
async fn list(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<Vec<PendingApproval>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT a.id, a.share_id, COALESCE(s.title, '/s/' || s.slug) AS share_label, a.requester_label, a.ip, a.country,
                    a.user_agent, a.created_at, a.expires_at
             FROM approvals a JOIN shares s ON s.id = a.share_id
             WHERE s.owner_id = ? AND a.status = 'pending' AND a.expires_at > ? ORDER BY a.created_at",
        )
        .bind(user.id)
        .bind(now())
        .fetch_all(&state.db)
        .await?,
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct Decide {
    pub approve: bool,
}

/// Approve or deny a pending request. Needs a fresh MFA when you have a second factor.
#[utoipa::path(post, path = "/approvals/{id}/decide", tag = "approvals", operation_id = "approvals_decide", params(("id" = String, Path)), request_body = Decide,
    responses((status = 204), (status = 403, body = crate::error::ErrorBody), (status = 404, body = crate::error::ErrorBody)))]
async fn decide(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<Decide>,
) -> AppResult<axum::http::StatusCode> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT a.share_id, a.requester_label FROM approvals a JOIN shares s ON s.id = a.share_id
         WHERE a.id = ? AND s.owner_id = ? AND a.status = 'pending' AND a.expires_at > ?",
    )
    .bind(&id)
    .bind(user.id)
    .bind(now())
    .fetch_optional(&state.db)
    .await?;
    let Some((share_id, requester)) = row else {
        return Err(AppError::NotFound);
    };
    require_fresh_mfa(&state, &user).await?;
    let status = if req.approve { "approved" } else { "denied" };
    sqlx::query("UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, expires_at = ? WHERE id = ? AND status = 'pending'")
        .bind(status)
        .bind(now())
        .bind(user.id)
        .bind(now() + APPROVED_TTL_SECS)
        .bind(&id)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE notifications SET read_at = ? WHERE approval_id = ? AND read_at IS NULL")
        .bind(now())
        .bind(&id)
        .execute(&state.db)
        .await?;
    let action = if req.approve {
        Action::ShareApprovalApproved
    } else {
        Action::ShareApprovalDenied
    };
    state
        .audit
        .record(
            user.event(action)
                .client(&client)
                .target("share", &share_id, None)
                .detail("approval_id", &id)
                .detail("requester", requester),
        )
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list)).routes(routes!(decide))
}
