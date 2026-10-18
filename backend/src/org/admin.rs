//! Admin API for team mode: users (invite, roles, disable, reset MFA, sign out), all shares
//! (metadata only, never content) and the member directory used by policy editors.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    app::AppState,
    audit::{Action, Event},
    auth::users::{CurrentUser, MeResponse, Role, hash_password, me_response, start_session},
    config::InstanceMode,
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    shares::{
        handlers::summary,
        model::ShareSummary,
        store::{self, Wipe},
    },
    util::{now, random_token, sha256},
};

fn require_admin(user: &CurrentUser) -> AppResult<()> {
    if !user.is_admin() {
        return Err(AppError::Forbidden("admins only".into()));
    }
    Ok(())
}

fn require_team(state: &AppState) -> AppResult<()> {
    if state.cfg.mode != InstanceMode::Team {
        return Err(AppError::BadRequest("user management needs mode = \"team\"".into()));
    }
    Ok(())
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct AdminUser {
    pub id: i64,
    pub email: Option<String>,
    pub name: String,
    pub role: Role,
    /// active | invited | disabled
    pub status: String,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
    pub sso_provider: Option<String>,
    pub totp: bool,
    pub passkeys: i64,
}

const ADMIN_USER_SELECT: &str = "SELECT u.id, u.email, u.name, u.role, u.status, u.created_at, u.last_login_at, u.sso_provider,
       u.totp_secret IS NOT NULL AS totp, (SELECT COUNT(*) FROM user_passkeys p WHERE p.user_id = u.id) AS passkeys
FROM users u";

async fn admin_user(state: &AppState, id: i64) -> AppResult<AdminUser> {
    sqlx::query_as(&format!("{ADMIN_USER_SELECT} WHERE u.id = ?"))
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)
}

/// All accounts.
#[utoipa::path(get, path = "/admin/users", tag = "admin", operation_id = "admin_users_list", responses((status = 200, body = Vec<AdminUser>)))]
async fn list_users(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<Vec<AdminUser>>> {
    require_admin(&user)?;
    Ok(Json(
        sqlx::query_as(&format!(
            "{ADMIN_USER_SELECT} ORDER BY u.status = 'disabled', lower(coalesce(u.email, u.name))"
        ))
        .fetch_all(&state.db)
        .await?,
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct InviteRequest {
    pub email: String,
    pub name: Option<String>,
    pub role: Role,
}

#[derive(Serialize, ToSchema)]
pub struct InviteResult {
    pub user: AdminUser,
    /// Link for the invitee to set a password (absent when local accounts are disabled: they use SSO).
    pub invite_url: Option<String>,
    /// Whether the invite was also emailed.
    pub emailed: bool,
}

async fn issue_invite(state: &AppState, id: i64, email: &str) -> AppResult<(Option<String>, bool)> {
    if !state.cfg.team.local_accounts {
        return Ok((None, false));
    }
    let token = random_token();
    sqlx::query("UPDATE users SET invite_token_hash = ?, invite_expires_at = ? WHERE id = ?")
        .bind(sha256(token.as_bytes()))
        .bind(now() + state.cfg.team.invite_days * 86_400)
        .bind(id)
        .execute(&state.db)
        .await?;
    let url = format!("{}/invite/{token}", state.cfg.base_url());
    let emailed = state.mailer.enabled();
    if emailed {
        let (mailer, to, body) = (
            state.mailer.clone(),
            email.to_string(),
            format!(
                "You've been invited to ShareSomething.\n\nSet your password here (valid for {} days):\n{url}\n",
                state.cfg.team.invite_days
            ),
        );
        tokio::spawn(async move {
            if let Err(e) = mailer.send_notice(&to, "Your ShareSomething invitation", &body).await {
                tracing::warn!(error = %e, "invite email failed");
            }
        });
    }
    Ok((Some(url), emailed))
}

/// Invite someone. With local accounts they get a link to set a password; with SSO only they
/// simply sign in with their company account.
#[utoipa::path(post, path = "/admin/users", tag = "admin", operation_id = "admin_users_invite", request_body = InviteRequest,
    responses((status = 201, body = InviteResult), (status = 409, body = crate::error::ErrorBody)))]
async fn invite(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Json(req): Json<InviteRequest>,
) -> AppResult<(StatusCode, Json<InviteResult>)> {
    require_admin(&user)?;
    require_team(&state)?;
    let email = req.email.trim().to_ascii_lowercase();
    if !email.split_once('@').is_some_and(|(l, d)| !l.is_empty() && d.contains('.')) || email.len() > 254 {
        return Err(AppError::BadRequest("enter a valid email address".into()));
    }
    let name = req
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| email.split('@').next().unwrap_or("").to_string());
    let status = if state.cfg.team.local_accounts { "invited" } else { "active" };
    let res = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO users (email, name, role, status, invited_by, created_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(&email)
    .bind(&name)
    .bind(req.role)
    .bind(status)
    .bind(user.id)
    .bind(now())
    .fetch_one(&state.db)
    .await;
    let id = match res {
        Ok((id,)) => id,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::Conflict("that email already has an account".into()));
        }
        Err(e) => return Err(e.into()),
    };
    let (invite_url, emailed) = issue_invite(&state, id, &email).await?;
    state
        .audit
        .record(
            user.event(Action::UserInvited)
                .client(&client)
                .target("user", id.to_string(), Some(email.clone()))
                .detail("role", req.role),
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(InviteResult {
            user: admin_user(&state, id).await?,
            invite_url,
            emailed,
        }),
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct UserUpdate {
    pub role: Option<Role>,
    /// `active` or `disabled`.
    pub status: Option<String>,
    pub name: Option<String>,
}

async fn active_admins(state: &AppState) -> AppResult<i64> {
    Ok(
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'")
            .fetch_one(&state.db)
            .await?
            .0,
    )
}

/// Change a user's role, name, or enable/disable the account. Disabling signs them out everywhere.
#[utoipa::path(patch, path = "/admin/users/{id}", tag = "admin", operation_id = "admin_users_update", params(("id" = i64, Path)), request_body = UserUpdate,
    responses((status = 200, body = AdminUser), (status = 409, body = crate::error::ErrorBody)))]
async fn update_user(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<i64>,
    Json(req): Json<UserUpdate>,
) -> AppResult<Json<AdminUser>> {
    require_admin(&user)?;
    let target = admin_user(&state, id).await?;
    let demoting = req.role.is_some_and(|r| r != Role::Admin) && target.role == Role::Admin;
    let disabling = req.status.as_deref() == Some("disabled") && target.status != "disabled";
    if let Some(s) = req.status.as_deref()
        && !matches!(s, "active" | "disabled")
    {
        return Err(AppError::BadRequest("status must be active or disabled".into()));
    }
    if id == user.id && (demoting || disabling) {
        return Err(AppError::Conflict("you can't demote or disable yourself".into()));
    }
    if (demoting || disabling) && target.role == Role::Admin && target.status == "active" && active_admins(&state).await? <= 1 {
        return Err(AppError::Conflict("there must always be at least one active admin".into()));
    }
    let mut changed = vec![];
    if let Some(role) = req.role {
        sqlx::query("UPDATE users SET role = ? WHERE id = ?")
            .bind(role)
            .bind(id)
            .execute(&state.db)
            .await?;
        changed.push(format!(
            "role:{}",
            serde_json::to_value(role).unwrap_or_default().as_str().unwrap_or("")
        ));
    }
    if let Some(status) = &req.status {
        // An invited user can't be "activated" by an admin; they activate by accepting the invite.
        let new = if status == "active" && target.status == "invited" {
            "invited"
        } else {
            status.as_str()
        };
        sqlx::query("UPDATE users SET status = ? WHERE id = ?")
            .bind(new)
            .bind(id)
            .execute(&state.db)
            .await?;
        changed.push(format!("status:{new}"));
        if disabling {
            sqlx::query("DELETE FROM user_sessions WHERE user_id = ?")
                .bind(id)
                .execute(&state.db)
                .await?;
        }
    }
    if let Some(name) = req.name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()) {
        sqlx::query("UPDATE users SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id)
            .execute(&state.db)
            .await?;
        changed.push("name".into());
    }
    state
        .audit
        .record(
            user.event(Action::UserUpdated)
                .client(&client)
                .target("user", id.to_string(), target.email.clone())
                .detail("changed", &changed),
        )
        .await?;
    Ok(Json(admin_user(&state, id).await?))
}

/// Remove a user's TOTP and passkeys (e.g. lost device) and sign them out.
#[utoipa::path(post, path = "/admin/users/{id}/reset-mfa", tag = "admin", operation_id = "admin_users_reset_mfa", params(("id" = i64, Path)),
    responses((status = 200, body = AdminUser)))]
async fn reset_mfa(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<i64>,
) -> AppResult<Json<AdminUser>> {
    require_admin(&user)?;
    let target = admin_user(&state, id).await?;
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_last_step = NULL WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM user_passkeys WHERE user_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    state
        .audit
        .record(
            user.event(Action::UserMfaReset)
                .client(&client)
                .target("user", id.to_string(), target.email),
        )
        .await?;
    Ok(Json(admin_user(&state, id).await?))
}

/// Sign a user out of every session.
#[utoipa::path(post, path = "/admin/users/{id}/sign-out", tag = "admin", operation_id = "admin_users_sign_out", params(("id" = i64, Path)),
    responses((status = 204)))]
async fn sign_out(State(state): State<AppState>, client: ClientInfo, user: CurrentUser, Path(id): Path<i64>) -> AppResult<StatusCode> {
    require_admin(&user)?;
    let target = admin_user(&state, id).await?;
    let n = sqlx::query("DELETE FROM user_sessions WHERE user_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    state
        .audit
        .record(
            user.event(Action::UserSessionsRevoked)
                .client(&client)
                .target("user", id.to_string(), target.email)
                .detail("sessions", n),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Issue a fresh invite link (the old one stops working).
#[utoipa::path(post, path = "/admin/users/{id}/reinvite", tag = "admin", operation_id = "admin_users_reinvite", params(("id" = i64, Path)),
    responses((status = 200, body = InviteResult)))]
async fn reinvite(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<i64>,
) -> AppResult<Json<InviteResult>> {
    require_admin(&user)?;
    let target = admin_user(&state, id).await?;
    if target.status != "invited" {
        return Err(AppError::Conflict("this user has already joined".into()));
    }
    let (invite_url, emailed) = issue_invite(&state, id, target.email.as_deref().unwrap_or_default()).await?;
    state
        .audit
        .record(
            user.event(Action::UserInvited)
                .client(&client)
                .target("user", id.to_string(), target.email.clone())
                .detail("reissued", true),
        )
        .await?;
    Ok(Json(InviteResult {
        user: target,
        invite_url,
        emailed,
    }))
}

#[derive(Serialize, ToSchema)]
pub struct AdminShare {
    pub share: ShareSummary,
    pub owner_id: i64,
    pub owner: String,
}

/// Every share in the organisation: settings and status only, never content.
#[utoipa::path(get, path = "/admin/shares", tag = "admin", operation_id = "admin_shares_list", responses((status = 200, body = Vec<AdminShare>)))]
async fn list_shares(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<Vec<AdminShare>>> {
    require_admin(&user)?;
    let rows: Vec<store::ShareRow> = sqlx::query_as("SELECT * FROM shares ORDER BY created_at DESC LIMIT 1000")
        .fetch_all(&state.db)
        .await?;
    let owners: Vec<(i64, String)> = sqlx::query_as("SELECT id, coalesce(email, name) FROM users")
        .fetch_all(&state.db)
        .await?;
    let mut rules = std::collections::HashMap::<String, Vec<_>>::new();
    for (id, r) in store::all_rules(&state.db).await? {
        rules.entry(id).or_default().push(r);
    }
    Ok(Json(
        rows.iter()
            .map(|r| AdminShare {
                owner_id: r.owner_id,
                owner: owners.iter().find(|o| o.0 == r.owner_id).map(|o| o.1.clone()).unwrap_or_default(),
                share: summary(&state, r, rules.remove(&r.id).unwrap_or_default()),
            })
            .collect(),
    ))
}

/// Revoke any share (its content is destroyed immediately).
#[utoipa::path(post, path = "/admin/shares/{id}/revoke", tag = "admin", operation_id = "admin_shares_revoke", params(("id" = String, Path)),
    responses((status = 204), (status = 404, body = crate::error::ErrorBody)))]
async fn revoke_share(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    require_admin(&user)?;
    let row = store::by_id(&state.db, &id).await?.ok_or(AppError::NotFound)?;
    store::wipe(&state.db, &id, Wipe::Revoked).await?;
    store::destroy_files(&state, &id).await?;
    state
        .audit
        .record(
            row.event(Action::ShareRevoked)
                .user(user.id, &user.label)
                .client(&client)
                .detail("by_admin", true),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct DirectoryUser {
    pub id: i64,
    pub email: Option<String>,
    pub name: String,
}

/// Active members, for picking people in access rules.
#[utoipa::path(get, path = "/directory/users", tag = "org", operation_id = "directory_users", responses((status = 200, body = Vec<DirectoryUser>)))]
async fn directory(State(state): State<AppState>, _user: CurrentUser) -> AppResult<Json<Vec<DirectoryUser>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT id, email, name FROM users WHERE status = 'active' AND role != 'auditor' ORDER BY lower(coalesce(email, name))",
        )
        .fetch_all(&state.db)
        .await?,
    ))
}

#[derive(Serialize, ToSchema)]
pub struct InviteInfo {
    pub email: String,
    pub name: String,
}

fn invite_lookup_sql() -> &'static str {
    "SELECT id, email, name FROM users WHERE invite_token_hash = ? AND invite_expires_at > ? AND status = 'invited'"
}

/// Who an invite link is for (404 when invalid or expired).
#[utoipa::path(get, path = "/invites/{token}", tag = "org", operation_id = "invite_info", params(("token" = String, Path)),
    responses((status = 200, body = InviteInfo), (status = 404, body = crate::error::ErrorBody)))]
async fn invite_info(State(state): State<AppState>, Path(token): Path<String>) -> AppResult<Json<InviteInfo>> {
    let row: Option<(i64, String, String)> = sqlx::query_as(invite_lookup_sql())
        .bind(sha256(token.as_bytes()))
        .bind(now())
        .fetch_optional(&state.db)
        .await?;
    let (_, email, name) = row.ok_or(AppError::NotFound)?;
    Ok(Json(InviteInfo { email, name }))
}

#[derive(Deserialize, ToSchema)]
pub struct AcceptInvite {
    pub password: String,
    pub name: Option<String>,
}

/// Accept an invite: set a password, activate the account and sign in.
#[utoipa::path(post, path = "/invites/{token}/accept", tag = "org", operation_id = "invite_accept", params(("token" = String, Path)), request_body = AcceptInvite,
    responses((status = 200, body = MeResponse), (status = 404, body = crate::error::ErrorBody)))]
async fn accept_invite(
    State(state): State<AppState>,
    client: ClientInfo,
    jar: CookieJar,
    Path(token): Path<String>,
    Json(req): Json<AcceptInvite>,
) -> AppResult<(CookieJar, Json<MeResponse>)> {
    if !state.limits.login.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let row: Option<(i64, String, String)> = sqlx::query_as(invite_lookup_sql())
        .bind(sha256(token.as_bytes()))
        .bind(now())
        .fetch_optional(&state.db)
        .await?;
    let (id, email, _) = row.ok_or(AppError::NotFound)?;
    if req.password.chars().count() < 12 {
        return Err(AppError::BadRequest("use at least 12 characters".into()));
    }
    let password = req.password;
    let hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(anyhow::Error::from)??;
    let name = req.name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    sqlx::query(
        "UPDATE users SET password_hash = ?, status = 'active', invite_token_hash = NULL, invite_expires_at = NULL, name = coalesce(?, name)
         WHERE id = ? AND status = 'invited'",
    )
    .bind(hash)
    .bind(name)
    .bind(id)
    .execute(&state.db)
    .await?;
    let user = crate::auth::users::load_user(&state, id).await?;
    let (jar, session) = start_session(&state, jar, &user, None).await?;
    state
        .audit
        .record(
            Event::new(Action::UserInviteAccepted)
                .user(id, &email)
                .client(&client)
                .target("user", id.to_string(), Some(email.clone())),
        )
        .await?;
    Ok((jar, Json(me_response(&state, Some(&session)).await?)))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_users, invite))
        .routes(routes!(update_user))
        .routes(routes!(reset_mfa))
        .routes(routes!(sign_out))
        .routes(routes!(reinvite))
        .routes(routes!(list_shares))
        .routes(routes!(revoke_share))
        .routes(routes!(directory))
        .routes(routes!(invite_info))
        .routes(routes!(accept_invite))
}
