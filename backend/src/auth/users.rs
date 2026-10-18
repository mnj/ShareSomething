//! User accounts: argon2id password + optional TOTP, cookie sessions, MFA step-up.
//!
//! Single mode has exactly one user (id 1, admin) and no email: sign-in is "the password". Team mode
//! adds more users identified by email (invites/SSO arrive in a later phase).

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json,
    extract::{FromRequestParts, OptionalFromRequestParts, State},
    http::request::Parts,
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::totp;
use crate::{
    app::AppState,
    audit::{Action, Event},
    config::InstanceMode,
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    shares::policy::MFA_FRESH_SECS,
    util::{now, random_token, sha256},
};

pub const COOKIE: &str = "ss_session";
/// The single-mode owner.
pub const OWNER_ID: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(rename_all = "lowercase", type_name = "TEXT")]
pub enum Role {
    Admin,
    Member,
    /// Read-only access to the audit trail; no shares.
    Auditor,
}

/// The signed-in user of the current request.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: i64,
    pub role: Role,
    /// Email, or the display name when there is none (single-mode owner).
    pub label: String,
    pub mfa_at: Option<i64>,
    token_hash: Vec<u8>,
}

impl CurrentUser {
    pub fn token_hash(&self) -> &[u8] {
        &self.token_hash
    }

    pub fn mfa_fresh(&self) -> bool {
        self.mfa_at.is_some_and(|t| now() - t <= MFA_FRESH_SECS)
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }

    /// May read the audit trail.
    pub fn can_audit(&self) -> bool {
        matches!(self.role, Role::Admin | Role::Auditor)
    }

    /// May create and manage shares: not an auditor, and MFA set up if the org requires it.
    pub async fn ensure_can_share(&self, state: &AppState) -> AppResult<()> {
        if self.role == Role::Auditor {
            return Err(AppError::Forbidden("auditors have read-only access".into()));
        }
        if mfa_setup_required(state, self.id).await? {
            return Err(AppError::Access(
                "mfa_setup_required",
                "your organisation requires a passkey or authenticator app; set one up in Settings".into(),
            ));
        }
        Ok(())
    }

    /// Attributes an audit event to this user.
    pub fn event(&self, action: Action) -> Event {
        Event::new(action).user(self.id, &self.label)
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct UserRow {
    pub id: i64,
    pub email: Option<String>,
    pub name: String,
    pub role: Role,
    pub status: String,
    pub password_hash: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_last_step: Option<i64>,
}

impl UserRow {
    pub fn label(&self) -> String {
        self.email.clone().unwrap_or_else(|| self.name.clone())
    }
}

const USER_COLS: &str = "id, email, name, role, status, password_hash, totp_secret, totp_last_step";

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))?
        .to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

pub(crate) async fn load_user(state: &AppState, id: i64) -> AppResult<UserRow> {
    sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLS} FROM users WHERE id = ?"))
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotInitialised)
}

/// Finds the account a sign-in attempt is for: by email in team mode, the owner in single mode.
pub(super) async fn resolve_login_user(state: &AppState, email: Option<&str>) -> AppResult<Option<UserRow>> {
    let any: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users").fetch_one(&state.db).await?;
    if any.0 == 0 {
        return Err(AppError::NotInitialised);
    }
    match email.map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty()) {
        Some(email) => Ok(
            sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLS} FROM users WHERE email = ?"))
                .bind(email)
                .fetch_optional(&state.db)
                .await?,
        ),
        None if state.cfg.mode == InstanceMode::Single => Ok(Some(load_user(state, OWNER_ID).await?)),
        None => Err(AppError::BadRequest("enter your email address".into())),
    }
}

/// Verifies a TOTP code and records its step so it can't be replayed.
async fn check_totp(state: &AppState, user: &UserRow, code: &str) -> AppResult<bool> {
    let Some(secret) = &user.totp_secret else {
        return Ok(false);
    };
    let Some(step) = totp::verify(secret, code, now())? else {
        return Ok(false);
    };
    if user.totp_last_step.is_some_and(|last| step <= last) {
        return Ok(false);
    }
    // Conditional update makes concurrent use of the same code fail for all but one request.
    let res = sqlx::query("UPDATE users SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)")
        .bind(step)
        .bind(user.id)
        .bind(step)
        .execute(&state.db)
        .await?;
    Ok(res.rows_affected() == 1)
}

/// (mfa_at, user id, role, email, name)
type SessionRow = (Option<i64>, i64, Role, Option<String>, String);

async fn session_from_jar(state: &AppState, jar: &CookieJar) -> AppResult<Option<CurrentUser>> {
    let Some(cookie) = jar.get(COOKIE) else {
        return Ok(None);
    };
    let token_hash = sha256(cookie.value().as_bytes());
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT s.mfa_at, u.id, u.role, u.email, u.name FROM user_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > ? AND u.status = 'active'",
    )
    .bind(&token_hash)
    .bind(now())
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|(mfa_at, id, role, email, name)| CurrentUser {
        id,
        role,
        label: email.unwrap_or(name),
        mfa_at,
        token_hash,
    }))
}

impl OptionalFromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Option<Self>, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        session_from_jar(state, &jar).await
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        <CurrentUser as OptionalFromRequestParts<AppState>>::from_request_parts(parts, state)
            .await?
            .ok_or(AppError::Unauthorized)
    }
}

fn session_cookie(state: &AppState, value: String, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((COOKIE, value))
        .http_only(true)
        .secure(state.cfg.cookie_secure())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(max_age_secs))
        .build()
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    /// Team mode: the account's email. Single mode: omit.
    pub email: Option<String>,
    pub password: String,
    /// Required when TOTP is enabled.
    pub totp: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct StepUpRequest {
    pub totp: String,
}

#[derive(Serialize, ToSchema)]
pub struct UserInfo {
    pub id: i64,
    pub email: Option<String>,
    pub name: String,
    pub role: Role,
    /// Webhook for notifications (Slack/Teams/Mattermost-compatible).
    pub notify_webhook: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct MeResponse {
    pub authenticated: bool,
    pub initialised: bool,
    /// `single` or `team`.
    pub mode: String,
    pub user: Option<UserInfo>,
    /// TOTP state of the signed-in user (single mode: of the owner, so the login form can ask for it).
    pub totp_enabled: bool,
    /// Registered passkeys (same scoping as `totp_enabled`); passkey sign-in is offered when > 0.
    pub passkeys: i64,
    /// Unix time until which the last MFA (TOTP or passkey) satisfies "require owner MFA" shares.
    pub mfa_valid_until: Option<i64>,
    /// The org requires MFA and this user hasn't set any up yet (sharing is blocked until they do).
    pub mfa_setup_required: bool,
}

/// Org policy says members need MFA, and this user has neither TOTP nor a passkey. Accounts that
/// sign in through SSO count as covered: their identity provider enforces MFA.
pub async fn mfa_setup_required(state: &AppState, user_id: i64) -> AppResult<bool> {
    if !crate::org::settings::load(state).await?.require_mfa {
        return Ok(false);
    }
    let sso: (Option<String>,) = sqlx::query_as("SELECT sso_provider FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    Ok(sso.0.is_none() && !user_has_mfa(state, user_id).await?)
}

pub(super) async fn passkey_count(state: &AppState, user_id: i64) -> AppResult<i64> {
    Ok(sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?
        .0)
}

pub(crate) async fn me_response(state: &AppState, user: Option<&CurrentUser>) -> AppResult<MeResponse> {
    let initialised = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?
        .0
        > 0;
    let single = state.cfg.mode == InstanceMode::Single;
    // Whose factors to describe: the signed-in user, or (single mode, signed out) the owner.
    let subject = match user {
        Some(u) => Some(u.id),
        None if single && initialised => Some(OWNER_ID),
        None => None,
    };
    let row = match subject {
        Some(id) => load_user(state, id).await.ok(),
        None => None,
    };
    let webhook: Option<String> = match user {
        Some(u) => {
            sqlx::query_as::<_, (Option<String>,)>("SELECT notify_webhook FROM users WHERE id = ?")
                .bind(u.id)
                .fetch_one(&state.db)
                .await?
                .0
        }
        None => None,
    };
    Ok(MeResponse {
        authenticated: user.is_some(),
        initialised,
        mode: if single { "single" } else { "team" }.into(),
        user: user.and(row.as_ref()).map(|r| UserInfo {
            id: r.id,
            email: r.email.clone(),
            name: r.name.clone(),
            role: r.role,
            notify_webhook: webhook.clone(),
        }),
        totp_enabled: row.as_ref().is_some_and(|r| r.totp_secret.is_some()),
        passkeys: match subject {
            Some(id) => passkey_count(state, id).await?,
            None => 0,
        },
        mfa_valid_until: user.and_then(|o| o.mfa_at).map(|t| t + MFA_FRESH_SECS).filter(|t| *t > now()),
        mfa_setup_required: match user {
            Some(u) => mfa_setup_required(state, u.id).await?,
            None => false,
        },
    })
}

/// Creates a session for `user` and adds its cookie.
pub(crate) async fn start_session(
    state: &AppState,
    jar: CookieJar,
    user: &UserRow,
    mfa_at: Option<i64>,
) -> AppResult<(CookieJar, CurrentUser)> {
    let token = random_token();
    let ttl = state.cfg.session_ttl_hours * 3600;
    let token_hash = sha256(token.as_bytes());
    sqlx::query("INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at, mfa_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&token_hash)
        .bind(user.id)
        .bind(now())
        .bind(now() + ttl)
        .bind(mfa_at)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
        .bind(now())
        .bind(user.id)
        .execute(&state.db)
        .await?;
    Ok((
        jar.add(session_cookie(state, token, ttl)),
        CurrentUser {
            id: user.id,
            role: user.role,
            label: user.label(),
            mfa_at,
            token_hash,
        },
    ))
}

/// Records a successful MFA (TOTP or passkey) on the current session.
pub(super) async fn mark_mfa(state: &AppState, user: CurrentUser) -> AppResult<CurrentUser> {
    let t = now();
    sqlx::query("UPDATE user_sessions SET mfa_at = ? WHERE token_hash = ?")
        .bind(t)
        .bind(&user.token_hash)
        .execute(&state.db)
        .await?;
    Ok(CurrentUser { mfa_at: Some(t), ..user })
}

/// A throwaway hash so a login for an unknown account costs as much as a real one.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$Hk2CaxcYsYk0MgwyE1JN2+B3H6HLBIL2wW1qxk+rvRI";

/// Sign in with a password (+ TOTP when enabled).
#[utoipa::path(post, path = "/auth/login", tag = "auth", request_body = LoginRequest,
    responses((status = 200, body = MeResponse), (status = 401, body = crate::error::ErrorBody)))]
async fn login(
    State(state): State<AppState>,
    client: ClientInfo,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> AppResult<(CookieJar, Json<MeResponse>)> {
    if !state.limits.login.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let user = resolve_login_user(&state, req.email.as_deref()).await?;
    let hash = user
        .as_ref()
        .and_then(|u| u.password_hash.clone())
        .unwrap_or_else(|| DUMMY_HASH.into());
    let password = req.password;
    let password_ok = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(anyhow::Error::from)?;
    let failed = |reason: &str, user: Option<&UserRow>| {
        let e = Event::new(Action::AuthLoginFailed)
            .denied()
            .client(&client)
            .detail("reason", reason)
            .detail("method", "password");
        match user {
            Some(u) => e.user(u.id, u.label()),
            None => e.recipient(req.email.clone()),
        }
    };
    let Some(user) = user.filter(|u| password_ok && u.password_hash.is_some()) else {
        state.audit.record(failed("bad_credentials", None)).await?;
        tracing::warn!(ip = %client.ip, "login failed");
        return Err(AppError::AuthFailed("invalid_credentials", "invalid password or code"));
    };
    if user.status != "active" {
        state.audit.record(failed("account_disabled", Some(&user))).await?;
        return Err(AppError::AuthFailed("invalid_credentials", "invalid password or code"));
    }
    let mfa_at = match (&user.totp_secret, req.totp.as_deref()) {
        (None, _) => None,
        (Some(_), None) => return Err(AppError::AuthFailed("totp_required", "enter the code from your authenticator app")),
        (Some(_), Some(code)) => {
            if !check_totp(&state, &user, code).await? {
                state.audit.record(failed("bad_totp", Some(&user))).await?;
                tracing::warn!(ip = %client.ip, "login failed: bad TOTP");
                return Err(AppError::AuthFailed("invalid_credentials", "invalid password or code"));
            }
            Some(now())
        }
    };
    let (jar, session) = start_session(&state, jar, &user, mfa_at).await?;
    state
        .audit
        .record(
            session
                .event(Action::AuthLogin)
                .client(&client)
                .detail("method", if mfa_at.is_some() { "password+totp" } else { "password" }),
        )
        .await?;
    Ok((jar, Json(me_response(&state, Some(&session)).await?)))
}

/// Sign out and invalidate the current session.
#[utoipa::path(post, path = "/auth/logout", tag = "auth", responses((status = 200, body = MeResponse)))]
async fn logout(
    State(state): State<AppState>,
    client: ClientInfo,
    user: Option<CurrentUser>,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<MeResponse>)> {
    if let Some(u) = user {
        sqlx::query("DELETE FROM user_sessions WHERE token_hash = ?")
            .bind(&u.token_hash)
            .execute(&state.db)
            .await?;
        state.audit.record(u.event(Action::AuthLogout).client(&client)).await?;
    }
    let me = me_response(&state, None).await?;
    Ok((jar.remove(session_cookie(&state, String::new(), 0)), Json(me)))
}

/// Current session state.
#[utoipa::path(get, path = "/auth/me", tag = "auth", responses((status = 200, body = MeResponse)))]
async fn me(State(state): State<AppState>, user: Option<CurrentUser>) -> AppResult<Json<MeResponse>> {
    Ok(Json(me_response(&state, user.as_ref()).await?))
}

/// Re-confirm TOTP to open shares that require fresh owner MFA.
#[utoipa::path(post, path = "/auth/step-up", tag = "auth", request_body = StepUpRequest,
    responses((status = 200, body = MeResponse), (status = 401, body = crate::error::ErrorBody)))]
async fn step_up(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Json(req): Json<StepUpRequest>,
) -> AppResult<Json<MeResponse>> {
    if !state.limits.login.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let row = load_user(&state, user.id).await?;
    if row.totp_secret.is_none() {
        return Err(AppError::BadRequest("TOTP is not set up for this account".into()));
    }
    if !check_totp(&state, &row, &req.totp).await? {
        state
            .audit
            .record(
                user.event(Action::AuthStepUpFailed)
                    .denied()
                    .client(&client)
                    .detail("method", "totp"),
            )
            .await?;
        return Err(AppError::AuthFailed("invalid_code", "invalid code"));
    }
    let fresh = mark_mfa(&state, user).await?;
    state
        .audit
        .record(fresh.event(Action::AuthStepUp).client(&client).detail("method", "totp"))
        .await?;
    Ok(Json(me_response(&state, Some(&fresh)).await?))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(login))
        .routes(routes!(logout))
        .routes(routes!(me))
        .routes(routes!(step_up))
        .routes(routes!(totp_setup))
        .routes(routes!(totp_confirm))
        .routes(routes!(totp_disable))
        .routes(routes!(update_profile))
}

#[derive(Deserialize, ToSchema)]
pub struct ProfileUpdate {
    pub name: Option<String>,
    /// Notification email. Single mode only (in team mode the email is the account identity).
    pub email: Option<String>,
    /// https webhook for notifications; empty string removes it.
    pub notify_webhook: Option<String>,
}

/// Update your name, notification email or webhook.
#[utoipa::path(put, path = "/auth/profile", tag = "auth", operation_id = "profile_update", request_body = ProfileUpdate,
    responses((status = 200, body = MeResponse), (status = 400, body = crate::error::ErrorBody)))]
async fn update_profile(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Json(req): Json<ProfileUpdate>,
) -> AppResult<Json<MeResponse>> {
    let mut changed = vec![];
    if let Some(name) = req.name.map(|n| n.trim().to_string()) {
        if name.is_empty() || name.chars().count() > 80 {
            return Err(AppError::BadRequest("name must be 1-80 characters".into()));
        }
        sqlx::query("UPDATE users SET name = ? WHERE id = ?")
            .bind(&name)
            .bind(user.id)
            .execute(&state.db)
            .await?;
        changed.push("name");
    }
    if let Some(email) = req.email.map(|e| e.trim().to_ascii_lowercase()) {
        if state.cfg.mode != InstanceMode::Single {
            return Err(AppError::BadRequest("in team mode an admin changes account emails".into()));
        }
        let email = (!email.is_empty()).then_some(email);
        if email.as_ref().is_some_and(|e| !e.contains('@') || e.len() > 254) {
            return Err(AppError::BadRequest("enter a valid email address".into()));
        }
        sqlx::query("UPDATE users SET email = ? WHERE id = ?")
            .bind(&email)
            .bind(user.id)
            .execute(&state.db)
            .await?;
        changed.push("email");
    }
    if let Some(hook) = req.notify_webhook.map(|h| h.trim().to_string()) {
        let hook = (!hook.is_empty()).then_some(hook);
        if let Some(h) = &hook {
            crate::notify::validate_webhook(h)?;
        }
        sqlx::query("UPDATE users SET notify_webhook = ? WHERE id = ?")
            .bind(&hook)
            .bind(user.id)
            .execute(&state.db)
            .await?;
        changed.push("notify_webhook");
    }
    if !changed.is_empty() {
        state
            .audit
            .record(
                user.event(Action::UserUpdated)
                    .client(&client)
                    .target("user", user.id.to_string(), Some(user.label.clone()))
                    .detail("changed", &changed),
            )
            .await?;
    }
    Ok(Json(me_response(&state, Some(&user)).await?))
}

/// Changing credentials requires a recent second factor, if one exists.
pub async fn require_fresh_mfa(state: &AppState, user: &CurrentUser) -> AppResult<()> {
    if user_has_mfa(state, user.id).await? && !user.mfa_fresh() {
        return Err(AppError::Access(
            "need_owner_mfa",
            "confirm with your authenticator or a passkey first".into(),
        ));
    }
    Ok(())
}

const TOTP_SETUP_TTL_SECS: i64 = 10 * 60;

#[derive(Serialize, ToSchema)]
pub struct TotpSetup {
    /// Base32 secret for manual entry.
    pub secret: String,
    pub otpauth_url: String,
    /// QR code as an SVG data URL.
    pub qr_svg: String,
}

#[derive(Deserialize, ToSchema)]
pub struct TotpConfirm {
    pub code: String,
}

/// Start (re)configuring the authenticator app. Needs a fresh MFA if a second factor exists.
#[utoipa::path(post, path = "/auth/totp/setup", tag = "auth", operation_id = "totp_setup",
    responses((status = 200, body = TotpSetup), (status = 403, body = crate::error::ErrorBody)))]
async fn totp_setup(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<TotpSetup>> {
    use base64::Engine;
    require_fresh_mfa(&state, &user).await?;
    let secret = totp::new_secret();
    let otpauth_url = totp::otpauth_url(&secret)?;
    let svg = qrcode::QrCode::new(otpauth_url.as_bytes())
        .map_err(anyhow::Error::from)?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .build();
    sqlx::query("UPDATE users SET totp_pending = ?, totp_pending_at = ? WHERE id = ?")
        .bind(&secret)
        .bind(now())
        .bind(user.id)
        .execute(&state.db)
        .await?;
    let qr_svg = format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg)
    );
    Ok(Json(TotpSetup {
        secret,
        otpauth_url,
        qr_svg,
    }))
}

/// Confirm the new authenticator with a code from it; replaces any previous TOTP secret.
#[utoipa::path(post, path = "/auth/totp/confirm", tag = "auth", operation_id = "totp_confirm", request_body = TotpConfirm,
    responses((status = 200, body = MeResponse), (status = 401, body = crate::error::ErrorBody)))]
async fn totp_confirm(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Json(req): Json<TotpConfirm>,
) -> AppResult<Json<MeResponse>> {
    if !state.limits.login.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let (pending, at): (Option<String>, Option<i64>) = sqlx::query_as("SELECT totp_pending, totp_pending_at FROM users WHERE id = ?")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    let Some(secret) = pending.filter(|_| at.is_some_and(|t| now() - t <= TOTP_SETUP_TTL_SECS)) else {
        return Err(AppError::BadRequest("start the setup again; it expired".into()));
    };
    let Some(step) = totp::verify(&secret, &req.code, now())? else {
        return Err(AppError::AuthFailed(
            "invalid_code",
            "that code doesn't match; check the time on your device",
        ));
    };
    sqlx::query("UPDATE users SET totp_secret = ?, totp_last_step = ?, totp_pending = NULL, totp_pending_at = NULL WHERE id = ?")
        .bind(&secret)
        .bind(step)
        .bind(user.id)
        .execute(&state.db)
        .await?;
    let fresh = mark_mfa(&state, user).await?;
    state.audit.record(fresh.event(Action::AuthTotpEnabled).client(&client)).await?;
    Ok(Json(me_response(&state, Some(&fresh)).await?))
}

/// Turn off the authenticator app. Refused if it would leave "require owner MFA" shares unopenable.
#[utoipa::path(delete, path = "/auth/totp", tag = "auth", operation_id = "totp_disable",
    responses((status = 200, body = MeResponse), (status = 409, body = crate::error::ErrorBody)))]
async fn totp_disable(State(state): State<AppState>, client: ClientInfo, user: CurrentUser) -> AppResult<Json<MeResponse>> {
    require_fresh_mfa(&state, &user).await?;
    let mfa_shares: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM shares WHERE owner_id = ? AND require_owner_mfa = 1 AND ciphertext IS NOT NULL")
            .bind(user.id)
            .fetch_one(&state.db)
            .await?;
    if passkey_count(&state, user.id).await? == 0 && mfa_shares.0 > 0 {
        return Err(AppError::Conflict(format!(
            "{} active share(s) require owner MFA; add a passkey first or change those shares",
            mfa_shares.0
        )));
    }
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_last_step = NULL WHERE id = ?")
        .bind(user.id)
        .execute(&state.db)
        .await?;
    state.audit.record(user.event(Action::AuthTotpDisabled).client(&client)).await?;
    Ok(Json(me_response(&state, Some(&user)).await?))
}

/// Whether a user has a second factor (TOTP or a passkey) for MFA step-ups.
pub async fn user_has_mfa(state: &AppState, user_id: i64) -> AppResult<bool> {
    Ok(load_user(state, user_id).await?.totp_secret.is_some() || passkey_count(state, user_id).await? > 0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dummy_hash_is_valid_argon2() {
        // If this ever fails, unknown-account logins would be measurably faster than real ones.
        assert!(argon2::PasswordHash::new(super::DUMMY_HASH).is_ok());
        assert!(!super::verify_password("anything", super::DUMMY_HASH));
    }
}
