//! Owner authentication: argon2id password + optional TOTP, cookie sessions, MFA step-up.

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
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    shares::policy::MFA_FRESH_SECS,
    util::{now, random_token, sha256},
};

pub const COOKIE: &str = "ss_owner";

/// An authenticated owner session.
#[derive(Debug, Clone)]
pub struct Owner {
    pub mfa_at: Option<i64>,
    token_hash: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct OwnerRow {
    password_hash: String,
    totp_secret: Option<String>,
    totp_last_step: Option<i64>,
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))?
        .to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

async fn load_owner(state: &AppState) -> AppResult<OwnerRow> {
    sqlx::query_as::<_, OwnerRow>("SELECT password_hash, totp_secret, totp_last_step FROM owner WHERE id = 1")
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotInitialised)
}

/// Verifies a TOTP code and records its step so it can't be replayed.
async fn check_totp(state: &AppState, owner: &OwnerRow, code: &str) -> AppResult<bool> {
    let Some(secret) = &owner.totp_secret else {
        return Ok(false);
    };
    let Some(step) = totp::verify(secret, code, now())? else {
        return Ok(false);
    };
    if owner.totp_last_step.is_some_and(|last| step <= last) {
        return Ok(false);
    }
    // Conditional update makes concurrent use of the same code fail for all but one request.
    let res = sqlx::query("UPDATE owner SET totp_last_step = ? WHERE id = 1 AND (totp_last_step IS NULL OR totp_last_step < ?)")
        .bind(step)
        .bind(step)
        .execute(&state.db)
        .await?;
    Ok(res.rows_affected() == 1)
}

async fn session_from_jar(state: &AppState, jar: &CookieJar) -> AppResult<Option<Owner>> {
    let Some(cookie) = jar.get(COOKIE) else {
        return Ok(None);
    };
    let token_hash = sha256(cookie.value().as_bytes());
    let row: Option<(Option<i64>,)> = sqlx::query_as("SELECT mfa_at FROM owner_sessions WHERE token_hash = ? AND expires_at > ?")
        .bind(&token_hash)
        .bind(now())
        .fetch_optional(&state.db)
        .await?;
    Ok(row.map(|(mfa_at,)| Owner { mfa_at, token_hash }))
}

impl OptionalFromRequestParts<AppState> for Owner {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Option<Self>, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        session_from_jar(state, &jar).await
    }
}

impl FromRequestParts<AppState> for Owner {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        <Owner as OptionalFromRequestParts<AppState>>::from_request_parts(parts, state)
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
        .max_age(time_duration(max_age_secs))
        .build()
}

fn time_duration(secs: i64) -> time::Duration {
    time::Duration::seconds(secs)
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub password: String,
    /// Required when TOTP is enabled.
    pub totp: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct StepUpRequest {
    pub totp: String,
}

#[derive(Serialize, ToSchema)]
pub struct MeResponse {
    pub authenticated: bool,
    pub initialised: bool,
    pub totp_enabled: bool,
    /// Number of registered passkeys (passkey sign-in is offered when > 0).
    pub passkeys: i64,
    /// Unix time until which the last MFA (TOTP or passkey) satisfies "require owner MFA" shares.
    pub mfa_valid_until: Option<i64>,
}

pub(super) async fn passkey_count(state: &AppState) -> AppResult<i64> {
    Ok(sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM owner_passkeys")
        .fetch_one(&state.db)
        .await?
        .0)
}

pub(super) async fn me_response(state: &AppState, owner: Option<&Owner>) -> AppResult<MeResponse> {
    let row = load_owner(state).await.ok();
    Ok(MeResponse {
        authenticated: owner.is_some(),
        initialised: row.is_some(),
        totp_enabled: row.as_ref().is_some_and(|r| r.totp_secret.is_some()),
        passkeys: passkey_count(state).await?,
        mfa_valid_until: owner.and_then(|o| o.mfa_at).map(|t| t + MFA_FRESH_SECS).filter(|t| *t > now()),
    })
}

/// Creates an owner session and adds its cookie.
pub(super) async fn start_session(state: &AppState, jar: CookieJar, mfa_at: Option<i64>) -> AppResult<(CookieJar, Owner)> {
    let token = random_token();
    let ttl = state.cfg.session_ttl_hours * 3600;
    let token_hash = sha256(token.as_bytes());
    sqlx::query("INSERT INTO owner_sessions (token_hash, created_at, expires_at, mfa_at) VALUES (?, ?, ?, ?)")
        .bind(&token_hash)
        .bind(now())
        .bind(now() + ttl)
        .bind(mfa_at)
        .execute(&state.db)
        .await?;
    Ok((jar.add(session_cookie(state, token, ttl)), Owner { mfa_at, token_hash }))
}

/// Records a successful MFA (TOTP or passkey) on the current session.
pub(super) async fn mark_mfa(state: &AppState, owner: Owner) -> AppResult<Owner> {
    let t = now();
    sqlx::query("UPDATE owner_sessions SET mfa_at = ? WHERE token_hash = ?")
        .bind(t)
        .bind(&owner.token_hash)
        .execute(&state.db)
        .await?;
    Ok(Owner { mfa_at: Some(t), ..owner })
}

impl Owner {
    pub fn token_hash(&self) -> &[u8] {
        &self.token_hash
    }

    pub fn mfa_fresh(&self) -> bool {
        self.mfa_at.is_some_and(|t| now() - t <= MFA_FRESH_SECS)
    }
}

/// Log in as the owner.
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
    let owner = load_owner(&state).await?;
    let hash = owner.password_hash.clone();
    let password = req.password;
    let ok = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .map_err(anyhow::Error::from)?;
    if !ok {
        tracing::warn!(ip = %client.ip, "owner login failed: bad password");
        return Err(AppError::AuthFailed("invalid_credentials", "invalid password or code"));
    }
    let mfa_at = match (&owner.totp_secret, req.totp.as_deref()) {
        (None, _) => None,
        (Some(_), None) => {
            return Err(AppError::AuthFailed("totp_required", "enter the code from your authenticator app"));
        }
        (Some(_), Some(code)) => {
            if !check_totp(&state, &owner, code).await? {
                tracing::warn!(ip = %client.ip, "owner login failed: bad TOTP");
                return Err(AppError::AuthFailed("invalid_credentials", "invalid password or code"));
            }
            Some(now())
        }
    };

    let (jar, session) = start_session(&state, jar, mfa_at).await?;
    tracing::info!(ip = %client.ip, "owner logged in");
    let me = me_response(&state, Some(&session)).await?;
    Ok((jar, Json(me)))
}

/// Log out and invalidate the current session.
#[utoipa::path(post, path = "/auth/logout", tag = "auth", responses((status = 200, body = MeResponse)))]
async fn logout(State(state): State<AppState>, owner: Option<Owner>, jar: CookieJar) -> AppResult<(CookieJar, Json<MeResponse>)> {
    if let Some(o) = owner {
        sqlx::query("DELETE FROM owner_sessions WHERE token_hash = ?")
            .bind(&o.token_hash)
            .execute(&state.db)
            .await?;
    }
    let me = me_response(&state, None).await?;
    Ok((jar.remove(session_cookie(&state, String::new(), 0)), Json(me)))
}

/// Current owner session state.
#[utoipa::path(get, path = "/auth/me", tag = "auth", responses((status = 200, body = MeResponse)))]
async fn me(State(state): State<AppState>, owner: Option<Owner>) -> AppResult<Json<MeResponse>> {
    Ok(Json(me_response(&state, owner.as_ref()).await?))
}

/// Re-confirm TOTP to open shares that require fresh owner MFA.
#[utoipa::path(post, path = "/auth/step-up", tag = "auth", request_body = StepUpRequest,
    responses((status = 200, body = MeResponse), (status = 401, body = crate::error::ErrorBody)))]
async fn step_up(
    State(state): State<AppState>,
    client: ClientInfo,
    owner: Owner,
    Json(req): Json<StepUpRequest>,
) -> AppResult<Json<MeResponse>> {
    if !state.limits.login.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let row = load_owner(&state).await?;
    if row.totp_secret.is_none() {
        return Err(AppError::BadRequest(
            "TOTP is not configured; run `sharesomething admin reset-totp`".into(),
        ));
    }
    if !check_totp(&state, &row, &req.totp).await? {
        return Err(AppError::AuthFailed("invalid_code", "invalid code"));
    }
    let fresh = mark_mfa(&state, owner).await?;
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
}

/// Changing credentials requires a recent second factor, if one exists.
pub(super) async fn require_fresh_mfa(state: &AppState, owner: &Owner) -> AppResult<()> {
    if owner_has_mfa(state).await? && !owner.mfa_fresh() {
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
async fn totp_setup(State(state): State<AppState>, owner: Owner) -> AppResult<Json<TotpSetup>> {
    use base64::Engine;
    require_fresh_mfa(&state, &owner).await?;
    let secret = totp::new_secret();
    let otpauth_url = totp::otpauth_url(&secret)?;
    let svg = qrcode::QrCode::new(otpauth_url.as_bytes())
        .map_err(anyhow::Error::from)?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .build();
    sqlx::query("UPDATE owner SET totp_pending = ?, totp_pending_at = ? WHERE id = 1")
        .bind(&secret)
        .bind(now())
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
    owner: Owner,
    Json(req): Json<TotpConfirm>,
) -> AppResult<Json<MeResponse>> {
    if !state.limits.login.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let (pending, at): (Option<String>, Option<i64>) = sqlx::query_as("SELECT totp_pending, totp_pending_at FROM owner WHERE id = 1")
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
    sqlx::query("UPDATE owner SET totp_secret = ?, totp_last_step = ?, totp_pending = NULL, totp_pending_at = NULL WHERE id = 1")
        .bind(&secret)
        .bind(step)
        .execute(&state.db)
        .await?;
    tracing::info!("owner TOTP configured from the web UI");
    let fresh = mark_mfa(&state, owner).await?;
    Ok(Json(me_response(&state, Some(&fresh)).await?))
}

/// Turn off the authenticator app. Refused if it would leave "require owner MFA" shares unopenable.
#[utoipa::path(delete, path = "/auth/totp", tag = "auth", operation_id = "totp_disable",
    responses((status = 200, body = MeResponse), (status = 409, body = crate::error::ErrorBody)))]
async fn totp_disable(State(state): State<AppState>, owner: Owner) -> AppResult<Json<MeResponse>> {
    require_fresh_mfa(&state, &owner).await?;
    let mfa_shares: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM shares WHERE require_owner_mfa = 1 AND ciphertext IS NOT NULL")
        .fetch_one(&state.db)
        .await?;
    if passkey_count(&state).await? == 0 && mfa_shares.0 > 0 {
        return Err(AppError::Conflict(format!(
            "{} active share(s) require owner MFA; add a passkey first or change those shares",
            mfa_shares.0
        )));
    }
    sqlx::query("UPDATE owner SET totp_secret = NULL, totp_last_step = NULL WHERE id = 1")
        .execute(&state.db)
        .await?;
    tracing::info!("owner TOTP disabled from the web UI");
    Ok(Json(me_response(&state, Some(&owner)).await?))
}

/// Whether the owner has a second factor (TOTP or a passkey) for MFA step-ups.
pub async fn owner_has_mfa(state: &AppState) -> AppResult<bool> {
    Ok(load_owner(state).await?.totp_secret.is_some() || passkey_count(state).await? > 0)
}
