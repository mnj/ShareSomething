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
    /// Unix time until which the last TOTP step-up satisfies "require owner MFA" shares.
    pub mfa_valid_until: Option<i64>,
}

async fn me_response(state: &AppState, owner: Option<&Owner>) -> AppResult<MeResponse> {
    let row = load_owner(state).await.ok();
    Ok(MeResponse {
        authenticated: owner.is_some(),
        initialised: row.is_some(),
        totp_enabled: row.as_ref().is_some_and(|r| r.totp_secret.is_some()),
        mfa_valid_until: owner.and_then(|o| o.mfa_at).map(|t| t + MFA_FRESH_SECS).filter(|t| *t > now()),
    })
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

    let token = random_token();
    let ttl = state.cfg.session_ttl_hours * 3600;
    sqlx::query("INSERT INTO owner_sessions (token_hash, created_at, expires_at, mfa_at) VALUES (?, ?, ?, ?)")
        .bind(sha256(token.as_bytes()))
        .bind(now())
        .bind(now() + ttl)
        .bind(mfa_at)
        .execute(&state.db)
        .await?;
    tracing::info!(ip = %client.ip, "owner logged in");
    let session = Owner {
        mfa_at,
        token_hash: vec![],
    };
    let me = me_response(&state, Some(&session)).await?;
    Ok((jar.add(session_cookie(&state, token, ttl)), Json(me)))
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
    let t = now();
    sqlx::query("UPDATE owner_sessions SET mfa_at = ? WHERE token_hash = ?")
        .bind(t)
        .bind(&owner.token_hash)
        .execute(&state.db)
        .await?;
    let fresh = Owner { mfa_at: Some(t), ..owner };
    Ok(Json(me_response(&state, Some(&fresh)).await?))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(login))
        .routes(routes!(logout))
        .routes(routes!(me))
        .routes(routes!(step_up))
}

pub async fn owner_has_totp(state: &AppState) -> AppResult<bool> {
    Ok(load_owner(state).await?.totp_secret.is_some())
}
