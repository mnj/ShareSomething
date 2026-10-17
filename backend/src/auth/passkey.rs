//! Owner passkeys (WebAuthn): register, sign in, and use as the MFA step-up.
//!
//! Passkeys require user verification, so a passkey sign-in counts as a fresh MFA. Ceremony
//! state lives in memory for a few minutes; a restart just means trying again.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Uuid, Webauthn, WebauthnBuilder,
};

use super::owner::{MeResponse, Owner, mark_mfa, me_response, require_fresh_mfa, start_session};
use crate::{
    app::AppState,
    config::Config,
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    util::{now, random_token},
};

const CEREMONY_TTL: Duration = Duration::from_secs(5 * 60);

enum Ceremony {
    Register { state: PasskeyRegistration, name: String },
    Login(PasskeyAuthentication),
    StepUp { state: PasskeyAuthentication, session: Vec<u8> },
}

pub struct Passkeys {
    webauthn: Option<Webauthn>,
    ceremonies: Mutex<HashMap<String, (Ceremony, Instant)>>,
}

impl Passkeys {
    /// The relying party is the host of `base_url`. WebAuthn needs a domain name (not an IP) and a
    /// secure context (https, or http://localhost); otherwise passkeys are disabled with a warning.
    pub fn new(cfg: &Config) -> Self {
        let webauthn = (|| -> anyhow::Result<Webauthn> {
            let origin = url::Url::parse(cfg.base_url())?;
            let host = origin.host_str().ok_or_else(|| anyhow::anyhow!("base_url has no host"))?;
            anyhow::ensure!(
                host.parse::<std::net::IpAddr>().is_err(),
                "base_url host must be a domain name, not an IP"
            );
            Ok(WebauthnBuilder::new(host, &origin)?.rp_name("ShareSomething").build()?)
        })();
        match webauthn {
            Ok(w) => Self {
                webauthn: Some(w),
                ceremonies: Mutex::new(HashMap::new()),
            },
            Err(e) => {
                tracing::warn!(error = %e, "passkeys disabled");
                Self {
                    webauthn: None,
                    ceremonies: Mutex::new(HashMap::new()),
                }
            }
        }
    }

    fn webauthn(&self) -> AppResult<&Webauthn> {
        self.webauthn
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("passkeys need base_url to be an https URL with a domain name".into()))
    }

    fn put(&self, c: Ceremony) -> String {
        let id = random_token();
        let mut map = self.ceremonies.lock().unwrap();
        map.retain(|_, (_, t)| t.elapsed() < CEREMONY_TTL);
        map.insert(id.clone(), (c, Instant::now()));
        id
    }

    fn take(&self, id: &str) -> AppResult<Ceremony> {
        match self.ceremonies.lock().unwrap().remove(id) {
            Some((c, t)) if t.elapsed() < CEREMONY_TTL => Ok(c),
            _ => Err(AppError::AuthFailed("ceremony_expired", "the passkey prompt expired; try again")),
        }
    }
}

fn cred_key(p: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(p.cred_id().as_ref())
}

async fn load_passkeys(state: &AppState) -> AppResult<Vec<Passkey>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT passkey FROM owner_passkeys").fetch_all(&state.db).await?;
    Ok(rows.into_iter().filter_map(|(json,)| serde_json::from_str(&json).ok()).collect())
}

/// Stable WebAuthn user handle for the single owner.
async fn user_id(state: &AppState) -> AppResult<Uuid> {
    let row: Option<(Option<String>,)> = sqlx::query_as("SELECT webauthn_user_id FROM owner WHERE id = 1")
        .fetch_optional(&state.db)
        .await?;
    match row {
        None => Err(AppError::NotInitialised),
        Some((Some(id),)) => Uuid::parse_str(&id).map_err(|e| AppError::Internal(e.into())),
        Some((None,)) => {
            let id = Uuid::new_v4();
            sqlx::query("UPDATE owner SET webauthn_user_id = ? WHERE id = 1")
                .bind(id.to_string())
                .execute(&state.db)
                .await?;
            Ok(id)
        }
    }
}

/// Verifies an assertion against stored passkeys and persists counter/backup-state changes.
async fn finish_auth(state: &AppState, ceremony: &PasskeyAuthentication, credential: Value) -> AppResult<()> {
    let cred: PublicKeyCredential =
        serde_json::from_value(credential).map_err(|e| AppError::BadRequest(format!("malformed passkey response: {e}")))?;
    let result = state
        .passkeys
        .webauthn()?
        .finish_passkey_authentication(&cred, ceremony)
        .map_err(|e| {
            tracing::warn!(error = %e, "passkey authentication failed");
            AppError::AuthFailed("passkey_failed", "passkey verification failed")
        })?;
    for mut pk in load_passkeys(state).await? {
        if pk.update_credential(&result).is_some() {
            sqlx::query("UPDATE owner_passkeys SET passkey = ?, last_used_at = ? WHERE cred_id = ?")
                .bind(serde_json::to_string(&pk).map_err(anyhow::Error::from)?)
                .bind(now())
                .bind(cred_key(&pk))
                .execute(&state.db)
                .await?;
        }
    }
    Ok(())
}

#[derive(Serialize, ToSchema)]
pub struct CeremonyStart {
    pub ceremony_id: String,
    /// WebAuthn options (base64url binary fields) for `navigator.credentials.create/get`.
    #[schema(value_type = std::collections::HashMap<String, Value>)]
    pub options: Value,
}

#[derive(Deserialize, ToSchema)]
pub struct CeremonyFinish {
    pub ceremony_id: String,
    /// The credential returned by the browser, binary fields base64url-encoded.
    #[schema(value_type = std::collections::HashMap<String, Value>)]
    pub credential: Value,
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterStart {
    /// Label shown in the passkey list, e.g. "Laptop".
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

fn options_json<T: Serialize>(o: &T) -> AppResult<Value> {
    serde_json::to_value(o).map_err(|e| AppError::Internal(e.into()))
}

/// List registered passkeys.
#[utoipa::path(get, path = "/auth/passkeys", tag = "auth", operation_id = "passkey_list", responses((status = 200, body = Vec<PasskeyInfo>)))]
async fn list(State(state): State<AppState>, _owner: Owner) -> AppResult<Json<Vec<PasskeyInfo>>> {
    let rows: Vec<(String, String, i64, Option<i64>)> =
        sqlx::query_as("SELECT cred_id, name, created_at, last_used_at FROM owner_passkeys ORDER BY created_at")
            .fetch_all(&state.db)
            .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name, created_at, last_used_at)| PasskeyInfo {
                id,
                name,
                created_at,
                last_used_at,
            })
            .collect(),
    ))
}

/// Remove a passkey. Needs a fresh MFA.
#[utoipa::path(delete, path = "/auth/passkeys/{id}", tag = "auth", operation_id = "passkey_delete", params(("id" = String, Path)),
    responses((status = 204), (status = 403, body = crate::error::ErrorBody)))]
async fn delete(State(state): State<AppState>, owner: Owner, Path(id): Path<String>) -> AppResult<StatusCode> {
    require_fresh_mfa(&state, &owner).await?;
    let res = sqlx::query("DELETE FROM owner_passkeys WHERE cred_id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    tracing::info!("owner passkey removed");
    Ok(StatusCode::NO_CONTENT)
}

/// Begin registering a new passkey. Needs a fresh MFA when TOTP or another passkey exists.
#[utoipa::path(post, path = "/auth/passkey/register/start", tag = "auth", operation_id = "passkey_register_start", request_body = RegisterStart,
    responses((status = 200, body = CeremonyStart), (status = 403, body = crate::error::ErrorBody)))]
async fn register_start(State(state): State<AppState>, owner: Owner, Json(req): Json<RegisterStart>) -> AppResult<Json<CeremonyStart>> {
    require_fresh_mfa(&state, &owner).await?;
    let name = req.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(AppError::BadRequest("passkey name must be 1-64 characters".into()));
    }
    let exclude: Vec<_> = load_passkeys(&state).await?.iter().map(|p| p.cred_id().clone()).collect();
    let (options, reg) = state
        .passkeys
        .webauthn()?
        .start_passkey_registration(user_id(&state).await?, "owner", "ShareSomething owner", Some(exclude))
        .map_err(|e| AppError::Internal(e.into()))?;
    let ceremony_id = state.passkeys.put(Ceremony::Register { state: reg, name });
    Ok(Json(CeremonyStart {
        ceremony_id,
        options: options_json(&options)?,
    }))
}

/// Finish registering a passkey.
#[utoipa::path(post, path = "/auth/passkey/register/finish", tag = "auth", operation_id = "passkey_register_finish", request_body = CeremonyFinish,
    responses((status = 200, body = PasskeyInfo), (status = 401, body = crate::error::ErrorBody)))]
async fn register_finish(State(state): State<AppState>, _owner: Owner, Json(req): Json<CeremonyFinish>) -> AppResult<Json<PasskeyInfo>> {
    let Ceremony::Register { state: reg, name } = state.passkeys.take(&req.ceremony_id)? else {
        return Err(AppError::BadRequest("wrong ceremony".into()));
    };
    let cred: RegisterPublicKeyCredential =
        serde_json::from_value(req.credential).map_err(|e| AppError::BadRequest(format!("malformed passkey response: {e}")))?;
    let passkey = state.passkeys.webauthn()?.finish_passkey_registration(&cred, &reg).map_err(|e| {
        tracing::warn!(error = %e, "passkey registration failed");
        AppError::AuthFailed("passkey_failed", "the passkey could not be registered")
    })?;
    let info = PasskeyInfo {
        id: cred_key(&passkey),
        name,
        created_at: now(),
        last_used_at: None,
    };
    sqlx::query("INSERT INTO owner_passkeys (cred_id, name, passkey, created_at) VALUES (?, ?, ?, ?)")
        .bind(&info.id)
        .bind(&info.name)
        .bind(serde_json::to_string(&passkey).map_err(anyhow::Error::from)?)
        .bind(info.created_at)
        .execute(&state.db)
        .await?;
    tracing::info!(name = %info.name, "owner passkey registered");
    Ok(Json(info))
}

/// Begin a passkey sign-in (replaces password + TOTP).
#[utoipa::path(post, path = "/auth/passkey/login/start", tag = "auth", operation_id = "passkey_login_start",
    responses((status = 200, body = CeremonyStart), (status = 400, body = crate::error::ErrorBody)))]
async fn login_start(State(state): State<AppState>, client: ClientInfo) -> AppResult<Json<CeremonyStart>> {
    if !state.limits.login.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let passkeys = load_passkeys(&state).await?;
    if passkeys.is_empty() {
        return Err(AppError::BadRequest("no passkeys registered".into()));
    }
    let (options, auth) = state
        .passkeys
        .webauthn()?
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(e.into()))?;
    let ceremony_id = state.passkeys.put(Ceremony::Login(auth));
    Ok(Json(CeremonyStart {
        ceremony_id,
        options: options_json(&options)?,
    }))
}

/// Finish a passkey sign-in; the new session counts as freshly MFA-verified.
#[utoipa::path(post, path = "/auth/passkey/login/finish", tag = "auth", operation_id = "passkey_login_finish", request_body = CeremonyFinish,
    responses((status = 200, body = MeResponse), (status = 401, body = crate::error::ErrorBody)))]
async fn login_finish(
    State(state): State<AppState>,
    client: ClientInfo,
    jar: CookieJar,
    Json(req): Json<CeremonyFinish>,
) -> AppResult<(CookieJar, Json<MeResponse>)> {
    let Ceremony::Login(auth) = state.passkeys.take(&req.ceremony_id)? else {
        return Err(AppError::BadRequest("wrong ceremony".into()));
    };
    finish_auth(&state, &auth, req.credential).await?;
    let (jar, session) = start_session(&state, jar, Some(now())).await?;
    tracing::info!(ip = %client.ip, "owner logged in with passkey");
    Ok((jar, Json(me_response(&state, Some(&session)).await?)))
}

/// Begin a passkey MFA step-up for the current session.
#[utoipa::path(post, path = "/auth/passkey/step-up/start", tag = "auth", operation_id = "passkey_step_up_start",
    responses((status = 200, body = CeremonyStart)))]
async fn step_up_start(State(state): State<AppState>, owner: Owner) -> AppResult<Json<CeremonyStart>> {
    let passkeys = load_passkeys(&state).await?;
    if passkeys.is_empty() {
        return Err(AppError::BadRequest("no passkeys registered".into()));
    }
    let (options, auth) = state
        .passkeys
        .webauthn()?
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(e.into()))?;
    let ceremony_id = state.passkeys.put(Ceremony::StepUp {
        state: auth,
        session: owner.token_hash().to_vec(),
    });
    Ok(Json(CeremonyStart {
        ceremony_id,
        options: options_json(&options)?,
    }))
}

/// Finish a passkey MFA step-up.
#[utoipa::path(post, path = "/auth/passkey/step-up/finish", tag = "auth", operation_id = "passkey_step_up_finish", request_body = CeremonyFinish,
    responses((status = 200, body = MeResponse), (status = 401, body = crate::error::ErrorBody)))]
async fn step_up_finish(State(state): State<AppState>, owner: Owner, Json(req): Json<CeremonyFinish>) -> AppResult<Json<MeResponse>> {
    let Ceremony::StepUp { state: auth, session } = state.passkeys.take(&req.ceremony_id)? else {
        return Err(AppError::BadRequest("wrong ceremony".into()));
    };
    if session != owner.token_hash() {
        return Err(AppError::BadRequest("ceremony belongs to another session".into()));
    }
    finish_auth(&state, &auth, req.credential).await?;
    let fresh = mark_mfa(&state, owner).await?;
    Ok(Json(me_response(&state, Some(&fresh)).await?))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(delete))
        .routes(routes!(register_start))
        .routes(routes!(register_finish))
        .routes(routes!(login_start))
        .routes(routes!(login_finish))
        .routes(routes!(step_up_start))
        .routes(routes!(step_up_finish))
}
