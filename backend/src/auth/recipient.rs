//! Recipient sign-in: a session cookie carrying verified identities (email one-time codes here,
//! OIDC in `oidc.rs`). Identities feed `AccessContext.identities` for email/domain policy rules.

use axum::{
    Json,
    extract::{FromRequestParts, State},
    http::request::Parts,
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    app::AppState,
    audit::{Action, Event},
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    shares::{policy, policy::Identity, store},
    util::{now, random_token, sha256},
};

pub const COOKIE: &str = "ss_recipient";
const CODE_TTL_SECS: i64 = 10 * 60;
const MAX_CODE_ATTEMPTS: i64 = 5;

/// The visitor's verified identities (empty when not signed in). Never rejects.
#[derive(Debug, Clone, Default)]
pub struct Recipient {
    session: Option<Vec<u8>>,
    pub identities: Vec<Identity>,
}

impl Recipient {
    /// Label for the access log.
    pub fn label(&self) -> Option<String> {
        let mut emails: Vec<&str> = self.identities.iter().map(|i| i.email.as_str()).collect();
        emails.dedup();
        (!emails.is_empty()).then(|| emails.join(","))
    }
}

impl FromRequestParts<AppState> for Recipient {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let Some(cookie) = jar.get(COOKIE) else {
            return Ok(Recipient::default());
        };
        let hash = sha256(cookie.value().as_bytes());
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT i.email, i.method FROM recipient_identities i
             JOIN recipient_sessions s ON s.token_hash = i.session_hash
             WHERE s.token_hash = ? AND s.expires_at > ?",
        )
        .bind(&hash)
        .bind(now())
        .fetch_all(&state.db)
        .await?;
        let valid: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM recipient_sessions WHERE token_hash = ? AND expires_at > ?")
            .bind(&hash)
            .bind(now())
            .fetch_optional(&state.db)
            .await?;
        Ok(Recipient {
            session: valid.map(|_| hash),
            identities: rows.into_iter().map(|(email, method)| Identity { email, method }).collect(),
        })
    }
}

fn session_cookie(state: &AppState, value: String, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((COOKIE, value))
        .http_only(true)
        .secure(state.cfg.cookie_secure())
        // Lax so the cookie set on the OIDC callback redirect is usable right away.
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::seconds(max_age_secs))
        .build()
}

/// Records verified emails in the visitor's session, creating the session if needed.
pub async fn add_identities(
    state: &AppState,
    jar: CookieJar,
    current: &Recipient,
    emails: &[String],
    method: &str,
) -> AppResult<CookieJar> {
    let (jar, session) = match &current.session {
        Some(hash) => (jar, hash.clone()),
        None => {
            let token = random_token();
            let ttl = state.cfg.recipient_session_hours * 3600;
            let hash = sha256(token.as_bytes());
            sqlx::query("INSERT INTO recipient_sessions (token_hash, created_at, expires_at) VALUES (?, ?, ?)")
                .bind(&hash)
                .bind(now())
                .bind(now() + ttl)
                .execute(&state.db)
                .await?;
            (jar.add(session_cookie(state, token, ttl)), hash)
        }
    };
    for email in emails {
        sqlx::query("INSERT OR REPLACE INTO recipient_identities (session_hash, email, method, verified_at) VALUES (?, ?, ?, ?)")
            .bind(&session)
            .bind(email.to_ascii_lowercase())
            .bind(method)
            .bind(now())
            .execute(&state.db)
            .await?;
    }
    Ok(jar)
}

#[derive(Serialize, ToSchema)]
pub struct AuthMethodInfo {
    /// `email_otp` or `oidc:<provider>`; matches policy rule `methods`.
    pub id: String,
    pub label: String,
}

/// The sign-in methods this server offers, in display order.
pub fn available_methods(state: &AppState) -> Vec<AuthMethodInfo> {
    let mut out: Vec<AuthMethodInfo> = state
        .oidc
        .providers()
        .map(|p| AuthMethodInfo {
            id: format!("oidc:{}", p.id),
            label: p.name.clone(),
        })
        .collect();
    if state.mailer.enabled() {
        out.push(AuthMethodInfo {
            id: "email_otp".into(),
            label: "Email code".into(),
        });
    }
    out
}

#[derive(Serialize, ToSchema)]
pub struct RecipientMe {
    pub identities: Vec<IdentityInfo>,
}

#[derive(Serialize, ToSchema)]
pub struct IdentityInfo {
    pub email: String,
    pub method: String,
}

fn me_of(identities: &[Identity]) -> RecipientMe {
    RecipientMe {
        identities: identities
            .iter()
            .map(|i| IdentityInfo {
                email: i.email.clone(),
                method: i.method.clone(),
            })
            .collect(),
    }
}

/// Sign-in methods available to recipients.
#[utoipa::path(operation_id = "recipient_methods", get, path = "/recipient/methods", tag = "recipient", responses((status = 200, body = Vec<AuthMethodInfo>)))]
async fn methods(State(state): State<AppState>) -> Json<Vec<AuthMethodInfo>> {
    Json(available_methods(&state))
}

/// The visitor's verified identities.
#[utoipa::path(operation_id = "recipient_me", get, path = "/recipient/me", tag = "recipient", responses((status = 200, body = RecipientMe)))]
async fn me(recipient: Recipient) -> Json<RecipientMe> {
    Json(me_of(&recipient.identities))
}

/// Forget all of the visitor's identities.
#[utoipa::path(operation_id = "recipient_logout", post, path = "/recipient/logout", tag = "recipient", responses((status = 200, body = RecipientMe)))]
async fn logout(
    State(state): State<AppState>,
    client: ClientInfo,
    recipient: Recipient,
    jar: CookieJar,
) -> AppResult<(CookieJar, Json<RecipientMe>)> {
    if let Some(hash) = &recipient.session {
        sqlx::query("DELETE FROM recipient_sessions WHERE token_hash = ?")
            .bind(hash)
            .execute(&state.db)
            .await?;
        state
            .audit
            .record(Event::new(Action::RecipientSignedOut).recipient(recipient.label()).client(&client))
            .await?;
    }
    Ok((jar.remove(session_cookie(&state, String::new(), 0)), Json(me_of(&[]))))
}

#[derive(Deserialize, ToSchema)]
pub struct EmailStartRequest {
    /// The share being opened; a code is only sent if this email could get access to it.
    pub slug: String,
    pub email: String,
}

#[derive(Serialize, ToSchema)]
pub struct EmailStartResponse {
    pub challenge_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct EmailVerifyRequest {
    pub challenge_id: String,
    pub code: String,
}

fn code_hash(challenge_id: &str, code: &str) -> Vec<u8> {
    sha256(format!("{challenge_id}:{}", code.trim()).as_bytes())
}

/// Ask for a one-time code by email. Always answers the same way, whether or not a code was
/// actually sent, so it can't be used to discover which addresses have access.
#[utoipa::path(operation_id = "recipient_email_start", post, path = "/recipient/email/start", tag = "recipient", request_body = EmailStartRequest,
    responses((status = 200, body = EmailStartResponse), (status = 429, body = crate::error::ErrorBody)))]
async fn email_start(
    State(state): State<AppState>,
    client: ClientInfo,
    Json(req): Json<EmailStartRequest>,
) -> AppResult<Json<EmailStartResponse>> {
    let email = req.email.trim().to_ascii_lowercase();
    let valid = email.len() <= 254
        && email
            .split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.contains('@'));
    if !valid {
        return Err(AppError::BadRequest("enter a valid email address".into()));
    }
    if !state.limits.email_ip.check(&client.ip.to_string()) || !state.limits.email_addr.check(&email) {
        return Err(AppError::TooManyRequests);
    }
    let challenge_id = random_token();
    let share = store::by_slug(&state.db, &req.slug).await?;
    let mut event = Event::new(Action::RecipientCodeRequested)
        .recipient(Some(email.clone()))
        .client(&client)
        .detail("slug", &req.slug);
    if let Some(row) = &share {
        event = event.target("share", &row.id, Some(row.audit_label()));
    }
    let eligible = match &share {
        Some(row) if state.mailer.enabled() && row.ciphertext.is_some() => {
            policy::email_could_satisfy(&store::rules(&state.db, &row.id).await?, &email, "email_otp")
        }
        _ => false,
    };
    // Recorded for the SOC either way; the visitor always gets the same response.
    state
        .audit
        .record(if eligible {
            event.detail("sent", true)
        } else {
            event.denied().detail("sent", false)
        })
        .await?;
    if eligible {
        let code = format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000));
        sqlx::query("INSERT INTO email_challenges (id, email, code_hash, expires_at) VALUES (?, ?, ?, ?)")
            .bind(&challenge_id)
            .bind(&email)
            .bind(code_hash(&challenge_id, &code))
            .bind(now() + CODE_TTL_SECS)
            .execute(&state.db)
            .await?;
        // Send in the background so response timing doesn't reveal whether a code went out.
        let (mailer, base) = (state.mailer.clone(), state.cfg.base_url().to_string());
        tokio::spawn(async move {
            if let Err(e) = mailer.send_code(&email, &code, &base).await {
                tracing::error!(error = %e, "failed to send one-time code");
            }
        });
    } else {
        tracing::info!(ip = %client.ip, slug = %req.slug, "email code requested for an address with no access; not sent");
    }
    Ok(Json(EmailStartResponse { challenge_id }))
}

/// Confirm an emailed code; on success the email is added to the visitor's identities.
#[utoipa::path(operation_id = "recipient_email_verify", post, path = "/recipient/email/verify", tag = "recipient", request_body = EmailVerifyRequest,
    responses((status = 200, body = RecipientMe), (status = 401, body = crate::error::ErrorBody)))]
async fn email_verify(
    State(state): State<AppState>,
    client: ClientInfo,
    recipient: Recipient,
    jar: CookieJar,
    Json(req): Json<EmailVerifyRequest>,
) -> AppResult<(CookieJar, Json<RecipientMe>)> {
    if !state.limits.email_verify.check(&client.ip.to_string()) {
        return Err(AppError::TooManyRequests);
    }
    let invalid = || AppError::AuthFailed("invalid_code", "that code is wrong or has expired");
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "UPDATE email_challenges SET attempts = attempts + 1
         WHERE id = ? AND expires_at > ? AND attempts < ?
         RETURNING email, code_hash",
    )
    .bind(&req.challenge_id)
    .bind(now())
    .bind(MAX_CODE_ATTEMPTS)
    .fetch_optional(&state.db)
    .await?;
    let failed = |email: Option<String>, reason: &str| {
        Event::new(Action::RecipientVerifyFailed)
            .denied()
            .recipient(email)
            .client(&client)
            .detail("method", "email_otp")
            .detail("reason", reason)
    };
    let Some((email, stored)) = row else {
        state.audit.record(failed(None, "unknown_or_expired_challenge")).await?;
        return Err(invalid());
    };
    if !bool::from(code_hash(&req.challenge_id, &req.code).ct_eq(&stored)) {
        state.audit.record(failed(Some(email), "wrong_code")).await?;
        return Err(invalid());
    }
    sqlx::query("DELETE FROM email_challenges WHERE id = ?")
        .bind(&req.challenge_id)
        .execute(&state.db)
        .await?;
    let jar = add_identities(&state, jar, &recipient, std::slice::from_ref(&email), "email_otp").await?;
    state
        .audit
        .record(
            Event::new(Action::RecipientVerified)
                .recipient(Some(email.clone()))
                .client(&client)
                .detail("method", "email_otp"),
        )
        .await?;
    let mut identities = recipient.identities;
    identities.push(Identity {
        email,
        method: "email_otp".into(),
    });
    Ok((jar, Json(me_of(&identities))))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(methods))
        .routes(routes!(me))
        .routes(routes!(logout))
        .routes(routes!(email_start))
        .routes(routes!(email_verify))
}
