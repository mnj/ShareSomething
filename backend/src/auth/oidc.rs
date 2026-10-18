//! Recipient sign-in with OpenID Connect providers (Google, Microsoft, Keycloak, ...) and GitHub.
//!
//! Authorization code flow with PKCE and a nonce. The `state` value is stored server-side and
//! bound to the browser with a short-lived cookie, so a callback can't be replayed into someone
//! else's browser (login CSRF).

use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreUserInfoClaims},
};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::recipient::{Recipient, add_identities};
use crate::{
    app::AppState,
    audit::{Action, Event},
    config::{OidcKind, OidcProviderConfig},
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    util::{now, random_token, sha256},
};

const STATE_COOKIE: &str = "ss_oidc_state";
const STATE_TTL_SECS: i64 = 10 * 60;

pub struct OidcProviders {
    http: reqwest::Client,
    providers: Vec<Provider>,
}

struct Provider {
    cfg: OidcProviderConfig,
    /// Discovered lazily so a provider outage doesn't stop the server from starting.
    metadata: RwLock<Option<CoreProviderMetadata>>,
}

impl OidcProviders {
    pub fn new(cfg: &[OidcProviderConfig]) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            // Following redirects from token endpoints is an SSRF risk (openidconnect docs).
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .user_agent("sharesomething")
            .build()?;
        Ok(Self {
            http,
            providers: cfg
                .iter()
                .map(|c| Provider {
                    cfg: c.clone(),
                    metadata: RwLock::new(None),
                })
                .collect(),
        })
    }

    pub fn providers(&self) -> impl Iterator<Item = &OidcProviderConfig> {
        self.providers.iter().map(|p| &p.cfg)
    }

    pub fn has(&self, id: &str) -> bool {
        self.providers.iter().any(|p| p.cfg.id == id)
    }

    fn get(&self, id: &str) -> AppResult<&Provider> {
        self.providers.iter().find(|p| p.cfg.id == id).ok_or(AppError::NotFound)
    }

    async fn metadata(&self, p: &Provider) -> anyhow::Result<CoreProviderMetadata> {
        if let Some(m) = p.metadata.read().await.clone() {
            return Ok(m);
        }
        let issuer = IssuerUrl::new(p.cfg.issuer.clone().unwrap_or_default())?;
        let m = CoreProviderMetadata::discover_async(issuer, &self.http).await?;
        *p.metadata.write().await = Some(m.clone());
        Ok(m)
    }
}

fn redirect_url(state: &AppState, provider: &str) -> String {
    format!("{}/api/recipient/oidc/{provider}/callback", state.cfg.base_url())
}

fn github_urls(cfg: &OidcProviderConfig) -> (String, String) {
    (
        cfg.github_web_url
            .clone()
            .unwrap_or_else(|| "https://github.com".into())
            .trim_end_matches('/')
            .to_string(),
        cfg.github_api_url
            .clone()
            .unwrap_or_else(|| "https://api.github.com".into())
            .trim_end_matches('/')
            .to_string(),
    )
}

/// Only same-site paths are allowed as post-login targets (no open redirects).
fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') && n.len() < 512 => n.to_string(),
        _ => "/".into(),
    }
}

fn state_cookie(state: &AppState, value: String, max_age: i64) -> Cookie<'static> {
    Cookie::build((STATE_COOKIE, value))
        .http_only(true)
        .secure(state.cfg.cookie_secure())
        .same_site(SameSite::Lax)
        .path("/api/recipient/oidc")
        .max_age(time::Duration::seconds(max_age))
        .build()
}

#[derive(Deserialize, IntoParams)]
struct StartQuery {
    /// Path to return to after signing in, e.g. `/s/my-share`.
    next: Option<String>,
    /// `member`: sign in to your ShareSomething account (team SSO). Default: verify a recipient.
    purpose: Option<String>,
}

/// Start signing in with a provider (redirects to it).
#[utoipa::path(operation_id = "oidc_start", get, path = "/recipient/oidc/{provider}/start", tag = "recipient", params(("provider" = String, Path), StartQuery),
    responses((status = 303, description = "Redirect to the identity provider")))]
async fn start(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(q): Query<StartQuery>,
    jar: CookieJar,
) -> AppResult<Response> {
    let p = state.oidc.get(&provider)?;
    let member = q.purpose.as_deref() == Some("member");
    if member && !(p.cfg.member_login && state.cfg.mode == crate::config::InstanceMode::Team) {
        return Err(AppError::NotFound);
    }
    let csrf = random_token();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let nonce = random_token();

    let auth_url = match p.cfg.kind {
        OidcKind::Oidc => {
            let meta = state.oidc.metadata(p).await.map_err(|e| {
                tracing::error!(provider = %provider, error = %e, "OIDC discovery failed");
                AppError::Internal(anyhow::anyhow!("identity provider unavailable"))
            })?;
            let client = CoreClient::from_provider_metadata(
                meta,
                ClientId::new(p.cfg.client_id.clone()),
                Some(ClientSecret::new(p.cfg.client_secret.clone())),
            )
            .set_redirect_uri(RedirectUrl::new(redirect_url(&state, &provider)).map_err(anyhow::Error::from)?);
            let (csrf_v, nonce_v) = (csrf.clone(), nonce.clone());
            let mut req = client
                .authorize_url(
                    CoreAuthenticationFlow::AuthorizationCode,
                    move || CsrfToken::new(csrf_v),
                    move || Nonce::new(nonce_v),
                )
                .set_pkce_challenge(pkce_challenge);
            let scopes = if p.cfg.scopes.is_empty() {
                vec!["email".to_string(), "profile".to_string()]
            } else {
                p.cfg.scopes.clone()
            };
            for s in scopes {
                req = req.add_scope(Scope::new(s));
            }
            req.url().0.to_string()
        }
        OidcKind::Github => {
            let (web, _) = github_urls(&p.cfg);
            let mut u = url::Url::parse(&format!("{web}/login/oauth/authorize")).map_err(anyhow::Error::from)?;
            u.query_pairs_mut()
                .append_pair("client_id", &p.cfg.client_id)
                .append_pair("redirect_uri", &redirect_url(&state, &provider))
                .append_pair("scope", "user:email")
                .append_pair("state", &csrf)
                .append_pair("code_challenge", pkce_challenge.as_str())
                .append_pair("code_challenge_method", "S256")
                .append_pair("allow_signup", "false");
            u.to_string()
        }
    };

    sqlx::query(
        "INSERT INTO oidc_states (state_hash, provider, pkce_verifier, nonce, next, expires_at, purpose) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(sha256(csrf.as_bytes()))
    .bind(&provider)
    .bind(pkce_verifier.secret())
    .bind(&nonce)
    .bind(safe_next(q.next.as_deref()))
    .bind(now() + STATE_TTL_SECS)
    .bind(if member { "member" } else { "recipient" })
    .execute(&state.db)
    .await?;
    Ok((jar.add(state_cookie(&state, csrf, STATE_TTL_SECS)), Redirect::to(&auth_url)).into_response())
}

#[derive(Deserialize, IntoParams)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn with_error(next: &str, code: &str) -> String {
    let sep = if next.contains('?') { '&' } else { '?' };
    format!("{next}{sep}auth_error={code}")
}

/// Provider redirects back here; on success the verified email(s) join the visitor's identities.
#[utoipa::path(operation_id = "oidc_callback", get, path = "/recipient/oidc/{provider}/callback", tag = "recipient", params(("provider" = String, Path), CallbackQuery),
    responses((status = 303, description = "Back to the share")))]
async fn callback(
    State(state): State<AppState>,
    client: ClientInfo,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
    recipient: Recipient,
    jar: CookieJar,
) -> AppResult<Response> {
    let p = state.oidc.get(&provider)?;
    let given = q.state.unwrap_or_default();
    let cookie_ok = jar
        .get(STATE_COOKIE)
        .is_some_and(|c| bool::from(c.value().as_bytes().ct_eq(given.as_bytes())));
    let jar = jar.remove(state_cookie(&state, String::new(), 0));
    let row: Option<(String, String, String, String)> = sqlx::query_as(
        "DELETE FROM oidc_states WHERE state_hash = ? AND provider = ? AND expires_at > ? RETURNING pkce_verifier, nonce, next, purpose",
    )
    .bind(sha256(given.as_bytes()))
    .bind(&provider)
    .bind(now())
    .fetch_optional(&state.db)
    .await?;
    let method = format!("oidc:{provider}");
    let failed = |reason: &str| {
        Event::new(Action::RecipientVerifyFailed)
            .denied()
            .recipient(None)
            .client(&client)
            .detail("method", &method)
            .detail("reason", reason)
    };
    let Some((verifier, nonce, next, purpose)) = row.filter(|_| cookie_ok && !given.is_empty()) else {
        state
            .audit
            .record(failed(if cookie_ok {
                "unknown_or_expired_state"
            } else {
                "state_not_bound_to_browser"
            }))
            .await?;
        return Ok((jar, Redirect::to(&with_error("/", "expired"))).into_response());
    };
    if q.error.is_some() {
        return Ok((jar, Redirect::to(&with_error(&next, "cancelled"))).into_response());
    }
    let Some(code) = q.code else {
        return Ok((jar, Redirect::to(&with_error(&next, "failed"))).into_response());
    };

    let emails = match p.cfg.kind {
        OidcKind::Oidc => oidc_emails(&state, p, &provider, code, verifier, nonce).await,
        OidcKind::Github => github_emails(&state, p, &provider, code, verifier).await,
    };
    if purpose == "member" {
        return member_sign_in(&state, &client, jar, &provider, emails, &next).await;
    }
    match emails {
        Ok(emails) if !emails.is_empty() => {
            let jar = add_identities(&state, jar, &recipient, &emails, &method).await?;
            state
                .audit
                .record(
                    Event::new(Action::RecipientVerified)
                        .recipient(Some(emails.join(",")))
                        .client(&client)
                        .detail("method", &method),
                )
                .await?;
            Ok((jar, Redirect::to(&next)).into_response())
        }
        Ok(_) => {
            state.audit.record(failed("no_verified_email")).await?;
            Ok((jar, Redirect::to(&with_error(&next, "no_verified_email"))).into_response())
        }
        Err(e) => {
            tracing::warn!(provider = %provider, error = %e, "sign-in failed");
            state.audit.record(failed("provider_error").detail("error", e.to_string())).await?;
            Ok((jar, Redirect::to(&with_error(&next, "failed"))).into_response())
        }
    }
}

async fn oidc_emails(
    state: &AppState,
    p: &Provider,
    provider: &str,
    code: String,
    verifier: String,
    nonce: String,
) -> anyhow::Result<Vec<String>> {
    let http = &state.oidc.http;
    let meta = state.oidc.metadata(p).await?;
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new(p.cfg.client_id.clone()),
        Some(ClientSecret::new(p.cfg.client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url(state, provider))?);
    let token = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(http)
        .await
        .map_err(|e| anyhow::anyhow!("token exchange failed: {e}"))?;
    let id_token = token.id_token().ok_or_else(|| anyhow::anyhow!("provider returned no ID token"))?;
    let claims = id_token.claims(&client.id_token_verifier(), &Nonce::new(nonce))?;

    let (mut email, mut verified) = (claims.email().map(|e| e.to_string()), claims.email_verified());
    if email.is_none() {
        // Some providers only expose the email via the userinfo endpoint.
        let info: CoreUserInfoClaims = client
            .user_info(token.access_token().clone(), Some(claims.subject().clone()))?
            .request_async(http)
            .await
            .map_err(|e| anyhow::anyhow!("userinfo failed: {e}"))?;
        email = info.email().map(|e| e.to_string());
        verified = info.email_verified();
    }
    Ok(match email {
        Some(e) if verified == Some(true) || p.cfg.trust_unverified_email => vec![e.to_ascii_lowercase()],
        _ => vec![],
    })
}

#[derive(Deserialize)]
struct GithubToken {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    verified: bool,
}

async fn github_emails(state: &AppState, p: &Provider, provider: &str, code: String, verifier: String) -> anyhow::Result<Vec<String>> {
    let (web, api) = github_urls(&p.cfg);
    let http = &state.oidc.http;
    let token: GithubToken = http
        .post(format!("{web}/login/oauth/access_token"))
        .header("accept", "application/json")
        .form(&[
            ("client_id", p.cfg.client_id.as_str()),
            ("client_secret", p.cfg.client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", redirect_url(state, provider).as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let access = token
        .access_token
        .ok_or_else(|| anyhow::anyhow!("github: {}", token.error.unwrap_or_default()))?;
    let emails: Vec<GithubEmail> = http
        .get(format!("{api}/user/emails"))
        .bearer_auth(access)
        .header("accept", "application/vnd.github+json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(emails
        .into_iter()
        .filter(|e| e.verified)
        .map(|e| e.email.to_ascii_lowercase())
        .collect())
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(start))
        .routes(routes!(callback))
        .routes(routes!(sso_providers))
}

/// Team SSO: sign in to an existing account, activate an invited one, or provision a member when
/// the verified email is in `team.allowed_domains`.
async fn member_sign_in(
    state: &AppState,
    client: &ClientInfo,
    jar: CookieJar,
    provider: &str,
    emails: anyhow::Result<Vec<String>>,
    next: &str,
) -> AppResult<Response> {
    let method = format!("sso:{provider}");
    let fail = |reason: &'static str, email: Option<String>| {
        let e = Event::new(Action::AuthLoginFailed)
            .denied()
            .recipient(email)
            .client(client)
            .detail("method", &method)
            .detail("reason", reason);
        (e, format!("/login?sso_error={reason}"))
    };
    let emails = match emails {
        Ok(e) if !e.is_empty() => e,
        Ok(_) => {
            let (e, to) = fail("no_verified_email", None);
            state.audit.record(e).await?;
            return Ok((jar, Redirect::to(&to)).into_response());
        }
        Err(err) => {
            tracing::warn!(provider, error = %err, "SSO sign-in failed");
            let (e, to) = fail("provider_error", None);
            state.audit.record(e.detail("error", err.to_string())).await?;
            return Ok((jar, Redirect::to(&to)).into_response());
        }
    };
    let mut found: Option<(i64, String)> = None;
    for email in &emails {
        if let Some(row) = sqlx::query_as::<_, (i64, String)>("SELECT id, status FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(&state.db)
            .await?
        {
            found = Some(row);
            break;
        }
    }
    let email = emails[0].clone();
    let id = match found {
        Some((_, status)) if status == "disabled" => {
            let (e, to) = fail("account_disabled", Some(email));
            state.audit.record(e).await?;
            return Ok((jar, Redirect::to(&to)).into_response());
        }
        Some((id, status)) => {
            if status == "invited" {
                sqlx::query(
                    "UPDATE users SET status = 'active', invite_token_hash = NULL, invite_expires_at = NULL, sso_provider = ? WHERE id = ?",
                )
                .bind(provider)
                .bind(id)
                .execute(&state.db)
                .await?;
                state
                    .audit
                    .record(
                        Event::new(Action::UserInviteAccepted)
                            .user(id, &email)
                            .client(client)
                            .detail("method", &method),
                    )
                    .await?;
            }
            id
        }
        None => {
            let domain_ok = emails.iter().find(|e| {
                e.rsplit_once('@')
                    .is_some_and(|(_, d)| state.cfg.team.allowed_domains.iter().any(|a| a.eq_ignore_ascii_case(d)))
            });
            let Some(email) = domain_ok.cloned() else {
                let (e, to) = fail("not_a_member", Some(email));
                state.audit.record(e).await?;
                return Ok((jar, Redirect::to(&to)).into_response());
            };
            let name = email.split('@').next().unwrap_or("").to_string();
            let (id,): (i64,) = sqlx::query_as(
                "INSERT INTO users (email, name, role, status, sso_provider, created_at) VALUES (?, ?, ?, 'active', ?, ?) RETURNING id",
            )
            .bind(&email)
            .bind(&name)
            .bind(&state.cfg.team.default_role)
            .bind(provider)
            .bind(now())
            .fetch_one(&state.db)
            .await?;
            state
                .audit
                .record(
                    Event::new(Action::UserCreated)
                        .system("sso")
                        .client(client)
                        .target("user", id.to_string(), Some(email.clone()))
                        .detail("method", &method)
                        .detail("role", &state.cfg.team.default_role),
                )
                .await?;
            id
        }
    };
    let user = super::users::load_user(state, id).await?;
    let (jar, session) = super::users::start_session(state, jar, &user, None).await?;
    state
        .audit
        .record(session.event(Action::AuthLogin).client(client).detail("method", &method))
        .await?;
    Ok((jar, Redirect::to(next)).into_response())
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct SsoProvider {
    pub id: String,
    pub name: String,
}

/// Providers members can sign in with (team mode).
#[utoipa::path(get, path = "/auth/sso-providers", tag = "auth", operation_id = "sso_providers", responses((status = 200, body = Vec<SsoProvider>)))]
async fn sso_providers(State(state): State<AppState>) -> axum::Json<Vec<SsoProvider>> {
    let team = state.cfg.mode == crate::config::InstanceMode::Team;
    axum::Json(
        state
            .oidc
            .providers()
            .filter(|p| team && p.member_login)
            .map(|p| SsoProvider {
                id: p.id.clone(),
                name: p.name.clone(),
            })
            .collect(),
    )
}
