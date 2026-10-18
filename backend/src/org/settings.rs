//! Org-wide policies set by admins and enforced server-side on every share create/update.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    app::AppState,
    audit::Action,
    auth::users::CurrentUser,
    error::{AppError, AppResult},
    net::client_ip::ClientInfo,
    shares::{
        model::EncMode,
        policy::{PolicyRule, Rule, RuleGroup},
    },
    util::now,
};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct OrgSettings {
    /// Users must set up a passkey or authenticator app before they can create shares.
    pub require_mfa: bool,
    /// Every share must be end-to-end encrypted.
    pub force_e2e: bool,
    /// Allow "anyone with the link" shares (otherwise every share needs an access rule).
    pub allow_public_shares: bool,
    /// Longest allowed lifetime in days; when set, every share must expire.
    pub max_expiry_days: Option<i64>,
    /// Highest allowed view limit; when set, every share must have one.
    pub max_views: Option<i64>,
    /// Email domains that email/domain rules may name (empty = any).
    pub allowed_recipient_domains: Vec<String>,
    /// Link styles members may use (empty = all enabled).
    pub allowed_slug_generators: Vec<String>,
}

impl Default for OrgSettings {
    fn default() -> Self {
        Self {
            require_mfa: false,
            force_e2e: false,
            allow_public_shares: true,
            max_expiry_days: None,
            max_views: None,
            allowed_recipient_domains: vec![],
            allowed_slug_generators: vec![],
        }
    }
}

pub async fn load(state: &AppState) -> sqlx::Result<OrgSettings> {
    let (json,): (String,) = sqlx::query_as("SELECT settings FROM org_settings WHERE id = 1")
        .fetch_one(&state.db)
        .await?;
    Ok(serde_json::from_str(&json).unwrap_or_default())
}

/// The parts of a share request org policy cares about.
pub struct ShareParams<'a> {
    pub enc_mode: Option<EncMode>,
    /// Absolute expiry; `Some(None)` = explicitly no expiry; `None` = unchanged.
    pub expires_at: Option<Option<i64>>,
    /// `Some(None)` = unlimited; `None` = unchanged.
    pub max_views: Option<Option<i64>>,
    pub policy: Option<&'a [PolicyRule]>,
    pub slug_generator: Option<&'a str>,
}

fn violation(msg: impl Into<String>) -> AppError {
    AppError::Access("org_policy", msg.into())
}

impl OrgSettings {
    pub fn enforce(&self, p: &ShareParams) -> AppResult<()> {
        if self.force_e2e && p.enc_mode == Some(EncMode::Server) {
            return Err(violation("your organisation requires end-to-end encryption"));
        }
        if let (Some(days), Some(exp)) = (self.max_expiry_days, p.expires_at) {
            match exp {
                None => return Err(violation(format!("shares must expire within {days} days"))),
                Some(t) if t > now() + days * 86_400 + 60 => return Err(violation(format!("shares must expire within {days} days"))),
                _ => {}
            }
        }
        if let (Some(max), Some(views)) = (self.max_views, p.max_views) {
            match views {
                None => return Err(violation(format!("shares need a view limit of at most {max}"))),
                Some(v) if v > max => return Err(violation(format!("shares need a view limit of at most {max}"))),
                _ => {}
            }
        }
        if let Some(rules) = p.policy {
            if !self.allow_public_shares && rules.iter().any(|r| r.group == RuleGroup::Include && r.rule == Rule::Everyone) {
                return Err(violation(
                    "public (anyone with the link) shares are not allowed; add an access rule",
                ));
            }
            if !self.allowed_recipient_domains.is_empty() {
                let allowed = |d: &str| self.allowed_recipient_domains.iter().any(|a| a.eq_ignore_ascii_case(d));
                for r in rules.iter().filter(|r| r.group != RuleGroup::Exclude) {
                    let bad = match &r.rule {
                        Rule::Email { emails, .. } => emails
                            .iter()
                            .find(|e| !e.rsplit_once('@').is_some_and(|(_, d)| allowed(d)))
                            .cloned(),
                        Rule::EmailDomain { domains, .. } => domains.iter().find(|d| !allowed(d)).cloned(),
                        _ => None,
                    };
                    if let Some(bad) = bad {
                        return Err(violation(format!("sharing with {bad} is not allowed by your organisation")));
                    }
                }
            }
        }
        if let Some(g) = p.slug_generator
            && !self.allowed_slug_generators.is_empty()
            && !self.allowed_slug_generators.iter().any(|a| a == g)
        {
            return Err(violation(format!("the '{g}' link style is not allowed")));
        }
        Ok(())
    }

    fn normalise(mut self) -> AppResult<Self> {
        if self.max_expiry_days.is_some_and(|d| !(1..=366).contains(&d)) {
            return Err(AppError::BadRequest("max_expiry_days must be 1-366".into()));
        }
        if self.max_views.is_some_and(|v| !(1..=10_000).contains(&v)) {
            return Err(AppError::BadRequest("max_views must be 1-10000".into()));
        }
        self.allowed_recipient_domains = self
            .allowed_recipient_domains
            .iter()
            .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        if self.allowed_recipient_domains.iter().any(|d| !d.contains('.')) {
            return Err(AppError::BadRequest("recipient domains look like example.com".into()));
        }
        Ok(self)
    }
}

fn require_admin(user: &CurrentUser) -> AppResult<()> {
    if !user.is_admin() {
        return Err(AppError::Forbidden("admins only".into()));
    }
    Ok(())
}

/// Org policies (readable by everyone signed in, so the UI can explain limits).
#[utoipa::path(get, path = "/org/settings", tag = "org", operation_id = "org_settings_get", responses((status = 200, body = OrgSettings)))]
async fn get(State(state): State<AppState>, _user: CurrentUser) -> AppResult<Json<OrgSettings>> {
    Ok(Json(load(&state).await?))
}

/// Replace org policies (admins).
#[utoipa::path(put, path = "/org/settings", tag = "org", operation_id = "org_settings_put", request_body = OrgSettings,
    responses((status = 200, body = OrgSettings), (status = 403, body = crate::error::ErrorBody)))]
async fn put(
    State(state): State<AppState>,
    client: ClientInfo,
    user: CurrentUser,
    Json(req): Json<OrgSettings>,
) -> AppResult<Json<OrgSettings>> {
    require_admin(&user)?;
    let new = req.normalise()?;
    for g in &new.allowed_slug_generators {
        if state.slugs.get(g).is_none() {
            return Err(AppError::BadRequest(format!("unknown link style '{g}'")));
        }
    }
    let old = load(&state).await?;
    sqlx::query("UPDATE org_settings SET settings = ?, updated_at = ?, updated_by = ? WHERE id = 1")
        .bind(serde_json::to_string(&new).map_err(anyhow::Error::from)?)
        .bind(now())
        .bind(user.id)
        .execute(&state.db)
        .await?;
    state
        .audit
        .record(
            user.event(Action::OrgSettingsChanged)
                .client(&client)
                .detail("before", &old)
                .detail("after", &new),
        )
        .await?;
    Ok(Json(new))
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(get, put))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(rule: Rule) -> PolicyRule {
        PolicyRule {
            group: RuleGroup::Include,
            rule,
        }
    }

    #[test]
    fn enforcement() {
        let s = OrgSettings {
            force_e2e: true,
            allow_public_shares: false,
            max_expiry_days: Some(7),
            max_views: Some(5),
            allowed_recipient_domains: vec!["acme.com".into()],
            allowed_slug_generators: vec!["words".into()],
            ..Default::default()
        };
        let ok_policy = [rule(Rule::EmailDomain {
            domains: vec!["acme.com".into()],
            methods: vec![],
        })];
        let base = || ShareParams {
            enc_mode: Some(EncMode::E2e),
            expires_at: Some(Some(now() + 86_400)),
            max_views: Some(Some(3)),
            policy: Some(&ok_policy),
            slug_generator: Some("words"),
        };
        assert!(s.enforce(&base()).is_ok());
        assert!(
            s.enforce(&ShareParams {
                enc_mode: Some(EncMode::Server),
                ..base()
            })
            .is_err()
        );
        assert!(
            s.enforce(&ShareParams {
                expires_at: Some(None),
                ..base()
            })
            .is_err()
        );
        assert!(
            s.enforce(&ShareParams {
                expires_at: Some(Some(now() + 30 * 86_400)),
                ..base()
            })
            .is_err()
        );
        assert!(
            s.enforce(&ShareParams {
                max_views: Some(None),
                ..base()
            })
            .is_err()
        );
        assert!(
            s.enforce(&ShareParams {
                max_views: Some(Some(6)),
                ..base()
            })
            .is_err()
        );
        assert!(
            s.enforce(&ShareParams {
                slug_generator: Some("custom"),
                ..base()
            })
            .is_err()
        );
        let public = [rule(Rule::Everyone)];
        assert!(
            s.enforce(&ShareParams {
                policy: Some(&public),
                ..base()
            })
            .is_err()
        );
        let outside = [rule(Rule::Email {
            emails: vec!["x@gmail.com".into()],
            methods: vec![],
        })];
        assert!(
            s.enforce(&ShareParams {
                policy: Some(&outside),
                ..base()
            })
            .is_err()
        );
        // Unchanged fields (None) aren't re-checked on updates.
        assert!(
            s.enforce(&ShareParams {
                enc_mode: None,
                expires_at: None,
                max_views: None,
                policy: None,
                slug_generator: None
            })
            .is_ok()
        );
        assert!(
            OrgSettings::default()
                .enforce(&ShareParams {
                    enc_mode: Some(EncMode::Server),
                    expires_at: Some(None),
                    ..base()
                })
                .is_ok()
        );
    }
}
