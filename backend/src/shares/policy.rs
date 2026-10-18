//! Per-share access policies, modelled on Cloudflare Access application policies.
//!
//! - **exclude**: any matching rule denies access
//! - **require**: every rule must match
//! - **include**: at least one rule must match (an empty include list denies everyone)
//!
//! Identity rules (email, domain, OIDC, owner) can't be decided for an anonymous visitor,
//! so they yield "needs auth" and the visitor is asked to sign in with an acceptable method.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::config::parse_net;

/// How long an owner TOTP step-up stays valid for `require_owner_mfa` shares.
pub const MFA_FRESH_SECS: i64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(rename_all = "lowercase", type_name = "TEXT")]
pub enum RuleGroup {
    Include,
    Require,
    Exclude,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Rule {
    /// Anyone with the link.
    Everyone,
    /// The signed-in owner.
    Owner,
    /// Client IP within any of these networks (CIDR or bare IP, v4/v6).
    Ip { cidrs: Vec<String> },
    /// Client country (ISO 3166-1 alpha-2), from a trusted Cloudflare header.
    Country { countries: Vec<String> },
    /// Verified email address. `methods` restricts how it is verified
    /// (`email_otp`, `oidc:<provider>`); empty allows any configured method.
    Email {
        emails: Vec<String>,
        #[serde(default)]
        methods: Vec<String>,
    },
    /// Any verified address at one of these domains.
    EmailDomain {
        domains: Vec<String>,
        #[serde(default)]
        methods: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PolicyRule {
    pub group: RuleGroup,
    #[serde(flatten)]
    pub rule: Rule,
}

impl Rule {
    pub fn type_name(&self) -> &'static str {
        match self {
            Rule::Everyone => "everyone",
            Rule::Owner => "owner",
            Rule::Ip { .. } => "ip",
            Rule::Country { .. } => "country",
            Rule::Email { .. } => "email",
            Rule::EmailDomain { .. } => "email_domain",
        }
    }

    /// Validates and canonicalises user input (lowercase emails, truncated CIDRs, ...).
    pub fn normalise(self) -> Result<Rule, String> {
        fn non_empty<T>(v: &[T], what: &str) -> Result<(), String> {
            if v.is_empty() {
                Err(format!("{what} list must not be empty"))
            } else {
                Ok(())
            }
        }
        fn methods(m: Vec<String>) -> Result<Vec<String>, String> {
            m.into_iter()
                .map(|m| {
                    let m = m.trim().to_ascii_lowercase();
                    let ok = m == "email_otp"
                        || m.strip_prefix("oidc:")
                            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
                    if ok { Ok(m) } else { Err(format!("unknown auth method '{m}'")) }
                })
                .collect()
        }
        Ok(match self {
            Rule::Everyone | Rule::Owner => self,
            Rule::Ip { cidrs } => {
                non_empty(&cidrs, "cidrs")?;
                let cidrs = cidrs
                    .iter()
                    .map(|c| parse_net(c).map(|n| n.to_string()).map_err(|_| format!("invalid IP/CIDR '{c}'")))
                    .collect::<Result<_, _>>()?;
                Rule::Ip { cidrs }
            }
            Rule::Country { countries } => {
                non_empty(&countries, "countries")?;
                let countries = countries
                    .into_iter()
                    .map(|c| {
                        let c = c.trim().to_ascii_uppercase();
                        if c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) {
                            Ok(c)
                        } else {
                            Err(format!("invalid country code '{c}'"))
                        }
                    })
                    .collect::<Result<_, _>>()?;
                Rule::Country { countries }
            }
            Rule::Email { emails, methods: m } => {
                non_empty(&emails, "emails")?;
                let emails = emails
                    .into_iter()
                    .map(|e| {
                        let e = e.trim().to_ascii_lowercase();
                        match e.split_once('@') {
                            Some((l, d)) if !l.is_empty() && d.contains('.') && !d.contains('@') => Ok(e),
                            _ => Err(format!("invalid email '{e}'")),
                        }
                    })
                    .collect::<Result<_, _>>()?;
                Rule::Email {
                    emails,
                    methods: methods(m)?,
                }
            }
            Rule::EmailDomain { domains, methods: m } => {
                non_empty(&domains, "domains")?;
                let domains = domains
                    .into_iter()
                    .map(|d| {
                        let d = d.trim().trim_start_matches('@').to_ascii_lowercase();
                        if d.contains('.') && d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
                            Ok(d)
                        } else {
                            Err(format!("invalid domain '{d}'"))
                        }
                    })
                    .collect::<Result<_, _>>()?;
                Rule::EmailDomain {
                    domains,
                    methods: methods(m)?,
                }
            }
        })
    }
}

/// A verified recipient identity.
#[derive(Debug, Clone)]
pub struct Identity {
    pub email: String,
    /// `email_otp` or `oidc:<provider>`.
    pub method: String,
}

/// The signed-in user of the request, if any.
#[derive(Debug, Clone, Default)]
pub struct UserCtx {
    pub id: i64,
    pub mfa_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AccessContext {
    pub now: i64,
    pub ip: IpAddr,
    pub country: Option<String>,
    pub user: Option<UserCtx>,
    pub identities: Vec<Identity>,
}

/// The parts of a share the evaluator needs.
#[derive(Debug, Clone)]
pub struct ShareState {
    pub available: bool,
    pub expires_at: Option<i64>,
    pub max_views: Option<i64>,
    pub views: i64,
    pub require_owner_mfa: bool,
    /// Time-lock: content is only released from this time on.
    pub available_from: Option<i64>,
    /// The user who owns the share; the `owner` rule and owner MFA refer to them.
    pub owner_id: i64,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Expired, burned, revoked or out of views.
    Unavailable,
    Denied,
    NeedOwnerLogin,
    NeedOwnerMfa,
    /// Allowed, but time-locked until this unix time.
    NotYet(i64),
    /// Sign in with one of these methods (`email_otp`, `oidc:<p>`; empty = any configured).
    NeedRecipientAuth(Vec<String>),
}

enum Match {
    Yes,
    No,
    /// Unknown until the visitor authenticates; carries acceptable methods ("owner" for the owner).
    NeedsAuth(Vec<String>),
}

fn identity_match(ctx: &AccessContext, methods: &[String], pred: impl Fn(&str) -> bool) -> Match {
    let usable = |i: &&Identity| methods.is_empty() || methods.contains(&i.method);
    if ctx.identities.iter().filter(usable).any(|i| pred(&i.email)) {
        Match::Yes
    } else if ctx.identities.iter().any(|i| usable(&i)) {
        // Signed in with an acceptable method, but not as an allowed identity.
        Match::No
    } else {
        Match::NeedsAuth(methods.to_vec())
    }
}

fn rule_match(rule: &Rule, ctx: &AccessContext, owner_id: i64) -> Match {
    let yes = |b: bool| if b { Match::Yes } else { Match::No };
    match rule {
        Rule::Everyone => Match::Yes,
        Rule::Owner => match &ctx.user {
            Some(u) if u.id == owner_id => Match::Yes,
            // Signed in, but as someone else: this rule can never match for them.
            Some(_) => Match::No,
            None => Match::NeedsAuth(vec!["owner".into()]),
        },
        Rule::Ip { cidrs } => yes(cidrs.iter().filter_map(|c| parse_net(c).ok()).any(|n| n.contains(&ctx.ip))),
        Rule::Country { countries } => yes(ctx.country.as_ref().is_some_and(|c| countries.contains(c))),
        Rule::Email { emails, methods } => identity_match(ctx, methods, |e| emails.iter().any(|x| x == e)),
        Rule::EmailDomain { domains, methods } => identity_match(ctx, methods, |e| {
            e.rsplit_once('@').is_some_and(|(_, d)| domains.iter().any(|x| x == d))
        }),
    }
}

/// Turns accumulated auth requirements into the decision shown to the visitor.
fn need_auth(methods: Vec<Vec<String>>) -> Decision {
    if methods.iter().any(|m| m.iter().any(|x| x == "owner")) {
        return Decision::NeedOwnerLogin;
    }
    let mut all: Vec<String> = Vec::new();
    for m in methods {
        if m.is_empty() {
            return Decision::NeedRecipientAuth(vec![]);
        }
        all.extend(m);
    }
    all.sort();
    all.dedup();
    Decision::NeedRecipientAuth(all)
}

/// Whether proving ownership of `email` via `method` could get a visitor past this policy's
/// identity rules. Used to decide whether sending a one-time code makes sense at all.
pub fn email_could_satisfy(rules: &[PolicyRule], email: &str, method: &str) -> bool {
    let allows = |methods: &[String]| methods.is_empty() || methods.iter().any(|m| m == method);
    let matches = |rule: &Rule| match rule {
        Rule::Email { emails, methods } => allows(methods) && emails.iter().any(|e| e == email),
        Rule::EmailDomain { domains, methods } => {
            allows(methods) && email.rsplit_once('@').is_some_and(|(_, d)| domains.iter().any(|x| x == d))
        }
        _ => false,
    };
    let excluded = rules.iter().filter(|r| r.group == RuleGroup::Exclude).any(|r| matches(&r.rule));
    !excluded && rules.iter().filter(|r| r.group != RuleGroup::Exclude).any(|r| matches(&r.rule))
}

pub fn evaluate(share: &ShareState, ctx: &AccessContext) -> Decision {
    if !share.available || share.expires_at.is_some_and(|t| t <= ctx.now) || share.max_views.is_some_and(|m| share.views >= m) {
        return Decision::Unavailable;
    }

    let group = |g: RuleGroup| {
        share
            .rules
            .iter()
            .filter(move |r| r.group == g)
            .map(|r| rule_match(&r.rule, ctx, share.owner_id))
    };

    // An exclude rule that can't be decided yet (anonymous visitor) doesn't block; identity
    // excludes only take effect once the visitor has authenticated for an include/require rule.
    if group(RuleGroup::Exclude).any(|m| matches!(m, Match::Yes)) {
        return Decision::Denied;
    }

    let mut pending = Vec::new();
    for m in group(RuleGroup::Require) {
        match m {
            Match::Yes => {}
            Match::No => return Decision::Denied,
            Match::NeedsAuth(methods) => pending.push(methods),
        }
    }

    let mut include_ok = false;
    let mut include_pending = Vec::new();
    for m in group(RuleGroup::Include) {
        match m {
            Match::Yes => include_ok = true,
            Match::No => {}
            Match::NeedsAuth(methods) => include_pending.push(methods),
        }
    }
    if !include_ok {
        if include_pending.is_empty() {
            return Decision::Denied;
        }
        pending.extend(include_pending);
    }
    if !pending.is_empty() {
        return need_auth(pending);
    }

    if share.require_owner_mfa {
        match &ctx.user {
            None => return Decision::NeedOwnerLogin,
            Some(u) if u.id != share.owner_id => return Decision::Denied,
            Some(o) if o.mfa_at.is_none_or(|t| ctx.now - t > MFA_FRESH_SECS) => {
                return Decision::NeedOwnerMfa;
            }
            Some(_) => {}
        }
    }
    // Checked last, so visitors who aren't allowed in don't even learn when it unlocks.
    if let Some(at) = share.available_from.filter(|at| *at > ctx.now) {
        return Decision::NotYet(at);
    }
    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn r(group: RuleGroup, rule: Rule) -> PolicyRule {
        PolicyRule {
            group,
            rule: rule.normalise().unwrap(),
        }
    }
    fn inc(rule: Rule) -> PolicyRule {
        r(RuleGroup::Include, rule)
    }
    fn req(rule: Rule) -> PolicyRule {
        r(RuleGroup::Require, rule)
    }
    fn exc(rule: Rule) -> PolicyRule {
        r(RuleGroup::Exclude, rule)
    }
    fn ip_rule(c: &str) -> Rule {
        Rule::Ip { cidrs: vec![c.into()] }
    }
    fn domain(d: &str) -> Rule {
        Rule::EmailDomain {
            domains: vec![d.into()],
            methods: vec![],
        }
    }

    fn share(rules: Vec<PolicyRule>) -> ShareState {
        ShareState {
            available: true,
            expires_at: None,
            max_views: None,
            views: 0,
            require_owner_mfa: false,
            available_from: None,
            owner_id: 1,
            rules,
        }
    }

    fn anon(ip: &str) -> AccessContext {
        AccessContext {
            now: NOW,
            ip: ip.parse().unwrap(),
            country: None,
            user: None,
            identities: vec![],
        }
    }

    fn with_email(mut c: AccessContext, email: &str, method: &str) -> AccessContext {
        c.identities.push(Identity {
            email: email.into(),
            method: method.into(),
        });
        c
    }

    fn owner(mut c: AccessContext, mfa_ago: Option<i64>) -> AccessContext {
        c.user = Some(UserCtx {
            id: 1,
            mfa_at: mfa_ago.map(|a| NOW - a),
        });
        c
    }

    #[test]
    fn owner_rule_is_the_shares_owner_not_any_user() {
        let mut s = share(vec![inc(Rule::Owner)]);
        let mut other = anon("1.1.1.1");
        other.user = Some(UserCtx { id: 2, mfa_at: Some(NOW) });
        assert_eq!(evaluate(&s, &other), Decision::Denied);
        s.rules = vec![inc(Rule::Everyone)];
        s.require_owner_mfa = true;
        assert_eq!(evaluate(&s, &other), Decision::Denied, "owner MFA is the owner's, not any user's");
        assert_eq!(evaluate(&s, &owner(anon("1.1.1.1"), Some(1))), Decision::Allow);
    }

    #[test]
    fn time_lock_applies_after_policy() {
        let mut s = share(vec![inc(ip_rule("10.0.0.0/8"))]);
        s.available_from = Some(NOW + 60);
        assert_eq!(
            evaluate(&s, &anon("8.8.8.8")),
            Decision::Denied,
            "outsiders don't learn the unlock time"
        );
        assert_eq!(evaluate(&s, &anon("10.0.0.1")), Decision::NotYet(NOW + 60));
        s.available_from = Some(NOW);
        assert_eq!(evaluate(&s, &anon("10.0.0.1")), Decision::Allow);
    }

    #[test]
    fn availability() {
        let mut s = share(vec![inc(Rule::Everyone)]);
        assert_eq!(evaluate(&s, &anon("1.2.3.4")), Decision::Allow);
        s.expires_at = Some(NOW);
        assert_eq!(evaluate(&s, &anon("1.2.3.4")), Decision::Unavailable);
        s.expires_at = Some(NOW + 1);
        s.max_views = Some(1);
        s.views = 1;
        assert_eq!(evaluate(&s, &anon("1.2.3.4")), Decision::Unavailable);
        s.views = 0;
        s.available = false;
        assert_eq!(evaluate(&s, &anon("1.2.3.4")), Decision::Unavailable);
    }

    #[test]
    fn empty_include_denies() {
        assert_eq!(evaluate(&share(vec![]), &anon("1.2.3.4")), Decision::Denied);
    }

    #[test]
    fn ip_include_and_exclude() {
        let s = share(vec![inc(ip_rule("203.0.113.0/24")), exc(ip_rule("203.0.113.66"))]);
        assert_eq!(evaluate(&s, &anon("203.0.113.5")), Decision::Allow);
        assert_eq!(evaluate(&s, &anon("203.0.113.66")), Decision::Denied);
        assert_eq!(evaluate(&s, &anon("198.51.100.1")), Decision::Denied);
        let v6 = share(vec![inc(ip_rule("2001:db8::/32"))]);
        assert_eq!(evaluate(&v6, &anon("2001:db8:1::9")), Decision::Allow);
    }

    #[test]
    fn domain_requires_auth_then_matches() {
        let s = share(vec![inc(domain("acme.com"))]);
        assert_eq!(evaluate(&s, &anon("1.1.1.1")), Decision::NeedRecipientAuth(vec![]));
        assert_eq!(
            evaluate(&s, &with_email(anon("1.1.1.1"), "bob@acme.com", "email_otp")),
            Decision::Allow
        );
        assert_eq!(
            evaluate(&s, &with_email(anon("1.1.1.1"), "bob@evil.com", "email_otp")),
            Decision::Denied
        );
    }

    #[test]
    fn method_restriction() {
        let s = share(vec![inc(Rule::Email {
            emails: vec!["Bob@Acme.com".into()],
            methods: vec!["oidc:google".into()],
        })]);
        let otp = with_email(anon("1.1.1.1"), "bob@acme.com", "email_otp");
        assert_eq!(evaluate(&s, &otp), Decision::NeedRecipientAuth(vec!["oidc:google".into()]));
        assert_eq!(evaluate(&s, &with_email(otp, "bob@acme.com", "oidc:google")), Decision::Allow);
    }

    #[test]
    fn require_ip_plus_include_domain() {
        let s = share(vec![inc(domain("acme.com")), req(ip_rule("10.0.0.0/8"))]);
        let good = with_email(anon("10.1.2.3"), "a@acme.com", "email_otp");
        assert_eq!(evaluate(&s, &good), Decision::Allow);
        // Outside the network: denied before even asking to sign in.
        assert_eq!(evaluate(&s, &anon("8.8.8.8")), Decision::Denied);
        assert_eq!(evaluate(&s, &anon("10.0.0.1")), Decision::NeedRecipientAuth(vec![]));
    }

    #[test]
    fn exclude_identity_after_auth() {
        let s = share(vec![
            inc(domain("acme.com")),
            exc(Rule::Email {
                emails: vec!["mallory@acme.com".into()],
                methods: vec![],
            }),
        ]);
        assert_eq!(
            evaluate(&s, &with_email(anon("1.1.1.1"), "mallory@acme.com", "email_otp")),
            Decision::Denied
        );
        assert_eq!(
            evaluate(&s, &with_email(anon("1.1.1.1"), "alice@acme.com", "email_otp")),
            Decision::Allow
        );
    }

    #[test]
    fn country_rule() {
        let s = share(vec![inc(Rule::Country {
            countries: vec!["dk".into()],
        })]);
        let mut c = anon("1.1.1.1");
        assert_eq!(evaluate(&s, &c), Decision::Denied);
        c.country = Some("DK".into());
        assert_eq!(evaluate(&s, &c), Decision::Allow);
    }

    #[test]
    fn owner_only_with_mfa() {
        let mut s = share(vec![inc(Rule::Owner)]);
        assert_eq!(evaluate(&s, &anon("1.1.1.1")), Decision::NeedOwnerLogin);
        assert_eq!(evaluate(&s, &owner(anon("1.1.1.1"), None)), Decision::Allow);
        s.require_owner_mfa = true;
        assert_eq!(evaluate(&s, &owner(anon("1.1.1.1"), None)), Decision::NeedOwnerMfa);
        assert_eq!(
            evaluate(&s, &owner(anon("1.1.1.1"), Some(MFA_FRESH_SECS + 1))),
            Decision::NeedOwnerMfa
        );
        assert_eq!(evaluate(&s, &owner(anon("1.1.1.1"), Some(10))), Decision::Allow);
        // MFA toggle also applies on top of a public policy.
        let mut p = share(vec![inc(Rule::Everyone)]);
        p.require_owner_mfa = true;
        assert_eq!(evaluate(&p, &anon("1.1.1.1")), Decision::NeedOwnerLogin);
    }

    #[test]
    fn owner_auth_wins_over_recipient_auth() {
        let s = share(vec![inc(Rule::Owner), inc(domain("acme.com"))]);
        assert_eq!(evaluate(&s, &anon("1.1.1.1")), Decision::NeedOwnerLogin);
    }

    #[test]
    fn email_could_satisfy_checks_rules_and_methods() {
        let rules = vec![
            inc(domain("acme.com")),
            inc(Rule::Email {
                emails: vec!["bob@x.org".into()],
                methods: vec!["oidc:google".into()],
            }),
            exc(Rule::Email {
                emails: vec!["mallory@acme.com".into()],
                methods: vec![],
            }),
        ];
        assert!(email_could_satisfy(&rules, "alice@acme.com", "email_otp"));
        assert!(!email_could_satisfy(&rules, "mallory@acme.com", "email_otp"));
        assert!(!email_could_satisfy(&rules, "bob@x.org", "email_otp"));
        assert!(email_could_satisfy(&rules, "bob@x.org", "oidc:google"));
        assert!(!email_could_satisfy(&[inc(Rule::Everyone)], "a@b.c", "email_otp"));
    }

    #[test]
    fn normalise_rejects_garbage() {
        assert!(
            Rule::Ip {
                cidrs: vec!["300.1.1.1".into()]
            }
            .normalise()
            .is_err()
        );
        assert!(Rule::Ip { cidrs: vec![] }.normalise().is_err());
        assert!(
            Rule::Email {
                emails: vec!["nope".into()],
                methods: vec![]
            }
            .normalise()
            .is_err()
        );
        assert!(
            Rule::Email {
                emails: vec!["a@b.c".into()],
                methods: vec!["sms".into()]
            }
            .normalise()
            .is_err()
        );
        assert_eq!(
            Rule::Ip {
                cidrs: vec!["10.1.2.3/8".into()]
            }
            .normalise()
            .unwrap(),
            Rule::Ip {
                cidrs: vec!["10.0.0.0/8".into()]
            }
        );
    }
}
