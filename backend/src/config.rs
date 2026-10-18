use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};

/// Runtime configuration. Sources, lowest to highest precedence: built-in defaults,
/// an optional TOML file, then `SS_*` environment variables (nested keys use `__`,
/// e.g. `SS_PROXY__MODE=cloudflare`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// `single`: one owner (self-hosting for yourself). `team`: multiple users with roles.
    pub mode: InstanceMode,
    pub bind: SocketAddr,
    /// Public URL the app is reached at; used to build share links and check `Origin`.
    pub base_url: String,
    pub data_dir: PathBuf,
    /// Base64 32-byte key wrapping server-side DEKs. Generated into `data_dir/master.key` if unset.
    pub master_key: Option<String>,
    pub session_ttl_hours: i64,
    /// Defaults to true when `base_url` is https.
    pub cookie_secure: Option<bool>,
    /// Max size of a text/link/credential payload (ciphertext) in bytes.
    pub max_text_bytes: usize,
    /// Max total size of the files in one file share.
    pub max_upload_bytes: u64,
    /// Max number of files in one file share.
    pub max_files: usize,
    /// How long a recipient can keep downloading files after opening a share.
    pub download_ttl_mins: i64,
    /// How long burned/expired/revoked shares stay visible on the dashboard before purge.
    pub retention_days: i64,
    /// Wrong passphrase attempts before a share is destroyed.
    pub max_passphrase_attempts: i64,
    /// How long a recipient stays signed in (email code / OIDC).
    pub recipient_session_hours: i64,
    pub audit: AuditConfig,
    pub team: TeamConfig,
    pub proxy: ProxyConfig,
    pub slugs: SlugConfig,
    pub email: EmailConfig,
    /// Sign-in providers for recipients.
    pub oidc: Vec<OidcProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailConfig {
    pub mode: EmailMode,
    /// e.g. `ShareSomething <share@example.com>`
    pub from: String,
    pub smtp_host: String,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_tls: SmtpTls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailMode {
    /// Email one-time codes are unavailable.
    Disabled,
    /// Codes are written to the server log instead of sent (development only).
    Log,
    Smtp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpTls {
    /// STARTTLS, usually port 587.
    Starttls,
    /// Implicit TLS, usually port 465.
    Tls,
    /// Plain text; only for a relay on localhost.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    /// Short id used in URLs and policy rules (`oidc:<id>`), e.g. `google`.
    pub id: String,
    /// Button label, e.g. `Google`.
    pub name: String,
    #[serde(default)]
    pub kind: OidcKind,
    /// OIDC issuer URL (discovery). Not used for `kind = "github"`.
    pub issuer: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Team mode: members may sign in to their account with this provider (company SSO).
    #[serde(default)]
    pub member_login: bool,
    /// Accept an email the provider doesn't mark as verified (some Microsoft tenants omit
    /// `email_verified`). Only enable for providers you trust to control email addresses.
    #[serde(default)]
    pub trust_unverified_email: bool,
    /// GitHub endpoint overrides (GitHub Enterprise / tests).
    #[serde(default)]
    pub github_web_url: Option<String>,
    #[serde(default)]
    pub github_api_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OidcKind {
    #[default]
    Oidc,
    Github,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            mode: EmailMode::Disabled,
            from: "ShareSomething <noreply@localhost>".into(),
            smtp_host: String::new(),
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            smtp_tls: SmtpTls::Starttls,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceMode {
    #[default]
    Single,
    Team,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TeamConfig {
    /// Email domains whose SSO sign-ins become members automatically (empty = invite only).
    #[serde(deserialize_with = "list_or_csv")]
    pub allowed_domains: Vec<String>,
    /// Role for auto-provisioned SSO members.
    pub default_role: String,
    /// Allow password accounts (invites). With SSO only, set this to false.
    pub local_accounts: bool,
    /// How long an invite link stays valid.
    pub invite_days: i64,
}

impl Default for TeamConfig {
    fn default() -> Self {
        Self {
            allowed_domains: vec![],
            default_role: "member".into(),
            local_accounts: true,
            invite_days: 7,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Delete audit records older than this (None = keep forever). The chain stays verifiable.
    pub retention_days: Option<i64>,
    /// Host name reported to SIEMs (defaults to the `base_url` host).
    pub hostname: Option<String>,
    /// SIEM / log destinations.
    pub shippers: Vec<crate::audit::ship::ShipperConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub mode: ProxyMode,
    /// Peers allowed to supply client-IP headers. List or comma-separated string.
    #[serde(deserialize_with = "list_or_csv")]
    pub trusted_proxies: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Use the socket peer address; ignore forwarding headers.
    None,
    /// Trust `CF-Connecting-IP` / `CF-IPCountry` from trusted peers (cloudflared, CF edge).
    Cloudflare,
    /// Trust `X-Forwarded-For` / `Forwarded` from trusted peers (Caddy, nginx, Traefik).
    Forwarded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlugConfig {
    pub default: String,
    /// Generators to enable; empty means all built-ins.
    #[serde(deserialize_with = "list_or_csv")]
    pub enabled: Vec<String>,
    /// Optional custom wordlist (one word per line) for the `words` generator.
    pub words_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".parse().unwrap(),
            base_url: "http://localhost:8080".into(),
            data_dir: "./data".into(),
            master_key: None,
            session_ttl_hours: 24 * 7,
            cookie_secure: None,
            max_text_bytes: 1024 * 1024,
            max_upload_bytes: 1024 * 1024 * 1024,
            max_files: 100,
            download_ttl_mins: 60,
            retention_days: 7,
            max_passphrase_attempts: 10,
            recipient_session_hours: 12,
            mode: InstanceMode::Single,
            audit: AuditConfig::default(),
            team: TeamConfig::default(),
            proxy: ProxyConfig::default(),
            slugs: SlugConfig::default(),
            email: EmailConfig::default(),
            oidc: vec![],
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            mode: ProxyMode::None,
            trusted_proxies: vec![],
        }
    }
}

impl Default for SlugConfig {
    fn default() -> Self {
        Self {
            default: "shortcode".into(),
            enabled: vec![],
            words_file: None,
        }
    }
}

fn list_or_csv<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ListOrCsv {
        List(Vec<String>),
        Csv(String),
    }
    Ok(match ListOrCsv::deserialize(d)? {
        ListOrCsv::List(v) => v,
        ListOrCsv::Csv(s) => s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
    })
}

impl Config {
    pub fn load(file: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(path) = file {
            if !path.exists() {
                bail!("config file {} not found", path.display());
            }
            fig = fig.merge(Toml::file(path));
        }
        let cfg: Config = fig
            .merge(Env::prefixed("SS_").split("__"))
            .extract()
            .context("invalid configuration")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let url = url::Url::parse(&self.base_url).context("base_url is not a valid URL")?;
        if !matches!(url.scheme(), "http" | "https") {
            bail!("base_url must be http(s)");
        }
        self.trusted_proxies()?;
        let mut seen = std::collections::HashSet::new();
        for p in &self.oidc {
            if p.id.is_empty() || !p.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                bail!("oidc provider id '{}' must be [A-Za-z0-9_-]+", p.id);
            }
            if !seen.insert(p.id.clone()) {
                bail!("duplicate oidc provider id '{}'", p.id);
            }
            if p.kind == OidcKind::Oidc && p.issuer.is_none() {
                bail!("oidc provider '{}' needs an issuer", p.id);
            }
        }
        let mut names = std::collections::HashSet::new();
        for s in &self.audit.shippers {
            if s.name.is_empty() || !names.insert(s.name.clone()) {
                bail!("audit shipper names must be unique and non-empty ('{}')", s.name);
            }
        }
        if !matches!(self.team.default_role.as_str(), "member" | "auditor") {
            bail!("team.default_role must be member or auditor");
        }
        if self.audit.retention_days.is_some_and(|d| d < 1) {
            bail!("audit.retention_days must be at least 1");
        }
        if self.email.mode == EmailMode::Smtp && self.email.smtp_host.is_empty() {
            bail!("email.mode = smtp needs email.smtp_host");
        }
        Ok(())
    }

    pub fn base_url(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    /// `scheme://host[:port]` of `base_url`, compared against request `Origin`.
    pub fn origin(&self) -> String {
        url::Url::parse(&self.base_url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default()
    }

    /// Host name reported in shipped audit events.
    pub fn audit_hostname(&self) -> String {
        self.audit
            .hostname
            .clone()
            .or_else(|| url::Url::parse(&self.base_url).ok().and_then(|u| u.host_str().map(String::from)))
            .unwrap_or_default()
    }

    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure.unwrap_or_else(|| self.base_url.starts_with("https://"))
    }

    pub fn trusted_proxies(&self) -> anyhow::Result<Vec<IpNet>> {
        self.proxy
            .trusted_proxies
            .iter()
            .map(|s| parse_net(s).with_context(|| format!("invalid trusted proxy '{s}'")))
            .collect()
    }

    /// Returns the master key, generating and persisting one on first run if not configured.
    pub fn master_key(&self) -> anyhow::Result<[u8; 32]> {
        let decode = |s: &str| -> anyhow::Result<[u8; 32]> {
            let bytes = B64.decode(s.trim()).context("master key is not valid base64")?;
            bytes.try_into().map_err(|_| anyhow::anyhow!("master key must be exactly 32 bytes"))
        };
        if let Some(k) = &self.master_key {
            return decode(k);
        }
        let path = self.data_dir.join("master.key");
        if path.exists() {
            return decode(&std::fs::read_to_string(&path)?);
        }
        let key: [u8; 32] = rand::random();
        std::fs::create_dir_all(&self.data_dir)?;
        write_private(&path, B64.encode(key).as_bytes())?;
        tracing::warn!(path = %path.display(), "generated new master key; back it up or set SS_MASTER_KEY");
        Ok(key)
    }
}

/// Parses a CIDR, or a bare IP as a single-host network.
pub fn parse_net(s: &str) -> anyhow::Result<IpNet> {
    let s = s.trim();
    if let Ok(n) = s.parse::<IpNet>() {
        return Ok(n.trunc());
    }
    let ip: std::net::IpAddr = s.parse()?;
    Ok(IpNet::from(ip.to_canonical()))
}

fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(data)
}
