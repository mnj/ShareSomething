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
    pub proxy: ProxyConfig,
    pub slugs: SlugConfig,
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
            proxy: ProxyConfig::default(),
            slugs: SlugConfig::default(),
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
