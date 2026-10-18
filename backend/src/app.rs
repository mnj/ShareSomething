use std::{ops::Deref, sync::Arc};

use sqlx::SqlitePool;

use crate::{
    audit::{Audit, format::Observer},
    auth::{oidc::OidcProviders, passkey::Passkeys},
    blobs::Blobs,
    config::Config,
    crypto::MasterKey,
    mailer::Mailer,
    net::{client_ip::ProxySettings, rate_limit::RateLimiters},
    slug::SlugRegistry,
};

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub cfg: Config,
    pub db: SqlitePool,
    pub master: MasterKey,
    pub slugs: SlugRegistry,
    pub proxy: ProxySettings,
    pub limits: RateLimiters,
    pub blobs: Blobs,
    pub mailer: Mailer,
    pub oidc: OidcProviders,
    pub passkeys: Passkeys,
    pub audit: Arc<Audit>,
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(cfg: Config, db: SqlitePool, master: MasterKey) -> anyhow::Result<Self> {
        let slugs = SlugRegistry::from_config(&cfg.slugs)?;
        let blobs = Blobs::new(&cfg.data_dir);
        let mailer = Mailer::from_config(&cfg.email)?;
        let oidc = OidcProviders::new(&cfg.oidc)?;
        let passkeys = Passkeys::new(&cfg);
        let audit = Arc::new(Audit::new(db.clone()));
        let proxy = ProxySettings {
            mode: cfg.proxy.mode,
            trusted: cfg.trusted_proxies()?,
        };
        Ok(Self(Arc::new(Inner {
            cfg,
            db,
            master,
            slugs,
            proxy,
            limits: RateLimiters::default(),
            blobs,
            mailer,
            oidc,
            passkeys,
            audit,
        })))
    }

    #[cfg(test)]
    pub fn set_mailer(&mut self, mailer: crate::mailer::Mailer) {
        Arc::get_mut(&mut self.0).expect("state not shared yet").mailer = mailer;
    }

    /// How this instance identifies itself in shipped audit events.
    pub fn observer(&self) -> Observer {
        Observer {
            hostname: self.cfg.audit_hostname(),
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    pub fn share_url(&self, slug: &str) -> String {
        format!("{}/s/{slug}", self.cfg.base_url())
    }
}
