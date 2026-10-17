use std::{ops::Deref, sync::Arc};

use sqlx::SqlitePool;

use crate::{
    blobs::Blobs,
    config::Config,
    crypto::MasterKey,
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
        })))
    }

    pub fn share_url(&self, slug: &str) -> String {
        format!("{}/s/{slug}", self.cfg.base_url())
    }
}
