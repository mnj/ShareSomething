mod admin;
mod api;
mod app;
mod auth;
mod blobs;
mod config;
mod crypto;
mod db;
mod error;
mod jobs;
mod mailer;
mod net;
mod shares;
mod slug;
mod static_files;
mod util;

#[cfg(test)]
mod tests;

use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::{app::AppState, config::Config, crypto::MasterKey};

#[derive(Parser)]
#[command(version, about = "Self-hosted sharing of text, links, files and credentials")]
struct Cli {
    /// Optional TOML config file; every key can also be set as SS_<KEY> (nested: SS_PROXY__MODE).
    #[arg(long, short, env = "SS_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (default).
    Serve,
    /// Manage the owner account.
    Admin {
        #[command(subcommand)]
        cmd: admin::AdminCmd,
    },
    /// Print the OpenAPI document (used to generate frontend types).
    Openapi,
    /// Exit 0 if the local server answers /healthz (for container HEALTHCHECK; no curl needed).
    Healthcheck,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("SS_LOG").unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=info")))
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Openapi => {
            println!("{}", api::openapi_json());
            Ok(())
        }
        Cmd::Admin { cmd } => {
            let cfg = Config::load(cli.config.as_deref())?;
            let db = db::connect(&cfg.data_dir).await?;
            admin::run(cmd, &db).await
        }
        Cmd::Serve => serve(Config::load(cli.config.as_deref())?).await,
        Cmd::Healthcheck => healthcheck(Config::load(cli.config.as_deref())?.bind.port()).await,
    }
}

async fn healthcheck(port: u16) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    stream.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
    let mut buf = vec![0u8; 64];
    let n = stream.read(&mut buf).await?;
    anyhow::ensure!(
        buf[..n].starts_with(b"HTTP/1.1 200") || buf[..n].starts_with(b"HTTP/1.0 200"),
        "unhealthy"
    );
    Ok(())
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    let db = db::connect(&cfg.data_dir).await?;
    let master = MasterKey::new(cfg.master_key()?);
    let bind = cfg.bind;
    let state = AppState::new(cfg, db, master)?;
    if sqlx::query("SELECT 1 FROM owner").fetch_optional(&state.db).await?.is_none() {
        tracing::warn!("no owner account yet: run `sharesomething admin init`");
    }
    jobs::spawn_sweeper(state.clone());
    let app = api::router(state.clone());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, base_url = %state.cfg.base_url(), proxy = ?state.cfg.proxy.mode, "listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok() };
    #[cfg(unix)]
    let term = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("shutting down");
}
