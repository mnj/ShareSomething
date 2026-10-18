//! SIEM log shipping. Each configured shipper runs its own worker with a durable cursor
//! (`audit_cursors`), so delivery is at-least-once and survives restarts and outages.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::SqlitePool;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{
    Action, Audit, Event, Record,
    format::{self, Observer},
};
use crate::util::now;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShipperConfig {
    /// Stable name; the delivery cursor is stored under it.
    pub name: String,
    #[serde(flatten)]
    pub kind: ShipperKind,
    #[serde(default = "default_batch")]
    pub batch_size: usize,
    /// Also ship records written before this shipper was configured.
    #[serde(default = "default_true")]
    pub backfill: bool,
}

fn default_batch() -> usize {
    200
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShipperKind {
    /// JSON lines on stdout, for Docker/Kubernetes log collectors.
    Stdout,
    /// Rotating JSON-lines file.
    File {
        path: PathBuf,
        #[serde(default)]
        max_bytes: Option<u64>,
        #[serde(default)]
        keep: Option<usize>,
    },
    /// RFC 5424 syslog with a JSON or CEF payload.
    Syslog {
        /// `host:port`
        address: String,
        #[serde(default)]
        transport: SyslogTransport,
        #[serde(default)]
        format: SyslogFormat,
        /// Extra CA certificate(s) (PEM) to trust for `transport = "tls"`, e.g. an internal CA.
        #[serde(default)]
        ca_file: Option<PathBuf>,
        #[serde(default)]
        app_name: Option<String>,
        /// Syslog facility number (default 16 = local0).
        #[serde(default)]
        facility: Option<u8>,
    },
    /// HTTP(S) POST of batches.
    Http {
        url: String,
        #[serde(default)]
        preset: HttpPreset,
        /// Splunk HEC token, Elastic API key, or bearer token (generic).
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        /// Generic preset: sign the body as `X-ShareSomething-Signature: sha256=<hex>`.
        #[serde(default)]
        hmac_secret: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogTransport {
    Udp,
    #[default]
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    #[default]
    Json,
    Cef,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpPreset {
    /// NDJSON of ECS documents.
    #[default]
    Generic,
    /// Splunk HTTP Event Collector (`.../services/collector/event`).
    SplunkHec,
    /// Elasticsearch / OpenSearch `_bulk` (URL like `https://es:9200/sharesomething-audit/_bulk`).
    Elastic,
}

impl ShipperKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            ShipperKind::Stdout => "stdout",
            ShipperKind::File { .. } => "file",
            ShipperKind::Syslog { .. } => "syslog",
            ShipperKind::Http { .. } => "http",
        }
    }
}

/// A live connection/handle for one shipper.
enum Sink {
    Stdout,
    File {
        path: PathBuf,
        max_bytes: u64,
        keep: usize,
    },
    Syslog {
        cfg: SyslogCfg,
        conn: Option<Box<dyn AsyncWrite + Unpin + Send>>,
    },
    Http {
        client: reqwest::Client,
        url: String,
        preset: HttpPreset,
        token: Option<String>,
        headers: BTreeMap<String, String>,
        hmac: Option<String>,
    },
}

struct SyslogCfg {
    address: String,
    transport: SyslogTransport,
    format: SyslogFormat,
    ca_file: Option<PathBuf>,
    app_name: String,
    facility: u8,
}

impl Sink {
    fn new(kind: &ShipperKind) -> anyhow::Result<Self> {
        Ok(match kind.clone() {
            ShipperKind::Stdout => Sink::Stdout,
            ShipperKind::File { path, max_bytes, keep } => Sink::File {
                path,
                max_bytes: max_bytes.unwrap_or(100 * 1024 * 1024),
                keep: keep.unwrap_or(5),
            },
            ShipperKind::Syslog {
                address,
                transport,
                format,
                ca_file,
                app_name,
                facility,
            } => Sink::Syslog {
                cfg: SyslogCfg {
                    address,
                    transport,
                    format,
                    ca_file,
                    app_name: app_name.unwrap_or_else(|| "sharesomething".into()),
                    facility: facility.unwrap_or(16).min(23),
                },
                conn: None,
            },
            ShipperKind::Http {
                url,
                preset,
                token,
                headers,
                hmac_secret,
            } => Sink::Http {
                client: reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .user_agent("sharesomething-audit")
                    .build()?,
                url,
                preset,
                token,
                headers,
                hmac: hmac_secret,
            },
        })
    }

    async fn send(&mut self, batch: &[Record], o: &Observer) -> anyhow::Result<()> {
        match self {
            Sink::Stdout => {
                let mut out = String::new();
                for r in batch {
                    out.push_str(&format::ecs(r, o).to_string());
                    out.push('\n');
                }
                let mut stdout = tokio::io::stdout();
                stdout.write_all(out.as_bytes()).await?;
                stdout.flush().await?;
            }
            Sink::File { path, max_bytes, keep } => {
                if let Some(dir) = path.parent() {
                    tokio::fs::create_dir_all(dir).await.ok();
                }
                if tokio::fs::metadata(&*path).await.is_ok_and(|m| m.len() >= *max_bytes) {
                    rotate(path, *keep).await?;
                }
                let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(&*path).await?;
                let mut out = String::new();
                for r in batch {
                    out.push_str(&format::ecs(r, o).to_string());
                    out.push('\n');
                }
                f.write_all(out.as_bytes()).await?;
                f.sync_data().await?;
            }
            Sink::Syslog { cfg, conn } => {
                let lines: Vec<String> = batch
                    .iter()
                    .map(|r| {
                        let msg = match cfg.format {
                            SyslogFormat::Json => format::ecs(r, o).to_string(),
                            SyslogFormat::Cef => format::cef(r, o),
                        };
                        format::syslog(r, o, &cfg.app_name, cfg.facility, &msg)
                    })
                    .collect();
                if cfg.transport == SyslogTransport::Udp {
                    let sock = tokio::net::UdpSocket::bind(if cfg.address.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" }).await?;
                    sock.connect(&cfg.address).await?;
                    for l in &lines {
                        sock.send(l.as_bytes()).await?;
                    }
                } else {
                    if conn.is_none() {
                        *conn = Some(connect_stream(cfg).await?);
                    }
                    let stream = conn.as_mut().expect("connected");
                    // RFC 6587 octet counting framing.
                    let mut buf = Vec::new();
                    for l in &lines {
                        buf.extend_from_slice(format!("{} {}", l.len(), l).as_bytes());
                    }
                    let res = async {
                        stream.write_all(&buf).await?;
                        stream.flush().await
                    }
                    .await;
                    if let Err(e) = res {
                        *conn = None; // reconnect next time
                        return Err(e.into());
                    }
                }
            }
            Sink::Http {
                client,
                url,
                preset,
                token,
                headers,
                hmac,
            } => {
                let mut body = String::new();
                for r in batch {
                    let doc = format::ecs(r, o);
                    match preset {
                        HttpPreset::Generic => body.push_str(&doc.to_string()),
                        HttpPreset::SplunkHec => body.push_str(
                            &serde_json::json!({
                                "time": r.ts, "host": o.hostname, "source": "sharesomething",
                                "sourcetype": "sharesomething:audit", "event": doc,
                            })
                            .to_string(),
                        ),
                        HttpPreset::Elastic => {
                            body.push_str("{\"create\":{}}\n");
                            body.push_str(&doc.to_string());
                        }
                    }
                    body.push('\n');
                }
                let mut req = client.post(url.as_str()).header("content-type", "application/x-ndjson");
                if let Some(t) = token {
                    req = match preset {
                        HttpPreset::SplunkHec => req.header("authorization", format!("Splunk {t}")),
                        HttpPreset::Elastic => req.header("authorization", format!("ApiKey {t}")),
                        HttpPreset::Generic => req.bearer_auth(t),
                    };
                }
                for (k, v) in headers.iter() {
                    req = req.header(k, v);
                }
                if let Some(secret) = hmac {
                    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
                    mac.update(body.as_bytes());
                    req = req.header(
                        "x-sharesomething-signature",
                        format!("sha256={}", super::hex(&mac.finalize().into_bytes())),
                    );
                }
                let res = req.body(body).send().await?;
                let status = res.status();
                let text = res.text().await.unwrap_or_default();
                anyhow::ensure!(status.is_success(), "HTTP {status}: {}", text.chars().take(300).collect::<String>());
                if *preset == HttpPreset::Elastic && text.contains("\"errors\":true") {
                    anyhow::bail!("elastic bulk reported item errors: {}", text.chars().take(300).collect::<String>());
                }
            }
        }
        Ok(())
    }
}

async fn rotate(path: &std::path::Path, keep: usize) -> std::io::Result<()> {
    let name = |i: usize| PathBuf::from(format!("{}.{i}", path.display()));
    for i in (1..keep).rev() {
        if tokio::fs::metadata(name(i)).await.is_ok() {
            tokio::fs::rename(name(i), name(i + 1)).await?;
        }
    }
    let _ = tokio::fs::remove_file(name(keep + 1)).await;
    tokio::fs::rename(path, name(1)).await
}

async fn connect_stream(cfg: &SyslogCfg) -> anyhow::Result<Box<dyn AsyncWrite + Unpin + Send>> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(&cfg.address))
        .await
        .context("syslog connect timed out")??;
    if cfg.transport == SyslogTransport::Tcp {
        return Ok(Box::new(tcp));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ca) = &cfg.ca_file {
        use rustls_pki_types::{CertificateDer, pem::PemObject};
        for cert in CertificateDer::pem_file_iter(ca).with_context(|| format!("reading {}", ca.display()))? {
            roots.add(cert?)?;
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let host = cfg
        .address
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&cfg.address)
        .trim_start_matches('[')
        .trim_end_matches(']');
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls)).connect(server_name, tcp).await?;
    Ok(Box::new(stream))
}

/// Starts one worker per configured shipper.
pub fn spawn_all(audit: Arc<Audit>, db: SqlitePool, shippers: Vec<ShipperConfig>, observer: Observer) {
    for cfg in shippers {
        let (audit, db, observer) = (audit.clone(), db.clone(), observer.clone());
        tokio::spawn(async move {
            if let Err(e) = run(audit, db, cfg.clone(), observer).await {
                tracing::error!(shipper = %cfg.name, error = %e, "audit shipper stopped");
            }
        });
    }
}

async fn cursor(db: &SqlitePool, cfg: &ShipperConfig) -> sqlx::Result<i64> {
    if let Some((seq,)) = sqlx::query_as::<_, (i64,)>("SELECT last_seq FROM audit_cursors WHERE shipper = ?")
        .bind(&cfg.name)
        .fetch_optional(db)
        .await?
    {
        return Ok(seq);
    }
    let start = if cfg.backfill {
        0
    } else {
        sqlx::query_as::<_, (Option<i64>,)>("SELECT MAX(seq) FROM audit_events")
            .fetch_one(db)
            .await?
            .0
            .unwrap_or(0)
    };
    sqlx::query("INSERT INTO audit_cursors (shipper, last_seq, updated_at) VALUES (?, ?, ?)")
        .bind(&cfg.name)
        .bind(start)
        .bind(now())
        .execute(db)
        .await?;
    Ok(start)
}

/// Delivers one batch if anything is pending. Returns how many records were shipped.
pub async fn ship_once(db: &SqlitePool, cfg: &ShipperConfig, sink: &mut SinkHandle, observer: &Observer) -> anyhow::Result<usize> {
    let from = cursor(db, cfg).await?;
    let batch: Vec<Record> = sqlx::query_as("SELECT * FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?")
        .bind(from)
        .bind(cfg.batch_size.clamp(1, 5000) as i64)
        .fetch_all(db)
        .await?;
    if batch.is_empty() {
        return Ok(0);
    }
    sink.0.send(&batch, observer).await?;
    let last = batch.last().expect("non-empty").seq;
    sqlx::query("UPDATE audit_cursors SET last_seq = ?, failures = 0, last_error = NULL, updated_at = ? WHERE shipper = ?")
        .bind(last)
        .bind(now())
        .bind(&cfg.name)
        .execute(db)
        .await?;
    Ok(batch.len())
}

/// Opaque per-shipper connection state.
pub struct SinkHandle(Sink);

impl SinkHandle {
    pub fn new(kind: &ShipperKind) -> anyhow::Result<Self> {
        Ok(Self(Sink::new(kind)?))
    }
}

async fn run(audit: Arc<Audit>, db: SqlitePool, cfg: ShipperConfig, observer: Observer) -> anyhow::Result<()> {
    let mut sink = SinkHandle::new(&cfg.kind)?;
    let mut failures: u32 = 0;
    let mut alerted = false;
    tracing::info!(shipper = %cfg.name, kind = cfg.kind.type_name(), "audit shipper started");
    loop {
        let notified = audit.notify.notified();
        match ship_once(&db, &cfg, &mut sink, &observer).await {
            Ok(0) => {
                // Idle: wake on new records, with a periodic safety poll.
                let _ = tokio::time::timeout(Duration::from_secs(5), notified).await;
            }
            Ok(_) => {
                if alerted {
                    alerted = false;
                    audit
                        .record(
                            Event::new(Action::SiemDeliveryRecovered)
                                .target("shipper", &cfg.name, None)
                                .detail("after_failures", failures),
                        )
                        .await?;
                }
                failures = 0;
            }
            Err(e) => {
                failures += 1;
                let msg = format!("{e:#}");
                tracing::warn!(shipper = %cfg.name, failures, error = %msg, "audit shipping failed");
                sqlx::query("UPDATE audit_cursors SET failures = ?, last_error = ?, updated_at = ? WHERE shipper = ?")
                    .bind(failures)
                    .bind(&msg)
                    .bind(now())
                    .bind(&cfg.name)
                    .execute(&db)
                    .await?;
                // Raise one alert per outage (it is shipped too, once delivery recovers, and is
                // visible immediately in the audit UI and to other shippers).
                if failures == 3 && !alerted {
                    alerted = true;
                    audit
                        .record(
                            Event::new(Action::SiemDeliveryFailed)
                                .outcome(super::Outcome::Error)
                                .target("shipper", &cfg.name, None)
                                .detail("error", &msg),
                        )
                        .await?;
                }
                let backoff = Duration::from_secs((1u64 << failures.min(8)).min(300));
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ShipperStatus {
    pub name: String,
    pub kind: String,
    pub last_seq: i64,
    /// Records not yet delivered.
    pub behind: i64,
    pub failures: i64,
    pub last_error: Option<String>,
    pub updated_at: Option<i64>,
}

pub async fn status(db: &SqlitePool, shippers: &[ShipperConfig]) -> sqlx::Result<Vec<ShipperStatus>> {
    let head = sqlx::query_as::<_, (Option<i64>,)>("SELECT MAX(seq) FROM audit_events")
        .fetch_one(db)
        .await?
        .0
        .unwrap_or(0);
    let mut out = vec![];
    for s in shippers {
        let row: Option<(i64, i64, Option<String>, i64)> =
            sqlx::query_as("SELECT last_seq, failures, last_error, updated_at FROM audit_cursors WHERE shipper = ?")
                .bind(&s.name)
                .fetch_optional(db)
                .await?;
        let (last_seq, failures, last_error, updated_at) = row.map(|(a, b, c, d)| (a, b, c, Some(d))).unwrap_or((0, 0, None, None));
        out.push(ShipperStatus {
            name: s.name.clone(),
            kind: s.kind.type_name().into(),
            last_seq,
            behind: head - last_seq,
            failures,
            last_error,
            updated_at,
        });
    }
    Ok(out)
}
