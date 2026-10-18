//! Audit trail for security teams: every security-relevant action is recorded here, and only here.
//!
//! - **Append-only and hash-chained:** `hash = SHA-256(prev_hash || canonical_json(record))`. Editing,
//!   reordering or deleting a row breaks the chain; `verify` (CLI: `sharesomething audit verify`)
//!   finds the first bad record.
//! - **Never contains secrets:** ids, titles, identities, IPs and outcomes only.
//! - **Shipped to SIEMs** by `ship` workers (stdout, file, syslog/CEF, HTTP/Splunk/Elastic), each
//!   with its own cursor, so delivery is at-least-once and survives restarts.

pub mod api;
pub mod format;
pub mod ship;

use std::sync::Arc;

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::sync::{Mutex, Notify};

use crate::{net::client_ip::ClientInfo, util::now};

pub const SCHEMA_VERSION: u32 = 1;
const GENESIS: [u8; 32] = [0; 32];

/// Every auditable action. Names are stable: SIEM rules key on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    SystemStarted,
    AuthLogin,
    AuthLoginFailed,
    AuthLogout,
    AuthStepUp,
    AuthStepUpFailed,
    AuthPasskeyAdded,
    AuthPasskeyRemoved,
    AuthTotpEnabled,
    AuthTotpDisabled,
    AuthPasswordChanged,
    UserCreated,
    UserUpdated,
    RecipientCodeRequested,
    RecipientVerified,
    RecipientVerifyFailed,
    RecipientSignedOut,
    ShareCreated,
    ShareUpdated,
    ShareRevoked,
    ShareDeleted,
    ShareOpened,
    ShareDenied,
    SharePassphraseFailed,
    ShareDestroyed,
    ShareFileUploaded,
    ShareFileDownloaded,
    SharePurged,
    ShareApprovalRequested,
    ShareApprovalApproved,
    ShareApprovalDenied,
    TemplateSaved,
    TemplateDeleted,
    AuditExported,
    AuditPruned,
    SiemDeliveryFailed,
    SiemDeliveryRecovered,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        use Action::*;
        match self {
            SystemStarted => "system.started",
            AuthLogin => "auth.login",
            AuthLoginFailed => "auth.login_failed",
            AuthLogout => "auth.logout",
            AuthStepUp => "auth.mfa.step_up",
            AuthStepUpFailed => "auth.mfa.step_up_failed",
            AuthPasskeyAdded => "auth.passkey.added",
            AuthPasskeyRemoved => "auth.passkey.removed",
            AuthTotpEnabled => "auth.totp.enabled",
            AuthTotpDisabled => "auth.totp.disabled",
            AuthPasswordChanged => "auth.password.changed",
            UserCreated => "user.created",
            UserUpdated => "user.updated",
            RecipientCodeRequested => "recipient.code_requested",
            RecipientVerified => "recipient.verified",
            RecipientVerifyFailed => "recipient.verify_failed",
            RecipientSignedOut => "recipient.signed_out",
            ShareCreated => "share.created",
            ShareUpdated => "share.updated",
            ShareRevoked => "share.revoked",
            ShareDeleted => "share.deleted",
            ShareOpened => "share.opened",
            ShareDenied => "share.denied",
            SharePassphraseFailed => "share.passphrase_failed",
            ShareDestroyed => "share.destroyed",
            ShareFileUploaded => "share.file_uploaded",
            ShareFileDownloaded => "share.file_downloaded",
            SharePurged => "share.purged",
            ShareApprovalRequested => "share.approval.requested",
            ShareApprovalApproved => "share.approval.approved",
            ShareApprovalDenied => "share.approval.denied",
            TemplateSaved => "template.saved",
            TemplateDeleted => "template.deleted",
            AuditExported => "audit.exported",
            AuditPruned => "audit.pruned",
            SiemDeliveryFailed => "siem.delivery_failed",
            SiemDeliveryRecovered => "siem.delivery_recovered",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    /// Refused by policy or authentication (the interesting ones for a SOC).
    Denied,
    Error,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
        }
    }
}

/// An event under construction. Build with the chained setters, then `Audit::record`.
#[derive(Debug, Clone)]
pub struct Event {
    action: Action,
    outcome: Outcome,
    actor_type: &'static str,
    actor_id: Option<String>,
    actor_label: Option<String>,
    ip: Option<String>,
    user_agent: Option<String>,
    target: Option<(&'static str, String, Option<String>)>,
    details: Map<String, Value>,
    ts: Option<i64>,
}

impl Event {
    pub fn new(action: Action) -> Self {
        Self {
            action,
            outcome: Outcome::Success,
            actor_type: "system",
            actor_id: None,
            actor_label: Some("server".into()),
            ip: None,
            user_agent: None,
            target: None,
            details: Map::new(),
            ts: None,
        }
    }

    pub fn outcome(mut self, o: Outcome) -> Self {
        self.outcome = o;
        self
    }

    pub fn denied(self) -> Self {
        self.outcome(Outcome::Denied)
    }

    pub fn user(mut self, id: i64, label: impl Into<String>) -> Self {
        self.actor_type = "user";
        self.actor_id = Some(id.to_string());
        self.actor_label = Some(label.into());
        self
    }

    /// A share visitor; `label` is their verified identity, if any.
    pub fn recipient(mut self, label: Option<String>) -> Self {
        self.actor_type = "recipient";
        self.actor_id = None;
        self.actor_label = label;
        self
    }

    pub fn system(mut self, label: &str) -> Self {
        self.actor_type = "system";
        self.actor_id = None;
        self.actor_label = Some(label.into());
        self
    }

    pub fn client(mut self, c: &ClientInfo) -> Self {
        self.ip = Some(c.ip.to_string());
        self.user_agent = c.user_agent.clone();
        if let Some(country) = &c.country {
            self.details.insert("country".into(), Value::String(country.clone()));
        }
        self
    }

    pub fn target(mut self, kind: &'static str, id: impl Into<String>, label: Option<String>) -> Self {
        self.target = Some((kind, id.into(), label));
        self
    }

    pub fn detail(mut self, key: &str, value: impl Serialize) -> Self {
        self.details.insert(key.into(), serde_json::to_value(value).unwrap_or(Value::Null));
        self
    }

    /// Backdated events (legacy import only).
    fn at(mut self, ts: i64) -> Self {
        self.ts = Some(ts);
        self
    }
}

/// A stored audit record, as hashed, queried and shipped.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Record {
    pub seq: i64,
    pub ts: i64,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub actor_label: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub target_label: Option<String>,
    pub outcome: String,
    /// JSON object (stored as text so the hashed bytes are exactly what's stored).
    pub details: String,
    #[serde(serialize_with = "hex_bytes")]
    #[schema(value_type = String)]
    pub prev_hash: Vec<u8>,
    #[serde(serialize_with = "hex_bytes")]
    #[schema(value_type = String)]
    pub hash: Vec<u8>,
}

fn hex_bytes<S: serde::Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex(b))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The exact bytes covered by a record's hash (everything except the hashes themselves).
fn canonical(r: &Record) -> Vec<u8> {
    #[derive(Serialize)]
    struct C<'a> {
        seq: i64,
        ts: i64,
        actor_type: &'a str,
        actor_id: &'a Option<String>,
        actor_label: &'a Option<String>,
        ip: &'a Option<String>,
        user_agent: &'a Option<String>,
        action: &'a str,
        target_type: &'a Option<String>,
        target_id: &'a Option<String>,
        target_label: &'a Option<String>,
        outcome: &'a str,
        details: &'a str,
    }
    serde_json::to_vec(&C {
        seq: r.seq,
        ts: r.ts,
        actor_type: &r.actor_type,
        actor_id: &r.actor_id,
        actor_label: &r.actor_label,
        ip: &r.ip,
        user_agent: &r.user_agent,
        action: &r.action,
        target_type: &r.target_type,
        target_id: &r.target_id,
        target_label: &r.target_label,
        outcome: &r.outcome,
        details: &r.details,
    })
    .expect("record serialises")
}

fn chain_hash(prev: &[u8], r: &Record) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(canonical(r));
    h.finalize().to_vec()
}

pub struct Audit {
    db: SqlitePool,
    /// Serialises this process's appends; `BEGIN IMMEDIATE` also covers other processes (the CLI).
    write: Mutex<()>,
    /// Wakes shippers when something new was written.
    pub notify: Arc<Notify>,
}

impl Audit {
    pub fn new(db: SqlitePool) -> Self {
        Self {
            db,
            write: Mutex::new(()),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Appends an event to the chain. Errors propagate: if the audit write fails, the action fails.
    pub async fn record(&self, e: Event) -> sqlx::Result<Record> {
        let _guard = self.write.lock().await;
        let mut conn = self.db.acquire().await?;
        // Take the write lock up front so the head we read is still the head when we append,
        // even if another process (e.g. the admin CLI) writes to the same database.
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result = Self::append(&mut conn, e).await;
        match &result {
            Ok(_) => sqlx::query("COMMIT").execute(&mut *conn).await.map(|_| ())?,
            Err(_) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            }
        }
        if result.is_ok() {
            self.notify.notify_waiters();
        }
        result
    }

    async fn append(conn: &mut sqlx::SqliteConnection, e: Event) -> sqlx::Result<Record> {
        let last: Option<(i64, Vec<u8>)> = sqlx::query_as("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
        let (seq, prev_hash) = last.map(|(s, h)| (s + 1, h)).unwrap_or((1, GENESIS.to_vec()));
        let (target_type, target_id, target_label) = match e.target {
            Some((t, id, label)) => (Some(t.to_string()), Some(id), label),
            None => (None, None, None),
        };
        let mut r = Record {
            seq,
            ts: e.ts.unwrap_or_else(now),
            actor_type: e.actor_type.into(),
            actor_id: e.actor_id,
            actor_label: e.actor_label,
            ip: e.ip,
            user_agent: e.user_agent,
            action: e.action.as_str().into(),
            target_type,
            target_id,
            target_label,
            outcome: e.outcome.as_str().into(),
            details: Value::Object(e.details).to_string(),
            prev_hash,
            hash: vec![],
        };
        r.hash = chain_hash(&r.prev_hash, &r);
        sqlx::query(
            "INSERT INTO audit_events (seq, ts, actor_type, actor_id, actor_label, ip, user_agent, action, target_type,
                target_id, target_label, outcome, details, prev_hash, hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(r.seq)
        .bind(r.ts)
        .bind(&r.actor_type)
        .bind(&r.actor_id)
        .bind(&r.actor_label)
        .bind(&r.ip)
        .bind(&r.user_agent)
        .bind(&r.action)
        .bind(&r.target_type)
        .bind(&r.target_id)
        .bind(&r.target_label)
        .bind(&r.outcome)
        .bind(&r.details)
        .bind(&r.prev_hash)
        .bind(&r.hash)
        .execute(&mut *conn)
        .await?;
        Ok(r)
    }

    /// Moves rows from the pre-v2 per-share `access_log` into the audit chain (once), then drops it.
    pub async fn import_legacy_access_log(&self) -> anyhow::Result<()> {
        let exists: Option<(String,)> = sqlx::query_as("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'access_log'")
            .fetch_optional(&self.db)
            .await?;
        if exists.is_none() {
            return Ok(());
        }
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            String,
            i64,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT l.share_id, l.ts, l.ip, l.country, l.identity, l.user_agent, l.outcome, s.title, s.slug
                 FROM access_log l LEFT JOIN shares s ON s.id = l.share_id ORDER BY l.ts, l.id",
        )
        .fetch_all(&self.db)
        .await?;
        let n = rows.len();
        for (share_id, ts, ip, country, identity, ua, outcome, title, slug) in rows {
            let action = match outcome.as_str() {
                "opened" | "opened_burned" => Action::ShareOpened,
                "wrong_passphrase" => Action::SharePassphraseFailed,
                "destroyed_bad_passphrase" => Action::ShareDestroyed,
                _ => Action::ShareDenied,
            };
            let mut e = Event::new(action)
                .recipient(identity)
                .target("share", share_id, title.or(slug))
                .at(ts)
                .detail("legacy_outcome", &outcome);
            if outcome == "opened_burned" {
                e = e.detail("burned", true);
            }
            if action == Action::ShareDenied {
                e = e.denied().detail("reason", outcome.trim_start_matches("blocked:"));
            }
            if action == Action::SharePassphraseFailed {
                e = e.denied();
            }
            e.ip = Some(ip);
            e.user_agent = ua;
            if let Some(c) = country {
                e = e.detail("country", c);
            }
            self.record(e).await?;
        }
        sqlx::query("DROP TABLE access_log").execute(&self.db).await?;
        if n > 0 {
            tracing::info!(rows = n, "imported legacy access log into the audit trail");
        }
        Ok(())
    }

    /// Deletes records older than `days`, keeping the newest record so the chain stays anchored,
    /// and records the pruning itself.
    pub async fn prune(&self, days: i64) -> sqlx::Result<u64> {
        let cutoff = now() - days * 86_400;
        let max: (Option<i64>,) = sqlx::query_as("SELECT MAX(seq) FROM audit_events").fetch_one(&self.db).await?;
        let Some(max) = max.0 else { return Ok(0) };
        let up_to: (Option<i64>,) = sqlx::query_as("SELECT MAX(seq) FROM audit_events WHERE ts < ? AND seq < ?")
            .bind(cutoff)
            .bind(max)
            .fetch_one(&self.db)
            .await?;
        let Some(up_to) = up_to.0 else { return Ok(0) };
        let n = sqlx::query("DELETE FROM audit_events WHERE seq <= ?")
            .bind(up_to)
            .execute(&self.db)
            .await?
            .rows_affected();
        self.record(
            Event::new(Action::AuditPruned)
                .detail("deleted", n)
                .detail("up_to_seq", up_to)
                .detail("retention_days", days),
        )
        .await?;
        Ok(n)
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct VerifyReport {
    pub ok: bool,
    pub checked: i64,
    pub first_seq: Option<i64>,
    pub head_seq: Option<i64>,
    pub head_hash: Option<String>,
    /// First record whose hash or link doesn't match.
    pub first_bad_seq: Option<i64>,
}

/// Re-computes the whole chain. The oldest remaining record anchors it (older ones may be pruned).
pub async fn verify(db: &SqlitePool) -> sqlx::Result<VerifyReport> {
    use futures_util::TryStreamExt;
    let mut rows = sqlx::query_as::<_, Record>("SELECT * FROM audit_events ORDER BY seq").fetch(db);
    let mut report = VerifyReport {
        ok: true,
        checked: 0,
        first_seq: None,
        head_seq: None,
        head_hash: None,
        first_bad_seq: None,
    };
    let mut prev: Option<(i64, Vec<u8>)> = None;
    while let Some(r) = rows.try_next().await? {
        report.checked += 1;
        report.first_seq.get_or_insert(r.seq);
        let linked = prev.as_ref().is_none_or(|(seq, hash)| r.seq == seq + 1 && &r.prev_hash == hash);
        if !linked || chain_hash(&r.prev_hash, &r) != r.hash {
            report.ok = false;
            report.first_bad_seq = Some(r.seq);
            break;
        }
        prev = Some((r.seq, r.hash.clone()));
    }
    if let Some((seq, hash)) = prev {
        report.head_seq = Some(seq);
        report.head_hash = Some(hex(&hash));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> SqlitePool {
        let dir = std::env::temp_dir().join(format!("ss-audit-{}", uuid::Uuid::new_v4()));
        crate::db::connect(&dir).await.unwrap()
    }

    #[tokio::test]
    async fn chain_verifies_and_detects_tampering() {
        let pool = db().await;
        let a = Audit::new(pool.clone());
        for i in 0..5 {
            a.record(
                Event::new(Action::ShareOpened)
                    .recipient(Some(format!("u{i}@x.dk")))
                    .target("share", "s1", None),
            )
            .await
            .unwrap();
        }
        let r = verify(&pool).await.unwrap();
        assert!(r.ok && r.checked == 5 && r.head_seq == Some(5), "{r:?}");

        sqlx::query("UPDATE audit_events SET actor_label = 'mallory' WHERE seq = 3")
            .execute(&pool)
            .await
            .unwrap();
        let r = verify(&pool).await.unwrap();
        assert_eq!((r.ok, r.first_bad_seq), (false, Some(3)));
    }

    #[tokio::test]
    async fn deletion_in_the_middle_is_detected_and_restart_continues_chain() {
        let pool = db().await;
        let a = Audit::new(pool.clone());
        for _ in 0..4 {
            a.record(Event::new(Action::AuthLogin)).await.unwrap();
        }
        // A fresh instance (restart) must pick up the existing head.
        let b = Audit::new(pool.clone());
        b.record(Event::new(Action::AuthLogout)).await.unwrap();
        assert!(verify(&pool).await.unwrap().ok);
        sqlx::query("DELETE FROM audit_events WHERE seq = 2").execute(&pool).await.unwrap();
        assert_eq!(verify(&pool).await.unwrap().first_bad_seq, Some(3));
    }

    #[tokio::test]
    async fn pruning_keeps_chain_verifiable() {
        let pool = db().await;
        let a = Audit::new(pool.clone());
        for _ in 0..3 {
            a.record(Event::new(Action::AuthLogin).at(now() - 100 * 86_400)).await.unwrap();
        }
        a.record(Event::new(Action::AuthLogin)).await.unwrap();
        assert_eq!(a.prune(30).await.unwrap(), 3);
        let r = verify(&pool).await.unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!(r.first_seq, Some(4));
        let (action,): (String,) = sqlx::query_as("SELECT action FROM audit_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(action, "audit.pruned");
    }
}
