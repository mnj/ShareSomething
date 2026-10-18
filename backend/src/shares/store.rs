//! Database access for shares.

use sqlx::{Sqlite, SqliteExecutor, Transaction};

use super::{
    model::{EncMode, ShareKind, ShareStatus},
    policy::{PolicyRule, RuleGroup, ShareState},
};
use crate::util::now;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ShareRow {
    pub id: String,
    pub slug: String,
    pub slug_generator: String,
    pub slug_opts: String,
    pub kind: String,
    pub title: Option<String>,
    pub enc_mode: String,
    pub enc_meta: String,
    pub ciphertext: Option<Vec<u8>>,
    pub passphrase_required: bool,
    pub passphrase_verifier: Option<Vec<u8>>,
    pub failed_attempts: i64,
    pub require_owner_mfa: bool,
    pub max_views: Option<i64>,
    pub views: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub burned_at: Option<i64>,
    pub upload_pending: bool,
    pub upload_dek: Option<Vec<u8>>,
    pub upload_token_hash: Option<Vec<u8>>,
    pub redirect_secs: Option<i64>,
    pub owner_id: i64,
    pub available_from: Option<i64>,
    pub require_approval: bool,
    pub notify_on_open: bool,
    pub split_k: Option<i64>,
    pub split_n: Option<i64>,
}

impl ShareRow {
    pub fn kind(&self) -> ShareKind {
        ShareKind::parse(&self.kind).unwrap_or(ShareKind::Text)
    }

    pub fn enc_mode(&self) -> EncMode {
        EncMode::parse(&self.enc_mode).unwrap_or(EncMode::Server)
    }

    pub fn status(&self, now: i64) -> ShareStatus {
        if self.revoked_at.is_some() {
            ShareStatus::Revoked
        } else if self.upload_pending {
            ShareStatus::Uploading
        } else if self.burned_at.is_some() || self.max_views.is_some_and(|m| self.views >= m) {
            ShareStatus::Burned
        } else if self.expires_at.is_some_and(|t| t <= now) {
            ShareStatus::Expired
        } else {
            ShareStatus::Active
        }
    }

    pub fn views_left(&self) -> Option<i64> {
        self.max_views.map(|m| (m - self.views).max(0))
    }

    pub fn state(&self, rules: Vec<PolicyRule>) -> ShareState {
        ShareState {
            available: self.ciphertext.is_some() && self.revoked_at.is_none() && self.burned_at.is_none() && !self.upload_pending,
            expires_at: self.expires_at,
            max_views: self.max_views,
            views: self.views,
            require_owner_mfa: self.require_owner_mfa,
            owner_id: self.owner_id,
            available_from: self.available_from,
            rules,
        }
    }
}

pub async fn by_slug(db: impl SqliteExecutor<'_>, slug: &str) -> sqlx::Result<Option<ShareRow>> {
    sqlx::query_as("SELECT * FROM shares WHERE slug = ?")
        .bind(slug)
        .fetch_optional(db)
        .await
}

pub async fn by_id(db: impl SqliteExecutor<'_>, id: &str) -> sqlx::Result<Option<ShareRow>> {
    sqlx::query_as("SELECT * FROM shares WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn list_owned(db: impl SqliteExecutor<'_>, owner_id: i64) -> sqlx::Result<Vec<ShareRow>> {
    sqlx::query_as("SELECT * FROM shares WHERE owner_id = ? ORDER BY created_at DESC")
        .bind(owner_id)
        .fetch_all(db)
        .await
}

fn decode_rule(group: RuleGroup, value: &str) -> Option<PolicyRule> {
    match serde_json::from_str(value) {
        Ok(rule) => Some(PolicyRule { group, rule }),
        Err(e) => {
            tracing::error!(error = %e, "skipping unreadable policy rule");
            None
        }
    }
}

pub async fn rules(db: impl SqliteExecutor<'_>, share_id: &str) -> sqlx::Result<Vec<PolicyRule>> {
    let rows: Vec<(RuleGroup, String)> = sqlx::query_as("SELECT grp, value FROM policy_rules WHERE share_id = ? ORDER BY id")
        .bind(share_id)
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().filter_map(|(g, v)| decode_rule(g, &v)).collect())
}

pub async fn all_rules(db: impl SqliteExecutor<'_>) -> sqlx::Result<Vec<(String, PolicyRule)>> {
    let rows: Vec<(String, RuleGroup, String)> = sqlx::query_as("SELECT share_id, grp, value FROM policy_rules ORDER BY id")
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, g, v)| decode_rule(g, &v).map(|r| (id, r)))
        .collect())
}

pub async fn replace_rules(tx: &mut Transaction<'_, Sqlite>, share_id: &str, rules: &[PolicyRule]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM policy_rules WHERE share_id = ?")
        .bind(share_id)
        .execute(&mut **tx)
        .await?;
    for r in rules {
        sqlx::query("INSERT INTO policy_rules (share_id, grp, rule_type, value) VALUES (?, ?, ?, ?)")
            .bind(share_id)
            .bind(r.group)
            .bind(r.rule.type_name())
            .bind(serde_json::to_string(&r.rule).expect("rule serialises"))
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Atomically consumes one view. Returns the new view count, or None if the share was used up,
/// expired or wiped in the meantime (i.e. a concurrent open won the last view).
pub async fn consume_view(tx: &mut Transaction<'_, Sqlite>, id: &str) -> sqlx::Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as(
        "UPDATE shares SET views = views + 1
         WHERE id = ? AND ciphertext IS NOT NULL AND revoked_at IS NULL AND burned_at IS NULL AND upload_pending = 0
           AND (max_views IS NULL OR views < max_views)
           AND (expires_at IS NULL OR expires_at > ?)
         RETURNING views",
    )
    .bind(id)
    .bind(now())
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|(v,)| v))
}

/// Destroys the content of a share but keeps its row (for the dashboard and access log).
pub async fn wipe(db: impl SqliteExecutor<'_>, id: &str, reason: Wipe) -> sqlx::Result<()> {
    let col = match reason {
        Wipe::Burned => "burned_at",
        Wipe::Revoked => "revoked_at",
    };
    sqlx::query(&format!(
        "UPDATE shares SET ciphertext = NULL, enc_meta = '{{}}', passphrase_verifier = NULL, {col} = COALESCE({col}, ?) WHERE id = ?"
    ))
    .bind(now())
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FileRow {
    pub idx: i64,
    pub size: i64,
    pub chunk_count: i64,
    pub uploaded_chunks: i64,
}

pub async fn files(db: impl SqliteExecutor<'_>, share_id: &str) -> sqlx::Result<Vec<FileRow>> {
    sqlx::query_as("SELECT idx, size, chunk_count, uploaded_chunks FROM share_files WHERE share_id = ? ORDER BY idx")
        .bind(share_id)
        .fetch_all(db)
        .await
}

/// Revokes a share's file downloads immediately: drops download tokens and deletes the blobs.
pub async fn destroy_files(state: &crate::app::AppState, id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM download_tokens WHERE share_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    state.blobs.remove_share(id).await;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum Wipe {
    Burned,
    Revoked,
}

impl ShareRow {
    /// Label used for this share in the audit trail (its title, else its link).
    pub fn audit_label(&self) -> String {
        self.title.clone().unwrap_or_else(|| format!("/s/{}", self.slug))
    }

    /// An audit event about this share.
    pub fn event(&self, action: crate::audit::Action) -> crate::audit::Event {
        crate::audit::Event::new(action)
            .target("share", &self.id, Some(self.audit_label()))
            .detail("owner_id", self.owner_id)
    }
}
