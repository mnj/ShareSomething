//! Background maintenance: wipes expired content and purges old shares, blobs and sessions.

use std::time::Duration;

use crate::{
    app::AppState,
    audit::{Action, Event},
    util::now,
};

/// Unfinished uploads are discarded after this long.
const PENDING_UPLOAD_TTL_SECS: i64 = 24 * 3600;

pub fn spawn_sweeper(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(e) = sweep(&state).await {
                tracing::error!(error = %e, "sweeper failed");
            }
        }
    });
}

pub async fn sweep(state: &AppState) -> sqlx::Result<()> {
    let t = now();
    let wiped = sqlx::query(
        "UPDATE shares SET ciphertext = NULL, enc_meta = '{}', passphrase_verifier = NULL
         WHERE ciphertext IS NOT NULL AND expires_at IS NOT NULL AND expires_at <= ?",
    )
    .bind(t)
    .execute(&state.db)
    .await?
    .rows_affected();
    sqlx::query("DELETE FROM download_tokens WHERE expires_at <= ?")
        .bind(t)
        .execute(&state.db)
        .await?;

    // File blobs of wiped shares can go once nobody holds a download token any more.
    let orphaned: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM shares s WHERE kind = 'files' AND ciphertext IS NULL
           AND NOT EXISTS (SELECT 1 FROM download_tokens d WHERE d.share_id = s.id)",
    )
    .fetch_all(&state.db)
    .await?;
    for (id,) in &orphaned {
        state.blobs.remove_share(id).await;
    }

    let cutoff = t - state.cfg.retention_days * 86_400;
    let purge: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM shares WHERE
           (ciphertext IS NULL AND MAX(COALESCE(revoked_at, 0), COALESCE(burned_at, 0), COALESCE(expires_at, 0)) < ?)
           OR (upload_pending = 1 AND created_at < ?)",
    )
    .bind(cutoff)
    .bind(t - PENDING_UPLOAD_TTL_SECS)
    .fetch_all(&state.db)
    .await?;
    for (id,) in &purge {
        sqlx::query("DELETE FROM shares WHERE id = ?").bind(id).execute(&state.db).await?;
        state.blobs.remove_share(id).await;
        state
            .audit
            .record(Event::new(Action::SharePurged).system("sweeper").target("share", id, None))
            .await?;
    }
    if let Some(days) = state.cfg.audit.retention_days {
        state.audit.prune(days).await?;
    }
    for table in ["user_sessions", "recipient_sessions", "email_challenges", "oidc_states"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE expires_at <= ?"))
            .bind(t)
            .execute(&state.db)
            .await?;
    }
    if wiped + purge.len() as u64 > 0 {
        tracing::info!(wiped, purged = purge.len(), "sweeper ran");
    }
    Ok(())
}
