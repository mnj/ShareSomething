//! Background maintenance: wipes expired content and purges old shares and sessions.

use std::time::Duration;

use crate::{app::AppState, util::now};

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
    let cutoff = t - state.cfg.retention_days * 86_400;
    let purged = sqlx::query(
        "DELETE FROM shares WHERE ciphertext IS NULL
           AND MAX(COALESCE(revoked_at, 0), COALESCE(burned_at, 0), COALESCE(expires_at, 0)) < ?",
    )
    .bind(cutoff)
    .execute(&state.db)
    .await?
    .rows_affected();
    sqlx::query("DELETE FROM owner_sessions WHERE expires_at <= ?")
        .bind(t)
        .execute(&state.db)
        .await?;
    if wiped + purged > 0 {
        tracing::info!(wiped, purged, "sweeper ran");
    }
    Ok(())
}
