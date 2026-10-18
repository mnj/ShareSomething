//! Notifications for users: always in-app, plus email and/or a webhook when configured.
//!
//! Delivery to email/webhooks happens in the background so it never slows down or fails the
//! action that triggered it.

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    app::AppState,
    auth::users::CurrentUser,
    error::{AppError, AppResult},
    util::now,
};

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    ShareOpened,
    ApprovalRequested,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::ShareOpened => "share_opened",
            Kind::ApprovalRequested => "approval_requested",
        }
    }
}

/// Notifies `user_id`. In-app always; email and webhook best-effort in the background.
pub async fn notify(
    state: &AppState,
    user_id: i64,
    kind: Kind,
    share_id: Option<&str>,
    approval_id: Option<&str>,
    subject: &str,
    message: &str,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO notifications (user_id, ts, kind, share_id, approval_id, message) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(user_id)
        .bind(now())
        .bind(kind.as_str())
        .bind(share_id)
        .bind(approval_id)
        .bind(message)
        .execute(&state.db)
        .await?;
    let (email, webhook): (Option<String>, Option<String>) = sqlx::query_as("SELECT email, notify_webhook FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    let link = format!("{}/", state.cfg.base_url());
    let (mailer, subject, body) = (
        state.mailer.clone(),
        subject.to_string(),
        format!("{message}\n\nOpen ShareSomething: {link}\n"),
    );
    if let Some(to) = email.filter(|_| mailer.enabled()) {
        let (subject, body) = (subject.clone(), body.clone());
        tokio::spawn(async move {
            if let Err(e) = mailer.send_notice(&to, &subject, &body).await {
                tracing::warn!(error = %e, "notification email failed");
            }
        });
    }
    if let Some(url) = webhook {
        let text = format!("{message} ({link})");
        tokio::spawn(async move {
            let res = reqwest::Client::new()
                .post(&url)
                .timeout(std::time::Duration::from_secs(10))
                // `text` is understood by Slack, Mattermost, Microsoft Teams and Rocket.Chat webhooks.
                .json(&serde_json::json!({ "text": text }))
                .send()
                .await
                .and_then(|r| r.error_for_status());
            if let Err(e) = res {
                tracing::warn!(error = %e, "notification webhook failed");
            }
        });
    }
    Ok(())
}

/// Webhook URLs are user-supplied: only https, so they can't be pointed at plain-http internals.
pub fn validate_webhook(url: &str) -> AppResult<()> {
    let u = url::Url::parse(url).map_err(|_| AppError::BadRequest("webhook must be a URL".into()))?;
    if u.scheme() != "https" || u.host_str().is_none() || url.len() > 2048 {
        return Err(AppError::BadRequest("webhook must be an https:// URL".into()));
    }
    Ok(())
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct Notification {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub share_id: Option<String>,
    pub approval_id: Option<String>,
    pub message: String,
    pub read: bool,
}

#[derive(Serialize, ToSchema)]
pub struct NotificationList {
    pub unread: i64,
    pub items: Vec<Notification>,
}

#[derive(Deserialize, IntoParams)]
struct ListQuery {
    /// Only unread ones.
    #[serde(default)]
    unread: bool,
}

/// Your latest notifications.
#[utoipa::path(get, path = "/notifications", tag = "notifications", operation_id = "notifications_list", params(ListQuery),
    responses((status = 200, body = NotificationList)))]
async fn list(State(state): State<AppState>, user: CurrentUser, Query(q): Query<ListQuery>) -> AppResult<Json<NotificationList>> {
    let items: Vec<Notification> = sqlx::query_as(
        "SELECT id, ts, kind, share_id, approval_id, message, read_at IS NOT NULL AS read FROM notifications
         WHERE user_id = ? AND (? = 0 OR read_at IS NULL) ORDER BY id DESC LIMIT 50",
    )
    .bind(user.id)
    .bind(q.unread)
    .fetch_all(&state.db)
    .await?;
    let unread: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(NotificationList { unread: unread.0, items }))
}

/// Mark all your notifications as read.
#[utoipa::path(post, path = "/notifications/read", tag = "notifications", operation_id = "notifications_read",
    responses((status = 200, body = NotificationList)))]
async fn mark_read(State(state): State<AppState>, user: CurrentUser) -> AppResult<Json<NotificationList>> {
    sqlx::query("UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL")
        .bind(now())
        .bind(user.id)
        .execute(&state.db)
        .await?;
    list(State(state), user, Query(ListQuery { unread: false })).await
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list)).routes(routes!(mark_read))
}
