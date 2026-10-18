use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    /// 401 with a machine-readable code, e.g. `totp_required`.
    #[error("{1}")]
    AuthFailed(&'static str, &'static str),
    #[error("{0}")]
    Forbidden(String),
    /// 403 with a machine-readable access code, e.g. `need_passphrase`.
    #[error("{1}")]
    Access(&'static str, String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("too many requests, slow down")]
    TooManyRequests,
    /// 403 `need_approval`: the owner has to approve this open.
    #[error("waiting for the owner to approve")]
    NeedApproval { id: String, secret: Option<String> },
    #[error("server is not initialised; run `sharesomething admin init`")]
    NotInitialised,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    /// Stable machine-readable code.
    pub error: String,
    pub message: String,
    /// `need_approval`: the pending approval to wait for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    /// `need_approval`, first answer only: proves the waiting browser is the requester.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_secret: Option<String>,
}

impl AppError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::AuthFailed(code, _) => (StatusCode::UNAUTHORIZED, code),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::Access(code, _) => (StatusCode::FORBIDDEN, code),
            AppError::NeedApproval { .. } => (StatusCode::FORBIDDEN, "need_approval"),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            AppError::NotInitialised => (StatusCode::SERVICE_UNAVAILABLE, "not_initialised"),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = match &self {
            AppError::Internal(e) => {
                tracing::error!(error = ?e, "internal error");
                "internal server error".to_string()
            }
            other => other.to_string(),
        };
        let (approval_id, approval_secret) = match self {
            AppError::NeedApproval { id, secret } => (Some(id), secret),
            _ => (None, None),
        };
        (
            status,
            Json(ErrorBody {
                error: code.into(),
                message,
                approval_id,
                approval_secret,
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}

pub type AppResult<T> = Result<T, AppError>;
