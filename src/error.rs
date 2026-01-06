use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Redis error: {0}")]
    Redis(String),

    #[error("Không tìm thấy mã")]
    SessionNotFound,

    #[error("Session expired")]
    SessionExpired,

    #[error("Session already used")]
    SessionAlreadyUsed,

    #[error("Invalid code")]
    InvalidCode,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Code generation failed after retries")]
    CodeGenerationFailed,

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Internal(e) => {
                tracing::error!("Internal error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
            AppError::Redis(e) => {
                tracing::error!("Redis error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
            }
            AppError::SessionNotFound => (StatusCode::NOT_FOUND, "Không tìm thấy mã".to_string()),
            AppError::SessionExpired => (StatusCode::GONE, "Session expired".to_string()),
            AppError::SessionAlreadyUsed => (StatusCode::GONE, "Session already used".to_string()),
            AppError::InvalidCode => (StatusCode::BAD_REQUEST, "Invalid code".to_string()),
            AppError::RateLimitExceeded => {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string())
            }
            AppError::CodeGenerationFailed => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Code generation failed".to_string())
            }
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::WebSocket(msg) => (StatusCode::BAD_REQUEST, format!("WebSocket error: {}", msg)),
            AppError::Config(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Configuration error: {}", msg)),
        };

        let body = Json(json!({
            "error": error_message,
            "code": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
