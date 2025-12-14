use serde::{Deserialize, Serialize};
use tracing::{debug, error, warn};

/// Cloudflare TURN credentials response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareTurnCredentials {
    #[serde(rename = "iceServers")]
    pub ice_servers: IceServersResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServersResponse {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

/// Request body for Cloudflare TURN API
#[derive(Debug, Clone, Serialize)]
struct TurnCredentialRequest {
    ttl: u64,
}

/// Service for fetching TURN credentials from Cloudflare
pub struct CloudflareTurnService;

impl CloudflareTurnService {
    /// Fetch short-lived TURN credentials from Cloudflare API
    /// 
    /// API: POST https://rtc.live.cloudflare.com/v1/turn/keys/{turn_token_id}/credentials/generate
    /// Headers: Authorization: Bearer {api_token}
    /// Body: { "ttl": 86400 }
    pub async fn get_credentials(
        token_id: &str,
        api_token: &str,
        ttl: u64,
    ) -> Result<CloudflareTurnCredentials, CloudflareTurnError> {
        if token_id.is_empty() || api_token.is_empty() {
            return Err(CloudflareTurnError::MissingCredentials);
        }

        let url = format!(
            "https://rtc.live.cloudflare.com/v1/turn/keys/{}/credentials/generate",
            token_id
        );

        debug!("Fetching TURN credentials from Cloudflare: {}", url);

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_token))
            .json(&TurnCredentialRequest { ttl })
            .send()
            .await
            .map_err(|e| {
                error!("Failed to request Cloudflare TURN credentials: {}", e);
                CloudflareTurnError::RequestFailed(e.to_string())
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!(
                "Cloudflare TURN API returned error: status={}, body={}",
                status, body
            );
            return Err(CloudflareTurnError::ApiError {
                status: status.as_u16(),
                message: body,
            });
        }

        let credentials: CloudflareTurnCredentials = response.json().await.map_err(|e| {
            error!("Failed to parse Cloudflare TURN response: {}", e);
            CloudflareTurnError::ParseError(e.to_string())
        })?;

        debug!(
            "Successfully fetched TURN credentials with {} URLs",
            credentials.ice_servers.urls.len()
        );

        Ok(credentials)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CloudflareTurnError {
    #[error("Missing Cloudflare TURN credentials (token_id or api_token)")]
    MissingCredentials,

    #[error("Failed to request TURN credentials: {0}")]
    RequestFailed(String),

    #[error("Cloudflare API error: status={status}, message={message}")]
    ApiError { status: u16, message: String },

    #[error("Failed to parse TURN response: {0}")]
    ParseError(String),
}
