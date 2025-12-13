use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Request DTOs
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    #[serde(default = "default_single_use")]
    pub single_use: Option<bool>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    pub metadata: Option<SessionMetadataRequest>,
}

fn default_single_use() -> Option<bool> {
    Some(true)
}

#[derive(Debug, Deserialize)]
pub struct SessionMetadataRequest {
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub file_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct JoinSessionRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct DownloadByCodeRequest {
    pub code: String,
}

// Response DTOs
#[derive(Debug, Serialize)]
pub struct CreateSessionResponse {
    pub code: String,
    pub session_id: Uuid,
    pub ws_url: String,
    pub ice_servers: IceServersConfig,
}

#[derive(Debug, Serialize)]
pub struct JoinSessionResponse {
    pub session_id: Uuid,
    pub ws_token: String,
    pub ws_url: String,
    pub ice_servers: IceServersConfig,
    pub peer_info: PeerInfo,
}

#[derive(Debug, Serialize)]
pub struct DownloadByCodeResponse {
    pub r#type: String,  // 'file' or 'text'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,  // for files
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,  // for text
}

#[derive(Debug, Serialize)]
pub struct PeerInfo {
    pub creator_client_id: String,
}

#[derive(Debug, Serialize)]
pub struct IceServersConfig {
    pub ice_servers: Vec<IceServer>,
}

#[derive(Debug, Serialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}
