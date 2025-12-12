use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalingMessage {
    #[serde(rename = "offer")]
    Offer {
        sdp: String,
    },
    #[serde(rename = "answer")]
    Answer {
        sdp: String,
    },
    #[serde(rename = "ice_candidate")]
    IceCandidate {
        candidate: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sdp_mid: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sdp_mline_index: Option<u16>,
    },
    #[serde(rename = "transfer_started")]
    TransferStarted {
        file_name: String,
        file_size: u64,
        file_type: Option<String>,
    },
    #[serde(rename = "transfer_progress")]
    TransferProgress {
        percent: f64,
        bytes_transferred: u64,
    },
    #[serde(rename = "transfer_completed")]
    TransferCompleted,
    #[serde(rename = "transfer_failed")]
    TransferFailed {
        error: String,
    },
    #[serde(rename = "peer_connected")]
    PeerConnected {
        client_id: String,
    },
    #[serde(rename = "peer_disconnected")]
    PeerDisconnected {
        client_id: String,
    },
    #[serde(rename = "error")]
    Error {
        message: String,
    },
}
