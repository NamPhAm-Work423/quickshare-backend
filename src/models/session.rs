use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: Uuid,
    pub code_hmac: String, // HMAC of the 6-digit code
    pub creator_client_id: String,
    pub participants: Vec<Participant>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub single_use: bool,
    pub used: bool,
    pub metadata: Option<SessionMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub client_id: String,
    pub joined_at: DateTime<Utc>,
    pub ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub file_type: Option<String>,
}

impl Session {
    pub fn new(
        session_id: Uuid,
        code_hmac: String,
        creator_client_id: String,
        ttl_seconds: u64,
        single_use: bool,
    ) -> Self {
        let now = Utc::now();
        let creator_id = creator_client_id.clone();
        Self {
            session_id,
            code_hmac,
            creator_client_id,
            participants: vec![Participant {
                client_id: creator_id,
                joined_at: now,
                ip_address: None,
            }],
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds as i64),
            single_use,
            used: false,
            metadata: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn can_join(&self) -> bool {
        !self.is_expired() && !self.used && self.participants.len() < 2
    }

    pub fn add_participant(&mut self, client_id: String, ip_address: Option<String>) {
        if self.participants.len() < 2 {
            self.participants.push(Participant {
                client_id,
                joined_at: Utc::now(),
                ip_address,
            });
        }
    }
}
