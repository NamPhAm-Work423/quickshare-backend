use crate::error::{AppError, Result};
use crate::models::session::Session;
use crate::services::hmac::{compute_code_hmac, get_code_hmac_prefix};
use crate::state::AppState;
use deadpool_redis::redis::{AsyncCommands, cmd};
use serde_json;
use uuid::Uuid;

pub struct SessionService;

impl SessionService {
    const SESSION_KEY_PREFIX: &'static str = "session:";
    const CODE_INDEX_PREFIX: &'static str = "code_index:";

    /// Create a new session and store in Redis
    pub async fn create_session(
        state: &AppState,
        session: Session,
        code: &str,
    ) -> Result<()> {
        let session_key = format!("{}:{}", Self::SESSION_KEY_PREFIX, session.session_id);
        let code_hmac = &session.code_hmac;
        let code_index_key = format!("{}:{}", Self::CODE_INDEX_PREFIX, code_hmac);

        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        let session_json = serde_json::to_string(&session)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        let ttl = state.config.session_ttl().as_secs();

        // Store session
        conn.set_ex(&session_key, session_json, ttl)
            .await
            .map_err(|e| AppError::Redis(e.to_string()))?;

        // Store code index
        conn.set_ex(&code_index_key, session.session_id.to_string(), ttl)
            .await
            .map_err(|e| AppError::Redis(e.to_string()))?;

        Ok(())
    }

    /// Get session by session_id
    pub async fn get_session(state: &AppState, session_id: &Uuid) -> Result<Session> {
        let session_key = format!("{}:{}", Self::SESSION_KEY_PREFIX, session_id);
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        let session_json: Option<String> = conn.get(&session_key).await.map_err(|e| AppError::Redis(e.to_string()))?;

        match session_json {
            Some(json) => {
                let session: Session = serde_json::from_str(&json)
                    .map_err(|e| AppError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))?;

                if session.is_expired() {
                    return Err(AppError::SessionExpired);
                }

                Ok(session)
            }
            None => Err(AppError::SessionNotFound),
        }
    }

    /// Get session by code (via code_index)
    pub async fn get_session_by_code(state: &AppState, code: &str) -> Result<Session> {
        let hmac_key = state.get_hmac_key();
        let code_hmac = compute_code_hmac(&hmac_key, code);
        let code_index_key = format!("{}:{}", Self::CODE_INDEX_PREFIX, code_hmac);

        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        let session_id_str: Option<String> = conn.get(&code_index_key).await.map_err(|e| AppError::Redis(e.to_string()))?;

        match session_id_str {
            Some(id_str) => {
                let session_id = Uuid::parse_str(&id_str)
                    .map_err(|_| AppError::Internal(anyhow::anyhow!("Invalid session ID")))?;
                Self::get_session(state, &session_id).await
            }
            None => Err(AppError::SessionNotFound),
        }
    }

    /// Add participant to session (atomic update)
    pub async fn add_participant(
        state: &AppState,
        session_id: &Uuid,
        client_id: String,
        ip_address: Option<String>,
    ) -> Result<Session> {
        let session_key = format!("{}:{}", Self::SESSION_KEY_PREFIX, session_id);
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        // Use Lua script for atomic update
        let script = r#"
            local session_key = KEYS[1]
            local session_json = redis.call('GET', session_key)
            if not session_json then
                return nil
            end
            
            local session = cjson.decode(session_json)
            if session.used or #session.participants >= 2 then
                return nil
            end
            
            table.insert(session.participants, {
                client_id = ARGV[1],
                joined_at = ARGV[2],
                ip_address = ARGV[3] ~= '' and ARGV[3] or nil
            })
            
            local ttl = redis.call('TTL', session_key)
            redis.call('SET', session_key, cjson.encode(session))
            if ttl > 0 then
                redis.call('EXPIRE', session_key, ttl)
            end
            
            return cjson.encode(session)
        "#;

        let now = chrono::Utc::now().to_rfc3339();
        let ip_str = ip_address.as_deref().unwrap_or("").to_string();

        // Use redis::cmd to execute Lua script
        // deadpool_redis::Connection doesn't have eval() directly, need to use cmd()
        let result: Option<String> = cmd("EVAL")
            .arg(script)
            .arg(1) // number of keys
            .arg(&session_key) // KEYS[1]
            .arg(&client_id) // ARGV[1]
            .arg(&now) // ARGV[2]
            .arg(&ip_str) // ARGV[3]
            .query_async(&mut *conn)
            .await
            .map_err(|e| AppError::Redis(e.to_string()))?;

        match result {
            Some(json) => {
                let session: Session = serde_json::from_str(&json)
                    .map_err(|e| AppError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))?;
                Ok(session)
            }
            None => {
                // Fallback: get and update manually
                let mut session = Self::get_session(state, session_id).await?;
                if session.used || session.participants.len() >= 2 {
                    return Err(AppError::SessionAlreadyUsed);
                }
                session.add_participant(client_id, ip_address);
                Self::update_session(state, &session).await?;
                Ok(session)
            }
        }
    }

    /// Mark session as used and clean up code_index
    pub async fn mark_session_used(state: &AppState, session_id: &Uuid) -> Result<()> {
        let session_key = format!("{}:{}", Self::SESSION_KEY_PREFIX, session_id);
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        let session_json: Option<String> = conn.get(&session_key).await.map_err(|e| AppError::Redis(e.to_string()))?;

        if let Some(json) = session_json {
            let mut session: Session = serde_json::from_str(&json)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))?;

            session.used = true;

            let updated_json = serde_json::to_string(&session)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

            let ttl = conn.ttl(&session_key).await.unwrap_or(0);
            conn.set(&session_key, updated_json).await.map_err(|e| AppError::Redis(e.to_string()))?;
            if ttl > 0 {
                conn.expire(&session_key, ttl)
                    .await
                    .map_err(|e| AppError::Redis(e.to_string()))?;
            }

            // Delete code index
            let code_index_key = format!("{}:{}", Self::CODE_INDEX_PREFIX, session.code_hmac);
            conn.del(&code_index_key).await.map_err(|e| AppError::Redis(e.to_string()))?;
        }

        Ok(())
    }

    /// Update session in Redis
    async fn update_session(state: &AppState, session: &Session) -> Result<()> {
        let session_key = format!("{}:{}", Self::SESSION_KEY_PREFIX, session.session_id);
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        let session_json = serde_json::to_string(&session)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        let ttl = conn.ttl(&session_key).await.unwrap_or(0);
        conn.set(&session_key, session_json).await.map_err(|e| AppError::Redis(e.to_string()))?;
        if ttl > 0 {
            conn.expire(&session_key, ttl)
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;
        }

        Ok(())
    }

    /// Get code HMAC prefix for rate limiting
    pub fn get_code_hmac_prefix_for_rate_limit(_state: &AppState, code_hmac: &str) -> String {
        // Use first 6 characters for rate limiting
        get_code_hmac_prefix(code_hmac, 6)
    }
}
