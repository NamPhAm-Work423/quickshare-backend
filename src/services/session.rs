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
    const CREATOR_INDEX_PREFIX: &'static str = "creator_sessions:";

    /// Create a new session and store in Redis
    pub async fn create_session(
        state: &AppState,
        session: Session,
        _code: &str,
    ) -> Result<()> {
        let session_key = format!("{}:{}", Self::SESSION_KEY_PREFIX, session.session_id);
        let code_hmac = &session.code_hmac;
        let code_index_key = format!("{}:{}", Self::CODE_INDEX_PREFIX, code_hmac);

        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        let session_json = serde_json::to_string(&session)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;

        let ttl = state.config.session_ttl().as_secs();

        // Store session
        conn.set_ex::<_, _, ()>(&session_key, session_json, ttl)
            .await
            .map_err(|e| AppError::Redis(e.to_string()))?;

        // Store code index
        conn.set_ex::<_, _, ()>(&code_index_key, session.session_id.to_string(), ttl)
            .await
            .map_err(|e| AppError::Redis(e.to_string()))?;

        // Add to creator index (set of session IDs for this creator)
        let creator_index_key = format!("{}:{}", Self::CREATOR_INDEX_PREFIX, session.creator_client_id);
        conn.sadd::<_, _, ()>(&creator_index_key, session.session_id.to_string())
            .await
            .map_err(|e| AppError::Redis(e.to_string()))?;
        conn.expire::<_, ()>(&creator_index_key, ttl as i64)
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
            conn.set::<_, _, ()>(&session_key, updated_json).await.map_err(|e| AppError::Redis(e.to_string()))?;
            if ttl > 0 {
                conn.expire::<_, ()>(&session_key, ttl)
                    .await
                    .map_err(|e| AppError::Redis(e.to_string()))?;
            }

            // Delete code index
            let code_index_key = format!("{}:{}", Self::CODE_INDEX_PREFIX, session.code_hmac);
            conn.del::<_, ()>(&code_index_key).await.map_err(|e| AppError::Redis(e.to_string()))?;
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
        conn.set::<_, _, ()>(&session_key, session_json).await.map_err(|e| AppError::Redis(e.to_string()))?;
        if ttl > 0 {
            conn.expire::<_, ()>(&session_key, ttl)
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

    /// Delete session and code_index from Redis
    pub async fn delete_session(state: &AppState, session_id: &Uuid) -> Result<()> {
        let session_key = format!("{}:{}", Self::SESSION_KEY_PREFIX, session_id);
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        // Get session to find code_hmac before deleting
        let session_json: Option<String> = conn.get(&session_key).await.map_err(|e| AppError::Redis(e.to_string()))?;
        
        if let Some(json) = session_json {
            let session: Session = serde_json::from_str(&json)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))?;
            
            // Delete code index
            let code_index_key = format!("{}:{}", Self::CODE_INDEX_PREFIX, session.code_hmac);
            conn.del::<_, ()>(&code_index_key).await.map_err(|e| AppError::Redis(e.to_string()))?;

            // Remove from creator index
            let creator_index_key = format!("{}:{}", Self::CREATOR_INDEX_PREFIX, session.creator_client_id);
            conn.srem::<_, _, ()>(&creator_index_key, session.session_id.to_string())
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;
        }

        // Delete session
        conn.del::<_, ()>(&session_key).await.map_err(|e| AppError::Redis(e.to_string()))?;

        Ok(())
    }

    /// Cleanup old sessions for a creator client_id (when creating new session)
    pub async fn cleanup_old_sessions_for_creator(
        state: &AppState,
        creator_client_id: &str,
    ) -> Result<()> {
        let creator_index_key = format!("{}:{}", Self::CREATOR_INDEX_PREFIX, creator_client_id);
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        // Get all session IDs for this creator
        let session_ids: Vec<String> = conn
            .smembers(&creator_index_key)
            .await
            .map_err(|e| AppError::Redis(e.to_string()))?;

        if session_ids.is_empty() {
            return Ok(());
        }

        // Cleanup each old session that is not used and has no other participants
        let mut cleaned_count = 0;
        for session_id_str in session_ids {
            if let Ok(session_id) = Uuid::parse_str(&session_id_str) {
                match Self::get_session(state, &session_id).await {
                    Ok(session) => {
                        // Only cleanup if:
                        // 1. Session is not used
                        // 2. Only has creator as participant (no other participants joined)
                        if !session.used && session.participants.len() == 1 {
                            // Verify it's the creator
                            if session.participants[0].client_id == creator_client_id {
                                if let Err(e) = Self::delete_session(state, &session_id).await {
                                    tracing::warn!("Failed to cleanup old session {}: {}", session_id, e);
                                } else {
                                    cleaned_count += 1;
                                    // Remove from creator index
                                    let _ = conn.srem::<_, _, ()>(&creator_index_key, &session_id_str).await;
                                }
                            }
                        }
                    }
                    Err(AppError::SessionNotFound) | Err(AppError::SessionExpired) => {
                        // Session already deleted or expired, remove from index
                        let _ = conn.srem::<_, _, ()>(&creator_index_key, &session_id_str).await;
                    }
                    Err(_) => {
                        // Other errors, skip
                    }
                }
            }
        }

        if cleaned_count > 0 {
            tracing::info!("Cleaned up {} old sessions for creator {}", cleaned_count, creator_client_id);
        }

        Ok(())
    }
}
