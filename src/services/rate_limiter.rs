use crate::error::{AppError, Result};
use crate::state::AppState;
use deadpool_redis::redis::AsyncCommands;

pub struct RateLimiter;

impl RateLimiter {
    /// Check if IP has exceeded join attempt limit
    pub async fn check_ip_limit(state: &AppState, ip: &str) -> Result<bool> {
        let key = format!("attempts:ip:{}", ip);
        let limit = state.config.rate_limit.join_attempts_per_ip;
        let window = state.config.rate_limit.join_window_seconds;

        Self::check_limit(state, &key, limit, window).await
    }

    /// Check if code prefix has exceeded join attempt limit
    pub async fn check_code_limit(state: &AppState, code_hmac_prefix: &str) -> Result<bool> {
        let key = format!("attempts:code:{}", code_hmac_prefix);
        let limit = state.config.rate_limit.join_attempts_per_code;
        let window = state.config.rate_limit.join_code_window_seconds;

        Self::check_limit(state, &key, limit, window).await
    }

    /// Increment attempt counter for IP
    pub async fn increment_ip_attempt(state: &AppState, ip: &str) -> Result<u32> {
        let key = format!("attempts:ip:{}", ip);
        let window = state.config.rate_limit.join_window_seconds;

        Self::increment_counter(state, &key, window).await
    }

    /// Increment attempt counter for code prefix
    pub async fn increment_code_attempt(state: &AppState, code_hmac_prefix: &str) -> Result<u32> {
        let key = format!("attempts:code:{}", code_hmac_prefix);
        let window = state.config.rate_limit.join_code_window_seconds;

        Self::increment_counter(state, &key, window).await
    }

    /// Generic limit check
    async fn check_limit(
        state: &AppState,
        key: &str,
        limit: u32,
        _window_seconds: u64,
    ) -> Result<bool> {
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        let count: u32 = conn.get(key).await.unwrap_or(0);

        Ok(count >= limit)
    }

    /// Increment counter with TTL
    async fn increment_counter(
        state: &AppState,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<u32> {
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

        let count: u32 = conn.incr(key, 1).await.map_err(|e| AppError::Redis(e.to_string()))?;

        // Set TTL if this is the first increment
        if count == 1 {
            conn.expire::<_, ()>(key, ttl_seconds as i64)
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;
        }

        Ok(count)
    }
}
