use crate::error::{AppError, Result};
use crate::state::AppState;
use deadpool_redis::redis::AsyncCommands;
use rand::{Rng, rngs::OsRng};
use std::time::Duration;
use tracing::warn;

pub struct CodeGenerator;

impl CodeGenerator {
    /// Generate a unique 6-digit code with collision handling using Redis SETNX
    pub async fn generate_unique_code(state: &AppState) -> Result<String> {
        let max_retries = state.config.security.code_retry_max;
        let lock_ttl = state.config.code_lock_ttl().as_secs();

        for attempt in 0..max_retries {
            let code = Self::generate_6_digit_code();
            let lock_key = format!("code_lock:{}", code);

            let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;

            // Try to acquire lock with SETNX
            let locked: bool = conn
                .set_nx(&lock_key, "1")
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;

            if locked {
                // Set expiration on the lock
                conn.expire::<_, ()>(&lock_key, lock_ttl as i64)
                    .await
                    .map_err(|e| AppError::Redis(e.to_string()))?;

                return Ok(code);
            }

            if attempt < max_retries - 1 {
                warn!("Code collision detected: {}, retrying...", code);
                // Small random delay to avoid thundering herd
                let delay = OsRng.gen_range(
                    state.config.code_generator.collision_delay_min_ms
                        ..=state.config.code_generator.collision_delay_max_ms
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }

        Err(AppError::CodeGenerationFailed)
    }

    /// Generate a random 6-digit code (000000-999999)
    fn generate_6_digit_code() -> String {
        let num = OsRng.gen_range(0..=999999);
        format!("{:06}", num)
    }

    /// Release the lock for a code (called after session is created)
    pub async fn release_code_lock(state: &AppState, code: &str) -> Result<()> {
        let lock_key = format!("code_lock:{}", code);
        let mut conn = state.redis.get().await.map_err(|e| AppError::Redis(e.to_string()))?;
        conn.del::<_, ()>(&lock_key).await.map_err(|e| AppError::Redis(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_6_digit_code() {
        let code = CodeGenerator::generate_6_digit_code();
        assert_eq!(code.len(), 6);
        assert!(code.parse::<u32>().is_ok());
        let num = code.parse::<u32>().unwrap();
        assert!(num <= 999999);
    }

    #[test]
    fn test_code_format() {
        for _ in 0..100 {
            let code = CodeGenerator::generate_6_digit_code();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
