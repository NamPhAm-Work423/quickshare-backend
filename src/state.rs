use crate::config::Config;
use deadpool_redis::{Config as RedisConfig, Pool, PoolConfig, Runtime};
use deadpool_redis::redis::cmd;
use hmac::Hmac;
use sha2::Sha256;
use std::sync::Arc;

pub type HmacKey = Hmac<Sha256>;

#[derive(Clone)]
pub struct AppState {
    pub redis: Pool,
    pub config: Arc<Config>,
    pub hmac_key_bytes: Arc<Vec<u8>>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, anyhow::Error> {
        // Initialize Redis pool with proper configuration
        let mut redis_config = RedisConfig::from_url(config.redis.url.clone());
        
        // Set max pool size from config
        redis_config.pool = Some(PoolConfig {
            max_size: config.redis.max_connections as usize,
            ..Default::default()
        });
        
        // Test connection before creating pool
        let redis = redis_config
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| anyhow::anyhow!("Failed to create Redis pool: {}", e))?;

        // Verify connection by getting a connection from the pool
        let mut conn = redis.get().await
            .map_err(|e| anyhow::anyhow!("Failed to get Redis connection: {}", e))?;
        
        // Test connection with a simple ping using cmd
        let _: String = cmd("PING")
            .query_async(&mut *conn)
            .await
            .map_err(|e| anyhow::anyhow!("Redis connection test failed: {}", e))?;

        // Store HMAC key as bytes for easy cloning
        let key_bytes = config.security.master_hmac_key.as_bytes().to_vec();

        Ok(Self {
            redis,
            config: Arc::new(config),
            hmac_key_bytes: Arc::new(key_bytes),
        })
    }

    /// Get HMAC key for computation
    pub fn get_hmac_key(&self) -> HmacKey {
        use hmac::Mac;
        Hmac::<Sha256>::new_from_slice(&self.hmac_key_bytes)
            .expect("HMAC key should be valid")
    }
}
