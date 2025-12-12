use crate::config::Config;
use deadpool_redis::{Config as RedisConfig, Pool, Runtime};
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
        // Initialize Redis pool
        let redis_config = RedisConfig::from_url(config.redis.url.clone());
        let redis = redis_config
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| anyhow::anyhow!("Failed to create Redis pool: {}", e))?;

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
