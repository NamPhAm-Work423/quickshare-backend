use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_server")]
    pub server: ServerConfig,
    #[serde(default = "default_redis")]
    pub redis: RedisConfig,
    #[serde(default = "default_session")]
    pub session: SessionConfig,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: RateLimitConfig,
    #[serde(default = "default_cloudflare_turn")]
    pub cloudflare_turn: CloudflareTurnConfig,
    #[serde(default = "default_cors")]
    pub cors: CorsConfig,
    #[serde(default = "default_websocket")]
    pub websocket: WebSocketConfig,
    #[serde(default = "default_code_generator")]
    pub code_generator: CodeGeneratorConfig,
    pub security: SecurityConfig,
}

fn default_server() -> ServerConfig {
    ServerConfig {
        host: "0.0.0.0".to_string(),
        port: 3001,
        ws_path: "/ws".to_string(),
    }
}

fn default_redis() -> RedisConfig {
    RedisConfig {
        url: "redis://localhost:6379".to_string(),
        max_connections: 16,
    }
}

fn default_session() -> SessionConfig {
    SessionConfig {
        default_ttl_seconds: 600,
        max_ttl_seconds: 3600,
        single_use_default: true,
        max_participants: 2,
    }
}

fn default_rate_limit() -> RateLimitConfig {
    RateLimitConfig {
        join_attempts_per_ip: 10,
        join_window_seconds: 60,
        join_attempts_per_code: 5,
        join_code_window_seconds: 300,
        ws_messages_per_minute: 100,
    }
}

fn default_cloudflare_turn() -> CloudflareTurnConfig {
    CloudflareTurnConfig {
        token_id: String::new(),
        api_token: String::new(),
        credential_ttl: 86400, // 24 hours
    }
}

fn default_cors() -> CorsConfig {
    CorsConfig {
        allowed_origin: default_cors_origin(),
    }
}

fn default_cors_origin() -> String {
    "http://localhost:3000".to_string()
}

fn default_websocket() -> WebSocketConfig {
    WebSocketConfig {
        base_url: default_ws_base_url(),
        channel_size: default_ws_channel_size(),
        max_message_size_bytes: default_ws_max_message_size(),
        heartbeat_interval_seconds: default_ws_heartbeat_interval(),
        connection_timeout_seconds: default_ws_connection_timeout(),
    }
}

fn default_ws_base_url() -> String {
    "ws://localhost".to_string()
}

fn default_ws_channel_size() -> usize {
    100
}

fn default_ws_max_message_size() -> usize {
    64 * 1024 // 64KB
}

fn default_ws_heartbeat_interval() -> u64 {
    30 // 30 seconds
}

fn default_ws_connection_timeout() -> u64 {
    300 // 5 minutes
}

fn default_code_generator() -> CodeGeneratorConfig {
    CodeGeneratorConfig {
        collision_delay_min_ms: default_code_delay_min(),
        collision_delay_max_ms: default_code_delay_max(),
    }
}

fn default_code_delay_min() -> u64 {
    10
}

fn default_code_delay_max() -> u64 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub ws_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub single_use_default: bool,
    pub max_participants: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub join_attempts_per_ip: u32,
    pub join_window_seconds: u64,
    pub join_attempts_per_code: u32,
    pub join_code_window_seconds: u64,
    pub ws_messages_per_minute: u32,
}

/// Cloudflare TURN server configuration
/// Uses Cloudflare's managed TURN service with short-lived credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareTurnConfig {
    /// Cloudflare TURN Token ID
    #[serde(default)]
    pub token_id: String,
    
    /// Cloudflare TURN API Token (secret)
    #[serde(default)]
    pub api_token: String,
    
    /// Credential TTL in seconds (default: 86400 = 24 hours, max: 86400)
    #[serde(default = "default_credential_ttl")]
    pub credential_ttl: u64,
}

fn default_credential_ttl() -> u64 {
    86400 // 24 hours
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub master_hmac_key: String,
    pub code_retry_max: u32,
    pub code_lock_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    #[serde(default = "default_cors_origin")]
    pub allowed_origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default = "default_ws_base_url")]
    pub base_url: String,
    #[serde(default = "default_ws_channel_size")]
    pub channel_size: usize,
    #[serde(default = "default_ws_max_message_size")]
    pub max_message_size_bytes: usize,
    #[serde(default = "default_ws_heartbeat_interval")]
    pub heartbeat_interval_seconds: u64,
    #[serde(default = "default_ws_connection_timeout")]
    pub connection_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeGeneratorConfig {
    #[serde(default = "default_code_delay_min")]
    pub collision_delay_min_ms: u64,
    #[serde(default = "default_code_delay_max")]
    pub collision_delay_max_ms: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, figment::Error> {
        dotenvy::dotenv().ok();

        use figment::{providers::Env, Figment};

        // Support REDIS_URL (Upstash format) - convert to REDIS__URL format if not already set
        if std::env::var("REDIS__URL").is_err() {
            if let Ok(redis_url) = std::env::var("REDIS_URL") {
                std::env::set_var("REDIS__URL", redis_url);
            }
        }

        let mut config: Config = Figment::new()
            .merge(Env::raw().split("__"))
            .extract()?;

        // Set defaults if not provided
        if config.server.host.is_empty() {
            config.server = default_server();
        }
        if config.redis.url.is_empty() {
            config.redis = default_redis();
        }
        if config.session.default_ttl_seconds == 0 {
            config.session = default_session();
        }
        if config.rate_limit.join_attempts_per_ip == 0 {
            config.rate_limit = default_rate_limit();
        }
        if config.cors.allowed_origin.is_empty() {
            config.cors = default_cors();
        }
        if config.websocket.base_url.is_empty() {
            config.websocket = default_websocket();
        }
        if config.code_generator.collision_delay_min_ms == 0 {
            config.code_generator = default_code_generator();
        }

        // Validate required fields
        if config.security.master_hmac_key.is_empty() {
            return Err(figment::Error::from("SECURITY__MASTER_HMAC_KEY is required"));
        }

        Ok(config)
    }

    pub fn session_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.session.default_ttl_seconds)
    }

    pub fn code_lock_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.security.code_lock_ttl_seconds)
    }
}
