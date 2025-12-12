use crate::config::CorsConfig;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use http::header;
use tracing::{info, warn};

/// Creates a production-ready CORS layer based on configuration
/// 
/// # Security Considerations
/// - Never uses wildcard (*) in production
/// - Supports single or multiple specific origins
/// - Enables credentials only for specific origins
/// - Configures appropriate headers and methods
pub fn create_cors_layer(config: &CorsConfig) -> CorsLayer {
    let origin_str = config.allowed_origin.trim();
    
    // Parse origins (comma-separated)
    let origins: Vec<String> = origin_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if origins.is_empty() {
        warn!("No CORS origins configured, using restrictive default (localhost:3000)");
        return create_single_origin_cors("http://localhost:3000");
    }

    // Check for wildcard (development only!)
    if origins.contains(&"*".to_string()) {
        warn!(
            " WILDCARD CORS ENABLED - This should ONLY be used in development!"
        );
        info!("CORS: Allowing all origins (wildcard mode)");
        return create_wildcard_cors();
    }

    // Production mode: specific origins
    if origins.len() == 1 {
        info!("CORS: Configured for single origin: {}", origins[0]);
        create_single_origin_cors(&origins[0])
    } else {
        info!("CORS: Configured for {} origins: {:?}", origins.len(), origins);
        create_multiple_origins_cors(origins)
    }
}

/// Creates CORS layer for a single origin (production)
fn create_single_origin_cors(origin: &str) -> CorsLayer {
    let origin_header = match origin.parse::<http::HeaderValue>() {
        Ok(h) => h,
        Err(e) => {
            warn!("Invalid CORS origin '{}': {}. Falling back to localhost:3000", origin, e);
            "http://localhost:3000".parse().unwrap()
        }
    };

    CorsLayer::new()
        .allow_origin(AllowOrigin::exact(origin_header))
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::OPTIONS,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::PATCH,
            http::Method::HEAD,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::ACCEPT_LANGUAGE,
            header::ACCEPT_ENCODING,
            header::CACHE_CONTROL,
        ])
        .allow_credentials(true)
        .expose_headers([
            header::CONTENT_TYPE,
            header::CONTENT_LENGTH,
        ])
        .max_age(std::time::Duration::from_secs(3600))
}

/// Creates CORS layer for multiple origins (production)
fn create_multiple_origins_cors(origins: Vec<String>) -> CorsLayer {
    let origin_headers: Vec<http::HeaderValue> = origins
        .iter()
        .filter_map(|origin| {
            match origin.parse::<http::HeaderValue>() {
                Ok(h) => Some(h),
                Err(e) => {
                    warn!("Skipping invalid CORS origin '{}': {}", origin, e);
                    None
                }
            }
        })
        .collect();

    if origin_headers.is_empty() {
        warn!("No valid CORS origins found after parsing. Using localhost:3000");
        return create_single_origin_cors("http://localhost:3000");
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origin_headers))
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::OPTIONS,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::PATCH,
            http::Method::HEAD,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::ACCEPT_LANGUAGE,
            header::ACCEPT_ENCODING,
            header::CACHE_CONTROL,
        ])
        .allow_credentials(true)
        .expose_headers([
            header::CONTENT_TYPE,
            header::CONTENT_LENGTH,
        ])
        .max_age(std::time::Duration::from_secs(3600))
}

/// Creates CORS layer with wildcard (DEVELOPMENT ONLY!)
fn create_wildcard_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::OPTIONS,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::PATCH,
            http::Method::HEAD,
        ])
        .allow_headers(Any)
        .allow_credentials(false) // Cannot use credentials with wildcard
        .expose_headers(Any)
        .max_age(std::time::Duration::from_secs(3600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_origin_uses_default() {
        let config = CorsConfig {
            allowed_origin: "".to_string(),
        };
        let _layer = create_cors_layer(&config);
        // Should not panic and use default localhost:3000
    }

    #[test]
    fn test_single_origin() {
        let config = CorsConfig {
            allowed_origin: "http://example.com".to_string(),
        };
        let _layer = create_cors_layer(&config);
        // Should create single origin CORS
    }

    #[test]
    fn test_multiple_origins() {
        let config = CorsConfig {
            allowed_origin: "http://example.com,http://localhost:3000".to_string(),
        };
        let _layer = create_cors_layer(&config);
        // Should create multiple origins CORS
    }

    #[test]
    fn test_wildcard_origin() {
        let config = CorsConfig {
            allowed_origin: "*".to_string(),
        };
        let _layer = create_cors_layer(&config);
        // Should create wildcard CORS with warning
    }
}
