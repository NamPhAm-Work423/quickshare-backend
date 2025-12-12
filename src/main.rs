use quickshare_backend::{
    config::Config,
    controllers::websocket::ConnectionManager,
    error::Result,
    routes,
    state::AppState,
};
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "quickshare_backend=info,tower_http=info".into()),
        )
        .with_target(false)
        .with_thread_ids(true)
        .init();

    info!("Starting Quickshare Backend...");

    // Load configuration
    let config = Config::from_env()
        .map_err(|e| quickshare_backend::error::AppError::Config(e.to_string()))?;

    info!("Configuration loaded");

    // Initialize application state
    let state = AppState::new(config.clone())
        .await
        .map_err(|e| quickshare_backend::error::AppError::Internal(e))?;

    info!("Application state initialized");

    // Initialize WebSocket connection manager
    let conn_manager = ConnectionManager::new();

    // Create router
    let app = routes::create_router(state, conn_manager);

    // Build address
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));

    info!("Server listening on {}", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| quickshare_backend::error::AppError::Internal(anyhow::anyhow!("Failed to bind: {}", e)))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| quickshare_backend::error::AppError::Internal(anyhow::anyhow!("Server error: {}", e)))?;

    Ok(())
}
