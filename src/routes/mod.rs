use crate::controllers::{health, session, websocket};
use crate::middleware::create_cors_layer;
use crate::state::AppState;
use crate::controllers::websocket::ConnectionManager;
use axum::{
    routing::{get, on, MethodFilter},
    Router,
    http::StatusCode,
    response::IntoResponse,
};

#[derive(Clone)]
pub struct RouterState {
    pub app_state: AppState,
    pub conn_manager: ConnectionManager,
}

// Handler for OPTIONS preflight requests
async fn handle_options() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

pub fn create_router(state: AppState, conn_manager: ConnectionManager) -> Router {
    let router_state = RouterState {
        app_state: state.clone(),
        conn_manager,
    };

    // Create production-ready CORS layer from configuration
    let cors = create_cors_layer(&state.config.cors);

    Router::new()
        .route("/health", get(health::health_check))
        .route("/api/session/create", 
            on(MethodFilter::POST, session::create_session)
                .on(MethodFilter::OPTIONS, handle_options)
        )
        .route("/api/session/join", 
            on(MethodFilter::POST, session::join_session)
                .on(MethodFilter::OPTIONS, handle_options)
        )
        .route("/ws", get(websocket::handle_websocket))
        .layer(cors)
        .with_state(router_state)
}
