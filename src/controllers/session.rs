use crate::controllers::websocket::generate_ws_token;
use crate::error::{AppError, Result};
use crate::extractors::extract_client_ip;
use crate::models::api::{
    CreateSessionRequest, CreateSessionResponse, IceServer, IceServersConfig, JoinSessionRequest,
    JoinSessionResponse, PeerInfo,
};
use crate::models::session::Session;
use crate::services::{
    code_generator::CodeGenerator, hmac::compute_code_hmac, rate_limiter::RateLimiter,
    session::SessionService,
};
use crate::state::AppState;
use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use uuid::Uuid;

/// Create a new session
pub async fn create_session(
    State(router_state): State<crate::routes::RouterState>,
    _headers: HeaderMap,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>> {
    let state = &router_state.app_state;
    // Generate unique 6-digit code
    let code = CodeGenerator::generate_unique_code(&state).await?;

    // Compute HMAC for code
    let code_hmac = compute_code_hmac(&state.get_hmac_key(), &code);

    // Generate session ID and client ID
    let session_id = Uuid::new_v4();
    let creator_client_id = Uuid::new_v4().to_string();

    // Determine TTL
    let ttl_seconds = req
        .ttl_seconds
        .unwrap_or(state.config.session.default_ttl_seconds)
        .min(state.config.session.max_ttl_seconds);

    // Determine single_use
    let single_use = req.single_use.unwrap_or(state.config.session.single_use_default);

    // Cleanup old sessions for this creator (best-effort, non-blocking)
    // This prevents accumulation of orphaned sessions
    let _ = SessionService::cleanup_old_sessions_for_creator(&state, &creator_client_id).await;

    // Create session
    let mut session = Session::new(session_id, code_hmac, creator_client_id.clone(), ttl_seconds, single_use);

    // Add metadata if provided
    if let Some(metadata) = req.metadata {
        session.metadata = Some(crate::models::session::SessionMetadata {
            file_name: metadata.file_name,
            file_size: metadata.file_size,
            file_type: metadata.file_type,
        });
    }

    // Store session in Redis
    SessionService::create_session(&state, session.clone(), &code).await?;

    // Release code lock
    CodeGenerator::release_code_lock(&state, &code).await?;

    // Build ICE servers config
    let ice_servers = build_ice_servers(&state);

    // Build WebSocket URL from config
    let mut base_url = state.config.websocket.base_url.clone();
    // Remove trailing slash if present
    if base_url.ends_with('/') {
        base_url.pop();
    }

    let ws_url = format!(
        "{}{}{}?session_id={}&client_id={}",
        base_url,
        state.config.server.ws_path,
        if state.config.server.ws_path.contains('?') { "&" } else { "?" },
        session_id,
        creator_client_id
    );

    Ok(Json(CreateSessionResponse {
        code,
        session_id,
        ws_url,
        ice_servers,
    }))
}

/// Join an existing session
pub async fn join_session(
    State(router_state): State<crate::routes::RouterState>,
    headers: HeaderMap,
    peer_addr: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    Json(req): Json<JoinSessionRequest>,
) -> Result<Json<JoinSessionResponse>> {
    let state = &router_state.app_state;
    // Validate code format
    if req.code.len() != 6 || !req.code.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::InvalidCode);
    }

    // Extract client IP for rate limiting
    let client_ip = extract_client_ip(
        &headers,
        peer_addr.as_ref().map(|ci| &ci.0),
    );

    let ip_str = client_ip.as_deref().unwrap_or("unknown");

    // Check IP rate limit
    if RateLimiter::check_ip_limit(&state, ip_str).await? {
        return Err(AppError::RateLimitExceeded);
    }

    // Get session by code
    let session = SessionService::get_session_by_code(&state, &req.code).await?;

    // Check code rate limit using HMAC prefix
    let code_hmac_prefix = SessionService::get_code_hmac_prefix_for_rate_limit(&state, &session.code_hmac);
    if RateLimiter::check_code_limit(&state, &code_hmac_prefix).await? {
        return Err(AppError::RateLimitExceeded);
    }

    // Validate session can be joined
    if !session.can_join() {
        if session.used {
            return Err(AppError::SessionAlreadyUsed);
        }
        if session.is_expired() {
            return Err(AppError::SessionExpired);
        }
        return Err(AppError::BadRequest("Session is full".to_string()));
    }

    // Increment rate limit counters
    RateLimiter::increment_ip_attempt(&state, ip_str).await?;
    RateLimiter::increment_code_attempt(&state, &code_hmac_prefix).await?;

    // Generate client ID for receiver
    let receiver_client_id = Uuid::new_v4().to_string();

    // Add participant to session
    let updated_session = SessionService::add_participant(
        &state,
        &session.session_id,
        receiver_client_id.clone(),
        client_ip.clone(),
    )
    .await?;

    // Generate WebSocket token
    let ws_token = generate_ws_token(&state, &updated_session.session_id, &receiver_client_id)?;

    // Build ICE servers config
    let ice_servers = build_ice_servers(&state);

    // Build WebSocket URL from config
    let mut base_url = state.config.websocket.base_url.clone();
    // Remove trailing slash if present
    if base_url.ends_with('/') {
        base_url.pop();
    }

    let ws_url = format!(
        "{}{}{}?session_id={}&client_id={}&token={}",
        base_url,
        state.config.server.ws_path,
        if state.config.server.ws_path.contains('?') { "&" } else { "?" },
        updated_session.session_id,
        receiver_client_id,
        ws_token
    );

    Ok(Json(JoinSessionResponse {
        session_id: updated_session.session_id,
        ws_token,
        ws_url,
        ice_servers,
        peer_info: PeerInfo {
            creator_client_id: updated_session.creator_client_id,
        },
    }))
}

/// Build ICE servers configuration from config
fn build_ice_servers(state: &AppState) -> IceServersConfig {
    let mut ice_servers = Vec::new();

    // Add STUN servers
    for stun_url in &state.config.turn.stun_servers {
        ice_servers.push(IceServer {
            urls: vec![stun_url.clone()],
            username: None,
            credential: None,
        });
    }

    // Add TURN servers
    for turn_server in &state.config.turn.turn_servers {
        ice_servers.push(IceServer {
            urls: turn_server.urls.clone(),
            username: Some(turn_server.username.clone()),
            credential: Some(turn_server.credential.clone()),
        });
    }

    IceServersConfig { ice_servers }
}
