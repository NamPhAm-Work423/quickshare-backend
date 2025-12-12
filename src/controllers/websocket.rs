use crate::error::Result;
use crate::models::signaling::SignalingMessage;
use crate::services::session::SessionService;
use crate::state::AppState;
use axum::{
    extract::{
        ws::Message,
        Query, State,
    },
};
use base64::{engine::general_purpose, Engine};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{interval, timeout};
use tracing::{error, info, warn};
use uuid::Uuid;

// In-memory connection manager for WebSocket signaling
#[derive(Clone)]
pub struct ConnectionManager {
    // Map from session_id -> Map from client_id -> sender
    connections: Arc<tokio::sync::RwLock<HashMap<Uuid, HashMap<String, broadcast::Sender<String>>>>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, session_id: Uuid, client_id: String, channel_size: usize) -> broadcast::Receiver<String> {
        let mut conns = self.connections.write().await;
        let session_conns = conns.entry(session_id).or_insert_with(HashMap::new);
        
        let (tx, rx) = broadcast::channel(channel_size);
        session_conns.insert(client_id.clone(), tx);
        
        info!("Registered client {} for session {}", client_id, session_id);
        rx
    }

    pub async fn unregister(&self, session_id: &Uuid, client_id: &str) {
        let mut conns = self.connections.write().await;
        if let Some(session_conns) = conns.get_mut(session_id) {
            session_conns.remove(client_id);
            if session_conns.is_empty() {
                conns.remove(session_id);
            }
        }
        info!("Unregistered client {} from session {}", client_id, session_id);
    }

    /// Check if session has any active connections
    pub async fn has_active_connections(&self, session_id: &Uuid) -> bool {
        let conns = self.connections.read().await;
        conns.get(session_id).map_or(false, |session_conns| !session_conns.is_empty())
    }

    pub async fn broadcast_to_session(
        &self,
        session_id: &Uuid,
        sender_client_id: &str,
        message: &str,
    ) -> Result<()> {
        let conns = self.connections.read().await;
        if let Some(session_conns) = conns.get(session_id) {
            for (client_id, tx) in session_conns.iter() {
                if client_id != sender_client_id {
                    let _ = tx.send(message.to_string());
                }
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct WsQuery {
    session_id: String,
    client_id: String,
    #[serde(default)]
    token: Option<String>,
}

/// Generate a simple WebSocket token (HMAC of session_id + client_id)
pub fn generate_ws_token(state: &AppState, session_id: &Uuid, client_id: &str) -> Result<String> {
    use hmac::Mac;
    let mut mac = state.get_hmac_key();
    
    let payload = format!("{}:{}", session_id, client_id);
    mac.update(payload.as_bytes());
    let result = mac.finalize();
    
    Ok(general_purpose::STANDARD.encode(result.into_bytes()))
}

/// Verify WebSocket token
fn verify_ws_token(state: &AppState, session_id: &Uuid, client_id: &str, token: &str) -> bool {
    match generate_ws_token(state, session_id, client_id) {
        Ok(expected_token) => expected_token == token,
        Err(_) => false,
    }
}

/// Handle WebSocket connection
pub async fn handle_websocket(
    ws: axum::extract::ws::WebSocketUpgrade,
    State(router_state): State<crate::routes::RouterState>,
    Query(params): Query<WsQuery>,
) -> axum::response::Response {
    let state = router_state.app_state.clone();
    let conn_manager = router_state.conn_manager.clone();
    // Parse session_id and client_id
    let session_id = match Uuid::parse_str(&params.session_id) {
        Ok(id) => id,
        Err(_) => {
            return axum::response::Response::builder()
                .status(400)
                .body("Invalid session_id".into())
                .unwrap();
        }
    };

    let client_id = params.client_id.clone();
    let token = params.token.clone();

    // Verify token if provided (for receivers)
    if let Some(ref token) = token {
        if !verify_ws_token(&state, &session_id, &client_id, token) {
            return axum::response::Response::builder()
                .status(401)
                .body("Invalid token".into())
                .unwrap();
        }
    }

    // Verify session exists
    let session = match SessionService::get_session(&state, &session_id).await {
        Ok(s) => s,
        Err(_) => {
            return axum::response::Response::builder()
                .status(404)
                .body("Session not found".into())
                .unwrap();
        }
    };

    // Verify client_id is in session participants
    let is_participant = session
        .participants
        .iter()
        .any(|p| p.client_id == client_id);

    if !is_participant {
        return axum::response::Response::builder()
            .status(403)
            .body("Client not authorized for this session".into())
            .unwrap();
    }

    // Register connection
    let receiver = conn_manager
        .register(session_id, client_id.clone(), state.config.websocket.channel_size)
        .await;

    // Handle WebSocket messages
    ws.on_upgrade(move |socket| {
        handle_websocket_stream(
            socket,
            state,
            conn_manager,
            session_id,
            client_id,
            receiver,
        )
    })
}

async fn handle_websocket_stream(
    socket: axum::extract::ws::WebSocket,
    state: AppState,
    conn_manager: ConnectionManager,
    session_id: Uuid,
    client_id: String,
    mut receiver: broadcast::Receiver<String>,
) {
    let (mut sender, mut recv) = socket.split();

    // Get configuration values
    let max_message_size = state.config.websocket.max_message_size_bytes;
    let heartbeat_interval = Duration::from_secs(state.config.websocket.heartbeat_interval_seconds);
    let connection_timeout = Duration::from_secs(state.config.websocket.connection_timeout_seconds);

    // Clone values needed in both tasks
    let client_id_clone = client_id.clone();
    let session_id_clone = session_id;

    // Track last pong time for heartbeat
    let last_pong = Arc::new(tokio::sync::Mutex::new(std::time::Instant::now()));

    // Channel for sending pings from heartbeat task to send task
    let (ping_tx, mut ping_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    // Spawn heartbeat task (ping/pong)
    let heartbeat_last_pong = last_pong.clone();
    let heartbeat_ping_tx = ping_tx.clone();
    let heartbeat_client_id = client_id_clone.clone();
    let heartbeat_session_id = session_id_clone;
    let mut heartbeat_task = tokio::spawn(async move {
        let mut interval = interval(heartbeat_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Check if we received a pong recently
                    let last_pong_time = heartbeat_last_pong.lock().await;
                    if last_pong_time.elapsed() > heartbeat_interval * 3 {
                        // No pong received in 3 intervals, consider connection dead
                        warn!("WebSocket heartbeat timeout for client {} in session {}", heartbeat_client_id, heartbeat_session_id);
                        let _ = heartbeat_ping_tx.send(());
                        break;
                    }
                    drop(last_pong_time);

                    // Trigger ping
                    let _ = heartbeat_ping_tx.send(());
                }
            }
        }
    });

    // Spawn task to forward messages from connection manager to client and handle pings
    let mut send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(msg) => {
                            if sender.send(Message::Text(msg)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => {
                            // Channel closed
                            break;
                        }
                    }
                }
                _ = ping_rx.recv() => {
                    // Send ping when heartbeat triggers
                    if sender.send(Message::Ping(vec![])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Spawn task to receive messages from client and broadcast
    let recv_last_pong = last_pong.clone();
    let recv_conn_manager = conn_manager.clone();
    let recv_client_id = client_id.clone();
    let recv_session_id = session_id;
    let recv_state = state.clone();
    let recv_max_message_size = max_message_size;
    let mut recv_task = tokio::spawn(async move {
        let timeout_duration = connection_timeout;
        loop {
            match timeout(timeout_duration, recv.next()).await {
                Ok(Some(Ok(msg))) => {
                    match msg {
                        Message::Text(text) => {
                            // Check message size limit
                            if text.len() > recv_max_message_size {
                                warn!(
                                    "Message size {} exceeds limit {} for client {} in session {}",
                                    text.len(), recv_max_message_size, recv_client_id, recv_session_id
                                );
                                // Send error and close connection
                                let _ = recv_conn_manager
                                    .broadcast_to_session(
                                        &recv_session_id,
                                        &recv_client_id,
                                        r#"{"type":"error","message":"Message too large"}"#,
                                    )
                                    .await;
                                break;
                            }

                            // Parse signaling message
                            match serde_json::from_str::<SignalingMessage>(&text) {
                                Ok(signaling_msg) => {
                                    // Broadcast to other participants in session
                                    if let Err(e) = recv_conn_manager
                                        .broadcast_to_session(&recv_session_id, &recv_client_id, &text)
                                        .await
                                    {
                                        error!("Failed to broadcast message: {}", e);
                                    }

                                    // Handle transfer completion to mark session as used
                                    if matches!(signaling_msg, SignalingMessage::TransferCompleted) {
                                        if let Err(e) = SessionService::mark_session_used(&recv_state, &recv_session_id).await {
                                            warn!("Failed to mark session as used: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Invalid signaling message: {}", e);
                                }
                            }
                        }
                        Message::Pong(_) => {
                            // Update last pong time
                            *recv_last_pong.lock().await = std::time::Instant::now();
                        }
                        Message::Ping(_) => {
                            // Respond to ping with pong (handled automatically by axum)
                        }
                        Message::Close(_) => {
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(Some(Err(_))) => {
                    // Connection error
                    break;
                }
                Ok(None) => {
                    // Stream ended
                    break;
                }
                Err(_) => {
                    // Timeout - connection idle too long
                    warn!("WebSocket receive timeout for client {} in session {}", recv_client_id, recv_session_id);
                    break;
                }
            }
        }
    });

    // Wait for any task to complete
    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
            heartbeat_task.abort();
        }
        _ = &mut recv_task => {
            send_task.abort();
            heartbeat_task.abort();
        }
        _ = &mut heartbeat_task => {
            send_task.abort();
            recv_task.abort();
        }
    }

    // Unregister connection
    conn_manager.unregister(&session_id, &client_id).await;

    // Cleanup session in Redis if no active connections remain and session is not used
    if !conn_manager.has_active_connections(&session_id).await {
        // Check if session exists and is not used before cleanup
        match SessionService::get_session(&state, &session_id).await {
            Ok(session) => {
                // Only cleanup if session is not used and has no active connections
                if !session.used {
                    if let Err(e) = SessionService::delete_session(&state, &session_id).await {
                        warn!("Failed to cleanup session {} after disconnect: {}", session_id, e);
                    } else {
                        info!("Cleaned up unused session {} after all connections closed", session_id);
                    }
                }
            }
            Err(_) => {
                // Session already deleted or expired, nothing to cleanup
            }
        }
    }
}

