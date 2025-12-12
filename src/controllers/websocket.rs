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
use tokio::sync::broadcast;
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

    // Clone values needed in both tasks
    let conn_manager_clone = conn_manager.clone();
    let client_id_clone = client_id.clone();
    let session_id_clone = session_id;

    // Spawn task to forward messages from connection manager to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = receiver.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // Spawn task to receive messages from client and broadcast
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = recv.next().await {
            match msg {
                Message::Text(text) => {
                    // Parse signaling message
                    match serde_json::from_str::<SignalingMessage>(&text) {
                        Ok(signaling_msg) => {
                            // Broadcast to other participants in session
                            if let Err(e) = conn_manager_clone
                                .broadcast_to_session(&session_id_clone, &client_id_clone, &text)
                                .await
                            {
                                error!("Failed to broadcast message: {}", e);
                            }

                            // Handle transfer completion to mark session as used
                            if matches!(signaling_msg, SignalingMessage::TransferCompleted) {
                                if let Err(e) = SessionService::mark_session_used(&state, &session_id_clone).await {
                                    warn!("Failed to mark session as used: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Invalid signaling message: {}", e);
                        }
                    }
                }
                Message::Close(_) => {
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        }
        _ = &mut recv_task => {
            send_task.abort();
        }
    }

    // Unregister connection
    conn_manager.unregister(&session_id, &client_id).await;
}

