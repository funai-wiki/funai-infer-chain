// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Funai Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use funai_common::{debug, error, info, warn};
use tokio::sync::mpsc;

use crate::inference_service::{
    InferTask, InferTaskResult, InferTaskStatus, InferenceNode,
    InferenceServiceEvent, NodeStatus,
    InferenceServiceState,
};
use serde_json::json;
use funailib::chainstate::funai::{
    FunaiTransaction, TransactionPayload, TransactionVersion, FunaiPublicKey,
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use funai_common::address::AddressHashMode;
use funai_common::types::chainstate::FunaiAddress;
use funai_common::util::hash::hex_bytes;
use funai_common::codec::FunaiMessageCodec;
use std::io::Cursor;
use clarity::vm::types::{PrincipalData, FunaiAddressExtensions};
use sha2::{Sha256, Digest};

/// Generic API response wrapper
#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the request was successful
    pub success: bool,
    /// The data returned by the API (if any)
    pub data: Option<T>,
    /// The error message (if any)
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    /// Create a successful response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    /// Create an error response
    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

/// Request to register an inference node
#[derive(Serialize, Deserialize)]
pub struct RegisterNodeRequest {
    /// Node ID
    pub node_id: String,
    /// Node endpoint
    pub endpoint: String,
    /// Node public key
    pub public_key: String,
    /// Supported model types
    pub supported_models: Vec<String>,
    /// Node performance score (optional)
    pub performance_score: Option<f64>,
}

/// Request for inference node to fetch a task (with signature authentication)
#[derive(Serialize, Deserialize)]
pub struct GetTaskRequest {
    /// Node ID
    pub node_id: String,
    /// Request timestamp (Unix timestamp in seconds)
    pub timestamp: u64,
    /// Signature of "GET_TASK:{node_id}:{timestamp}" using the node's private key
    /// Format: hex-encoded recoverable signature (65 bytes)
    pub signature: String,
}

/// Request to submit an inference task via API
#[derive(Serialize, Deserialize)]
pub struct SubmitTaskRequest {
    /// Task ID (optional, will be generated if not provided)
    pub task_id: Option<String>,
    /// User address
    pub user_address: String,
    /// User input (may be encrypted JSON if is_encrypted is true)
    pub user_input: String,
    /// Context information (may be encrypted JSON if is_encrypted is true)
    pub context: String,
    /// Transaction fee (optional)
    pub fee: Option<u64>,
    /// Nonce (optional)
    pub nonce: Option<u64>,
    /// Inference fee
    pub infer_fee: u64,
    /// Maximum inference time (seconds)
    pub max_infer_time: u64,
    /// Model name
    pub model_name: String,
    /// Signed transaction hex (optional)
    pub signed_tx: Option<String>,
    /// Whether the user_input and context are encrypted
    #[serde(default)]
    pub is_encrypted: bool,
    /// Signer's public key used for encryption (required if is_encrypted is true)
    pub signer_public_key: Option<String>,
}

/// Node status response
#[derive(Serialize, Deserialize)]
pub struct NodeStatusResponse {
    /// Node ID
    pub node_id: String,
    /// Node status
    pub status: String,
}

/// Request to decrypt inference input (from Infer Node or other Signers)
#[derive(Serialize, Deserialize)]
pub struct DecryptInputRequest {
    /// Task ID for which decryption is requested
    pub task_id: String,
    /// The requester's public key (for verification)
    pub requester_public_key: String,
    /// Signature of task_id by the requester (proves they control the key)
    pub signature: String,
    /// Requester type: "infer_node" or "signer"
    pub requester_type: String,
}

/// Response for decrypt input request
#[derive(Serialize, Deserialize)]
pub struct DecryptInputResponse {
    /// Task ID
    pub task_id: String,
    /// Decrypted user input (only provided if authorized)
    pub user_input: Option<String>,
    /// Decrypted context (only provided if authorized)
    pub context: Option<String>,
    /// Whether the request was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Response containing the signer's public key for encryption
#[derive(Serialize, Deserialize)]
pub struct SignerPublicKeyResponse {
    /// The signer's public key in hex format
    pub public_key: String,
    /// The signer's address
    pub signer_address: String,
}

/// Inference result response
#[derive(Serialize, Deserialize)]
pub struct InferenceResultResponse {
    /// Task ID
    pub task_id: String,
    /// Inference output
    pub output: String,
    /// Inference confidence
    pub confidence: f64,
    /// Inference node ID
    pub inference_node_id: String,
}

/// Task status response
#[derive(Serialize, Deserialize)]
pub struct TaskStatusResponse {
    /// Task ID
    pub task_id: String,
    /// User input
    pub user_input: String,
    /// Context information
    pub context: String,
    /// Model name
    pub model_name: String,
    /// Maximum inference time
    pub max_infer_time: u64,
    /// Inference fee
    pub infer_fee: u64,
    /// Creation time
    pub created_at: u64,
    /// Task status
    pub status: String,
    /// Inference result (if completed)
    pub result: Option<TaskResultData>,
    /// Transaction ID (hash of the signed transaction)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
}

/// Task result data (returned when task is completed)
#[derive(Serialize, Deserialize)]
pub struct TaskResultData {
    /// Inference output
    pub output: String,
    /// Inference confidence
    pub confidence: f64,
    /// Completion time
    pub completed_at: u64,
    /// Inference node ID
    pub inference_node_id: String,
}

/// Authenticated task status query request
#[derive(Serialize, Deserialize)]
pub struct AuthenticatedTaskStatusRequest {
    /// Task ID to query
    pub task_id: String,
    /// User's public key (hex-encoded, compressed format)
    pub public_key: String,
    /// Signature of the message: "query_task:{task_id}:{timestamp}"
    /// This proves the requester controls the private key corresponding to user_address
    pub signature: String,
    /// Unix timestamp (in seconds) when signature was created
    /// Request is valid for 5 minutes from this timestamp
    pub timestamp: u64,
}

/// Heartbeat request from inference node
#[derive(Deserialize)]
pub struct HeartbeatRequest {
    /// Node ID
    pub node_id: String,
    /// Node status
    pub status: String,
}

/// Complete task request from inference node
#[derive(Deserialize)]
pub struct CompleteTaskRequest {
    /// Task ID
    pub task_id: String,
    /// Inference output
    pub output: String,
    /// Inference confidence
    pub confidence: f64,
    /// Inference node ID
    pub inference_node_id: String,
}

/// Response for get task API
#[derive(Serialize)]
pub struct GetTaskResponse {
    /// Task ID
    pub task_id: String,
    /// User input
    pub user_input: String,
    /// Context information
    pub context: String,
    /// Model name
    pub model_name: String,
    /// Maximum inference time
    pub max_infer_time: u64,
    /// Inference fee
    pub infer_fee: u64,
    /// Signed transaction hex
    pub signed_tx: Option<String>,
}

/// HTTP API server
pub struct InferenceApiServer {
    shared_state: Arc<Mutex<InferenceServiceState>>,
    event_sender: mpsc::Sender<InferenceServiceEvent>,
}

impl InferenceApiServer {
    /// Create a new API server
    pub fn new(
        shared_state: Arc<Mutex<InferenceServiceState>>,
        event_sender: mpsc::Sender<InferenceServiceEvent>,
    ) -> Self {
        Self {
            shared_state,
            event_sender,
        }
    }

    /// Start the HTTP server
    pub async fn start(&self, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = ([127, 0, 0, 1], port).into();
        
        let service = Arc::new(self.clone());
        
        let make_svc = make_service_fn(move |_conn| {
            let service = Arc::clone(&service);
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let service = Arc::clone(&service);
                    async move { service.handle_request(req).await }
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);
        info!("Inference API server running on http://{}", addr);

        if let Err(e) = server.await {
            error!("Server error: {}", e);
        }

        Ok(())
    }

    /// Handle HTTP requests
    async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let method = req.method();
        let path = req.uri().path();

        debug!("Received {} request to {}", method, path);

        let response = match (method, path) {
            // Inference node registration
            (&Method::POST, "/api/v1/nodes/register") => {
                self.handle_register_node(req).await
            }
            // User submit inference task
            (&Method::POST, "/api/v1/tasks/submit") => {
                self.handle_submit_task(req).await
            }
            // Inference node heartbeat
            (&Method::POST, "/api/v1/nodes/heartbeat") => {
                self.handle_heartbeat(req).await
            }
            // Inference node fetch task (POST with signature authentication)
            (&Method::POST, "/api/v1/nodes/tasks") => {
                self.handle_get_task(req).await
            }
            // Inference node complete task
            (&Method::POST, "/api/v1/tasks/complete") => {
                self.handle_complete_task(req).await
            }
            // User query task status (authenticated - POST with signature)
            (&Method::POST, "/api/v1/tasks/status") => {
                self.handle_authenticated_task_status(req).await
            }
            // Internal task status query (for Miner/internal use only - no auth)
            // Note: In production, this should be restricted to internal IPs or removed
            (&Method::GET, path) if path.starts_with("/api/v1/internal/tasks/") && path.contains("/status") => {
                let task_id = self.extract_task_id_from_path(path);
                self.handle_get_task_status_internal(task_id).await
            }
            // Get service statistics
            (&Method::GET, "/api/v1/stats") => {
                self.handle_get_statistics().await
            }
            // Get all node statuses
            (&Method::GET, "/api/v1/nodes") => {
                self.handle_get_nodes().await
            }
            // Get signer's public key for encryption
            (&Method::GET, "/api/v1/encryption/public-key") => {
                self.handle_get_public_key().await
            }
            // Request decryption of inference input (for Infer Nodes and other Signers)
            (&Method::POST, "/api/v1/encryption/decrypt") => {
                self.handle_decrypt_input(req).await
            }
            // Health check
            (&Method::GET, "/health") => {
                self.handle_health_check().await
            }
            _ => {
                self.not_found().await
            }
        };

        Ok(response)
    }

    /// Handle inference node registration
    async fn handle_register_node(&self, req: Request<Body>) -> Response<Body> {
        match self.parse_json_body::<RegisterNodeRequest>(req).await {
            Ok(request) => {
                let node = InferenceNode {
                    node_id: request.node_id.clone(),
                    endpoint: request.endpoint,
                    public_key: request.public_key,
                    status: NodeStatus::Online,
                    supported_models: request.supported_models.into_iter()
                        .map(|model| self.parse_model_type(&model))
                        .collect(),
                    performance_score: request.performance_score.unwrap_or(1.0),
                    last_heartbeat: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let result = {
                    let service = self.shared_state.lock().unwrap();
                    service.register_inference_node(node)
                };

                match result {
                    Ok(()) => {
                        info!("Node {} registered successfully", request.node_id);
                        self.json_response(ApiResponse::success("Node registered successfully".to_string()), StatusCode::OK)
                    }
                    Err(e) => {
                        error!("Failed to register node {}: {}", request.node_id, e);
                        self.json_response(ApiResponse::<String>::error(e), StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse register node request: {}", e);
                self.json_response(ApiResponse::<String>::error(e), StatusCode::BAD_REQUEST)
            }
        }
    }

    /// Handle user task submission
    async fn handle_submit_task(&self, req: Request<Body>) -> Response<Body> {
        match self.parse_json_body::<SubmitTaskRequest>(req).await {
            Ok(request) => {
                // Verify signed_tx
                let signed_tx_hex = match request.signed_tx {
                    Some(ref tx) => tx,
                    None => {
                        return self.json_response(
                            ApiResponse::<String>::error("Missing signed_tx".to_string()),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                };

                let tx_bytes = match hex_bytes(signed_tx_hex) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return self.json_response(
                            ApiResponse::<String>::error(format!("Invalid signed_tx hex: {}", e)),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                };

                let mut cursor = Cursor::new(&tx_bytes);
                let tx: FunaiTransaction = match FunaiTransaction::consensus_deserialize(&mut cursor) {
                    Ok(tx) => tx,
                    Err(e) => {
                        return self.json_response(
                            ApiResponse::<String>::error(format!("Failed to deserialize transaction: {}", e)),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                };

                if let Err(e) = tx.verify() {
                    return self.json_response(
                        ApiResponse::<String>::error(format!("Invalid transaction signature: {:?}", e)),
                        StatusCode::BAD_REQUEST,
                    );
                }

                let origin = tx.auth.origin();
                let origin_address = tx.origin_address().to_string();
                if origin_address != request.user_address {
                    return self.json_response(
                        ApiResponse::<String>::error(format!(
                            "Address mismatch: expected {}, got {}",
                            request.user_address, origin_address
                        )),
                        StatusCode::UNAUTHORIZED,
                    );
                }

                if let Some(nonce) = request.nonce {
                    if origin.nonce() != nonce {
                        return self.json_response(
                            ApiResponse::<String>::error(format!(
                                "Nonce mismatch: expected {}, got {}",
                                nonce,
                                origin.nonce()
                            )),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                }

                let task_id = request.task_id.unwrap_or_else(|| {
                    format!("api-{}", uuid::Uuid::new_v4().to_string())
                });

                // Create task based on whether it's encrypted or not
                let task = if request.is_encrypted {
                    // For encrypted tasks:
                    // - user_input contains the encrypted JSON data
                    // - we store it in encrypted_user_input for decryption later
                    // - user_input field stores "[encrypted]" placeholder
                    let signer_pubkey = request.signer_public_key.unwrap_or_else(|| {
                        // Get signer's public key from state
                        let service = self.shared_state.lock().unwrap();
                        service.signer_public_key_hex.clone().unwrap_or_default()
                    });
                    
                    info!("Creating encrypted task {}", task_id);
                    InferTask::new_encrypted(
                        task_id.clone(),
                        request.user_address,
                        "[encrypted]".to_string(), // Placeholder for user_input
                        request.user_input,        // Encrypted data goes to encrypted_user_input
                        "[encrypted]".to_string(), // Placeholder for context
                        request.context,           // Encrypted data goes to encrypted_context
                        request.fee.unwrap_or(0),
                        request.nonce.unwrap_or(origin.nonce()),
                        request.infer_fee,
                        request.max_infer_time,
                        self.parse_model_type(&request.model_name),
                        request.signed_tx,
                        signer_pubkey,
                    )
                } else {
                    InferTask::new(
                        task_id.clone(),
                        request.user_address,
                        request.user_input,
                        request.context,
                        request.fee.unwrap_or(0),
                        request.nonce.unwrap_or(origin.nonce()),
                        request.infer_fee,
                        request.max_infer_time,
                        self.parse_model_type(&request.model_name),
                        request.signed_tx,
                    )
                };

                let is_encrypted = request.is_encrypted;
                let result = {
                    let service = self.shared_state.lock().unwrap();
                    service.submit_task(task)
                };

                match result {
                    Ok(()) => {
                        // Notify via event sender
                        if let Err(e) = self.event_sender.send(InferenceServiceEvent::TaskSubmitted(task_id.clone())).await {
                            error!("Failed to send task submitted event: {}", e);
                        }

                        info!("Task {} submitted via API successfully (encrypted: {})", task_id, is_encrypted);
                        
                        if is_encrypted {
                            self.json_response(ApiResponse::success(json!({ 
                                "task_id": task_id,
                                "encrypted": true,
                                "message": "Inference task submitted with end-to-end encryption"
                            })), StatusCode::OK)
                        } else {
                            self.json_response(ApiResponse::success(json!({ "task_id": task_id })), StatusCode::OK)
                        }
                    }
                    Err(e) => {
                        error!("Failed to submit task {}: {}", task_id, e);
                        self.json_response(ApiResponse::<String>::error(e), StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse submit task request: {}", e);
                self.json_response(ApiResponse::<String>::error(e), StatusCode::BAD_REQUEST)
            }
        }
    }

    /// Handle inference node heartbeat
    async fn handle_heartbeat(&self, req: Request<Body>) -> Response<Body> {
        match self.parse_json_body::<HeartbeatRequest>(req).await {
            Ok(request) => {
                let status = match request.status.as_str() {
                    "online" => NodeStatus::Online,
                    "offline" => NodeStatus::Offline,
                    "busy" => NodeStatus::Busy,
                    "maintenance" => NodeStatus::Maintenance,
                    _ => NodeStatus::Online,
                };

                let result = {
                    let service = self.shared_state.lock().unwrap();
                    service.update_node_status(&request.node_id, status)
                };

                match result {
                    Ok(()) => {
                        debug!("Heartbeat received from node {}", request.node_id);
                        self.json_response(ApiResponse::success("Heartbeat received".to_string()), StatusCode::OK)
                    }
                    Err(e) => {
                        error!("Failed to update node status for {}: {}", request.node_id, e);
                        self.json_response(ApiResponse::<String>::error(e), StatusCode::NOT_FOUND)
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse heartbeat request: {}", e);
                self.json_response(ApiResponse::<String>::error(e), StatusCode::BAD_REQUEST)
            }
        }
    }

    /// Handle inference node fetch task (with signature authentication)
    async fn handle_get_task(&self, req: Request<Body>) -> Response<Body> {
        // Parse request body
        let request: GetTaskRequest = match self.parse_json_body(req).await {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to parse get task request: {}", e);
                return self.json_response(
                    ApiResponse::<String>::error(e),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        let node_id = request.node_id.clone();

        // Validate timestamp (must be within 5 minutes)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if current_time.abs_diff(request.timestamp) > 300 {
            return self.json_response(
                ApiResponse::<String>::error("Request timestamp expired (must be within 5 minutes)".to_string()),
                StatusCode::BAD_REQUEST,
            );
        }

        // Get node's registered public key for signature verification
        let node_public_key_hex = {
            let service = self.shared_state.lock().unwrap();
            let nodes = service.inference_nodes.lock().unwrap();
            if let Some(node) = nodes.get(&node_id) {
                Some(node.public_key.clone())
            } else {
                None
            }
        };

        let node_public_key_hex = match node_public_key_hex {
            Some(pk) => pk,
            None => {
                warn!("Node {} not registered, cannot fetch tasks", node_id);
                return self.json_response(
                    ApiResponse::<String>::error(format!("Node {} not registered", node_id)),
                    StatusCode::FORBIDDEN,
                );
            }
        };

        // Verify signature
        // Message format: "GET_TASK:{node_id}:{timestamp}"
        let message = format!("GET_TASK:{}:{}", node_id, request.timestamp);
        let message_hash = {
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            hasher.finalize()
        };

        // Parse signature (expect 65-byte RSV format or 64-byte compact)
        let signature_bytes = match hex_bytes(&request.signature) {
            Ok(bytes) => bytes,
            Err(e) => {
                return self.json_response(
                    ApiResponse::<String>::error(format!("Invalid signature hex: {}", e)),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        // Verify signature using secp256k1
        let secp = secp256k1::Secp256k1::verification_only();
        let message = match secp256k1::Message::from_slice(&message_hash) {
            Ok(m) => m,
            Err(e) => {
                return self.json_response(
                    ApiResponse::<String>::error(format!("Invalid message hash: {}", e)),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        // Parse the registered public key
        let expected_pubkey_bytes = match hex_bytes(&node_public_key_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return self.json_response(
                    ApiResponse::<String>::error(format!("Invalid registered public key: {}", e)),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };

        let expected_pubkey = match secp256k1::PublicKey::from_slice(&expected_pubkey_bytes) {
            Ok(pk) => pk,
            Err(e) => {
                return self.json_response(
                    ApiResponse::<String>::error(format!("Invalid registered public key format: {}", e)),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };

        // Parse signature (handle both 65-byte RSV and 64-byte compact formats)
        let signature = if signature_bytes.len() == 65 {
            // RSV format: take first 64 bytes (R+S)
            match secp256k1::ecdsa::Signature::from_compact(&signature_bytes[..64]) {
                Ok(sig) => sig,
                Err(e) => {
                    return self.json_response(
                        ApiResponse::<String>::error(format!("Invalid signature format: {}", e)),
                        StatusCode::BAD_REQUEST,
                    );
                }
            }
        } else if signature_bytes.len() == 64 {
            match secp256k1::ecdsa::Signature::from_compact(&signature_bytes) {
                Ok(sig) => sig,
                Err(e) => {
                    return self.json_response(
                        ApiResponse::<String>::error(format!("Invalid signature format: {}", e)),
                        StatusCode::BAD_REQUEST,
                    );
                }
            }
        } else {
            return self.json_response(
                ApiResponse::<String>::error(format!("Invalid signature length: {} (expected 64 or 65)", signature_bytes.len())),
                StatusCode::BAD_REQUEST,
            );
        };

        // Verify the signature matches the registered public key
        if secp.verify_ecdsa(&message, &signature, &expected_pubkey).is_err() {
            warn!("Signature verification failed for node {}", node_id);
            return self.json_response(
                ApiResponse::<String>::error("Signature verification failed".to_string()),
                StatusCode::FORBIDDEN,
            );
        }

        info!("Node {} authenticated successfully", node_id);

        // Get tasks that this node can process
        let (task, node_pk_opt) = {
            let service = self.shared_state.lock().unwrap();
            
            // 1. Get supported models for the node
            let (supported_models, node_pk) = {
                let nodes = service.inference_nodes.lock().unwrap();
                if let Some(node) = nodes.get(&node_id) {
                    (node.supported_models.clone(), Some(node.public_key.clone()))
                } else {
                    (Vec::new(), None)
                }
            };

            if supported_models.is_empty() {
                (None, node_pk)
            } else {
                // 2. Find a suitable pending task
                let mut found_task_id = None;
                {
                    let pending = service.pending_tasks.lock().unwrap();
                    for (id, task) in pending.iter() {
                        // Check if the node supports the task's model type
                        if supported_models.contains(&task.model_type) {
                            found_task_id = Some(id.clone());
                            break;
                        }
                    }
                }

                // 3. Move task from pending to processing
                if let Some(task_id) = found_task_id {
                    let mut pending = service.pending_tasks.lock().unwrap();
                    if let Some(mut task) = pending.remove(&task_id) {
                        task.update_status(InferTaskStatus::InProgress);
                        
                        let mut processing = service.processing_tasks.lock().unwrap();
                        processing.insert(task_id.clone(), task.clone());
                        
                        // Save to database
                        if let Ok(db) = service.database.lock() {
                            if let Err(e) = db.save_task(&task) {
                                error!("Failed to save task to database: {}", e);
                            }
                        }
                        
                        (Some(task), node_pk)
                    } else {
                        (None, node_pk)
                    }
                } else {
                    (None, node_pk)
                }
            }
        };

        match task {
            Some(task) => {
                // If the task has a signed_tx, we need to inject the node_id into the payload
                // This is allowed because the txid calculation for Infer transactions masks the node_principal
                // so the signature remains valid even after we modify the node_principal
                let signed_tx = if let Some(signed_tx_hex) = task.signed_tx {
                    match hex_bytes(&signed_tx_hex) {
                        Ok(tx_bytes) => {
                            let mut cursor = Cursor::new(&tx_bytes);
                            match FunaiTransaction::consensus_deserialize(&mut cursor) {
                                Ok(mut tx) => {
                                    if let TransactionPayload::Infer(from, amount, input, context, _, model, output_hash) = tx.payload {
                                        // Try to get principal from node_id or fallback to deriving from public key
                                        let node_principal = match PrincipalData::parse(&node_id) {
                                            Ok(p) => p,
                                            Err(_) => {
                                                // Fallback: use the node's public key from registry
                                                if let Some(pk_hex) = node_pk_opt {
                                                    match FunaiPublicKey::from_hex(&pk_hex) {
                                                        Ok(pk) => {
                                                            let is_mainnet = tx.version == TransactionVersion::Mainnet;
                                                            let addr = FunaiAddress::p2pkh(
                                                                is_mainnet,
                                                                &pk,
                                                            );
                                                            addr.to_account_principal()
                                                        }
                                                        Err(e) => {
                                                            error!("Invalid public key in registry for node {}: {}", node_id, e);
                                                            return self.json_response(
                                                                ApiResponse::<String>::error(format!("Invalid public key for node")),
                                                                StatusCode::INTERNAL_SERVER_ERROR,
                                                            );
                                                        }
                                                    }
                                                } else {
                                                    error!("Node {} not found in registry and ID is not a valid principal", node_id);
                                                    return self.json_response(
                                                        ApiResponse::<String>::error(format!("Node {} not registered", node_id)),
                                                        StatusCode::NOT_FOUND,
                                                    );
                                                }
                                            }
                                        };
                                        
                                        // Modify payload with actual node principal
                                        tx.payload = TransactionPayload::Infer(
                                            from,
                                            amount,
                                            input,
                                            context,
                                            node_principal,
                                            model,
                                            output_hash,
                                        );
                                        
                                        // Re-serialize
                                        let mut new_bytes: Vec<u8> = Vec::new();
                                        if let Err(e) = tx.consensus_serialize(&mut new_bytes) {
                                            error!("Failed to re-serialize transaction: {}", e);
                                            Some(signed_tx_hex)
                                        } else {
                                            Some(hex::encode(new_bytes))
                                        }
                                    } else {
                                        Some(signed_tx_hex)
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to deserialize transaction for node injection: {}", e);
                                    Some(signed_tx_hex)
                                }
                            }
                        }
                        Err(e) => {
                            error!("Invalid hex in stored transaction: {}", e);
                            Some(signed_tx_hex)
                        }
                    }
                } else {
                    None
                };

                // For registered Infer Nodes, decrypt the input directly
                // No need for a separate decryption request
                let decrypted_user_input = if task.is_encrypted {
                    info!("Task {} is encrypted, attempting decryption", task.task_id);
                    // Task is encrypted, need to decrypt
                    if let Some(ref encrypted_input) = task.encrypted_user_input {
                        info!("Found encrypted_user_input, length: {}", encrypted_input.len());
                        match crate::encryption::EncryptedData::from_json(encrypted_input) {
                            Ok(encrypted_data) => {
                                info!("Parsed encrypted data successfully");
                                info!("  - signer_public_key: {}", encrypted_data.signer_public_key);
                                info!("  - ephemeral_public_key: {}", encrypted_data.ephemeral_public_key);
                                info!("  - nonce: {}", encrypted_data.nonce);
                                info!("  - ciphertext length: {}", encrypted_data.ciphertext.len());
                                
                                // Get signer's private key to decrypt
                                let (signer_key, signer_pub) = {
                                    let service = self.shared_state.lock().unwrap();
                                    (service.signer_private_key.clone(), service.signer_public_key_hex.clone())
                                };
                                
                                info!("Signer public key from state: {:?}", signer_pub);
                                
                                match signer_key {
                                    Some(key) => {
                                        info!("Attempting decryption with signer key...");
                                        match crate::encryption::InferenceEncryption::decrypt(&encrypted_data, &key) {
                                            Ok(plaintext) => {
                                                info!("Decryption successful! Plaintext length: {}", plaintext.len());
                                                plaintext
                                            }
                                            Err(e) => {
                                                error!("Failed to decrypt task input: {}", e);
                                                // Fallback to stored user_input
                                                task.user_input.clone()
                                            }
                                        }
                                    }
                                    None => {
                                        warn!("Signer key not set, returning stored user_input");
                                        task.user_input.clone()
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to parse encrypted data: {}", e);
                                error!("Raw encrypted input: {}", encrypted_input);
                                task.user_input.clone()
                            }
                        }
                    } else {
                        // Encrypted flag is true but no encrypted data, use plain text
                        warn!("Task is_encrypted=true but encrypted_user_input is None!");
                        task.user_input.clone()
                    }
                } else {
                    // Task is not encrypted, use plain text directly
                    task.user_input.clone()
                };

                let response = GetTaskResponse {
                    task_id: task.task_id,
                    user_input: decrypted_user_input, // Return decrypted plaintext
                    context: task.context,
                    model_name: format!("{:?}", task.model_type),
                    max_infer_time: task.max_infer_time,
                    infer_fee: task.infer_fee,
                    signed_tx: signed_tx,
                };
                
                info!("Assigned task {} to node {} (input decrypted: {})", 
                    response.task_id, node_id, task.is_encrypted);
                self.json_response(ApiResponse::success(response), StatusCode::OK)
            }
            None => {
                debug!("No available tasks for node {}", node_id);
                self.json_response(
                    ApiResponse::<String>::error("No available tasks".to_string()),
                    StatusCode::NO_CONTENT,
                )
            }
        }
    }

    /// Handle inference node complete task
    async fn handle_complete_task(&self, req: Request<Body>) -> Response<Body> {
        match self.parse_json_body::<CompleteTaskRequest>(req).await {
            Ok(request) => {
                let result = InferTaskResult {
                    output: request.output,
                    confidence: request.confidence,
                    completed_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    inference_node_id: request.inference_node_id,
                };

                let complete_result = {
                    let service = self.shared_state.lock().unwrap();
                    service.complete_task(&request.task_id, result)
                };

                match complete_result {
                    Ok(()) => {
                        info!("Task {} completed successfully", request.task_id);
                        self.json_response(ApiResponse::success("Task completed".to_string()), StatusCode::OK)
                    }
                    Err(e) => {
                        error!("Failed to complete task {}: {}", request.task_id, e);
                        self.json_response(ApiResponse::<String>::error(e), StatusCode::NOT_FOUND)
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse complete task request: {}", e);
                self.json_response(ApiResponse::<String>::error(e), StatusCode::BAD_REQUEST)
            }
        }
    }

    /// Handle authenticated task status query (for users)
    /// Requires signature proof that the requester owns the user_address
    async fn handle_authenticated_task_status(&self, req: Request<Body>) -> Response<Body> {
        let auth_request: AuthenticatedTaskStatusRequest = match self.parse_json_body(req).await {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to parse authenticated task status request: {}", e);
                return self.json_response(
                    ApiResponse::<String>::error(format!("Invalid request format: {}", e)),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        // Validate timestamp (request must be within 5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let time_diff = if now > auth_request.timestamp {
            now - auth_request.timestamp
        } else {
            auth_request.timestamp - now
        };
        
        if time_diff > 300 {
            warn!("Task status request expired: timestamp {} vs now {}", auth_request.timestamp, now);
            return self.json_response(
                ApiResponse::<String>::error("Request expired. Timestamp must be within 5 minutes.".to_string()),
                StatusCode::UNAUTHORIZED,
            );
        }

        // Get the task first to check if it exists and get the user_address
        let task = {
            let service = self.shared_state.lock().unwrap();
            service.get_task_status(&auth_request.task_id)
        };

        let task = match task {
            Some(t) => t,
            None => {
                warn!("Task {} not found", auth_request.task_id);
                return self.json_response(
                    ApiResponse::<String>::error("Task not found".to_string()),
                    StatusCode::NOT_FOUND,
                );
            }
        };

        // Verify the signature
        // Message format: "query_task:{task_id}:{timestamp}"
        let message = format!("query_task:{}:{}", auth_request.task_id, auth_request.timestamp);
        let message_hash = {
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            hasher.finalize()
        };

        // Parse the public key
        let public_key = match FunaiPublicKey::from_hex(&auth_request.public_key) {
            Ok(pk) => pk,
            Err(e) => {
                error!("Invalid public key format: {}", e);
                return self.json_response(
                    ApiResponse::<String>::error("Invalid public key format".to_string()),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        // Parse the signature (remove 0x prefix if present)
        let sig_hex = auth_request.signature.strip_prefix("0x")
            .unwrap_or(&auth_request.signature);
        let signature_bytes = match hex_bytes(sig_hex) {
            Ok(s) => s,
            Err(e) => {
                error!("Invalid signature hex format: {}", e);
                return self.json_response(
                    ApiResponse::<String>::error("Invalid signature format".to_string()),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        // Verify the signature using secp256k1
        use secp256k1::{Secp256k1, Message, ecdsa::Signature as EcdsaSignature, PublicKey as Secp256k1PubKey};
        
        let secp = Secp256k1::verification_only();
        
        let msg = match Message::from_slice(&message_hash) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to create message from hash: {}", e);
                return self.json_response(
                    ApiResponse::<String>::error("Internal error".to_string()),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };

        // Handle different signature formats:
        // - RSV format (65 bytes): R (32) + S (32) + V (1) - from SDK signMessageHashRsv
        // - Compact format (64 bytes): R (32) + S (32)
        // - DER format (variable length)
        let compact_bytes = if signature_bytes.len() == 65 {
            // RSV format: extract R+S (first 64 bytes), ignore V (recovery byte)
            debug!("Parsing RSV format signature (65 bytes)");
            signature_bytes[0..64].to_vec()
        } else {
            signature_bytes.clone()
        };

        let sig = match EcdsaSignature::from_compact(&compact_bytes) {
            Ok(s) => s,
            Err(_) => {
                // Try DER format with original bytes
                match EcdsaSignature::from_der(&signature_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Invalid signature (tried compact and DER): {}", e);
                        return self.json_response(
                            ApiResponse::<String>::error("Invalid signature format".to_string()),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                }
            }
        };

        let pk = match Secp256k1PubKey::from_slice(&public_key.to_bytes_compressed()) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to parse public key: {}", e);
                return self.json_response(
                    ApiResponse::<String>::error("Invalid public key".to_string()),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        // Verify signature
        if secp.verify_ecdsa(&msg, &sig, &pk).is_err() {
            warn!("Signature verification failed for task {}", auth_request.task_id);
            return self.json_response(
                ApiResponse::<String>::error("Signature verification failed".to_string()),
                StatusCode::UNAUTHORIZED,
            );
        }

        // Derive address from the public key and compare with task's user_address
        let derived_address_mainnet = FunaiAddress::from_public_keys(
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![public_key.clone()],
        );
        let derived_address_testnet = FunaiAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![public_key.clone()],
        );
        
        let mainnet_matches = derived_address_mainnet
            .as_ref()
            .map(|a| a.to_string() == task.user_address)
            .unwrap_or(false);
        let testnet_matches = derived_address_testnet
            .as_ref()
            .map(|a| a.to_string() == task.user_address)
            .unwrap_or(false);
            
        if !mainnet_matches && !testnet_matches {
            let mainnet_str = derived_address_mainnet.map(|a| a.to_string()).unwrap_or_default();
            let testnet_str = derived_address_testnet.map(|a| a.to_string()).unwrap_or_default();
            warn!(
                "Address mismatch: task owner {} vs requester {} / {}",
                task.user_address, mainnet_str, testnet_str
            );
            return self.json_response(
                ApiResponse::<String>::error("Unauthorized: you are not the owner of this task".to_string()),
                StatusCode::FORBIDDEN,
            );
        }

        info!("Authenticated status query for task {} by {}", auth_request.task_id, task.user_address);

        // For encrypted tasks, decrypt the user_input and context for display
        let (display_user_input, display_context) = if task.is_encrypted {
            let signer_key = {
                let service = self.shared_state.lock().unwrap();
                service.signer_private_key.clone()
            };
            
            let decrypted_input = if let (Some(ref encrypted_input), Some(ref key)) = (&task.encrypted_user_input, &signer_key) {
                match crate::encryption::EncryptedData::from_json(encrypted_input) {
                    Ok(encrypted_data) => {
                        match crate::encryption::InferenceEncryption::decrypt(&encrypted_data, key) {
                            Ok(plaintext) => plaintext,
                            Err(e) => {
                                warn!("Failed to decrypt user_input for display: {}", e);
                                task.user_input.clone()
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse encrypted user_input: {}", e);
                        task.user_input.clone()
                    }
                }
            } else {
                task.user_input.clone()
            };
            
            let decrypted_context = if let (Some(ref encrypted_ctx), Some(ref key)) = (&task.encrypted_context, &signer_key) {
                match crate::encryption::EncryptedData::from_json(encrypted_ctx) {
                    Ok(encrypted_data) => {
                        match crate::encryption::InferenceEncryption::decrypt(&encrypted_data, key) {
                            Ok(plaintext) => plaintext,
                            Err(e) => {
                                warn!("Failed to decrypt context for display: {}", e);
                                task.context.clone()
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse encrypted context: {}", e);
                        task.context.clone()
                    }
                }
            } else {
                task.context.clone()
            };
            
            (decrypted_input, decrypted_context)
        } else {
            (task.user_input.clone(), task.context.clone())
        };

        // Return task status
        let result_data = task.result.as_ref().map(|r| TaskResultData {
            output: r.output.clone(),
            confidence: r.confidence,
            completed_at: r.completed_at,
            inference_node_id: r.inference_node_id.clone(),
        });

        // Calculate txid from signed_tx (SHA256 hash of the transaction bytes)
        let txid = task.signed_tx.as_ref().and_then(|tx_hex| {
            Self::calculate_txid(tx_hex)
        });

        let response = TaskStatusResponse {
            task_id: task.task_id.clone(),
            user_input: display_user_input,
            context: display_context,
            model_name: format!("{:?}", task.model_type),
            max_infer_time: task.max_infer_time,
            infer_fee: task.infer_fee,
            created_at: task.created_at,
            status: task.status.to_string(),
            result: result_data,
            txid,
        };

        self.json_response(ApiResponse::success(response), StatusCode::OK)
    }

    /// Handle get task status (internal use only - no authentication)
    /// This is for Miner and internal services that need to query task status
    async fn handle_get_task_status_internal(&self, task_id: Option<String>) -> Response<Body> {
        let task_id = match task_id {
            Some(id) => id,
            None => {
                return self.json_response(
                    ApiResponse::<String>::error("Invalid task ID".to_string()),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        let task = {
            let service = self.shared_state.lock().unwrap();
            service.get_task_status(&task_id)
        };

        match task {
            Some(task) => {
                info!("Retrieved internal status for task {}: {:?}", task_id, task.status);
                
                // Convert result if present
                let result_data = task.result.as_ref().map(|r| TaskResultData {
                    output: r.output.clone(),
                    confidence: r.confidence,
                    completed_at: r.completed_at,
                    inference_node_id: r.inference_node_id.clone(),
                });

                // Calculate txid from signed_tx
                let txid = task.signed_tx.as_ref().and_then(|tx_hex| {
                    Self::calculate_txid(tx_hex)
                });

                let response = TaskStatusResponse {
                    task_id: task.task_id.clone(),
                    user_input: task.user_input.clone(),
                    context: task.context.clone(),
                    model_name: format!("{:?}", task.model_type),
                    max_infer_time: task.max_infer_time,
                    infer_fee: task.infer_fee,
                    created_at: task.created_at,
                    status: task.status.to_string(),
                    result: result_data,
                    txid,
                };
                self.json_response(ApiResponse::success(response), StatusCode::OK)
            }
            None => {
                warn!("Task {} not found", task_id);
                self.json_response(
                    ApiResponse::<String>::error("Task not found".to_string()),
                    StatusCode::NOT_FOUND,
                )
            }
        }
    }

    /// Handle get statistics
    async fn handle_get_statistics(&self) -> Response<Body> {
        let stats = {
            let service = self.shared_state.lock().unwrap();
            service.get_task_statistics()
        };

        self.json_response(ApiResponse::success(stats), StatusCode::OK)
    }

    /// Handle get nodes
    async fn handle_get_nodes(&self) -> Response<Body> {
        let nodes = {
            let service = self.shared_state.lock().unwrap();
            service.get_node_status()
        };

        self.json_response(ApiResponse::success(nodes), StatusCode::OK)
    }

    /// Handle get public key request - returns the signer's public key for encryption
    async fn handle_get_public_key(&self) -> Response<Body> {
        let (public_key, signer_address) = {
            let service = self.shared_state.lock().unwrap();
            service.get_encryption_public_key()
        };

        let response = SignerPublicKeyResponse {
            public_key,
            signer_address,
        };

        self.json_response(ApiResponse::success(response), StatusCode::OK)
    }

    /// Handle decrypt input request - decrypts inference input for authorized requesters
    async fn handle_decrypt_input(&self, req: Request<Body>) -> Response<Body> {
        match self.parse_json_body::<DecryptInputRequest>(req).await {
            Ok(request) => {
                // Validate the request
                if request.task_id.is_empty() {
                    return self.json_response(
                        ApiResponse::<DecryptInputResponse>::error("Task ID is required".to_string()),
                        StatusCode::BAD_REQUEST,
                    );
                }

                // Attempt to decrypt
                let result = {
                    let service = self.shared_state.lock().unwrap();
                    service.decrypt_task_input(
                        &request.task_id,
                        &request.requester_public_key,
                        &request.signature,
                        &request.requester_type,
                    )
                };

                match result {
                    Ok((user_input, context)) => {
                        let response = DecryptInputResponse {
                            task_id: request.task_id,
                            user_input: Some(user_input),
                            context: Some(context),
                            success: true,
                            error: None,
                        };
                        info!("Successfully decrypted input for task");
                        self.json_response(ApiResponse::success(response), StatusCode::OK)
                    }
                    Err(e) => {
                        warn!("Failed to decrypt input: {}", e);
                        let response = DecryptInputResponse {
                            task_id: request.task_id,
                            user_input: None,
                            context: None,
                            success: false,
                            error: Some(e),
                        };
                        self.json_response(ApiResponse::success(response), StatusCode::OK)
                    }
                }
            }
            Err(e) => {
                self.json_response(
                    ApiResponse::<DecryptInputResponse>::error(format!("Invalid request: {}", e)),
                    StatusCode::BAD_REQUEST,
                )
            }
        }
    }

    /// Handle health check
    async fn handle_health_check(&self) -> Response<Body> {
        let health_status = json!({
            "status": "healthy",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        self.json_response(ApiResponse::success(health_status), StatusCode::OK)
    }

    /// 404 response
    async fn not_found(&self) -> Response<Body> {
        self.json_response(
            ApiResponse::<String>::error("Not found".to_string()),
            StatusCode::NOT_FOUND,
        )
    }

    /// Parse JSON request body
    async fn parse_json_body<T: for<'de> Deserialize<'de>>(&self, req: Request<Body>) -> Result<T, String> {
        let body_bytes = hyper::body::to_bytes(req.into_body())
            .await
            .map_err(|e| format!("Failed to read request body: {}", e))?;

        serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("Failed to parse JSON: {}", e))
    }

    /// Calculate transaction ID (txid) from signed transaction hex
    /// The txid is the SHA-512/256 hash of the serialized transaction
    /// For Infer transactions, the node_principal and output_hash are zeroed out before hashing
    fn calculate_txid(signed_tx_hex: &str) -> Option<String> {
        use funai_common::util::hash::hex_bytes;
        use funailib::chainstate::funai::FunaiTransaction;
        use funailib::codec::FunaiMessageCodec;
        
        // Parse the hex string to bytes
        let tx_bytes = match hex_bytes(signed_tx_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to parse signed_tx hex: {}", e);
                return None;
            }
        };
        
        // Deserialize the transaction
        let tx = match FunaiTransaction::consensus_deserialize(&mut &tx_bytes[..]) {
            Ok(tx) => tx,
            Err(e) => {
                warn!("Failed to deserialize transaction: {:?}", e);
                return None;
            }
        };
        
        // Calculate txid using the transaction's txid() method
        // This handles Infer transactions correctly (zeroing node_principal and output_hash)
        let txid = tx.txid();
        
        // Return as 0x-prefixed hex string
        Some(format!("0x{}", txid))
    }

    /// Create JSON response
    fn json_response<T: Serialize>(&self, data: T, status: StatusCode) -> Response<Body> {
        let json = match serde_json::to_string(&data) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize response: {}", e);
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal server error"))
                    .unwrap();
            }
        };

        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(json))
            .unwrap()
    }

    /// Extract node ID from path
    fn extract_node_id_from_path(&self, path: &str) -> Option<String> {
        // Path format: /api/v1/nodes/{node_id}/tasks
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 5 && parts[1] == "api" && parts[2] == "v1" && parts[3] == "nodes" {
            Some(parts[4].to_string())
        } else {
            None
        }
    }

    /// Extract task ID from path
    fn extract_task_id_from_path(&self, path: &str) -> Option<String> {
        // Path format: /api/v1/internal/tasks/{task_id}/status
        // or legacy: /api/v1/tasks/{task_id}/status
        let parts: Vec<&str> = path.split('/').collect();
        
        // Check for internal path: /api/v1/internal/tasks/{task_id}/status
        if parts.len() >= 6 && parts[1] == "api" && parts[2] == "v1" 
            && parts[3] == "internal" && parts[4] == "tasks" {
            return Some(parts[5].to_string());
        }
        
        // Legacy path: /api/v1/tasks/{task_id}/status
        if parts.len() >= 5 && parts[1] == "api" && parts[2] == "v1" && parts[3] == "tasks" {
            Some(parts[4].to_string())
        } else {
            None
        }
    }

    /// Parse model type
    fn parse_model_type(&self, model_str: &str) -> libsigner::InferModelType {
        use libsigner::InferModelType;
        match model_str.to_lowercase().as_str() {
            s if s.contains("deepseek") => InferModelType::DeepSeek(Some(model_str.to_string())),
            s if s.contains("llama") => InferModelType::Llama(Some(model_str.to_string())),
            s if s.contains("mistral") => InferModelType::Mistral(Some(model_str.to_string())),
            s if s.contains("gemma") => InferModelType::Gemma(Some(model_str.to_string())),
            s if s.contains("neox") || s.contains("gpt-j") => InferModelType::GptNeoX(Some(model_str.to_string())),
            _ => InferModelType::Unknown(Some(model_str.to_string())),
        }
    }
}

impl Clone for InferenceApiServer {
    fn clone(&self) -> Self {
        Self {
            shared_state: Arc::clone(&self.shared_state),
            event_sender: self.event_sender.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn test_extract_node_id_from_path() {
        let server = create_test_server();
        
        assert_eq!(
            server.extract_node_id_from_path("/api/v1/nodes/node123/tasks"),
            Some("node123".to_string())
        );
        
        assert_eq!(
            server.extract_node_id_from_path("/invalid/path"),
            None
        );
    }

    #[test]
    fn test_extract_task_id_from_path() {
        let server = create_test_server();
        
        assert_eq!(
            server.extract_task_id_from_path("/api/v1/tasks/task456/status"),
            Some("task456".to_string())
        );
        
        assert_eq!(
            server.extract_task_id_from_path("/invalid/path"),
            None
        );
    }

    #[test]
    fn test_parse_model_type() {
        let server = create_test_server();
        
        use libsigner::InferModelType;
        
        assert!(matches!(
            server.parse_model_type("deepseek-coder"),
            InferModelType::DeepSeek(_)
        ));
        
        assert!(matches!(
            server.parse_model_type("llama-3"),
            InferModelType::Llama(_)
        ));
        
        assert!(matches!(
            server.parse_model_type("unknown-model"),
            InferModelType::Unknown(_)
        ));
    }

    fn create_test_server() -> InferenceApiServer {
        use crate::inference_service::InferenceService;
        use libsigner::SignerEvent;
        let (_tx, rx) = mpsc::channel::<SignerEvent>(100);
        let (inference_service, _) = InferenceService::new(rx, std::path::PathBuf::from("test.db"));
        let (event_sender, _) = mpsc::channel::<InferenceServiceEvent>(100);
        
        InferenceApiServer::new(Arc::new(Mutex::new(inference_service.get_shared_state())), event_sender)
    }
} 
