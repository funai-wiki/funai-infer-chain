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

/// Request to submit an inference task via API
#[derive(Serialize, Deserialize)]
pub struct SubmitTaskRequest {
    /// Task ID (optional, will be generated if not provided)
    pub task_id: Option<String>,
    /// User address
    pub user_address: String,
    /// User input
    pub user_input: String,
    /// Context information
    pub context: String,
    /// Transaction fee (optional)
    pub fee: Option<u64>,
    /// Nonce (optional)
    pub nonce: Option<u64>,
    /// Inference fee
    pub infer_fee: u64,
    /// Maximum inference time (seconds)
    pub max_infer_time: u64,
    /// Model type
    pub model_type: String,
}

/// Node status response
#[derive(Serialize, Deserialize)]
pub struct NodeStatusResponse {
    /// Node ID
    pub node_id: String,
    /// Node status
    pub status: String,
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
    /// Model type
    pub model_type: String,
    /// Maximum inference time
    pub max_infer_time: u64,
    /// Inference fee
    pub infer_fee: u64,
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
    /// Model type
    pub model_type: String,
    /// Maximum inference time
    pub max_infer_time: u64,
    /// Inference fee
    pub infer_fee: u64,
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

        info!("Received {} request to {}", method, path);

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
            // Inference node fetch task
            (&Method::GET, path) if path.starts_with("/api/v1/nodes/") && path.ends_with("/tasks") => {
                let node_id = self.extract_node_id_from_path(path);
                self.handle_get_task(node_id).await
            }
            // Inference node complete task
            (&Method::POST, "/api/v1/tasks/complete") => {
                self.handle_complete_task(req).await
            }
            // Miner fetch completed task status
            (&Method::GET, path) if path.starts_with("/api/v1/tasks/") && path.contains("/status") => {
                let task_id = self.extract_task_id_from_path(path);
                self.handle_get_task_status(task_id).await
            }
            // Get service statistics
            (&Method::GET, "/api/v1/stats") => {
                self.handle_get_statistics().await
            }
            // Get all node statuses
            (&Method::GET, "/api/v1/nodes") => {
                self.handle_get_nodes().await
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
                let task_id = request.task_id.unwrap_or_else(|| {
                    format!("api-{}", uuid::Uuid::new_v4().to_string())
                });

                let task = InferTask::new(
                    task_id.clone(),
                    request.user_address,
                    request.user_input,
                    request.context,
                    request.fee.unwrap_or(0),
                    request.nonce.unwrap_or(0),
                    request.infer_fee,
                    request.max_infer_time,
                    self.parse_model_type(&request.model_type),
                );

                let result = {
                    let service = self.shared_state.lock().unwrap();
                    service.submit_task(task)
                };

                match result {
                    Ok(()) => {
                // Notify via event sender
                        if let Err(e) = self.event_sender.blocking_send(InferenceServiceEvent::TaskSubmitted(task_id.clone())) {
                     error!("Failed to send task submitted event: {}", e);
                }

                        info!("Task {} submitted via API successfully", task_id);
                self.json_response(ApiResponse::success(json!({ "task_id": task_id })), StatusCode::OK)
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

    /// Handle inference node fetch task
    async fn handle_get_task(&self, node_id: Option<String>) -> Response<Body> {
        let node_id = match node_id {
            Some(id) => id,
            None => {
                return self.json_response(
                    ApiResponse::<String>::error("Invalid node ID".to_string()),
                    StatusCode::BAD_REQUEST,
                );
            }
        };

        // Get tasks that this node can process
        let task = {
            let service = self.shared_state.lock().unwrap();
            
            // 1. Get supported models for the node
            let supported_models = {
                let nodes = service.inference_nodes.lock().unwrap();
                if let Some(node) = nodes.get(&node_id) {
                    node.supported_models.clone()
                } else {
                    Vec::new()
                }
            };

            if supported_models.is_empty() {
                None
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
                        
                        Some(task)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        match task {
            Some(task) => {
                let response = GetTaskResponse {
                    task_id: task.task_id,
                    user_input: task.user_input,
                    context: task.context,
                    model_type: format!("{:?}", task.model_type),
                    max_infer_time: task.max_infer_time,
                    infer_fee: task.infer_fee,
                };
                
                info!("Assigned task {} to node {}", response.task_id, node_id);
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

    /// Handle get task status
    async fn handle_get_task_status(&self, task_id: Option<String>) -> Response<Body> {
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
                info!("Retrieved status for task {}: {:?}", task_id, task.status);
                self.json_response(ApiResponse::success(task), StatusCode::OK)
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
        // Path format: /api/v1/tasks/{task_id}/status
        let parts: Vec<&str> = path.split('/').collect();
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
        let (event_receiver, _) = mpsc::channel(100);
        let (inference_service, _) = InferenceService::new(event_receiver, std::path::PathBuf::from("test.db"));
        let (event_sender, _) = mpsc::channel(100);
        
        InferenceApiServer::new(Arc::new(Mutex::new(inference_service.get_shared_state())), event_sender)
    }
} 
