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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::PathBuf;

use libsigner::{InferModelType, SignerEvent, SubmitInferTask};
use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_error, slog_info};
use funai_common::{debug, error, info};
use tokio::sync::mpsc;
use rusqlite::{Connection, Result as SqliteResult, params};

/// Inference task status
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum InferTaskStatus {
    /// Task submitted, waiting for inference node to process
    Pending,
    /// Task has been picked up by an inference node and is being processed
    InProgress,
    /// Task completed, waiting to be submitted to miner
    Completed,
    /// Task has been submitted to miner
    Submitted,
    /// Task failed
    Failed,
    /// Task timed out
    Timeout,
}

impl InferTaskStatus {
    /// Convert task status to string representation.
    pub fn to_string(&self) -> String {
        match self {
            InferTaskStatus::Pending => "pending".to_string(),
            InferTaskStatus::InProgress => "in_progress".to_string(),
            InferTaskStatus::Completed => "completed".to_string(),
            InferTaskStatus::Submitted => "submitted".to_string(),
            InferTaskStatus::Failed => "failed".to_string(),
            InferTaskStatus::Timeout => "timeout".to_string(),
        }
    }

    /// Parse task status from string.
    pub fn from_string(s: &str) -> Self {
        match s {
            "pending" => InferTaskStatus::Pending,
            "in_progress" => InferTaskStatus::InProgress,
            "completed" => InferTaskStatus::Completed,
            "submitted" => InferTaskStatus::Submitted,
            "failed" => InferTaskStatus::Failed,
            "timeout" => InferTaskStatus::Timeout,
            _ => InferTaskStatus::Pending,
        }
    }
}

/// Inference task result
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InferTaskResult {
    /// Inference output
    pub output: String,
    /// Inference confidence
    pub confidence: f64,
    /// Inference completion time
    pub completed_at: u64,
    /// Inference node ID
    pub inference_node_id: String,
}

/// Inference task data structure
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InferTask {
    /// Task ID
    pub task_id: String,
    /// User address
    pub user_address: String,
    /// User input
    pub user_input: String,
    /// Context information
    pub context: String,
    /// Transaction fee
    pub fee: u64,
    /// Nonce
    pub nonce: u64,
    /// Inference fee
    pub infer_fee: u64,
    /// Maximum inference time (seconds)
    pub max_infer_time: u64,
    /// Model type
    pub model_type: InferModelType,
    /// Signed transaction hex
    pub signed_tx: Option<String>,
    /// Task status
    pub status: InferTaskStatus,
    /// Creation time
    pub created_at: u64,
    /// Update time
    pub updated_at: u64,
    /// Inference result (if completed)
    pub result: Option<InferTaskResult>,
}

impl InferTask {
    /// Create a new inference task
    pub fn new(
        task_id: String,
        user_address: String,
        user_input: String,
        context: String,
        fee: u64,
        nonce: u64,
        infer_fee: u64,
        max_infer_time: u64,
        model_type: InferModelType,
        signed_tx: Option<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            task_id,
            user_address,
            user_input,
            context,
            fee,
            nonce,
            infer_fee,
            max_infer_time,
            model_type,
            signed_tx,
            status: InferTaskStatus::Pending,
            created_at: now,
            updated_at: now,
            result: None,
        }
    }

    /// Update task status
    pub fn update_status(&mut self, status: InferTaskStatus) {
        self.status = status;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Set inference result
    pub fn set_result(&mut self, result: InferTaskResult) {
        self.result = Some(result);
        self.status = InferTaskStatus::Completed;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Check if the task is timed out
    pub fn is_timeout(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.created_at > self.max_infer_time
    }
}

/// Inference node information
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InferenceNode {
    /// Node ID
    pub node_id: String,
    /// Node endpoint
    pub endpoint: String,
    /// Node public key
    pub public_key: String,
    /// Node status
    pub status: NodeStatus,
    /// Supported model types
    pub supported_models: Vec<InferModelType>,
    /// Node performance score
    pub performance_score: f64,
    /// Last heartbeat time
    pub last_heartbeat: u64,
}

/// Inference node status
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Online
    Online,
    /// Offline
    Offline,
    /// Busy
    Busy,
    /// Maintenance
    Maintenance,
}

impl NodeStatus {
    /// Convert node status to string representation.
    pub fn to_string(&self) -> String {
        match self {
            NodeStatus::Online => "online".to_string(),
            NodeStatus::Offline => "offline".to_string(),
            NodeStatus::Busy => "busy".to_string(),
            NodeStatus::Maintenance => "maintenance".to_string(),
        }
    }

    /// Parse node status from string.
    pub fn from_string(s: &str) -> Self {
        match s {
            "online" => NodeStatus::Online,
            "offline" => NodeStatus::Offline,
            "busy" => NodeStatus::Busy,
            "maintenance" => NodeStatus::Maintenance,
            _ => NodeStatus::Offline,
        }
    }
}

/// SQLite database manager
pub struct InferenceDatabase {
    conn: Connection,
}

impl InferenceDatabase {
    /// Create a new database connection
    pub fn new(db_path: &PathBuf) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;
        
        // Create inference tasks table
        conn.execute::<[&dyn rusqlite::ToSql; 0]>(
            "CREATE TABLE IF NOT EXISTS inference_tasks (
                task_id TEXT PRIMARY KEY,
                user_address TEXT NOT NULL,
                user_input TEXT NOT NULL,
                context TEXT NOT NULL,
                fee INTEGER NOT NULL,
                nonce INTEGER NOT NULL,
                infer_fee INTEGER NOT NULL,
                max_infer_time INTEGER NOT NULL,
                model_type TEXT NOT NULL,
                signed_tx TEXT,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                output TEXT,
                confidence REAL,
                completed_at INTEGER,
                inference_node_id TEXT
            )",
            [],
        )?;

        // Create inference nodes table
        conn.execute::<[&dyn rusqlite::ToSql; 0]>(
            "CREATE TABLE IF NOT EXISTS inference_nodes (
                node_id TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                public_key TEXT NOT NULL,
                status TEXT NOT NULL,
                supported_models TEXT NOT NULL,
                performance_score REAL NOT NULL,
                last_heartbeat INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    /// Save inference task to database
    pub fn save_task(&self, task: &InferTask) -> SqliteResult<()> {
        let model_type_str = match &task.model_type {
            InferModelType::DeepSeek(_) => "deepseek",
            InferModelType::Llama(_) => "llama",
            InferModelType::Mistral(_) => "mistral",
            InferModelType::Gemma(_) => "gemma",
            InferModelType::GptNeoX(_) => "gptneox",
            InferModelType::Unknown(_) => "unknown",
        };

        let output = task.result.as_ref().map(|r| r.output.clone());
        let confidence = task.result.as_ref().map(|r| r.confidence);
        let completed_at = task.result.as_ref().map(|r| r.completed_at as i64);
        let inference_node_id = task.result.as_ref().map(|r| r.inference_node_id.clone());

        self.conn.execute(
            "INSERT OR REPLACE INTO inference_tasks 
             (task_id, user_address, user_input, context, fee, nonce, infer_fee, 
              max_infer_time, model_type, signed_tx, status, created_at, updated_at, 
              output, confidence, completed_at, inference_node_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                task.task_id,
                task.user_address,
                task.user_input,
                task.context,
                task.fee as i64,
                task.nonce as i64,
                task.infer_fee as i64,
                task.max_infer_time as i64,
                model_type_str,
                task.signed_tx,
                task.status.to_string(),
                task.created_at as i64,
                task.updated_at as i64,
                output,
                confidence,
                completed_at,
                inference_node_id,
            ],
        )?;

        Ok(())
    }

    /// Load inference task from database
    pub fn load_task(&self, task_id: &str) -> SqliteResult<Option<InferTask>> {
        let mut stmt = self.conn.prepare(
            "SELECT task_id, user_address, user_input, context, fee, nonce, infer_fee,
                    max_infer_time, model_type, signed_tx, status, created_at, updated_at,
                    output, confidence, completed_at, inference_node_id
             FROM inference_tasks WHERE task_id = ?"
        )?;

        let mut rows = stmt.query(params![task_id])?;
        
        if let Some(row) = rows.next()? {
            let task_id: String = row.get(0)?;
            let user_address: String = row.get(1)?;
            let user_input: String = row.get(2)?;
            let context: String = row.get(3)?;
            let fee: i64 = row.get(4)?;
            let nonce: i64 = row.get(5)?;
            let infer_fee: i64 = row.get(6)?;
            let max_infer_time: i64 = row.get(7)?;
            let model_type_str: String = row.get(8)?;
            let signed_tx: Option<String> = row.get(9)?;
            let status_str: String = row.get(10)?;
            let created_at: i64 = row.get(11)?;
            let updated_at: i64 = row.get(12)?;
            let output: Option<String> = row.get(13)?;
            let confidence: Option<f64> = row.get(14)?;
            let completed_at: Option<i64> = row.get(15)?;
            let inference_node_id: Option<String> = row.get(16)?;

            let model_type = match model_type_str.as_str() {
                "deepseek" => InferModelType::DeepSeek(None),
                "llama" => InferModelType::Llama(None),
                "mistral" => InferModelType::Mistral(None),
                "gemma" => InferModelType::Gemma(None),
                "gptneox" => InferModelType::GptNeoX(None),
                _ => InferModelType::Unknown(None),
            };

            let status = InferTaskStatus::from_string(&status_str);

            let result = if let (Some(output), Some(confidence), Some(completed_at), Some(node_id)) = 
                (output, confidence, completed_at, inference_node_id) {
                Some(InferTaskResult {
                    output,
                    confidence,
                    completed_at: completed_at as u64,
                    inference_node_id: node_id,
                })
            } else {
                None
            };

            Ok(Some(InferTask {
                task_id,
                user_address,
                user_input,
                context,
                fee: fee as u64,
                nonce: nonce as u64,
                infer_fee: infer_fee as u64,
                max_infer_time: max_infer_time as u64,
                model_type,
                signed_tx,
                status,
                created_at: created_at as u64,
                updated_at: updated_at as u64,
                result,
            }))
        } else {
            Ok(None)
        }
    }

    /// Save inference node to database
    pub fn save_node(&self, node: &InferenceNode) -> SqliteResult<()> {
        let supported_models_str = serde_json::to_string(&node.supported_models)
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;

        self.conn.execute(
            "INSERT OR REPLACE INTO inference_nodes 
             (node_id, endpoint, public_key, status, supported_models, performance_score, last_heartbeat)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                node.node_id,
                node.endpoint,
                node.public_key,
                node.status.to_string(),
                supported_models_str,
                node.performance_score,
                node.last_heartbeat as i64,
            ],
        )?;

        Ok(())
    }

    /// Load all inference nodes from database
    pub fn load_nodes(&self) -> SqliteResult<Vec<InferenceNode>> {
        let mut stmt = self.conn.prepare(
            "SELECT node_id, endpoint, public_key, status, supported_models, 
                    performance_score, last_heartbeat
             FROM inference_nodes"
        )?;

        let mut rows = stmt.query::<[&dyn rusqlite::ToSql; 0]>([])?;
        let mut nodes = Vec::new();

        while let Some(row) = rows.next()? {
            let node_id: String = row.get(0)?;
            let endpoint: String = row.get(1)?;
            let public_key: String = row.get(2)?;
            let status_str: String = row.get(3)?;
            let supported_models_str: String = row.get(4)?;
            let performance_score: f64 = row.get(5)?;
            let last_heartbeat: i64 = row.get(6)?;

            let status = NodeStatus::from_string(&status_str);
            let supported_models: Vec<InferModelType> = serde_json::from_str(&supported_models_str)
                .unwrap();

            nodes.push(InferenceNode {
                node_id,
                endpoint,
                public_key,
                status,
                supported_models,
                performance_score,
                last_heartbeat: last_heartbeat as u64,
            });
        }

        Ok(nodes)
    }

    /// Load all tasks from database
    pub fn load_all_tasks(&self) -> SqliteResult<Vec<InferTask>> {
        let mut stmt = self.conn.prepare(
            "SELECT task_id, user_address, user_input, context, fee, nonce, infer_fee,
                    max_infer_time, model_type, signed_tx, status, created_at, updated_at,
                    output, confidence, completed_at, inference_node_id
             FROM inference_tasks"
        )?;

        let mut rows = stmt.query::<[&dyn rusqlite::ToSql; 0]>([])?;
        let mut tasks = Vec::new();

        while let Some(row) = rows.next()? {
            let task_id: String = row.get(0)?;
            let user_address: String = row.get(1)?;
            let user_input: String = row.get(2)?;
            let context: String = row.get(3)?;
            let fee: i64 = row.get(4)?;
            let nonce: i64 = row.get(5)?;
            let infer_fee: i64 = row.get(6)?;
            let max_infer_time: i64 = row.get(7)?;
            let model_type_str: String = row.get(8)?;
            let signed_tx: Option<String> = row.get(9)?;
            let status_str: String = row.get(10)?;
            let created_at: i64 = row.get(11)?;
            let updated_at: i64 = row.get(12)?;
            let output: Option<String> = row.get(13)?;
            let confidence: Option<f64> = row.get(14)?;
            let completed_at: Option<i64> = row.get(15)?;
            let inference_node_id: Option<String> = row.get(16)?;

            let model_type = match model_type_str.as_str() {
                "deepseek" => InferModelType::DeepSeek(None),
                "llama" => InferModelType::Llama(None),
                "mistral" => InferModelType::Mistral(None),
                "gemma" => InferModelType::Gemma(None),
                "gptneox" => InferModelType::GptNeoX(None),
                _ => InferModelType::Unknown(None),
            };

            let status = InferTaskStatus::from_string(&status_str);

            let result = if let (Some(output), Some(confidence), Some(completed_at), Some(node_id)) = 
                (output, confidence, completed_at, inference_node_id) {
                Some(InferTaskResult {
                    output,
                    confidence,
                    completed_at: completed_at as u64,
                    inference_node_id: node_id,
                })
            } else {
                None
            };

            tasks.push(InferTask {
                task_id,
                user_address,
                user_input,
                context,
                fee: fee as u64,
                nonce: nonce as u64,
                infer_fee: infer_fee as u64,
                max_infer_time: max_infer_time as u64,
                model_type,
                signed_tx,
                status,
                created_at: created_at as u64,
                updated_at: updated_at as u64,
                result,
            });
        }

        Ok(tasks)
    }
}

/// Shared state for inference service that can be accessed by both the service and API server
#[derive(Clone)]
pub struct InferenceServiceState {
    /// Pending inference tasks
    pub pending_tasks: Arc<Mutex<HashMap<String, InferTask>>>,
    /// In-progress inference tasks
    pub processing_tasks: Arc<Mutex<HashMap<String, InferTask>>>,
    /// Completed inference tasks
    pub completed_tasks: Arc<Mutex<HashMap<String, InferTask>>>,
    /// Registered inference nodes
    pub inference_nodes: Arc<Mutex<HashMap<String, InferenceNode>>>,
    /// Database connection
    pub database: Arc<Mutex<InferenceDatabase>>,
}

impl InferenceServiceState {
    /// Create a new shared state
    pub fn new(db_path: PathBuf) -> Self {
        let database = Arc::new(Mutex::new(
            InferenceDatabase::new(&db_path).expect("Failed to create database")
        ));

        let state = Self {
            pending_tasks: Arc::new(Mutex::new(HashMap::new())),
            processing_tasks: Arc::new(Mutex::new(HashMap::new())),
            completed_tasks: Arc::new(Mutex::new(HashMap::new())),
            inference_nodes: Arc::new(Mutex::new(HashMap::new())),
            database,
        };

        // Load data from database
        if let Err(e) = state.load_from_database() {
            error!("Failed to load data from database: {}", e);
        }

        state
    }

    /// Load data from database into memory
    pub fn load_from_database(&self) -> Result<(), String> {
        let db = self.database.lock().map_err(|e| e.to_string())?;
        
        // Load nodes
        let nodes = db.load_nodes().map_err(|e| e.to_string())?;
        {
            let mut nodes_map = self.inference_nodes.lock().map_err(|e| e.to_string())?;
            for node in nodes {
                nodes_map.insert(node.node_id.clone(), node);
            }
        }

        // Load tasks
        let tasks = db.load_all_tasks().map_err(|e| e.to_string())?;
        {
            let mut pending = self.pending_tasks.lock().map_err(|e| e.to_string())?;
            let mut completed = self.completed_tasks.lock().map_err(|e| e.to_string())?;

            for task in tasks {
                match task.status {
                    InferTaskStatus::Pending => {
                        pending.insert(task.task_id.clone(), task);
                    }
                    InferTaskStatus::InProgress => {
                        // If it was in progress when shut down, we might want to move it back to pending
                        // or keep it in processing if we can resume. For now, move to pending to be safe.
                        let mut task = task;
                        task.status = InferTaskStatus::Pending;
                        pending.insert(task.task_id.clone(), task);
                    }
                    InferTaskStatus::Completed | InferTaskStatus::Submitted => {
                        completed.insert(task.task_id.clone(), task);
                    }
                    InferTaskStatus::Failed | InferTaskStatus::Timeout => {
                        completed.insert(task.task_id.clone(), task);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get task status
    pub fn get_task_status(&self, task_id: &str) -> Option<InferTask> {
        // Check pending tasks
        if let Ok(pending) = self.pending_tasks.lock() {
            if let Some(task) = pending.get(task_id) {
                return Some(task.clone());
            }
        }

        // Check processing tasks
        if let Ok(processing) = self.processing_tasks.lock() {
            if let Some(task) = processing.get(task_id) {
                return Some(task.clone());
            }
        }

        // Check completed tasks
        if let Ok(completed) = self.completed_tasks.lock() {
            if let Some(task) = completed.get(task_id) {
                return Some(task.clone());
            }
        }

        None
    }

    /// Submit a new inference task manually via API
    pub fn submit_task(&self, task: InferTask) -> Result<(), String> {
        // Save to database
        if let Ok(db) = self.database.lock() {
            if let Err(e) = db.save_task(&task) {
                error!("Failed to save task to database: {}", e);
                return Err(format!("Database error: {}", e));
            }
        }

        // Add to pending tasks
        if let Ok(mut pending) = self.pending_tasks.lock() {
            pending.insert(task.task_id.clone(), task);
        }

        Ok(())
    }

    /// Register inference node
    pub fn register_inference_node(&self, node: InferenceNode) -> Result<(), String> {
        let mut nodes = self.inference_nodes.lock().map_err(|e| e.to_string())?;
        
        if nodes.contains_key(&node.node_id) {
            info!("Node {} already registered, updating registration", node.node_id);
        }

        nodes.insert(node.node_id.clone(), node.clone());
        
        // Save to database
        if let Ok(db) = self.database.lock() {
            if let Err(e) = db.save_node(&node) {
                error!("Failed to save node to database: {}", e);
            }
        }

        Ok(())
    }

    /// Update node status
    pub fn update_node_status(&self, node_id: &str, status: NodeStatus) -> Result<(), String> {
        let mut nodes = self.inference_nodes.lock().map_err(|e| e.to_string())?;
        
        if let Some(node) = nodes.get_mut(node_id) {
            node.status = status;
            node.last_heartbeat = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            // Save to database
            if let Ok(db) = self.database.lock() {
                if let Err(e) = db.save_node(node) {
                    error!("Failed to save node to database: {}", e);
                }
            }
            
            Ok(())
        } else {
            Err("Node not found".to_string())
        }
    }

    /// Complete task
    pub fn complete_task(&self, task_id: &str, result: InferTaskResult) -> Result<(), String> {
        // Remove from processing tasks
        let mut task = {
            let mut processing = self.processing_tasks.lock().map_err(|e| e.to_string())?;
            processing.remove(task_id).ok_or("Task not found in processing")?
        };

        // Set result and move to completed
        task.set_result(result);
        
        {
            let mut completed = self.completed_tasks.lock().map_err(|e| e.to_string())?;
            completed.insert(task_id.to_string(), task.clone());
        }

        // Save to database
        if let Ok(db) = self.database.lock() {
            if let Err(e) = db.save_task(&task) {
                error!("Failed to save task to database: {}", e);
            }
        }

        Ok(())
    }

    /// Get node status
    pub fn get_node_status(&self) -> HashMap<String, InferenceNode> {
        self.inference_nodes.lock().unwrap().clone()
    }

    /// Get task statistics
    pub fn get_task_statistics(&self) -> TaskStatistics {
        let pending_count = self.pending_tasks.lock().unwrap().len();
        let processing_count = self.processing_tasks.lock().unwrap().len();
        let completed_count = self.completed_tasks.lock().unwrap().len();

        TaskStatistics {
            pending_tasks: pending_count,
            processing_tasks: processing_count,
            completed_tasks: completed_count,
            total_tasks: pending_count + processing_count + completed_count,
        }
    }
}

/// Main structure for the inference service
pub struct InferenceService {
    /// Shared state
    state: InferenceServiceState,
    /// Event receiver
    event_receiver: mpsc::Receiver<SignerEvent>,
    /// Event sender
    event_sender: mpsc::Sender<InferenceServiceEvent>,
}

/// Inference service events
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum InferenceServiceEvent {
    /// New task submitted
    TaskSubmitted(String),
    /// Task started processing
    TaskStarted(String),
    /// Task completed
    TaskCompleted(String),
    /// Task failed
    TaskFailed(String, String),
    /// Node registered
    NodeRegistered(String),
    /// Node status updated
    NodeStatusUpdated(String, NodeStatus),
}

impl InferenceService {
    /// Create a new inference service
    pub fn new(
        event_receiver: mpsc::Receiver<SignerEvent>,
        db_path: PathBuf,
    ) -> (Self, mpsc::Receiver<InferenceServiceEvent>) {
        let (event_sender, service_event_receiver) = mpsc::channel(1000);
        
        let state = InferenceServiceState::new(db_path);

        let service = Self {
            state,
            event_receiver,
            event_sender,
        };

        (service, service_event_receiver)
    }

    /// Start the inference service
    pub async fn run(&mut self) {
        info!("Starting Inference Service...");

        // Main event loop
        while let Some(event) = self.event_receiver.recv().await {
            self.handle_event(event).await;
        }
    }

    /// Handle received events
    async fn handle_event(&mut self, event: SignerEvent) {
        match event {
            SignerEvent::InferTaskMessage(submit_task) => {
                self.handle_submit_task(submit_task).await;
            }
            _ => {
                // Ignore other events for now
                debug!("Ignoring event: {:?}", event);
            }
        }
    }

    /// Handle task submission
    async fn handle_submit_task(&mut self, submit_task: SubmitInferTask) {
        info!("Received inference task submission: {}", submit_task.task_id);

        let task = InferTask::new(
            submit_task.task_id,
            submit_task.infer_user_address,
            submit_task.user_input,
            submit_task.context,
            submit_task.fee,
            submit_task.nonce,
            submit_task.infer_fee,
            submit_task.max_infer_time,
            submit_task.model_type,
            None, // No signed_tx from event sender for now
        );

        // Add to pending tasks
        {
            let mut pending = self.state.pending_tasks.lock().unwrap();
            pending.insert(task.task_id.clone(), task.clone());
        }

        // Save to database
        if let Ok(db) = self.state.database.lock() {
            if let Err(e) = db.save_task(&task) {
                error!("Failed to save task to database: {}", e);
            }
        }

        // Send task submitted event
        if let Err(e) = self.event_sender.send(InferenceServiceEvent::TaskSubmitted(task.task_id)).await {
            error!("Failed to send task submitted event: {}", e);
        }
    }

    /// Get task status
    pub fn get_task_status(&self, task_id: &str) -> Option<InferTask> {
        self.state.get_task_status(task_id)
    }

    /// Register inference node
    pub fn register_inference_node(&mut self, node: InferenceNode) -> Result<(), String> {
        info!("Registering inference node: {}", node.node_id);

        // Save to database
        if let Ok(db) = self.state.database.lock() {
            if let Err(e) = db.save_node(&node) {
                return Err(format!("Failed to save node to database: {}", e));
            }
        }

        // Add to memory
        {
            let mut nodes = self.state.inference_nodes.lock().unwrap();
            nodes.insert(node.node_id.clone(), node.clone());
        }

        // Send node registration event
        if let Err(e) = self.event_sender.try_send(InferenceServiceEvent::NodeRegistered(node.node_id)) {
            error!("Failed to send node registered event: {}", e);
        }

        Ok(())
    }

    /// Update node status
    pub fn update_node_status(&mut self, node_id: &str, status: NodeStatus) -> Result<(), String> {
        info!("Updating node {} status to {:?}", node_id, status);

        // Update node status in memory
        {
            let mut nodes = self.state.inference_nodes.lock().unwrap();
            if let Some(node) = nodes.get_mut(node_id) {
                node.status = status.clone();
                node.last_heartbeat = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Save to database
                if let Ok(db) = self.state.database.lock() {
                    if let Err(e) = db.save_node(node) {
                        return Err(format!("Failed to save node to database: {}", e));
                    }
                }
            } else {
                return Err(format!("Node {} not found", node_id));
            }
        }

        // Send node status update event
        if let Err(e) = self.event_sender.try_send(InferenceServiceEvent::NodeStatusUpdated(node_id.to_string(), status)) {
            error!("Failed to send node status update event: {}", e);
        }

        Ok(())
    }

    /// Complete task
    pub fn complete_task(&mut self, task_id: &str, result: InferTaskResult) -> Result<(), String> {
        info!("Completing task: {}", task_id);

        // Move task from processing to completed
        {
            let mut processing = self.state.processing_tasks.lock().unwrap();
            let mut completed = self.state.completed_tasks.lock().unwrap();

            if let Some(mut task) = processing.remove(task_id) {
                task.set_result(result);
                completed.insert(task_id.to_string(), task.clone());

                // Save to database
                if let Ok(db) = self.state.database.lock() {
                    if let Err(e) = db.save_task(&task) {
                        return Err(format!("Failed to save task to database: {}", e));
                    }
                }

                // Send task completion event
                if let Err(e) = self.event_sender.try_send(InferenceServiceEvent::TaskCompleted(task_id.to_string())) {
                    error!("Failed to send task completion event: {}", e);
                }
            } else {
                return Err(format!("Task {} not found in processing", task_id));
            }
        }

        Ok(())
    }

    /// Get node status
    pub fn get_node_status(&self) -> HashMap<String, InferenceNode> {
        self.state.get_node_status()
    }

    /// Get task statistics
    pub fn get_task_statistics(&self) -> TaskStatistics {
        self.state.get_task_statistics()
    }

    /// Get a clone of the shared state for API server
    pub fn get_shared_state(&self) -> InferenceServiceState {
        self.state.clone()
    }
}

/// Task statistics
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaskStatistics {
    /// Number of pending tasks
    pub pending_tasks: usize,
    /// Number of processing tasks
    pub processing_tasks: usize,
    /// Number of completed tasks
    pub completed_tasks: usize,
    /// Total number of tasks
    pub total_tasks: usize,
}