use clap::Parser;
use log::{error, info, warn};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

mod config;
use config::Config;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let config = Config::from_file(&args.config)?;

    info!("Starting Infer Node: {}", config.node_id);

    let client = reqwest::Client::new();

    // 1. Register with Signer
    register_with_signer(&client, &config).await?;

    // 2. Main Loop
    loop {
        if let Some(task) = poll_for_task(&client, &config).await? {
            info!("Received task: {}", task.task_id);
            
            // 3. Do Inference
            let result = execute_inference(&task).await;
            
            // 4. Submit result back to Signer
            submit_result_to_signer(&client, &config, &task.task_id, result).await?;
            
            // 5. Submit Infer TX to Miner
            submit_tx_to_miner(&client, &config, &task).await?;
        }

        sleep(Duration::from_millis(config.polling_interval_ms)).await;
    }
}

async fn register_with_signer(client: &reqwest::Client, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/nodes/register", config.signer_endpoint);
    let body = serde_json::json!({
        "node_id": config.node_id,
        "endpoint": "http://localhost:8000", // Placeholder
        "public_key": "node-public-key", // Placeholder
        "supported_models": config.supported_models,
    });

    let resp = client.post(&url).json(&body).send().await?;
    if resp.status().is_success() {
        info!("Successfully registered with Signer");
    } else {
        error!("Failed to register with Signer: {:?}", resp.status());
    }
    Ok(())
}

#[derive(serde::Deserialize, Debug)]
struct TaskResponse {
    task_id: String,
    user_input: String,
    context: String,
    model_type: String,
    max_infer_time: u64,
    infer_fee: u64,
    signed_tx: Option<String>,
}

#[derive(serde::Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

async fn poll_for_task(client: &reqwest::Client, config: &Config) -> Result<Option<TaskResponse>, Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/nodes/{}/tasks", config.signer_endpoint, config.node_id);
    let resp = client.get(&url).send().await?;

    if resp.status() == reqwest::StatusCode::OK {
        let api_resp: ApiResponse<TaskResponse> = resp.json().await?;
        return Ok(api_resp.data);
    } else if resp.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }

    Ok(None)
}

async fn execute_inference(task: &TaskResponse) -> String {
    info!("Executing inference for task {}...", task.task_id);
    // Use libllm for inference
    match libllm::infer(&task.user_input, None).await {
        Ok(output) => {
            info!("Inference completed successfully");
            output
        }
        Err(e) => {
            error!("Inference failed: {}", e);
            format!("Error: {}", e)
        }
    }
}

async fn submit_result_to_signer(client: &reqwest::Client, config: &Config, task_id: &str, output: String) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/tasks/complete", config.signer_endpoint);
    let body = serde_json::json!({
        "task_id": task_id,
        "output": output,
        "confidence": 0.95,
        "inference_node_id": config.node_id,
    });

    let resp = client.post(&url).json(&body).send().await?;
    if resp.status().is_success() {
        info!("Successfully submitted result to Signer");
    } else {
        error!("Failed to submit result to Signer: {:?}", resp.status());
    }
    Ok(())
}

async fn submit_tx_to_miner(client: &reqwest::Client, config: &Config, task: &TaskResponse) -> Result<(), Box<dyn error::Error>> {
    if let Some(signed_tx_hex) = &task.signed_tx {
        info!("Submitting infer transaction to Miner...");
        let url = format!("{}/v2/transactions", config.miner_endpoint);
        let tx_bytes = hex::decode(signed_tx_hex)?;
        
        let resp = client.post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(tx_bytes)
            .send()
            .await?;

        if resp.status().is_success() {
            let txid = resp.text().await?;
            info!("Successfully submitted transaction, TXID: {}", txid);
        } else {
            error!("Failed to submit transaction: {:?}", resp.status());
        }
    } else {
        warn!("No signed transaction provided for task {}", task.task_id);
    }
    Ok(())
}

