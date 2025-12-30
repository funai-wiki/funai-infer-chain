use clap::Parser;
use log::{error, info, warn};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use funailib::chainstate::funai::{FunaiTransaction, TransactionPayload};
use funai_common::codec::FunaiMessageCodec;
use clarity::vm::types::PrincipalData;

mod config;
use config::Config;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let config = Config::from_file(&args.config)?;

    info!("Starting Infer Node: {}", config.node_id);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        // Run the node logic in a spawned task to allow for future parallel tasks (like an API server)
        // and graceful shutdown handling.
        let node_handle = tokio::spawn(async move {
            if let Err(e) = run_node(config).await {
                error!("Node execution error: {}", e);
            }
        });

        // Wait for Ctrl+C or node completion
        tokio::select! {
            _ = node_handle => {
                info!("Node task finished");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
            }
        }
        
        Ok(())
    })
}

async fn run_node(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

async fn register_with_signer(client: &reqwest::Client, config: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/api/v1/nodes/register", config.signer_endpoint);
    let body = serde_json::json!({
        "node_id": config.node_id,
        "endpoint": "http://localhost:8000", // Placeholder
        "public_key": "node-public-key", // Placeholder
        "supported_models": config.supported_models,
    });

    // Retry registration with exponential backoff
    let mut retries = 0;
    let max_retries = 10;
    loop {
        match client.post(&url).json(&body).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    info!("Successfully registered with Signer");
                    return Ok(());
                } else {
                    let status = resp.status();
                    let error_text = resp.text().await.unwrap_or_default();
                    error!("Failed to register with Signer: {} - {}", status, error_text);
                    if retries >= max_retries {
                        return Err(format!("Failed to register after {} retries: {}", max_retries, status).into());
                    }
                }
            }
            Err(e) => {
                warn!("Failed to connect to Signer at {}: {}. Retrying... ({}/{})", 
                      config.signer_endpoint, e, retries + 1, max_retries);
                if retries >= max_retries {
                    return Err(format!("Failed to connect to Signer after {} retries: {}", max_retries, e).into());
                }
            }
        }
        
        retries += 1;
        let backoff = Duration::from_secs(2_u64.pow(retries.min(5))); // Max 32 seconds
        info!("Retrying registration in {:?}...", backoff);
        sleep(backoff).await;
    }
}

#[derive(serde::Deserialize, Debug)]
struct TaskResponse {
    task_id: String,
    user_input: String,
    context: String,
    model_name: String,
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

async fn poll_for_task(client: &reqwest::Client, config: &Config) -> Result<Option<TaskResponse>, Box<dyn std::error::Error + Send + Sync>> {
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

async fn submit_result_to_signer(client: &reqwest::Client, config: &Config, task_id: &str, output: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

async fn submit_tx_to_miner(client: &reqwest::Client, config: &Config, task: &TaskResponse) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(signed_tx_hex) = &task.signed_tx {
        info!("Submitting infer transaction to Miner...");
        let url = format!("{}/v2/transactions", config.miner_endpoint);
        let tx_bytes = hex::decode(signed_tx_hex)?;

        // Deserialize the transaction
        let mut reader = &tx_bytes[..];
        let (mut tx, _) = FunaiTransaction::consensus_deserialize_with_len(&mut reader)
            .map_err(|e| format!("Failed to deserialize transaction: {}", e))?;

        // Set the actual node_principal who completed the task
        // FIXME: Modifying payload invalidates the signature.
        // if let TransactionPayload::Infer(from, amount, input, context, _, model) = tx.payload {
        //    let node_principal = PrincipalData::parse(&config.node_address)
        //        .map_err(|e| format!("Invalid node_address in config: {}", e))?;
        //    tx.payload = TransactionPayload::Infer(from, amount, input, context, node_principal, model);
        // }

        // Re-serialize the transaction with the assigned worker address
        let mut new_tx_bytes = vec![];
        tx.consensus_serialize(&mut new_tx_bytes)
            .map_err(|e| format!("Failed to re-serialize transaction: {}", e))?;

        let resp = client.post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(new_tx_bytes)
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
