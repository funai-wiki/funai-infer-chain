
use std::error;
use std::io::{Error, ErrorKind};
// test-only
#[cfg(test)]
use std::thread;

use serde::{Deserialize, Serialize};

use hex;
use log::{info, error};
use openai::chat::ChatCompletionMessage;
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use k256::EncodedPoint;
use k256::sha2::{Sha256, Digest};
use chrono::Utc;

use funai_common::util::hash::Sha256Sum;

mod db;

pub const INFER_CHECK_SUCCESS: i32 = 1;
pub const INFER_CHECK_FAIL: i32 = 0;

/// Generate signature headers for a request
/// Returns (pubkey_hex, signature_hex, timestamp) or None if private key is not available
fn generate_signature_headers(path: &str, body_json: &str) -> Option<(String, String, String)> {
    // 1. Try to get private key from global setting
    // 2. Fallback to environment variable STX_PRIVATE_KEY
    let priv_key_hex = get_private_key()
        .or_else(|| std::env::var("STX_PRIVATE_KEY").ok())?;

    // Remove the last byte if it's a type marker (e.g., 01 for compressed)
    let raw_priv_hex = if priv_key_hex.len() > 64 {
        &priv_key_hex[..64]
    } else {
        &priv_key_hex[..]
    };

    let priv_bytes = hex::decode(raw_priv_hex).ok()?;
    if priv_bytes.len() != 32 {
        return None;
    }

    let signing_key = SigningKey::from_slice(&priv_bytes).ok()?;

    // Get compressed public key
    let pubkey_point: EncodedPoint = signing_key.verifying_key().to_encoded_point(true);
    let pubkey_hex = hex::encode(pubkey_point.as_bytes());

    // Generate timestamp and message
    let timestamp = Utc::now().timestamp().to_string();
    let message = format!("{}:{}:{}", timestamp, path, body_json);

    // Sign the message
    let digest = Sha256::digest(message.as_bytes());
    let signature: Signature = signing_key.sign_prehash(&digest).ok()?;
    let sig_der_hex = hex::encode(signature.to_bytes());

    Some((pubkey_hex, sig_der_hex, timestamp))
}

pub async fn infer(user_input: &str, context_messages: Option<Vec<ChatCompletionMessage>>) -> Result<String, Box<dyn error::Error>> {
    if user_input.is_empty() {
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "EMPTY_USER_INPUT")));
    }

    // Avoid unused warning; context may be supported later in the local endpoint
    let _ = context_messages;

    #[derive(Serialize)]
    struct GenerateRequest {
        prompt: String,
    }

    #[derive(Deserialize)]
    struct GenerateResponse {
        text: String,
    }

    let request_body = GenerateRequest {
        prompt: user_input.to_string(),
    };
    let body_json = serde_json::to_string(&request_body).unwrap_or_default();

    // Generate signature headers if private key is available
    let mut request = reqwest::Client::new()
        .post("http://34.143.166.224:8000/generate");

    if let Some((pubkey_hex, sig_der_hex, timestamp)) = generate_signature_headers("/generate", &body_json) {
        request = request
            .header("X-Address", pubkey_hex)
            .header("X-Signature", sig_der_hex)
            .header("X-Timestamp", timestamp);
    }

    let response = request
        .json(&request_body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_else(|e| format!("Failed to read body: {}", e));
        error!("infer request failed status: {}, body: {}", status, body);
        return Err(Box::new(Error::new(
            ErrorKind::Other,
            format!("NON_200_STATUS {} body: {}", status, body),
        )));
    } else {
        info!("infer request succeeded: status: {}", response.status());
    }

    let payload: GenerateResponse = response.json().await?;
    Ok(payload.text)
}

pub async fn infer_check(user_input: &str, output: &str, context_messages: Option<Vec<ChatCompletionMessage>>)  -> Result<i32, Box<dyn error::Error>> {
    if user_input.is_empty() {
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "EMPTY_USER_INPUT")));
    }

    if output.is_empty() {
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "EMPTY_OUTPUT")));
    }

    // Avoid unused warning; context may be supported later in the local endpoint
    let _ = context_messages;

    #[derive(Serialize)]
    struct GenerateRequest {
        prompt: String,
    }

    #[derive(Deserialize)]
    struct GenerateResponse {
        text: String,
    }

    let prompt = format!(
        "请评估问题和答案是否匹配，匹配：1，不匹配：0。\n# 说明\n直接提供最终分数，不要解释和说明\n# 问题\n{user_input}\n# 回答\n{output}",
        user_input = user_input,
        output = output
    );
    let request_body = GenerateRequest { prompt };
    let body_json = serde_json::to_string(&request_body).unwrap_or_default();

    // Generate signature headers if private key is available
    let mut request = reqwest::Client::new()
        .post("http://34.143.166.224:8000/generate");

    if let Some((pubkey_hex, sig_der_hex, timestamp)) = generate_signature_headers("/generate", &body_json) {
        request = request
            .header("X-Address", pubkey_hex)
            .header("X-Signature", sig_der_hex)
            .header("X-Timestamp", timestamp);
    }

    let response = request
        .json(&request_body)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(Box::new(Error::new(
            ErrorKind::Other,
            format!("NON_200_STATUS {}", response.status()),
        )));
    }
    let payload: GenerateResponse = response.json().await?;
    let score = payload.text.trim().parse::<i32>()?;
    Ok(score)
}


pub async fn random_question() -> Result<String, Box<dyn error::Error>> {
    #[derive(Serialize)]
    struct GenerateRequest {
        prompt: String,
    }

    #[derive(Deserialize)]
    struct GenerateResponse {
        text: String,
    }

    let request_body = GenerateRequest {
        prompt: "简单直接给我随机出一个问题，文本长度在10-100之间。不需要解释和说明。".to_string(),
    };
    let body_json = serde_json::to_string(&request_body).unwrap_or_default();

    // Generate signature headers if private key is available
    let mut request = reqwest::Client::new()
        .post("http://34.143.166.224:8000/generate");

    if let Some((pubkey_hex, sig_der_hex, timestamp)) = generate_signature_headers("/generate", &body_json) {
        request = request
            .header("X-Address", pubkey_hex)
            .header("X-Signature", sig_der_hex)
            .header("X-Timestamp", timestamp);
    }

    let response = request
        .json(&request_body)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(Box::new(Error::new(
            ErrorKind::Other,
            format!("NON_200_STATUS {}", response.status()),
        )));
    }
    let payload: GenerateResponse = response.json().await?;
    Ok(payload.text)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InferStatus {
    Created = 1,
    InProgress = 2,
    Success = 3,
    Failure = 4,
    NotFound = 5,
}

impl From<u8> for InferStatus {
    fn from(value: u8) -> Self {
        match value {
            1 => InferStatus::Created,
            2 => InferStatus::InProgress,
            3 => InferStatus::Success,
            4 => InferStatus::Failure,
            5 => InferStatus::NotFound,
            _ => panic!("UNKNOWN_VALUE {}", value),
        }
    }
}


#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferResult {
    pub txid: String,
    pub status: InferStatus,
    pub input: String,
    pub output: String,
    pub output_hash: String,
    pub inference_node_id: String,
}


pub fn set_db_path(path: String) {
    db::set_db_path(path);
}

#[allow(unused_variables)]
pub fn infer_chain(txid: String, user_input: &str, context_messages: Option<Vec<ChatCompletionMessage>>) -> Result<InferStatus, Box<dyn error::Error>> {
    info!("infer_chain txid: {} user_input: {}", txid, user_input);
    let llm_db = db::open(db::get_db_path().as_str())?;
    let _ = db::sqlite_create(&llm_db, &txid.as_str(), &"", user_input, InferStatus::Created as u8)?;
    Ok(InferStatus::Created)
}

pub fn get_output_hash(output: &str) -> String {
    hex::encode(Sha256Sum::from_data(output.as_bytes()))
}

pub fn save_infer_result(txid: String, user_input: &str, output: &str, node_id: &str) -> Result<(), Box<dyn error::Error>> {
    info!("save_infer_result txid: {} node: {}", txid, node_id);
    let llm_db = db::open(db::get_db_path().as_str())?;
    db::sqlite_create(&llm_db, &txid, "", user_input, InferStatus::Success as u8)?;
    let output_hash = get_output_hash(output);
    db::sqlite_end_llm(&llm_db, &txid, output, &output_hash, InferStatus::Success as u8, node_id)?;
    Ok(())
}


pub fn query(txid: String) -> Result<InferResult, Box<dyn error::Error>> {
    let llm_db = db::open(db::get_db_path().as_str())?;
    let result = db::sqlite_get(&llm_db, &txid.as_str())?;
    Ok(InferResult{
        txid: result.txid,
        status:  result.status.into(),
        input: result.input,
        output: result.output,
        output_hash: result.output_hash,
        inference_node_id: result.inference_node_id,
    })
}

use std::sync::RwLock;
use lazy_static::lazy_static;

lazy_static! {
    static ref SIGNER_URL: RwLock<Option<String>> = RwLock::new(None);
    static ref PRIVATE_KEY: RwLock<Option<String>> = RwLock::new(None);
}

pub fn set_private_key(key: String) {
    let mut priv_key = PRIVATE_KEY.write().unwrap();
    *priv_key = Some(key);
}

pub fn get_private_key() -> Option<String> {
    PRIVATE_KEY.read().unwrap().clone()
}

pub fn set_signer_url(url: String) {
    let mut signer_url = SIGNER_URL.write().unwrap();
    *signer_url = Some(url);
}

pub fn get_signer_url() -> Option<String> {
    SIGNER_URL.read().unwrap().clone()
}

pub fn query_hash(txid: String) -> Result<InferResult, Box<dyn error::Error>> {
    if let Some(signer_url) = get_signer_url() {
        let url = format!("{}/api/v1/tasks/{}/status", signer_url, txid);
        let resp = reqwest::blocking::get(&url)?;
        if resp.status().is_success() {
            #[derive(Deserialize)]
            struct SignerTaskResponse {
                pub status: String,
                pub model_name: String,
                pub result: Option<serde_json::Value>,
            }
            #[derive(Deserialize)]
            struct SignerApiResponse {
                pub success: bool,
                pub data: Option<SignerTaskResponse>,
            }
            let api_resp: SignerApiResponse = resp.json()?;
            if api_resp.success {
                if let Some(task) = api_resp.data {
                    let status = match task.status.as_str() {
                        "completed" | "submitted" => InferStatus::Success,
                        "failed" => InferStatus::Failure,
                        "in_progress" => InferStatus::InProgress,
                        _ => InferStatus::Created,
                    };
                    let (output_hash, node_id) = if let Some(res) = task.result {
                        (
                            res.get("output_hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            res.get("inference_node_id").and_then(|v| v.as_str()).unwrap_or("").to_string()
                        )
                    } else {
                        ("".to_string(), "".to_string())
                    };
                    return Ok(InferResult {
                        txid,
                        status,
                        input: "".to_string(),
                        output: "".to_string(),
                        output_hash,
                        inference_node_id: node_id,
                    });
                }
            }
        }
    }

    let llm_db = db::open(db::get_db_path().as_str())?;
    let result = db::sqlite_get(&llm_db, &txid.as_str())?;
    Ok(InferResult{
        txid: result.txid,
        status: result.status.into(),
        input: "".to_string(),
        output: "".to_string(),
        output_hash: result.output_hash,
        inference_node_id: result.inference_node_id,
    })
}

pub async fn _internal_do_infer() -> Result<(), Box<dyn error::Error>>{
    // todo llm infer
    // 0. open connection
    let llm_db = db::open(db::get_db_path().as_str())?;
    // 1. get to_do infer row
    let row = db::sqlite_filter_to_infer(&llm_db)?;
    // 2. do infer
    db::sqlite_start_llm(&llm_db, row.txid.as_str(), InferStatus::InProgress as u8)?;
    let result = infer(row.input.as_str(), None).await;
    if !result.is_ok() {
        error!("infer error: {:?}", result.err());
        db::sqlite_end_llm(&llm_db, row.txid.as_str(), "", "", InferStatus::Failure as u8, "")?;
    } else {
        let output = result.unwrap();
        info!("output: {}", output);
        let output_hash = hex::encode(Sha256Sum::from_data(output.as_bytes()));
        // Note: when doing local infer via _internal_do_infer, we don't have a specific node_id here
        // unless it is passed in. For now using empty string or a default.
        db::sqlite_end_llm(&llm_db, row.txid.as_str(), output.as_str(), output_hash.as_str(), InferStatus::Success as u8, "")?;
    }
    Ok(())
}

pub fn do_infer() -> Result<(), Box<dyn error::Error>>{
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(_internal_do_infer())
}

/// Register a model by name with parameters if it does not already exist.
/// Returns Ok(true) if inserted, Ok(false) if already existed.
pub fn register_model_if_absent(name: &str, params: &str) -> Result<bool, Box<dyn error::Error>> {
    let llm_db = db::open(db::get_db_path().as_str())?;
    // use result_table to store models in a simple way: txid=name, context=params
    // check existence
    let exist = db::sqlite_get(&llm_db, name).is_ok();
    if exist {
        // found existing entry
        return Ok(false);
    }
    // create a placeholder row with status=Created
    db::sqlite_create(&llm_db, name, params, "", InferStatus::Created as u8)?;
    Ok(true)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_infer() {
        let user_input = "Is the Earth round?";
        let context_messages = None;

        let result = infer(user_input, context_messages).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        println!("{}", response)
    }

    #[tokio::test]
    async fn test_infer_with_no_userinput() {
        let user_input = "";
        let context_messages = None;

        let result = infer(user_input, context_messages).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_infer_check() {
        let user_input = "Is the Earth round?";
        let context_messages = None;

        let result = infer(user_input, context_messages).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        println!("{}", response);

        let context_messages = None;
        // let response = "不相关的回答";
        let check_result = infer_check(user_input, &response, context_messages).await;
        assert!(check_result.is_ok());

        let res = check_result.unwrap();
        println!("res: {}", res);
    }

    #[tokio::test]
    async fn test_random_question() {

        let result = random_question().await;
        assert!(result.is_ok());

        let response = result.unwrap();
        println!("Question: {}", response);
    }

    #[tokio::test]
    async fn test_infer_chain() {
        let txid = "0".to_string();
        let user_input = "Is the Earth round?";
        let context_messages = None;

        let result = infer_chain(txid, &user_input, context_messages);
        assert!(result.is_ok());
        assert!(result.unwrap() == InferStatus::Created);
    }

    #[tokio::test]
    async fn test_query() {
        let txid = "0".to_string();

        let result = query(txid);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_query_hash() {
        let txid = "0".to_string();

        let result = query_hash(txid);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_query_not_found() {
        let txid = "1".to_string();

        let result = query(txid);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, InferStatus::NotFound)
    }

    #[tokio::test]
    async fn test_internal_do_infer() {
        let result = _internal_do_infer().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_do_infer() {
        let result = do_infer();
        assert!(result.is_ok());
    }

    #[test]
    fn test_do_infer_thread() {
        let llm_thread_handle = thread::Builder::new()
            .name("test_thread".to_string())
            .spawn(move || {
                let _ = do_infer();
            })
            .expect("FATAL: failed to spawn chain llm thread");

        llm_thread_handle.join().unwrap();
    }
}
