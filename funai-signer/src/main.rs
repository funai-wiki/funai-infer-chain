//! # funai-signer: Funai signer binary for executing DKG rounds, signing transactions and blocks, and more.
//!
//! Usage documentation can be found in the [README]("https://github.com/blockstack/funai-blockchain/funai-signer/README.md).
//!
//!
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
extern crate slog;
extern crate funai_common;

extern crate clarity;
extern crate serde;
extern crate serde_json;
extern crate toml;

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
use std::sync::{Arc, Mutex};

use funailib::chainstate::nakamoto::NakamotoBlock;
use funailib::util_lib::signed_structured_data::pox4::make_pox_4_signer_key_signature;
use clap::Parser;
use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::{RunningSigner, Signer, SignerEventReceiver, SignerSession, FunaiDBSession, SignerEvent};
use libfunaidb::FunaiDBChunkData;
use slog::{slog_debug, slog_error, slog_info};
use funai_common::codec::read_next;
use funai_common::types::chainstate::FunaiPrivateKey;
use funai_common::util::hash::to_hex;
use funai_common::util::secp256k1::{MessageSignature, Secp256k1PublicKey};
use funai_common::{debug, error, info};
use funai_signer::cli::{
    Cli, Command, GenerateFilesArgs, GenerateStackingSignatureArgs, GetChunkArgs,
    GetLatestChunkArgs, PutChunkArgs, RunDkgArgs, RunSignerArgs, SignArgs, FunaiDBArgs,
    RunInferenceServiceArgs,
};
use funai_signer::config::{build_signer_config_tomls, GlobalConfig};
use funai_signer::runloop::{RunLoop, RunLoopCommand};
use funai_signer::signer::Command as SignerCommand;
use funai_signer::inference_service::InferenceService;
use funai_signer::inference_api::InferenceApiServer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use wsts::state_machine::OperationResult;
use tokio::sync::mpsc;
use std::net::SocketAddr;

struct SpawnedSigner {
    running_signer: RunningSigner<SignerEventReceiver, Vec<OperationResult>>,
    cmd_send: Sender<RunLoopCommand>,
    res_recv: Receiver<Vec<OperationResult>>,
}

/// Create a new funai db session
fn funaidb_session(host: &str, contract: QualifiedContractIdentifier) -> FunaiDBSession {
    let mut session = FunaiDBSession::new(host, contract.clone());
    session.connect(host.to_string(), contract).unwrap();
    session
}

/// Write the chunk to stdout
fn write_chunk_to_stdout(chunk_opt: Option<Vec<u8>>) {
    if let Some(chunk) = chunk_opt.as_ref() {
        let bytes = io::stdout().write(chunk).unwrap();
        if bytes < chunk.len() {
            print!(
                "Failed to write complete chunk to stdout. Missing {} bytes",
                chunk.len() - bytes
            );
        }
    }
}

// Spawn a running signer and return its handle, command sender, and result receiver
fn spawn_running_signer(path: &PathBuf, inference_task_sender: Option<tokio::sync::mpsc::Sender<SignerEvent>>) -> SpawnedSigner {
    let config = GlobalConfig::try_from(path).unwrap();
    let endpoint = config.endpoint;
    info!("Starting signer with config: {}", config);
    let (cmd_send, cmd_recv) = channel();
    let (res_send, res_recv) = channel();
    let ev = SignerEventReceiver::new(config.network.is_mainnet());
    let mut runloop = RunLoop::from(config);
    runloop.inference_task_sender = inference_task_sender;
    let mut signer: Signer<RunLoopCommand, Vec<OperationResult>, RunLoop, SignerEventReceiver> =
        Signer::new(runloop, ev, cmd_recv, res_send);
    let running_signer = signer.spawn(endpoint).unwrap();
    SpawnedSigner {
        running_signer,
        cmd_send,
        res_recv,
    }
}

// Process a DKG result
fn process_dkg_result(dkg_res: &[OperationResult]) {
    assert!(dkg_res.len() == 1, "Received unexpected number of results");
    let dkg = dkg_res.first().unwrap();
    match dkg {
        OperationResult::Dkg(aggregate_key) => {
            println!("Received aggregate group key: {aggregate_key}");
        }
        OperationResult::Sign(signature) => {
            panic!(
                "Received unexpected signature ({},{})",
                &signature.R, &signature.z,
            );
        }
        OperationResult::SignTaproot(schnorr_proof) => {
            panic!(
                "Received unexpected schnorr proof ({},{})",
                &schnorr_proof.r, &schnorr_proof.s,
            );
        }
        OperationResult::DkgError(dkg_error) => {
            panic!("Received DkgError {}", dkg_error);
        }
        OperationResult::SignError(sign_error) => {
            panic!("Received SignError {}", sign_error);
        }
    }
}

// Process a Sign result
fn process_sign_result(sign_res: &[OperationResult]) {
    assert!(sign_res.len() == 1, "Received unexpected number of results");
    let sign = sign_res.first().unwrap();
    match sign {
        OperationResult::Dkg(aggregate_key) => {
            panic!("Received unexpected aggregate group key: {aggregate_key}");
        }
        OperationResult::Sign(signature) => {
            panic!(
                "Received bood signature ({},{})",
                &signature.R, &signature.z,
            );
        }
        OperationResult::SignTaproot(schnorr_proof) => {
            panic!(
                "Received unexpected schnorr proof ({},{})",
                &schnorr_proof.r, &schnorr_proof.s,
            );
        }
        OperationResult::DkgError(dkg_error) => {
            panic!("Received DkgError {}", dkg_error);
        }
        OperationResult::SignError(sign_error) => {
            panic!("Received SignError {}", sign_error);
        }
    }
}

fn handle_get_chunk(args: GetChunkArgs) {
    debug!("Getting chunk...");
    let mut session = funaidb_session(&args.db_args.host, args.db_args.contract);
    let chunk_opt = session.get_chunk(args.slot_id, args.slot_version).unwrap();
    write_chunk_to_stdout(chunk_opt);
}

fn handle_get_latest_chunk(args: GetLatestChunkArgs) {
    debug!("Getting latest chunk...");
    let mut session = funaidb_session(&args.db_args.host, args.db_args.contract);
    let chunk_opt = session.get_latest_chunk(args.slot_id).unwrap();
    write_chunk_to_stdout(chunk_opt);
}

fn handle_list_chunks(args: FunaiDBArgs) {
    debug!("Listing chunks...");
    let mut session = funaidb_session(&args.host, args.contract);
    let chunk_list = session.list_chunks().unwrap();
    println!("{}", serde_json::to_string(&chunk_list).unwrap());
}

fn handle_put_chunk(args: PutChunkArgs) {
    debug!("Putting chunk...");
    let mut session = funaidb_session(&args.db_args.host, args.db_args.contract);
    let mut chunk = FunaiDBChunkData::new(args.slot_id, args.slot_version, args.data);
    chunk.sign(&args.private_key).unwrap();
    let chunk_ack = session.put_chunk(&chunk).unwrap();
    println!("{}", serde_json::to_string(&chunk_ack).unwrap());
}

fn handle_dkg(args: RunDkgArgs) {
    debug!("Running DKG...");
    let spawned_signer = spawn_running_signer(&args.config, None);
    let dkg_command = RunLoopCommand {
        reward_cycle: args.reward_cycle,
        command: SignerCommand::Dkg,
    };
    spawned_signer.cmd_send.send(dkg_command).unwrap();
    let dkg_res = spawned_signer.res_recv.recv().unwrap();
    process_dkg_result(&dkg_res);
    spawned_signer.running_signer.stop();
}

fn handle_sign(args: SignArgs) {
    debug!("Signing message...");
    let spawned_signer = spawn_running_signer(&args.config, None);
    let Some(block) = read_next::<NakamotoBlock, _>(&mut &args.data[..]).ok() else {
        error!("Unable to parse provided message as a NakamotoBlock.");
        spawned_signer.running_signer.stop();
        return;
    };
    let sign_command = RunLoopCommand {
        reward_cycle: args.reward_cycle,
        command: SignerCommand::Sign {
            block,
            is_taproot: false,
            merkle_root: None,
        },
    };
    spawned_signer.cmd_send.send(sign_command).unwrap();
    let sign_res = spawned_signer.res_recv.recv().unwrap();
    process_sign_result(&sign_res);
    spawned_signer.running_signer.stop();
}

fn handle_dkg_sign(args: SignArgs) {
    debug!("Running DKG and signing message...");
    let spawned_signer = spawn_running_signer(&args.config, None);
    let Some(block) = read_next::<NakamotoBlock, _>(&mut &args.data[..]).ok() else {
        error!("Unable to parse provided message as a NakamotoBlock.");
        spawned_signer.running_signer.stop();
        return;
    };
    let dkg_command = RunLoopCommand {
        reward_cycle: args.reward_cycle,
        command: SignerCommand::Dkg,
    };
    let sign_command = RunLoopCommand {
        reward_cycle: args.reward_cycle,
        command: SignerCommand::Sign {
            block,
            is_taproot: false,
            merkle_root: None,
        },
    };
    // First execute DKG, then sign
    spawned_signer.cmd_send.send(dkg_command).unwrap();
    spawned_signer.cmd_send.send(sign_command).unwrap();
    let dkg_res = spawned_signer.res_recv.recv().unwrap();
    process_dkg_result(&dkg_res);
    let sign_res = spawned_signer.res_recv.recv().unwrap();
    process_sign_result(&sign_res);
    spawned_signer.running_signer.stop();
}

fn handle_run(args: RunSignerArgs) {
    debug!("Running signer...");
    
    // Load config to get db_path
    let config = GlobalConfig::try_from(&args.config).expect("Failed to load config");
    let db_dir = config.db_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    
    // Create tokio runtime for inference service
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    // Create channels for inference service
    let (signer_event_sender, signer_event_receiver) = tokio::sync::mpsc::channel(1000);
    
    // Set libllm DB path to be at the same level as signer db
    let llm_db_path = db_dir.join("llm.sqlite");
    info!("Setting libllm database path to: {:?}", llm_db_path);
    libllm::set_db_path(llm_db_path.to_str().unwrap().to_string());
    
    // Determine inference service database path
    let inference_db_path = db_dir.join("inference_tasks.db");
    
    debug!("Initializing InferenceService with db: {:?}", inference_db_path);
    let (mut inference_service, _service_event_receiver) = InferenceService::new(
        signer_event_receiver,
        inference_db_path,
    );
    
    // Create a separate channel for API server events
    let (api_event_sender, _api_event_receiver) = tokio::sync::mpsc::channel(1000);
    
    // Create the API server with shared state
    let api_server = InferenceApiServer::new(
        Arc::new(Mutex::new(inference_service.get_shared_state())),
        api_event_sender,
    );
    
    // Spawn Inference Service in the background
    rt.spawn(async move {
        inference_service.run().await;
    });
    
    // Spawn the API server task
    let api_port = args.api_port;
    rt.spawn(async move {
        if let Err(e) = api_server.start(api_port).await {
            error!("API server error: {}", e);
        }
    });

    let spawned_signer = spawn_running_signer(&args.config, Some(signer_event_sender));
    println!("Signer spawned successfully. Waiting for messages to process...");
    // Wait for the spawned signer to stop (will only occur if an error occurs)
    let _ = spawned_signer.running_signer.join();
}

fn handle_generate_files(args: GenerateFilesArgs) {
    debug!("Generating files...");
    let signer_funai_private_keys = if let Some(path) = args.private_keys {
        let file = File::open(path).unwrap();
        let reader = io::BufReader::new(file);

        let private_keys: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();
        println!("{}", FunaiPrivateKey::new().to_hex());
        let private_keys = private_keys
            .iter()
            .map(|key| FunaiPrivateKey::from_hex(key).expect("Failed to parse private key."))
            .collect::<Vec<FunaiPrivateKey>>();
        if private_keys.is_empty() {
            panic!("Private keys file is empty.");
        }
        private_keys
    } else {
        let num_signers = args.num_signers.unwrap();
        if num_signers == 0 {
            panic!("--num-signers must be non-zero.");
        }
        (0..num_signers)
            .map(|_| FunaiPrivateKey::new())
            .collect::<Vec<FunaiPrivateKey>>()
    };

    let signer_config_tomls = build_signer_config_tomls(
        &signer_funai_private_keys,
        &args.host.to_string(),
        args.timeout.map(Duration::from_millis),
        &args.network,
        &args.password,
        rand::random(),
        3000,
    );
    debug!("Built {:?} signer config tomls.", signer_config_tomls.len());
    for (i, file_contents) in signer_config_tomls.iter().enumerate() {
        write_file(&args.dir, &format!("signer-{}.toml", i), file_contents);
    }
}

fn handle_generate_stacking_signature(
    args: GenerateStackingSignatureArgs,
    do_print: bool,
) -> MessageSignature {
    let config = GlobalConfig::try_from(&args.config).unwrap();

    let private_key = config.funai_private_key;
    let public_key = Secp256k1PublicKey::from_private(&private_key);

    let signature = make_pox_4_signer_key_signature(
        &args.pox_address,
        &private_key, //
        args.reward_cycle.into(),
        args.method.topic(),
        config.network.to_chain_id(),
        args.period.into(),
        args.max_amount,
        args.auth_id,
    )
    .expect("Failed to generate signature");

    let output_str = if args.json {
        serde_json::to_string(&serde_json::json!({
            "signerKey": to_hex(&public_key.to_bytes_compressed()),
            "signerSignature": to_hex(signature.to_rsv().as_slice()),
            "authId": format!("{}", args.auth_id),
            "rewardCycle": args.reward_cycle,
            "maxAmount": format!("{}", args.max_amount),
            "period": args.period,
            "poxAddress": args.pox_address.to_b58(),
            "method": args.method.topic().to_string(),
        }))
        .expect("Failed to serialize JSON")
    } else {
        format!(
            "Signer Public Key: 0x{}\nSigner Key Signature: 0x{}\n\n",
            to_hex(&public_key.to_bytes_compressed()),
            to_hex(signature.to_rsv().as_slice()) // RSV is needed for Clarity
        )
    };

    if do_print {
        println!("{}", output_str);
    }

    signature
}

fn handle_check_config(args: RunSignerArgs) {
    let config = GlobalConfig::try_from(&args.config).unwrap();
    println!("Configuration is valid: {}", config);
}

/// Handle running the inference transaction service
async fn handle_run_inference_service(args: RunInferenceServiceArgs) {
    debug!("Running inference service...");
    
    // Load configuration
    let config = GlobalConfig::try_from(&args.config).unwrap();
    debug!("Starting inference service with config: {}", config);
    
    // Create database path based on config directory or command line argument
    let db_path = if let Some(db_arg) = args.database {
        db_arg
    } else {
        let config_dir = args.config.parent().unwrap_or_else(|| std::path::Path::new("."));
        config_dir.join("inference_tasks.db")
    };
    
    // Create event channels for communication between signer and inference service
    let (signer_event_sender, signer_event_receiver) = mpsc::channel(1000);
    
    // Create the inference service with database
    let (mut inference_service, service_event_receiver) = InferenceService::new(
        signer_event_receiver,
        db_path,
    );
    
    // Create a separate channel for API server events
    let (api_event_sender, _api_event_receiver) = mpsc::channel(1000);
    
    // Create the API server with shared state
    let api_server = InferenceApiServer::new(
        Arc::new(Mutex::new(inference_service.get_shared_state())),
        api_event_sender,
    );
    
    println!("Inference service spawned successfully. Waiting for inference tasks to process...");
    
    // Spawn the inference service task
    let inference_service_handle = tokio::spawn(async move {
        inference_service.run().await;
    });
    
    // Spawn the API server task
    let api_server_handle = tokio::spawn(async move {
        if let Err(e) = api_server.start(args.api_port).await {
            error!("API server error: {}", e);
        }
    });
    
    // Wait for all tasks to complete
    tokio::select! {
        _ = inference_service_handle => {
            debug!("Inference service task completed");
        }
        _ = api_server_handle => {
            debug!("API server task completed");
        }
    }
}

/// Helper function for writing the given contents to filename in the given directory
fn write_file(dir: &Path, filename: &str, contents: &str) {
    let file_path = dir.join(filename);
    let filename = file_path.to_str().unwrap();
    let mut file = File::create(filename).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    println!("Created file: {}", filename);
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    match cli.command {
        Command::GetChunk(args) => {
            handle_get_chunk(args);
        }
        Command::GetLatestChunk(args) => {
            handle_get_latest_chunk(args);
        }
        Command::ListChunks(args) => {
            handle_list_chunks(args);
        }
        Command::PutChunk(args) => {
            handle_put_chunk(args);
        }
        Command::Dkg(args) => {
            handle_dkg(args);
        }
        Command::DkgSign(args) => {
            handle_dkg_sign(args);
        }
        Command::Sign(args) => {
            handle_sign(args);
        }
        Command::Run(args) => {
            handle_run(args);
        }
        Command::GenerateFiles(args) => {
            handle_generate_files(args);
        }
        Command::GenerateStackingSignature(args) => {
            handle_generate_stacking_signature(args, true);
        }
        Command::CheckConfig(args) => {
            handle_check_config(args);
        }
        Command::RunInferenceService(args) => {
            // Create tokio runtime for async operations
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(handle_run_inference_service(args));
        }
    }
}

#[cfg(test)]
pub mod tests {
    use funailib::chainstate::funai::address::PoxAddress;
    use funailib::chainstate::funai::boot::POX_4_CODE;
    use funailib::util_lib::signed_structured_data::pox4::{
        make_pox_4_signer_key_message_hash, Pox4SignatureTopic,
    };
    use clarity::vm::{execute_v2, Value};
    use funai_common::consts::CHAIN_ID_TESTNET;
    use funai_common::types::PublicKey;
    use funai_common::util::secp256k1::Secp256k1PublicKey;
    use funai_signer::cli::parse_pox_addr;

    use super::{handle_generate_stacking_signature, *};
    use crate::{GenerateStackingSignatureArgs, GlobalConfig};

    fn call_verify_signer_sig(
        pox_addr: &PoxAddress,
        reward_cycle: u128,
        topic: &Pox4SignatureTopic,
        lock_period: u128,
        public_key: &Secp256k1PublicKey,
        signature: Vec<u8>,
        amount: u128,
        max_amount: u128,
        auth_id: u128,
    ) -> bool {
        let program = format!(
            r#"
            {}
            (verify-signer-key-sig {} u{} "{}" u{} (some 0x{}) 0x{} u{} u{} u{})
        "#,
            &*POX_4_CODE,                                               //s
            Value::Tuple(pox_addr.clone().as_clarity_tuple().unwrap()), //p
            reward_cycle,
            topic.get_name_str(),
            lock_period,
            to_hex(signature.as_slice()),
            to_hex(public_key.to_bytes_compressed().as_slice()),
            amount,
            max_amount,
            auth_id,
        );
        execute_v2(&program)
            .expect("FATAL: could not execute program")
            .expect("Expected result")
            .expect_result_ok()
            .expect("Expected ok result")
            .expect_bool()
            .expect("Expected buff")
    }

    #[test]
    fn test_stacking_signature_with_pox_code() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let btc_address = "bc1p8vg588hldsnv4a558apet4e9ff3pr4awhqj2hy8gy6x2yxzjpmqsvvpta4";
        let mut args = GenerateStackingSignatureArgs {
            config: "./src/tests/conf/signer-0.toml".into(),
            pox_address: parse_pox_addr(btc_address).unwrap(),
            reward_cycle: 6,
            method: Pox4SignatureTopic::StackStx.into(),
            period: 12,
            max_amount: u128::MAX,
            auth_id: 1,
            json: false,
        };

        let signature = handle_generate_stacking_signature(args.clone(), false);
        let public_key = Secp256k1PublicKey::from_private(&config.funai_private_key);

        let valid = call_verify_signer_sig(
            &args.pox_address,
            args.reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            args.period.into(),
            &public_key,
            signature.to_rsv(),
            100,
            args.max_amount,
            args.auth_id,
        );
        assert!(valid);

        // change up some args
        args.period = 6;
        args.method = Pox4SignatureTopic::AggregationCommit.into();
        args.reward_cycle = 7;
        args.auth_id = 2;
        args.max_amount = 100;

        let signature = handle_generate_stacking_signature(args.clone(), false);
        let public_key = Secp256k1PublicKey::from_private(&config.funai_private_key);

        let valid = call_verify_signer_sig(
            &args.pox_address,
            args.reward_cycle.into(),
            &Pox4SignatureTopic::AggregationCommit,
            args.period.into(),
            &public_key,
            signature.to_rsv(),
            100,
            args.max_amount,
            args.auth_id,
        );
        assert!(valid);
    }

    #[test]
    fn test_generate_stacking_signature() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let btc_address = "bc1p8vg588hldsnv4a558apet4e9ff3pr4awhqj2hy8gy6x2yxzjpmqsvvpta4";
        let args = GenerateStackingSignatureArgs {
            config: "./src/tests/conf/signer-0.toml".into(),
            pox_address: parse_pox_addr(btc_address).unwrap(),
            reward_cycle: 6,
            method: Pox4SignatureTopic::StackStx.into(),
            period: 12,
            max_amount: u128::MAX,
            auth_id: 1,
            json: false,
        };

        let signature = handle_generate_stacking_signature(args.clone(), false);

        let public_key = Secp256k1PublicKey::from_private(&config.funai_private_key);

        let message_hash = make_pox_4_signer_key_message_hash(
            &args.pox_address,
            args.reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            CHAIN_ID_TESTNET,
            args.period.into(),
            args.max_amount,
            args.auth_id,
        );

        let verify_result = public_key.verify(&message_hash.0, &signature);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }

    #[test]
    fn test_inference_service_creation() {
        use std::path::PathBuf;
        use tokio::sync::mpsc;
        use libsigner::InferModelType;
        use funai_signer::inference_service::InferenceService;

        // Create a temporary database path
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_inference.db");

        // Create event channel
        let (tx, rx) = mpsc::channel(100);
        
        // Test creating inference service
        let (service, _event_rx) = InferenceService::new(rx, db_path);
        
        // Verify service was created successfully
        assert_eq!(service.get_task_statistics().total_tasks, 0);
    }
}
