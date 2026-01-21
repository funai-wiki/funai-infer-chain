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
use libsigner::{RunningSigner, Signer as SignerTrait, SignerEventReceiver, SignerSession, FunaiDBSession, SignerEvent};
use libfunaidb::FunaiDBChunkData;
use slog::{slog_debug, slog_error, slog_info};
use funai_common::codec::FunaiMessageCodec;
use funai_common::types::chainstate::FunaiPrivateKey;
use funai_common::util::hash::{to_hex, hex_bytes};
use funai_common::util::secp256k1::{MessageSignature, Secp256k1PublicKey};
use funai_common::{debug, error, info};
use funai_signer::cli::{
    Cli, Command, GenerateFilesArgs, GenerateStackingSignatureArgs, GetChunkArgs,
    GetLatestChunkArgs, PutChunkArgs, RunDkgArgs, RunSignerArgs, FunaiDBArgs,
    RunInferenceServiceArgs, SignArgs
};
use funai_signer::config::{build_signer_config_tomls, GlobalConfig};
use funai_signer::runloop::{RunLoop, RunLoopCommand};
use funai_signer::signer::{Command as SignerCommand, Signer};
use funai_signer::inference_service::InferenceService;
use funai_signer::inference_api::InferenceApiServer;
use wsts::state_machine::OperationResult;

/// Represents a spawned signer
pub struct SpawnedSigner {
    /// handle to join the spawned thread
    pub running_signer: RunningSigner<SignerEventReceiver, Vec<OperationResult>>,
    /// handle to send commands to the signer
    pub cmd_send: Sender<RunLoopCommand>,
    /// handle to receive results from the signer
    pub res_recv: Receiver<Vec<OperationResult>>,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => handle_run(args),
        Command::GenerateFiles(args) => handle_generate_files(args),
        Command::GenerateStackingSignature(args) => {
            let signature = handle_generate_stacking_signature(args, true);
            println!("{}", to_hex(&signature.0));
        }
        Command::Dkg(args) => handle_run_dkg(args),
        Command::Sign(args) => handle_run_sign(args),
        Command::ListChunks(args) => handle_list_chunks(args),
        Command::GetChunk(args) => handle_get_chunk_args(args),
        Command::GetLatestChunk(args) => handle_get_latest_chunk_args(args),
        Command::PutChunk(args) => handle_put_chunk_args(args),
        Command::RunInferenceService(args) => handle_run_inference_service(args),
        _ => {
            println!("Command not implemented yet");
        }
    }
}

fn spawn_running_signer(path: &PathBuf, inference_task_sender: Option<tokio::sync::mpsc::Sender<SignerEvent>>) -> SpawnedSigner {
    let config = GlobalConfig::try_from(path).unwrap();
    let endpoint = config.endpoint;
    info!("Starting signer with config: {:?}", config);
    let (cmd_send, cmd_recv) = channel();
    let (res_send, res_recv) = channel();
    let ev = SignerEventReceiver::new(config.network.is_mainnet());
    let mut runloop = RunLoop::from(config);
    runloop.inference_task_sender = inference_task_sender;
    let signer: libsigner::Signer<RunLoopCommand, Vec<OperationResult>, RunLoop, SignerEventReceiver> =
        SignerTrait::new(runloop, ev, cmd_recv, res_send);
    let mut signer = signer;
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
        OperationResult::Sign(signature) => {
            println!("Received signature (R,z) = ({},{})", &signature.R, &signature.z);
        }
        OperationResult::SignTaproot(schnorr_proof) => {
            println!(
                "Received schnorr proof (r,s) = ({},{})",
                &schnorr_proof.r, &schnorr_proof.s
            );
        }
        OperationResult::Dkg(aggregate_key) => {
            panic!("Received unexpected aggregate group key: {aggregate_key}");
        }
        OperationResult::DkgError(dkg_error) => {
            panic!("Received DkgError {}", dkg_error);
        }
        OperationResult::SignError(sign_error) => {
            panic!("Received SignError {}", sign_error);
        }
    }
}

fn handle_run_dkg(args: RunDkgArgs) {
    let spawned_signer = spawn_running_signer(&args.config, None);
    let dkg_command = RunLoopCommand {
        command: SignerCommand::Dkg,
        reward_cycle: args.reward_cycle,
    };
    spawned_signer.cmd_send.send(dkg_command).unwrap();
    let dkg_res = spawned_signer.res_recv.recv().unwrap();
    process_dkg_result(&dkg_res);
    spawned_signer.running_signer.stop();
}

fn handle_run_sign(args: SignArgs) {
    let spawned_signer = spawn_running_signer(&args.config, None);
    let dkg_command = RunLoopCommand {
        command: SignerCommand::Dkg,
        reward_cycle: args.reward_cycle,
    };
    let sign_command = RunLoopCommand {
        command: SignerCommand::Sign {
            is_taproot: false,
            block: NakamotoBlock::consensus_deserialize(&mut hex_bytes(&to_hex(&args.data)).unwrap().as_slice())
                .unwrap(),
            merkle_root: None,
        },
        reward_cycle: args.reward_cycle,
    };
    // First execute DKG, then sign
    spawned_signer.cmd_send.send(dkg_command).unwrap();
    let dkg_res = spawned_signer.res_recv.recv().unwrap();
    process_dkg_result(&dkg_res);
    spawned_signer.cmd_send.send(sign_command).unwrap();
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
    
    // Set the signer's private key for encryption/decryption
    {
        use funai_common::address::AddressHashMode;
        use funai_common::types::chainstate::FunaiAddress;
        use funailib::chainstate::funai::{FunaiPublicKey, C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
        
        let private_key = config.funai_private_key.clone();
        let public_key = Secp256k1PublicKey::from_private(&private_key);
        let signer_address = FunaiAddress::from_public_keys(
            if config.network.is_mainnet() {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG
            } else {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG
            },
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![FunaiPublicKey::from_slice(
                &public_key.to_bytes_compressed()
            ).expect("Invalid public key")],
        ).expect("Failed to create signer address");
        
        // Set signer key on the inference service (modifies internal state)
        inference_service.set_signer_key(private_key, signer_address.to_string());
        info!("Signer encryption key configured for address: {}", signer_address);
    }
    
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

fn handle_run_inference_service(args: RunInferenceServiceArgs) {
    debug!("Running inference service...");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_, signer_event_receiver) = tokio::sync::mpsc::channel(1000);
    let db_path = args.database.unwrap_or_else(|| PathBuf::from("inference_tasks.db"));
    let (mut inference_service, _) = InferenceService::new(signer_event_receiver, db_path);
    let (api_event_sender, _) = tokio::sync::mpsc::channel(1000);
    let api_server = InferenceApiServer::new(
        Arc::new(Mutex::new(inference_service.get_shared_state())),
        api_event_sender,
    );
    rt.spawn(async move {
        inference_service.run().await;
    });
    rt.block_on(async {
        if let Err(e) = api_server.start(args.api_port).await {
            error!("API server error: {}", e);
        }
    });
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
        &private_key,
        args.reward_cycle as u128,
        &args.method.topic(),
        config.network.to_chain_id(),
        args.period as u128,
        args.max_amount,
        args.auth_id,
    )
    .expect("Failed to generate signature");

    if do_print {
        println!("{}", to_hex(&signature.0));
    }

    signature
}

fn handle_list_chunks(args: FunaiDBArgs) {
    let rpc_socket = args.host;
    let contract_id = args.contract;
    let mut session = FunaiDBSession::new(&rpc_socket, contract_id);
    let res = session.list_chunks().unwrap();
    println!("Metadata listing: {:?}", res);
}

fn handle_get_chunk_args(args: GetChunkArgs) {
    let mut session = FunaiDBSession::new(&args.db_args.host, args.db_args.contract);
    let res = session
        .get_chunks(&[(args.slot_id, args.slot_version)])
        .unwrap();
    let chunk = res.first().unwrap();
    match chunk {
        Some(data) => println!("{}", to_hex(data)),
        None => println!("Chunk not found"),
    }
}

fn handle_get_latest_chunk_args(args: GetLatestChunkArgs) {
    let mut session = FunaiDBSession::new(&args.db_args.host, args.db_args.contract);
    let res = session.get_latest_chunks(&[args.slot_id]).unwrap();
    let chunk = res.first().unwrap();
    match chunk {
        Some(data) => println!("{}", to_hex(data)),
        None => println!("Chunk not found"),
    }
}

fn handle_put_chunk_args(args: PutChunkArgs) {
    let mut session = FunaiDBSession::new(&args.db_args.host, args.db_args.contract);
    let mut chunk = FunaiDBChunkData::new(
        args.slot_id,
        args.slot_version,
        args.data,
    );
    chunk.sign(&args.private_key).unwrap();
    let res = session.put_chunk(&chunk).unwrap();
    println!("Chunk put successful: {:?}", res);
}

fn write_file(dir: &PathBuf, filename: &str, contents: &str) {
    let path = dir.join(filename);
    let mut file = File::create(path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
}
