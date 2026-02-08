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
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Instant;

use tokio::sync::mpsc::Sender as TokioSender;

use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature as K256Signature, SigningKey};
use k256::EncodedPoint;
use k256::sha2::{Sha256, Digest};
use chrono::Utc;

use funailib::chainstate::burn::ConsensusHashExtensions;
use funailib::chainstate::nakamoto::signer_set::NakamotoSigners;
use funailib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockVote};
use funailib::chainstate::funai::boot::SIGNERS_VOTING_FUNCTION_NAME;
use funailib::chainstate::funai::{FunaiTransaction, TransactionPayload};
use funailib::net::api::postblock_proposal::{BlockValidateResponse, ValidateRejectCode};
use hashbrown::HashSet;
use libsigner::{
    BlockProposalSigners, BlockRejection, BlockResponse, MessageSlotID, RejectCode, SignerEvent,
    SignerMessage, SignerEndpointAnnouncement,
};
use funai_common::util::secp256k1::Secp256k1PublicKey;
use serde_derive::{Deserialize, Serialize};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use tokio::runtime::Runtime;
use funai_common::codec::{read_next, FunaiMessageCodec};
use funai_common::types::chainstate::{ConsensusHash, FunaiAddress};
use funai_common::types::{PrivateKey, FunaiEpochId};
use funai_common::util::hash::Sha512Trunc256Sum;
use funai_common::{debug, error, info, warn};
use wsts::common::{MerkleRoot, Signature};
use wsts::curve::keys::PublicKey;
use wsts::curve::point::Point;
use wsts::net::{Message, NonceRequest, Packet, SignatureShareRequest};
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::coordinator::{
    Config as CoordinatorConfig, Coordinator, State as CoordinatorState,
};
use wsts::state_machine::signer::Signer as SignerStateMachine;
use wsts::state_machine::{OperationResult, SignError};
use wsts::traits::Signer as _;
use wsts::v2;

use crate::client::{retry_with_exponential_backoff, ClientError, FunaiDB, FunaiClient};
use crate::config::SignerConfig;
use crate::coordinator::CoordinatorSelector;
use crate::signerdb::SignerDb;

/// The signer FunaiDB slot ID, purposefully wrapped to prevent conflation with SignerID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, PartialOrd, Ord)]
pub struct SignerSlotID(pub u32);

impl std::fmt::Display for SignerSlotID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Additional Info about a proposed block
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BlockInfo {
    /// The block we are considering
    pub block: NakamotoBlock,
    /// Our vote on the block if we have one yet
    pub vote: Option<NakamotoBlockVote>,
    /// Whether the block contents are valid
    valid: Option<bool>,
    /// Invalid transactions discovered during validation
    invalid_txids: Vec<String>,
    /// The associated packet nonce request if we have one
    nonce_request: Option<NonceRequest>,
    /// Whether this block is already being signed over
    pub signed_over: bool,
}

impl BlockInfo {
    /// Create a new BlockInfo
    pub const fn new(block: NakamotoBlock) -> Self {
        Self {
            block,
            vote: None,
            valid: None,
            invalid_txids: Vec::new(),
            nonce_request: None,
            signed_over: false,
        }
    }

    /// Create a new BlockInfo with an associated nonce request packet
    pub const fn new_with_request(block: NakamotoBlock, nonce_request: NonceRequest) -> Self {
        Self {
            block,
            vote: None,
            valid: None,
            invalid_txids: Vec::new(),
            nonce_request: Some(nonce_request),
            signed_over: true,
        }
    }

    /// Return the block's signer signature hash
    pub fn signer_signature_hash(&self) -> Sha512Trunc256Sum {
        self.block.header.signer_signature_hash()
    }
}

/// Which signer operation to perform
#[derive(PartialEq, Clone, Debug)]
pub enum Command {
    /// Generate a DKG aggregate public key
    Dkg,
    /// Sign a message
    Sign {
        /// The block to sign over
        block: NakamotoBlock,
        /// Whether to make a taproot signature
        is_taproot: bool,
        /// Taproot merkle root
        merkle_root: Option<MerkleRoot>,
    },
}

/// The Signer state
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum State {
    /// The signer is idle, waiting for messages and commands
    Idle,
    /// The signer is executing a DKG or Sign round
    OperationInProgress,
}

/// The funai signer registered for the reward cycle
pub struct Signer {
    /// The coordinator for inbound messages for a specific reward cycle
    pub coordinator: FireCoordinator<v2::Aggregator>,
    /// The signing round used to sign messages for a specific reward cycle
    pub state_machine: SignerStateMachine<v2::Signer>,
    /// the state of the signer
    pub state: State,
    /// Received Commands that need to be processed
    pub commands: VecDeque<Command>,
    /// The funaidb client
    pub funaidb: FunaiDB,
    /// Whether the signer is a mainnet signer or not
    pub mainnet: bool,
    /// The signer id
    pub signer_id: u32,
    /// The signer slot ids for the signers in the reward cycle
    pub signer_slot_ids: Vec<SignerSlotID>,
    /// The addresses of other signers
    pub signer_addresses: Vec<FunaiAddress>,
    /// The signer slot ids for the signers in the NEXT reward cycle
    pub next_signer_slot_ids: Vec<SignerSlotID>,
    /// The addresses of the signers for the NEXT reward cycle
    pub next_signer_addresses: Vec<FunaiAddress>,
    /// The reward cycle this signer belongs to
    pub reward_cycle: u64,
    /// The tx fee in uSTX to use if the epoch is pre Nakamoto (Epoch 3.0)
    pub tx_fee_ustx: u64,
    /// The coordinator info for the signer
    pub coordinator_selector: CoordinatorSelector,
    /// The approved key registered to the contract
    pub approved_aggregate_public_key: Option<Point>,
    /// The current active miner's key (if we know it!)
    pub miner_key: Option<PublicKey>,
    /// Signer DB path
    pub db_path: PathBuf,
    /// SignerDB for state management
    pub signer_db: SignerDb,
    /// Supported model names for inference validation
    pub support_models: Vec<String>,
    /// The Funai private key for signing requests
    pub funai_private_key: funai_common::types::chainstate::FunaiPrivateKey,
    /// Channel to send inference tasks to the inference service
    pub inference_task_sender: Option<TokioSender<SignerEvent>>,
    /// This signer's HTTP endpoint URL for API requests
    pub signer_endpoint: Option<String>,
    /// Whether endpoint has been broadcasted
    pub endpoint_broadcasted: bool,
    /// Registry of other signers' endpoints (discovered via funaiDB)
    pub signer_registry: crate::encryption::SignerRegistry,
}

impl std::fmt::Display for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cycle #{} Signer #{}(C:{})",
            self.reward_cycle,
            self.signer_id,
            self.coordinator_selector.get_coordinator().0,
        )
    }
}

impl Signer {
    /// Return the signing coordinator. In the active reward cycle, this is the miner.
    fn get_signing_coordinator(&self, current_reward_cycle: u64) -> (Option<u32>, PublicKey) {
        if self.reward_cycle == current_reward_cycle {
            if let Some(ref cur_miner) = self.miner_key {
                return (None, cur_miner.clone());
            }
            // If we don't have a miner key yet, we're likely in the early phase of the cycle.
            // Log a debug message instead of an error, as this is expected during DKG/initialization.
            debug!(
                "Signer #{}: Miner key not yet known in cycle {}. Falling back to signer-based coordinator.",
                self.signer_id, self.reward_cycle
            );
        }
        let selected = self.coordinator_selector.get_coordinator();
        (Some(selected.0), selected.1)
    }

    /// Return the DKG coordinator. This is always a signer.
    fn get_dkg_coordinator(&self) -> (u32, PublicKey) {
        self.coordinator_selector.get_coordinator()
    }
}

impl From<SignerConfig> for Signer {
    fn from(signer_config: SignerConfig) -> Self {
        let funaidb = FunaiDB::from(&signer_config);

        let num_signers = signer_config
            .signer_entries
            .count_signers()
            .expect("FATAL: Too many registered signers to fit in a u32");
        let num_keys = signer_config
            .signer_entries
            .count_keys()
            .expect("FATAL: Too many key ids to fit in a u32");
        let threshold = signer_config
            .signer_entries
            .get_signing_threshold()
            .expect("FATAL: Too many key ids to fit in a u32");
        let dkg_threshold = signer_config
            .signer_entries
            .get_dkg_threshold()
            .expect("FATAL: Too many key ids to fit in a u32");

        let coordinator_config = CoordinatorConfig {
            threshold,
            dkg_threshold,
            num_signers,
            num_keys,
            message_private_key: signer_config.ecdsa_private_key,
            dkg_public_timeout: signer_config.dkg_public_timeout,
            dkg_private_timeout: signer_config.dkg_private_timeout,
            dkg_end_timeout: signer_config.dkg_end_timeout,
            nonce_timeout: signer_config.nonce_timeout,
            sign_timeout: signer_config.sign_timeout,
            signer_key_ids: signer_config.signer_entries.coordinator_key_ids,
            signer_public_keys: signer_config.signer_entries.signer_public_keys,
        };

        let coordinator = FireCoordinator::new(coordinator_config);
        let coordinator_selector =
            CoordinatorSelector::from(signer_config.signer_entries.public_keys.clone());

        debug!(
            "Reward cycle #{} Signer #{}: initial coordinator is signer {}",
            signer_config.reward_cycle,
            signer_config.signer_id,
            coordinator_selector.get_coordinator().0
        );
        let signer_db =
            SignerDb::new(&signer_config.db_path).expect("Failed to connect to signer Db");

        let mut state_machine = SignerStateMachine::new(
            threshold,
            num_signers,
            num_keys,
            signer_config.signer_id,
            signer_config.key_ids,
            signer_config.ecdsa_private_key,
            signer_config.signer_entries.public_keys,
        );

        if let Some(state) = signer_db
            .get_signer_state(signer_config.reward_cycle)
            .expect("Failed to load signer state")
        {
            debug!(
                "Reward cycle #{} Signer #{}: Loading signer",
                signer_config.reward_cycle, signer_config.signer_id
            );
            state_machine.signer = v2::Signer::load(&state);
        }

        Self {
            coordinator,
            state_machine,
            state: State::Idle,
            commands: VecDeque::new(),
            funaidb,
            mainnet: signer_config.mainnet,
            signer_id: signer_config.signer_id,
            signer_addresses: signer_config
                .signer_entries
                .signer_ids
                .into_keys()
                .collect(),
            signer_slot_ids: signer_config.signer_slot_ids.clone(),
            next_signer_slot_ids: vec![],
            next_signer_addresses: vec![],
            reward_cycle: signer_config.reward_cycle,
            tx_fee_ustx: signer_config.tx_fee_ustx,
            coordinator_selector,
            approved_aggregate_public_key: None,
            miner_key: None,
            db_path: signer_config.db_path.clone(),
            signer_db,
            support_models: signer_config.support_models,
            funai_private_key: signer_config.funai_private_key,
            inference_task_sender: None,
            signer_endpoint: None,
            endpoint_broadcasted: false,
            signer_registry: crate::encryption::SignerRegistry::new(),
        }
    }
}

impl Signer {
    /// Generate signature headers for a request
    /// Returns (pubkey_hex, signature_hex, timestamp)
    fn generate_signature_headers(
        &self,
        path: &str,
        body_json: &str,
    ) -> Result<(String, String, String), String> {
        // Convert FunaiPrivateKey to k256 SigningKey
        let priv_key_bytes = self.funai_private_key.to_bytes();
        // Remove the last byte if it's a type marker (65 bytes -> 32 bytes)
        let raw_priv = if priv_key_bytes.len() > 32 {
            &priv_key_bytes[..32]
        } else if priv_key_bytes.len() == 32 {
            &priv_key_bytes[..]
        } else {
            return Err("Invalid private key length".to_string());
        };
        
        let signing_key = SigningKey::from_slice(raw_priv)
            .map_err(|e| format!("Failed to create signing key: {}", e))?;
        
        // Get compressed public key
        let pubkey_point: EncodedPoint = signing_key.verifying_key().to_encoded_point(true);
        let pubkey_hex = hex::encode(pubkey_point.as_bytes());
        
        // Generate timestamp and message
        let timestamp = Utc::now().timestamp().to_string();
        let message = format!("{}:{}:{}", timestamp, path, body_json);
        
        // Sign the message
        let digest = Sha256::digest(message.as_bytes());
        let signature: K256Signature = signing_key.sign_prehash(&digest)
            .map_err(|e| format!("Failed to sign message: {}", e))?;
        let sig_der_hex = hex::encode(signature.to_bytes());
        
        Ok((pubkey_hex, sig_der_hex, timestamp))
    }

    /// Refresh the coordinator selector
    pub fn refresh_coordinator(&mut self) {
        // TODO: do not use an empty consensus hash
        let pox_consensus_hash = ConsensusHash::empty();
        let old_coordinator_id = self.coordinator_selector.get_coordinator().0;
        let updated_coordinator_id = self
            .coordinator_selector
            .refresh_coordinator(&pox_consensus_hash);
        if old_coordinator_id != updated_coordinator_id {
            debug!(
                "{self}: Coordinator updated. Resetting state to Idle.";
                "old_coordinator_id" => {old_coordinator_id},
                "updated_coordinator_id" => {updated_coordinator_id},
                "pox_consensus_hash" => %pox_consensus_hash
            );
            self.coordinator.state = CoordinatorState::Idle;
            self.state = State::Idle;
        }
    }

    /// Finish an operation and update the coordinator selector accordingly
    fn finish_operation(&mut self) {
        self.state = State::Idle;
        self.coordinator_selector.last_message_time = None;
    }

    /// Update operation
    fn update_operation(&mut self) {
        self.state = State::OperationInProgress;
        self.coordinator_selector.last_message_time = Some(Instant::now());
    }

    /// Execute the given command and update state accordingly
    fn execute_command(&mut self, funai_client: &FunaiClient, command: &Command) {
        match command {
            Command::Dkg => {
                if self.approved_aggregate_public_key.is_some() {
                    debug!("Reward cycle #{} Signer #{}: Already have an aggregate key. Ignoring DKG command.", self.reward_cycle, self.signer_id);
                    return;
                }
                let vote_round = match retry_with_exponential_backoff(|| {
                    funai_client
                        .get_last_round(self.reward_cycle)
                        .map_err(backoff::Error::transient)
                }) {
                    Ok(last_round) => last_round,
                    Err(e) => {
                        error!("{self}: Unable to perform DKG. Failed to get last round from funai node: {e:?}");
                        return;
                    }
                };
                // The dkg id will increment internally following "start_dkg_round" so do not increment it here
                self.coordinator.current_dkg_id = vote_round.unwrap_or(0);
                info!(
                    "{self}: Starting DKG vote";
                    "round" => self.coordinator.current_dkg_id.wrapping_add(1),
                    "cycle" => self.reward_cycle,
                );
                match self.coordinator.start_dkg_round() {
                    Ok(msg) => {
                        let ack = self.funaidb.send_message_with_retry(msg.into());
                        debug!("{self}: ACK: {ack:?}",);
                    }
                    Err(e) => {
                        error!("{self}: Failed to start DKG: {e:?}",);
                        return;
                    }
                }
            }
            Command::Sign {
                block,
                is_taproot,
                merkle_root,
            } => {
                if self.approved_aggregate_public_key.is_none() {
                    debug!("{self}: Cannot sign a block without an approved aggregate public key. Ignore it.");
                    return;
                }
                let signer_signature_hash = block.header.signer_signature_hash();
                let mut block_info = self
                    .signer_db
                    .block_lookup(self.reward_cycle, &signer_signature_hash)
                    .unwrap_or_else(|_| Some(BlockInfo::new(block.clone())))
                    .unwrap_or_else(|| BlockInfo::new(block.clone()));
                if block_info.signed_over {
                    debug!("{self}: Received a sign command for a block we are already signing over. Ignore it.");
                    return;
                }
                info!("{self}: Signing block";
                         "block_consensus_hash" => %block.header.consensus_hash,
                         "block_height" => block.header.chain_length,
                         "pre_sign_block_id" => %block.block_id(),
                );
                match self.coordinator.start_signing_round(
                    &block.serialize_to_vec(),
                    *is_taproot,
                    *merkle_root,
                ) {
                    Ok(msg) => {
                        let ack = self.funaidb.send_message_with_retry(msg.into());
                        debug!("{self}: ACK: {ack:?}",);
                        block_info.signed_over = true;
                        self.signer_db
                            .insert_block(self.reward_cycle, &block_info)
                            .unwrap_or_else(|e| {
                                error!("{self}: Failed to insert block in DB: {e:?}");
                            });
                    }
                    Err(e) => {
                        error!("{self}: Failed to start signing block: {e:?}",);
                        return;
                    }
                }
            }
        }
        self.update_operation();
    }

    /// Attempt to process the next command in the queue, and update state accordingly
    pub fn process_next_command(
        &mut self,
        funai_client: &FunaiClient,
        current_reward_cycle: u64,
    ) {
        let command = self.commands.front();
        let coordinator_id = match command {
            Some(Command::Dkg) => Some(self.get_dkg_coordinator().0),
            _ => self.get_signing_coordinator(current_reward_cycle).0,
        };
        match &self.state {
            State::Idle => {
                if coordinator_id != Some(self.signer_id) {
                    debug!(
                        "{self}: Coordinator is {coordinator_id:?}. Will not process any commands...",
                    );
                    return;
                }
                if let Some(command) = self.commands.pop_front() {
                    self.execute_command(funai_client, &command);
                } else {
                    debug!("{self}: Nothing to process. Waiting for command...",);
                }
            }
            State::OperationInProgress => {
                // We cannot execute the next command until the current one is finished...
                debug!("{self}: Waiting for coordinator {coordinator_id:?} operation to finish. Coordinator state = {:?}", self.coordinator.state);
            }
        }
    }

    /// Handle the block validate response returned from our prior calls to submit a block for validation
    fn handle_block_validate_response(
        &mut self,
        funai_client: &FunaiClient,
        block_validate_response: &BlockValidateResponse,
        res: Sender<Vec<OperationResult>>,
        current_reward_cycle: u64,
    ) {
        let coordinator_id = self.get_signing_coordinator(current_reward_cycle).0;
        let mut block_info = match block_validate_response {
            BlockValidateResponse::Ok(block_validate_ok) => {
                let signer_signature_hash = block_validate_ok.signer_signature_hash;
                // For mutability reasons, we need to take the block_info out of the map and add it back after processing
                let mut block_info = match self
                    .signer_db
                    .block_lookup(self.reward_cycle, &signer_signature_hash)
                {
                    Ok(Some(block_info)) => block_info,
                    Ok(None) => {
                        // We have not seen this block before. Why are we getting a response for it?
                        debug!("{self}: Received a block validate response for a block we have not seen before. Ignoring...");
                        return;
                    }
                    Err(e) => {
                        error!("{self}: Failed to lookup block in signer db: {e:?}",);
                        return;
                    }
                };
                match self.verify_block_transactions(funai_client, &block_info.block) {
                    Ok(_) => {
                        block_info.valid = Some(true);
                        block_info.invalid_txids = Vec::new();
                    }
                    Err(invalid_txs) => {
                        // New policy: Accept block even with failed Infer transactions.
                        // Failed Infer transactions will be processed on-chain but marked as failed
                        // (no funds transferred, user loses only tx fee).
                        // This prevents one failed Infer tx from blocking the entire block.
                        let mut sorted_invalid_txs = invalid_txs.clone();
                        sorted_invalid_txs.sort();
                        block_info.invalid_txids = sorted_invalid_txs.clone();
                        
                        if !sorted_invalid_txs.is_empty() {
                            // Log warning but still accept the block
                            warn!("{self}: Block contains {} invalid Infer transactions, but accepting block anyway: {:?}", 
                                sorted_invalid_txs.len(), sorted_invalid_txs);
                            // Notify miners about invalid transactions (informational only)
                            let filter = BlockResponse::filter(signer_signature_hash, sorted_invalid_txs);
                            if let Err(e) = self.funaidb.send_message_with_retry(filter.into()) {
                                warn!("{self}: Failed to send block filter to funai-db: {e:?}");
                            }
                        }
                        
                        // Accept the block - failed Infer txs will be handled on-chain
                        block_info.valid = Some(true);
                    }
                }
                self.signer_db
                    .insert_block(self.reward_cycle, &block_info)
                    .unwrap_or_else(|_| panic!("{self}: Failed to insert block in DB"));
                info!(
                    "{self}: Treating block validation for block {} as valid: {:?}",
                    &block_info.block.block_id(),
                    block_info.valid
                );
                block_info
            }
            BlockValidateResponse::Reject(block_validate_reject) => {
                let signer_signature_hash = block_validate_reject.signer_signature_hash;
                let mut block_info = match self
                    .signer_db
                    .block_lookup(self.reward_cycle, &signer_signature_hash)
                {
                    Ok(Some(block_info)) => block_info,
                    Ok(None) => {
                        // We have not seen this block before. Why are we getting a response for it?
                        debug!("{self}: Received a block validate response for a block we have not seen before. Ignoring...");
                        return;
                    }
                    Err(e) => {
                        error!("{self}: Failed to lookup block in signer db: {e:?}");
                        return;
                    }
                };
                block_info.valid = Some(false);
                // Submit a rejection response to the .signers contract for miners
                // to observe so they know to send another block and to prove signers are doing work);
                warn!("{self}: Broadcasting a block rejection due to funai node validation failure...");
                let block_rejection = BlockRejection::new(
                    signer_signature_hash,
                    RejectCode::ValidationFailed(block_validate_reject.reason_code.clone()),
                );
                if let Err(e) = self
                    .funaidb
                    .send_message_with_retry(block_rejection.into())
                {
                    warn!("{self}: Failed to send block rejection to funai-db: {e:?}",);
                }
                block_info
            }
            BlockValidateResponse::Filter(filter) => {
                let signer_signature_hash = filter.signer_signature_hash;
                let mut block_info = match self
                    .signer_db
                    .block_lookup(self.reward_cycle, &signer_signature_hash)
                {
                    Ok(Some(block_info)) => block_info,
                    Ok(None) => {
                        debug!("{self}: Received a block validate filter response for a block we have not seen before. Ignoring...");
                        return;
                    }
                    Err(e) => {
                        error!("{self}: Failed to lookup block in signer db: {e:?}");
                        return;
                    }
                };
                
                // Mark as invalid for now, but we've sent the filter info to the miner
                block_info.valid = Some(false);
                block_info.invalid_txids = filter.invalid_transactions.clone();
                
                // Submit a rejection response with BadTransactions code
                warn!("{self}: Broadcasting a block filter due to funai node validation failure (bad transactions)...");
                let block_rejection = BlockRejection::new(
                    signer_signature_hash,
                    RejectCode::ValidationFailed(ValidateRejectCode::BadTransactions),
                );
                if let Err(e) = self
                    .funaidb
                    .send_message_with_retry(block_rejection.into())
                {
                    warn!("{self}: Failed to send block rejection (filter) to funai-db: {e:?}",);
                }
                block_info
            }
        };
        if let Some(mut nonce_request) = block_info.nonce_request.take() {
            debug!("{self}: Received a block validate response from the funai node for a block we already received a nonce request for. Responding to the nonce request...");
            // We have received validation from the funai node. Determine our vote and update the request message
            self.determine_vote(&mut block_info, &mut nonce_request);
            // Persist the updated block_info (with vote) to DB immediately.
            // This is critical: when the miner later sends a SignatureShareRequest,
            // validate_signature_share_request() loads block_info from DB and checks
            // block_info.vote. Without this save, the vote would remain None in DB
            // and the SignatureShareRequest would be rejected.
            self.signer_db
                .insert_block(self.reward_cycle, &block_info)
                .unwrap_or_else(|_| panic!("{self}: Failed to insert block with vote in DB"));
            info!(
                "{self}: Saved block vote to DB after deferred validation";
                "signer_sighash" => %block_info.block.header.signer_signature_hash(),
                "vote_rejected" => block_info.vote.as_ref().map(|v| v.rejected),
            );
            // Send the nonce request through with our vote
            let packet = Packet {
                msg: Message::NonceRequest(nonce_request),
                sig: vec![],
            };
            self.handle_packets(funai_client, res, &[packet], current_reward_cycle);
        } else {
            if block_info.valid.unwrap_or(false)
                && !block_info.signed_over
                && coordinator_id == Some(self.signer_id)
            {
                // We are the coordinator. Trigger a signing round for this block
                debug!(
                    "{self}: attempt to trigger a signing round for block";
                    "signer_sighash" => %block_info.block.header.signer_signature_hash(),
                    "block_hash" => %block_info.block.header.block_hash(),
                );
                self.commands.push_back(Command::Sign {
                    block: block_info.block.clone(),
                    is_taproot: false,
                    merkle_root: None,
                });
            } else {
                debug!(
                    "{self}: ignoring block.";
                    "block_hash" => block_info.block.header.block_hash(),
                    "valid" => block_info.valid,
                    "signed_over" => block_info.signed_over,
                    "coordinator_id" => ?coordinator_id
                );
            }
        }
    }

    /// Handle signer messages submitted to signers funaidb
    fn handle_signer_messages(
        &mut self,
        funai_client: &FunaiClient,
        res: Sender<Vec<OperationResult>>,
        messages: &[SignerMessage],
        coordinator_pubkey: &PublicKey,
        current_reward_cycle: u64,
    ) {
        let packets: Vec<Packet> = messages
            .iter()
            .filter_map(|msg| match msg {
                SignerMessage::DkgResults { .. }
                | SignerMessage::BlockResponse(_)
                | SignerMessage::Transactions(_) => None,
                SignerMessage::EndpointAnnouncement(announcement) => {
                    // Process endpoint announcement from other signers
                    self.handle_endpoint_announcement(announcement);
                    None
                }
                // TODO: if a signer tries to trigger DKG and we already have one set in the contract, ignore the request.
                SignerMessage::Packet(packet) => {
                    self.verify_packet(funai_client, packet.clone(), coordinator_pubkey)
                }
            })
            .collect();
        self.handle_packets(funai_client, res, &packets, current_reward_cycle);
    }

    /// Handle proposed blocks submitted by the miners to funaidb
    fn handle_proposed_blocks(
        &mut self,
        miner_endpoint: &Option<String>,
        funai_client: &FunaiClient,
        proposals: &[BlockProposalSigners],
    ) {
        for proposal in proposals {
            if proposal.reward_cycle != self.reward_cycle {
                debug!(
                    "{self}: Received proposal for block outside of my reward cycle, ignoring.";
                    "proposal_reward_cycle" => proposal.reward_cycle,
                    "proposal_burn_height" => proposal.burn_height,
                );
                continue;
            }
            let sig_hash = proposal.block.header.signer_signature_hash();
            match self.signer_db.block_lookup(self.reward_cycle, &sig_hash) {
                Ok(Some(block)) => {
                    debug!(
                        "{self}: Received proposal for block already known, ignoring new proposal.";
                        "signer_sighash" => %sig_hash,
                        "proposal_burn_height" => proposal.burn_height,
                        "vote" => ?block.vote.as_ref().map(|v| {
                            if v.rejected {
                                "REJECT"
                            } else {
                                "ACCEPT"
                            }
                        }),
                        "signed_over" => block.signed_over,
                    );
                    continue;
                }
                Ok(None) => {
                    // Store the block in our cache
                    self.signer_db
                        .insert_block(self.reward_cycle, &BlockInfo::new(proposal.block.clone()))
                        .unwrap_or_else(|e| {
                            error!("{self}: Failed to insert block in DB: {e:?}");
                        });
                    // Store the miner endpoint for this block
                    self.signer_db
                        .insert_blocks_miner_endpoint(miner_endpoint, self.reward_cycle, &BlockInfo::new(proposal.block.clone()))
                        .unwrap_or_else(|e| {
                            error!("{self}: Failed to insert miner endpoint in DB: {e:?}");
                        });
                    // Submit the block for validation
                    funai_client
                        .submit_block_for_validation_with_retry(proposal.block.clone())
                        .unwrap_or_else(|e| {
                            warn!("{self}: Failed to submit block for validation: {e:?}");
                        });
                }
                Err(e) => {
                    error!(
                        "{self}: Failed to lookup block in DB: {e:?}. Dropping proposal request."
                    );
                    continue;
                }
            }
        }
    }

    /// Process inbound packets as both a signer and a coordinator
    /// Will send outbound packets and operation results as appropriate
    fn handle_packets(
        &mut self,
        funai_client: &FunaiClient,
        res: Sender<Vec<OperationResult>>,
        packets: &[Packet],
        current_reward_cycle: u64,
    ) {
        let signer_outbound_messages = self
            .state_machine
            .process_inbound_messages(packets)
            .unwrap_or_else(|e| {
                error!("{self}: Failed to process inbound messages as a signer: {e:?}",);
                vec![]
            });

        // Next process the message as the coordinator
        let (coordinator_outbound_messages, operation_results) = if self.reward_cycle
            != current_reward_cycle
        {
            self.coordinator
                .process_inbound_messages(packets)
                .unwrap_or_else(|e| {
                    error!("{self}: Failed to process inbound messages as a coordinator: {e:?}");
                    (vec![], vec![])
                })
        } else {
            (vec![], vec![])
        };

        if !operation_results.is_empty() {
            // We have finished a signing or DKG round, either successfully or due to error.
            // Regardless of the why, update our state to Idle as we should not expect the operation to continue.
            self.process_operation_results(funai_client, &operation_results);
            self.send_operation_results(res, operation_results);
            self.finish_operation();
        } else if !packets.is_empty() && self.coordinator.state != CoordinatorState::Idle {
            // We have received a message and are in the middle of an operation. Update our state accordingly
            self.update_operation();
        }

        debug!("{self}: Saving signer state");
        self.save_signer_state();
        self.send_outbound_messages(signer_outbound_messages);
        self.send_outbound_messages(coordinator_outbound_messages);
    }

    /// Validate a signature share request, updating its message where appropriate.
    /// If the request is for a block it has already agreed to sign, it will overwrite the message with the agreed upon value
    /// Returns whether the request is valid or not.
    fn validate_signature_share_request(&self, request: &mut SignatureShareRequest) -> bool {
        let Some(block_vote): Option<NakamotoBlockVote> = read_next(&mut &request.message[..]).ok()
        else {
            // We currently reject anything that is not a block vote
            debug!(
                "{self}: Received a signature share request for an unknown message stream. Reject it.",
            );
            return false;
        };

        match self
            .signer_db
            .block_lookup(self.reward_cycle, &block_vote.signer_signature_hash)
            .unwrap_or_else(|_| panic!("{self}: Failed to connect to DB"))
            .map(|b| b.vote)
        {
            Some(Some(vote)) => {
                // Overwrite with our agreed upon value in case another message won majority or the coordinator is trying to cheat...
                debug!(
                    "{self}: Set vote (rejected = {}) to {vote:?}", block_vote.rejected;
                    "requested_sighash" => %block_vote.signer_signature_hash,
                );
                request.message = vote.serialize_to_vec();
                true
            }
            Some(None) => {
                // We never agreed to sign this block. Reject it.
                // This can happen if the coordinator received enough votes to sign yes
                // or no on a block before we received validation from the funai node.
                debug!(
                    "{self}: Received a signature share request for a block we never agreed to sign. Ignore it.";
                    "requested_sighash" => %block_vote.signer_signature_hash,
                );
                false
            }
            None => {
                // We will only sign across block hashes or block hashes + b'n' byte for
                // blocks we have seen a Nonce Request for (and subsequent validation)
                // We are missing the context here necessary to make a decision. Reject the block
                debug!(
                    "{self}: Received a signature share request from an unknown block. Reject it.";
                    "requested_sighash" => %block_vote.signer_signature_hash,
                );
                false
            }
        }
    }

    /// Validate a nonce request, updating its message appropriately.
    /// If the request is for a block, we will update the request message
    /// as either a hash indicating a vote no or the signature hash indicating a vote yes
    /// Returns whether the request is valid or not
    fn validate_nonce_request(
        &mut self,
        funai_client: &FunaiClient,
        nonce_request: &mut NonceRequest,
    ) -> Option<BlockInfo> {
        let Some(block) =
            NakamotoBlock::consensus_deserialize(&mut nonce_request.message.as_slice()).ok()
        else {
            // We currently reject anything that is not a block
            warn!("{self}: Received a nonce request for an unknown message stream. Reject it.",);
            return None;
        };
        let signer_signature_hash = block.header.signer_signature_hash();
        let Some(mut block_info) = self
            .signer_db
            .block_lookup(self.reward_cycle, &signer_signature_hash)
            .expect("Failed to connect to signer DB")
        else {
            debug!(
                "{self}: We have received a block sign request for a block we have not seen before. Cache the nonce request and submit the block for validation...";
                "signer_sighash" => %block.header.signer_signature_hash(),
            );
            let block_info = BlockInfo::new_with_request(block.clone(), nonce_request.clone());
            funai_client
                .submit_block_for_validation_with_retry(block)
                .unwrap_or_else(|e| {
                    warn!("{self}: Failed to submit block for validation: {e:?}",);
                });
            return Some(block_info);
        };

        if block_info.valid.is_none() {
            // We have not yet received validation from the funai node. Cache the request and wait for validation
            debug!("{self}: We have yet to receive validation from the funai node for a nonce request. Cache the nonce request and wait for block validation...");
            block_info.nonce_request = Some(nonce_request.clone());
            return Some(block_info);
        }

        self.determine_vote(&mut block_info, nonce_request);
        Some(block_info)
    }

    /// Remove common invisible Unicode characters from a token.
    /// Matches Python regex class: [\u200b-\u200f\u202a-\u202e\ufeff]
    fn clean_invisible_token(token: &str) -> String {
        token
            .chars()
            .filter(|&ch| {
                !((('\u{200B}'..='\u{200F}').contains(&ch))
                    || (('\u{202A}'..='\u{202E}').contains(&ch))
                    || ch == '\u{FEFF}')
            })
            .collect()
    }

    /// Try to extract an array of string tokens from a JSON value.
    /// Only supports object field "first_top_logprobs" (array of strings).
    fn extract_tokens_from_json(value: &serde_json::Value) -> Option<Vec<String>> {
        let obj = value.as_object()?;
        let arr_val = obj.get("first_top_logprobs")?;
        let arr = arr_val.as_array()?;
        let tokens: Option<Vec<String>> = arr
            .iter()
            .map(|v| v.as_str().map(|s| Self::clean_invisible_token(s)))
            .collect();
        tokens.filter(|ts| !ts.is_empty())
    }

    /// Verify the transactions in a block are as expected
    fn verify_block_transactions(
        &mut self,
        funai_client: &FunaiClient,
        block: &NakamotoBlock,
    ) -> Result<(), Vec<String>> {
        let mut invalid_txids = Vec::new();
        let sig_hash = block.header.signer_signature_hash();
        match  self.signer_db.miner_endpoint_lookup(self.reward_cycle, &sig_hash) {
            Ok(Some(miner_endpoint)) => {
                for tx in block.txs.iter() {
                    match &tx.payload {
                        TransactionPayload::Infer(_from, _amount, input, context, _node_principal, _model_name, _) => {
                            let txid = tx.txid().to_string();
                            let infer_res = funai_client
                                .get_infer_res_with_retry(txid.clone(), miner_endpoint.clone());
                            match infer_res {
                                Ok(infer_res) => {
                                    info!("Infer res for tx {txid}: {infer_res:?}");
                                    
                                    // Verify node_principal matches the worker assigned by the Signer
                                    if let TransactionPayload::Infer(_, _, _, _, ref node_principal, _, _) = tx.payload {
                                        let node_addr = node_principal.to_string();
                                        if node_addr != infer_res.inference_node_id {
                                            warn!("Node principal mismatch for tx {txid}: expected {}, found {}", infer_res.inference_node_id, node_addr);
                                            invalid_txids.push(txid);
                                            continue;
                                        }
                                    }

                                    if !matches!(infer_res.status, libllm::InferStatus::Success) {
                                        warn!("Infer res isn't ok for tx {txid}: {infer_res:?}");
                                        invalid_txids.push(txid);
                                        continue;
                                    }
                                    let output = infer_res.output.clone();
                                    let user_input = input.to_string();
                                    let context_str = context.to_string();
                                    let chat_completion_message: Vec<serde_json::Value> = serde_json::from_str(context_str.as_str()).unwrap_or(vec![]);
                                    let _context_messages = if chat_completion_message.is_empty() {
                                        None::<Vec<serde_json::Value>>
                                    } else {
                                        Some(chat_completion_message)
                                    };
                                    // Call local verifier (port 8000) with signature
                                    let rt = Runtime::new().unwrap();
                                    let post_body = serde_json::json!({
                                        "prompt": user_input
                                    });
                                    let body_json = post_body.to_string();
                                    
                                    // Generate signature headers
                                    let (pubkey_hex, sig_der_hex, timestamp) = match self.generate_signature_headers("/generate", &body_json) {
                                        Ok(headers) => headers,
                                        Err(e) => {
                                            warn!("Failed to generate signature headers for tx {txid}: {}", e);
                                            // Fallback to request without signature
                                            ("".to_string(), "".to_string(), "".to_string())
                                        }
                                    };
                                    
                                    let local_resp = rt.block_on(async {
                                        let mut request = reqwest::Client::new()
                                            .post("http://34.143.166.224:8000/generate");
                                        
                                        if !pubkey_hex.is_empty() {
                                            request = request
                                                .header("X-Address", pubkey_hex)
                                                .header("X-Signature", sig_der_hex)
                                                .header("X-Timestamp", timestamp);
                                        }
                                        
                                        request
                                            .json(&post_body)
                                            .send()
                                            .await
                                    });
                                    let ok = match local_resp {
                                        Ok(resp) => {
                                            if !resp.status().is_success() {
                                                warn!("Local verifier returned non-200 for tx {txid}: {:?}", resp.status());
                                                false
                                            } else {
                                                match rt.block_on(async { resp.json::<serde_json::Value>().await }) {
                                                    Ok(local_json) => {
                                                        // Extract token arrays from both local and node JSONs
                                                        let local_tokens = Self::extract_tokens_from_json(&local_json);
                                                        let node_tokens = serde_json::from_str::<serde_json::Value>(&output)
                                                            .ok()
                                                            .and_then(|v| Self::extract_tokens_from_json(&v));
                                                        if let (Some(lt), Some(rtoks)) = (local_tokens, node_tokens) {
                                                            let len_l = lt.len();
                                                            let len_r = rtoks.len();
                                                            // Build a membership set for tokens2 (node side)
                                                            let set_r: std::collections::HashSet<&str> = rtoks.iter().map(|s| s.as_str()).collect();
                                                            // Count tokens from tokens1 that exist in tokens2 (duplicates in tokens1 count)
                                                            let same_count: usize = lt.iter().filter(|t| set_r.contains(t.as_str())).count();
                                                            let required: i64 = (std::cmp::max(len_l, len_r) as i64) - 2;
                                                            let same_i64: i64 = same_count as i64;
                                                            if same_i64 >= required {
                                                                info!("Infer tokens overlap satisfied for tx {txid}: same={same_count}/max={}", std::cmp::max(len_l, len_r));
                                                                true
                                                            } else {
                                                                warn!("Infer tokens overlap NOT satisfied for tx {txid}: same={same_count}/max={}", std::cmp::max(len_l, len_r));
                                                                debug!("file1(local): {:?}", lt);
                                                                debug!("file2(node): {:?}", rtoks);
                                                                false
                                                            }
                                                        } else {
                                                            warn!("Missing token arrays in verifier/node JSON for tx {txid}");
                                                            false
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to parse local verifier JSON for tx {txid}: {:?}", e);
                                                        false
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Local verifier request failed for tx {txid}: {:?}", e);
                                            false
                                        }
                                    };
                                    if !ok {
                                        invalid_txids.push(txid);
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    error!("{self}: Failed to get infer res for tx {txid}: {e:?}");
                                    invalid_txids.push(txid);
                                    continue;
                                }
                            }
                        }
                        TransactionPayload::RegisterModel(ref model_name, ref _model_params) => {
                            // Check if this signer supports the model being registered
                            let name = model_name.to_string();
                            if !self.support_models.contains(&name) {
                                warn!("{self}: Rejecting RegisterModel tx for unsupported model: {}", name);
                                invalid_txids.push(tx.txid().to_string());
                                continue;
                            }
                        }
                        _ => {} // just ignore other tx types
                    }
                }
            }
            Ok(None) => {
                warn!("{self}: No miner endpoint found for block {sig_hash}.");
                // If we can't find the endpoint, we can't verify Infer transactions.
                // We should return any already found invalid txids.
                return Err(invalid_txids);
            }
            Err(e) => {
                error!("{self}: Failed to connect to signer DB: {e:?}");
                return Err(invalid_txids);
            }
        }

        if !invalid_txids.is_empty() {
            return Err(invalid_txids);
        }

        if self.approved_aggregate_public_key.is_some() {
            // We do not enforce a block contain any transactions except the aggregate votes when it is NOT already set
            // TODO: should be only allow special cased transactions during prepare phase before a key is set?
            debug!("{self}: Already have an aggregate key. Skipping transaction verification...");
            return Ok(());
        }
        if let Ok(expected_transactions) = self.get_expected_transactions(funai_client) {
            //It might be worth building a hashset of the blocks' txids and checking that against the expected transaction's txid.
            let block_tx_hashset = block.txs.iter().map(|tx| tx.txid()).collect::<HashSet<_>>();
            // Ensure the block contains the transactions we expect
            let missing_transactions = expected_transactions
                .into_iter()
                .filter_map(|tx| {
                    if !block_tx_hashset.contains(&tx.txid()) {
                        debug!("{self}: missing expected txid {} is in the block", &tx.txid());
                        Some(tx)
                    } else {
                        debug!("{self}: expected txid {} is in the block", &tx.txid());
                        None
                    }
                })
                .collect::<Vec<_>>();
            if !missing_transactions.is_empty() {
                debug!("{self}: Broadcasting a block rejection due to missing expected transactions...");
                let block_rejection = BlockRejection::new(
                    block.header.signer_signature_hash(),
                    RejectCode::MissingTransactions(missing_transactions),
                );
                // Submit signature result to miners to observe
                if let Err(e) = self
                    .funaidb
                    .send_message_with_retry(block_rejection.into())
                {
                    warn!("{self}: Failed to send block rejection to funai-db: {e:?}",);
                }
                return Err(invalid_txids);
            }
            Ok(())
        } else {
            // Failed to connect to the funai node to get transactions. Cannot validate the block. Reject it.
            debug!("{self}: Broadcasting a block rejection due to signer connectivity issues...",);
            let block_rejection = BlockRejection::new(
                block.header.signer_signature_hash(),
                RejectCode::ConnectivityIssues,
            );
            // Submit signature result to miners to observe
            if let Err(e) = self
                .funaidb
                .send_message_with_retry(block_rejection.into())
            {
                warn!("{self}: Failed to send block submission to funai-db: {e:?}",);
            }
            Err(invalid_txids)
        }
    }

    /// Get transactions from funaidb for the given addresses and account nonces, filtering out any malformed transactions
    fn get_signer_transactions(
        &mut self,
        nonces: &std::collections::HashMap<FunaiAddress, u64>,
    ) -> Result<Vec<FunaiTransaction>, ClientError> {
        let transactions: Vec<_> = self
            .funaidb
            .get_current_transactions_with_retry()?
            .into_iter()
            .filter_map(|tx| {
                if !NakamotoSigners::valid_vote_transaction(nonces, &tx, self.mainnet) {
                    return None;
                }
                Some(tx)
            })
            .collect();
        Ok(transactions)
    }

    /// Get the transactions that should be included in the block, filtering out any invalid transactions
    fn get_expected_transactions(
        &mut self,
        funai_client: &FunaiClient,
    ) -> Result<Vec<FunaiTransaction>, ClientError> {
        if self.next_signer_slot_ids.is_empty() {
            debug!("{self}: No next signers. Skipping transaction retrieval.",);
            return Ok(vec![]);
        }
        // Get all the account nonces for the next signers
        let account_nonces = self.get_account_nonces(funai_client, &self.next_signer_addresses);
        let transactions: Vec<_> = self
            .funaidb
            .get_next_transactions_with_retry(&self.next_signer_slot_ids)?;
        let mut filtered_transactions = std::collections::HashMap::new();
        NakamotoSigners::update_filtered_transactions(
            &mut filtered_transactions,
            &account_nonces,
            self.mainnet,
            transactions,
        );
        // We only allow enforcement of one special cased transaction per signer address per block
        Ok(filtered_transactions.into_values().collect())
    }

    /// Determine the vote for a block and update the block info and nonce request accordingly
    fn determine_vote(&self, block_info: &mut BlockInfo, nonce_request: &mut NonceRequest) {
        let rejected = !block_info.valid.unwrap_or(false);
        if rejected {
            debug!("{self}: Rejecting block {}", block_info.block.block_id());
        } else {
            debug!("{self}: Accepting block {}", block_info.block.block_id());
        }
        
        let mut invalid_txids = block_info.invalid_txids.clone();
        invalid_txids.sort();

        let block_vote = NakamotoBlockVote {
            signer_signature_hash: block_info.block.header.signer_signature_hash(),
            rejected: !block_info.valid.unwrap_or(false),
            invalid_transactions: if invalid_txids.is_empty() {
                None
            } else {
                Some(invalid_txids)
            },
        };
        let block_vote_bytes = block_vote.serialize_to_vec();
        // Cache our vote
        block_info.vote = Some(block_vote);
        nonce_request.message = block_vote_bytes;
    }

    /// Verify a chunk is a valid wsts packet. Returns the packet if it is valid, else None.
    /// NOTE: The packet will be updated if the signer wishes to respond to NonceRequest
    /// and SignatureShareRequests with a different message than what the coordinator originally sent.
    /// This is done to prevent a malicious coordinator from sending a different message than what was
    /// agreed upon and to support the case where the signer wishes to reject a block by voting no
    fn verify_packet(
        &mut self,
        funai_client: &FunaiClient,
        mut packet: Packet,
        coordinator_public_key: &PublicKey,
    ) -> Option<Packet> {
        // We only care about verified wsts packets. Ignore anything else.
        if packet.verify(&self.state_machine.public_keys, coordinator_public_key) {
            match &mut packet.msg {
                Message::SignatureShareRequest(request) => {
                    info!("{self}: Received SignatureShareRequest from miner");
                    if !self.validate_signature_share_request(request) {
                        warn!("{self}: SignatureShareRequest validation failed");
                        return None;
                    }
                    info!("{self}: SignatureShareRequest validated successfully");
                }
                Message::NonceRequest(request) => {
                    info!("{self}: Received NonceRequest from miner, validating...");
                    let Some(updated_block_info) =
                        self.validate_nonce_request(funai_client, request)
                    else {
                        warn!("{self}: Failed to validate and parse nonce request");
                        return None;
                    };
                    info!("{self}: NonceRequest validated, vote = {:?}", updated_block_info.vote);
                    self.signer_db
                        .insert_block(self.reward_cycle, &updated_block_info)
                        .expect(&format!("{self}: Failed to insert block in DB"));
                    let process_request = updated_block_info.vote.is_some();
                    if !process_request {
                        debug!("Failed to validate nonce request");
                        return None;
                    }
                }
                _ => {
                    // Nothing to do for other message types
                }
            }
            Some(packet)
        } else {
            debug!(
                "{self}: Failed to verify wsts packet with {}: {packet:?}",
                coordinator_public_key
            );
            None
        }
    }

    /// Processes the operation results, broadcasting block acceptance or rejection messages
    /// and DKG vote results accordingly
    fn process_operation_results(
        &mut self,
        funai_client: &FunaiClient,
        operation_results: &[OperationResult],
    ) {
        for operation_result in operation_results {
            // Signers only every trigger non-taproot signing rounds over blocks. Ignore SignTaproot results
            match operation_result {
                OperationResult::Sign(signature) => {
                    debug!("{self}: Received signature result");
                    self.process_signature(signature);
                }
                OperationResult::SignTaproot(_) => {
                    debug!("{self}: Received a signature result for a taproot signature. Nothing to broadcast as we currently sign blocks with a FROST signature.");
                }
                OperationResult::Dkg(aggregate_key) => {
                    self.process_dkg(funai_client, aggregate_key);
                }
                OperationResult::SignError(e) => {
                    warn!("{self}: Received a Sign error: {e:?}");
                    self.process_sign_error(e);
                }
                OperationResult::DkgError(e) => {
                    warn!("{self}: Received a DKG error: {e:?}");
                    // TODO: process these errors and track malicious signers to report
                }
            }
        }
    }

    /// Process a dkg result by broadcasting a vote to the funai node
    fn process_dkg(&mut self, funai_client: &FunaiClient, dkg_public_key: &Point) {
        info!("{self}: DKG completed successfully, setting aggregate public key: {dkg_public_key}");
        let mut dkg_results_bytes = vec![];
        if let Err(e) = SignerMessage::serialize_dkg_result(
            &mut dkg_results_bytes,
            dkg_public_key,
            self.coordinator.party_polynomials.iter(),
        ) {
            error!("{}: Failed to serialize DKGResults message for FunaiDB, will continue operating.", self.signer_id;
                   "error" => %e);
        } else {
            if let Err(e) = self
                .funaidb
                .send_message_bytes_with_retry(&MessageSlotID::DkgResults, dkg_results_bytes)
            {
                error!("{}: Failed to send DKGResults message to FunaiDB, will continue operating.", self.signer_id;
                       "error" => %e);
            }
        }

        let epoch = retry_with_exponential_backoff(|| {
            funai_client
                .get_node_epoch()
                .map_err(backoff::Error::transient)
        })
        .unwrap_or(FunaiEpochId::Epoch24);
        let tx_fee = if epoch < FunaiEpochId::Epoch30 {
            debug!("{self}: in pre Epoch 3.0 cycles, must set a transaction fee for the DKG vote.");
            Some(self.tx_fee_ustx)
        } else {
            None
        };
        // Get our current nonce from the funai node and compare it against what we have sitting in the funaidb instance
        let signer_address = funai_client.get_signer_address();
        // Retreieve ALL account nonces as we may have transactions from other signers in our funaidb slot that we care about
        let account_nonces = self.get_account_nonces(funai_client, &self.signer_addresses);
        let account_nonce = account_nonces.get(signer_address).unwrap_or(&0);
        let signer_transactions = retry_with_exponential_backoff(|| {
            self.get_signer_transactions(&account_nonces)
                .map_err(backoff::Error::transient)
        })
        .map_err(|e| {
            warn!("{self}: Unable to get signer transactions: {e:?}");
        })
        .unwrap_or_default();
        // If we have a transaction in the funaidb slot, we need to increment the nonce hence the +1, else should use the account nonce
        let next_nonce = signer_transactions
            .first()
            .map(|tx| tx.get_origin_nonce().wrapping_add(1))
            .unwrap_or(*account_nonce);
        match funai_client.build_vote_for_aggregate_public_key(
            self.funaidb.get_signer_slot_id().0,
            self.coordinator.current_dkg_id,
            *dkg_public_key,
            self.reward_cycle,
            tx_fee,
            next_nonce,
        ) {
            Ok(new_transaction) => {
                if let Err(e) = self.broadcast_dkg_vote(
                    funai_client,
                    epoch,
                    signer_transactions,
                    new_transaction,
                ) {
                    warn!(
                        "{self}: Failed to broadcast DKG public key vote ({dkg_public_key:?}): {e:?}"
                    );
                }
            }
            Err(e) => {
                warn!(
                    "{self}: Failed to build DKG public key vote ({dkg_public_key:?}) transaction: {e:?}."
                );
            }
        }
    }

    // Get the account nonces for the provided list of signer addresses
    fn get_account_nonces(
        &self,
        funai_client: &FunaiClient,
        signer_addresses: &[FunaiAddress],
    ) -> std::collections::HashMap<FunaiAddress, u64> {
        let mut account_nonces = std::collections::HashMap::with_capacity(signer_addresses.len());
        for address in signer_addresses {
            let Ok(account_nonce) = funai_client.get_account_nonce(address) else {
                warn!("{self}: Unable to get account nonce for address: {address}.");
                continue;
            };
            account_nonces.insert(*address, account_nonce);
        }
        account_nonces
    }

    /// broadcast the dkg vote transaction according to the current epoch
    fn broadcast_dkg_vote(
        &mut self,
        funai_client: &FunaiClient,
        epoch: FunaiEpochId,
        mut signer_transactions: Vec<FunaiTransaction>,
        new_transaction: FunaiTransaction,
    ) -> Result<(), ClientError> {
        let txid = new_transaction.txid();
        if self.approved_aggregate_public_key.is_some() {
            // We do not enforce a block contain any transactions except the aggregate votes when it is NOT already set
            info!(
                "{self}: Already has an approved aggregate key. Do not broadcast the transaction ({txid:?})."
            );
            return Ok(());
        }
        if epoch >= FunaiEpochId::Epoch30 {
            debug!("{self}: Received a DKG result while in epoch 3.0. Broadcast the transaction only to funaiDB.");
        } else if epoch == FunaiEpochId::Epoch25 {
            debug!("{self}: Received a DKG result while in epoch 2.5. Broadcast the transaction to the mempool.");
            funai_client.submit_transaction_with_retry(&new_transaction)?;
            info!("{self}: Submitted DKG vote transaction ({txid:?}) to the mempool");
        } else {
            debug!("{self}: Received a DKG result, but are in an unsupported epoch. Do not broadcast the transaction ({}).", new_transaction.txid());
            return Ok(());
        }
        // For all Pox-4 epochs onwards, broadcast the results also to funaiDB for other signers/miners to observe
        signer_transactions.push(new_transaction);
        let signer_message = SignerMessage::Transactions(signer_transactions);
        self.funaidb.send_message_with_retry(signer_message)?;
        info!("{self}: Broadcasted DKG vote transaction ({txid}) to funai DB");
        Ok(())
    }

    /// Set this signer's endpoint URL
    pub fn set_endpoint(&mut self, endpoint: String) {
        self.signer_endpoint = Some(endpoint);
        self.endpoint_broadcasted = false;
    }

    /// Handle an endpoint announcement from another signer
    fn handle_endpoint_announcement(&mut self, announcement: &SignerEndpointAnnouncement) {
        debug!(
            "{self}: Received endpoint announcement from signer: public_key={}, endpoint={}, principal={}",
            announcement.public_key, announcement.endpoint, announcement.principal
        );

        // Register the signer's endpoint in our local registry
        let signer_info = crate::encryption::SignerInfo {
            public_key: announcement.public_key.clone(),
            endpoint: announcement.endpoint.clone(),
            principal: announcement.principal.clone(),
            last_seen: announcement.timestamp,
        };

        self.signer_registry.register(signer_info);
        info!(
            "{self}: Registered signer endpoint: {} -> {}",
            announcement.public_key, announcement.endpoint
        );
    }

    /// Get the endpoint URL for a signer by their public key
    pub fn get_signer_endpoint(&self, public_key: &str) -> Option<String> {
        self.signer_registry.get_endpoint(public_key)
    }

    /// Get all registered signer endpoints
    pub fn get_all_signer_endpoints(&self) -> Vec<&crate::encryption::SignerInfo> {
        self.signer_registry.get_all()
    }

    /// Broadcast this signer's endpoint to other signers via funaiDB
    /// This allows other signers to discover this signer's API endpoint for decryption requests
    pub fn broadcast_endpoint(&mut self) -> Result<(), ClientError> {
        if self.endpoint_broadcasted {
            debug!("{self}: Endpoint already broadcasted, skipping");
            return Ok(());
        }

        let endpoint = match &self.signer_endpoint {
            Some(e) => e.clone(),
            None => {
                debug!("{self}: No endpoint configured, skipping broadcast");
                return Ok(());
            }
        };

        // Get signer's public key
        let public_key = Secp256k1PublicKey::from_private(&self.funai_private_key);
        let public_key_hex = funai_common::util::hash::to_hex(&public_key.to_bytes_compressed());

        // Get signer's principal address
        let signer_address = FunaiAddress::p2pkh(self.mainnet, &public_key);
        let principal = signer_address.to_string();

        // Create announcement message
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let announcement = SignerEndpointAnnouncement {
            public_key: public_key_hex.clone(),
            endpoint: endpoint.clone(),
            principal: principal.clone(),
            timestamp,
        };

        let message = SignerMessage::EndpointAnnouncement(announcement);
        
        match self.funaidb.send_message_with_retry(message) {
            Ok(ack) => {
                info!("{self}: Broadcasted endpoint announcement to funaiDB: endpoint={}, public_key={}", 
                    endpoint, public_key_hex);
                debug!("{self}: Endpoint broadcast ACK: {:?}", ack);
                self.endpoint_broadcasted = true;
                Ok(())
            }
            Err(e) => {
                error!("{self}: Failed to broadcast endpoint to funaiDB: {:?}", e);
                Err(e)
            }
        }
    }

    /// Process a signature from a signing round by deserializing the signature and
    /// broadcasting an appropriate Reject or Approval message to funaidb
    fn process_signature(&mut self, signature: &Signature) {
        // Deserialize the signature result and broadcast an appropriate Reject or Approval message to funaidb
        let message = self.coordinator.get_message();
        let Some(block_vote): Option<NakamotoBlockVote> = read_next(&mut &message[..]).ok() else {
            debug!("{self}: Received a signature result for a non-block. Nothing to broadcast.");
            return;
        };

        let block_submission = if block_vote.rejected {
            // We signed a rejection message. Return a rejection message
            BlockResponse::rejected(block_vote.signer_signature_hash, signature.clone())
        } else {
            // we agreed to sign the block hash. Return an approval message
            BlockResponse::accepted(block_vote.signer_signature_hash, signature.clone())
        };

        // Submit signature result to miners to observe
        info!("{self}: Submit block response: {block_submission}");
        if let Err(e) = self
            .funaidb
            .send_message_with_retry(block_submission.into())
        {
            warn!("{self}: Failed to send block submission to funai-db: {e:?}");
        }
    }

    /// Process a sign error from a signing round, broadcasting a rejection message to funaidb accordingly
    fn process_sign_error(&mut self, e: &SignError) {
        let message = self.coordinator.get_message();
        // We do not sign across blocks, but across their hashes. however, the first sign request is always across the block
        // so we must handle this case first

        let block: NakamotoBlock = read_next(&mut &message[..]).ok().unwrap_or({
            // This is not a block so maybe its across its hash
            let Some(block_vote): Option<NakamotoBlockVote> = read_next(&mut &message[..]).ok()
            else {
                // This is not a block vote either. We cannot process this error
                debug!(
                    "{self}: Received a signature error for a non-block. Nothing to broadcast."
                );
                return;
            };
            let Some(block_info) = self
                .signer_db
                .block_lookup(self.reward_cycle, &block_vote.signer_signature_hash)
                .unwrap_or_else(|_| panic!("{self}: Failed to connect to signer DB"))
            else {
                debug!(
                    "{self}: Received a signature result for a block we have not seen before. Ignoring..."
                );
                return;
            };
            block_info.block
        });
        let block_rejection =
            BlockRejection::new(block.header.signer_signature_hash(), RejectCode::from(e));
        debug!("{self}: Broadcasting block rejection: {block_rejection:?}");
        // Submit signature result to miners to observe
        if let Err(e) = self
            .funaidb
            .send_message_with_retry(block_rejection.into())
        {
            warn!("{self}: Failed to send block rejection submission to funai-db: {e:?}");
        }
    }

    /// Persist state needed to ensure the signer can continue to perform
    /// DKG and participate in signing rounds accross crashes
    ///
    /// # Panics
    /// Panics if the insertion fails
    fn save_signer_state(&self) {
        let state = self.state_machine.signer.save();
        self.signer_db
            .insert_signer_state(self.reward_cycle, &state)
            .expect("Failed to persist signer state");
    }

    /// Send any operation results across the provided channel
    fn send_operation_results(
        &mut self,
        res: Sender<Vec<OperationResult>>,
        operation_results: Vec<OperationResult>,
    ) {
        let nmb_results = operation_results.len();
        match res.send(operation_results) {
            Ok(_) => {
                debug!("{self}: Successfully sent {nmb_results} operation result(s)")
            }
            Err(e) => {
                warn!("{self}: Failed to send {nmb_results} operation results: {e:?}");
            }
        }
    }

    /// Sending all provided packets through funaidb with a retry
    fn send_outbound_messages(&mut self, outbound_messages: Vec<Packet>) {
        debug!(
            "{self}: Sending {} messages to other funai-db instances.",
            outbound_messages.len()
        );
        for msg in outbound_messages {
            info!("{self}: Sending message type: {:?}", std::mem::discriminant(&msg.msg));
            let ack = self.funaidb.send_message_with_retry(msg.into());
            if let Ok(ack) = ack {
                info!("{self}: send outbound ACK: {ack:?}");
            } else {
                warn!("{self}: Failed to send message to funai-db instance: {ack:?}");
            }
        }
    }

    /// Update the DKG for the provided signer info, triggering it if required
    pub fn update_dkg(
        &mut self,
        funai_client: &FunaiClient,
        current_reward_cycle: u64,
    ) -> Result<(), ClientError> {
        let reward_cycle = self.reward_cycle;
        let old_dkg = self.approved_aggregate_public_key;
        self.approved_aggregate_public_key =
            funai_client.get_approved_aggregate_key(reward_cycle)?;
        if self.approved_aggregate_public_key.is_some() {
            // TODO: this will never work as is. We need to have stored our party shares on the side etc for this particular aggregate key.
            // Need to update state to store the necessary info, check against it to see if we have participated in the winning round and
            // then overwrite our value accordingly. Otherwise, we will be locked out of the round and should not participate.
            self.coordinator
                .set_aggregate_public_key(self.approved_aggregate_public_key);
            if old_dkg != self.approved_aggregate_public_key {
                debug!(
                    "{self}: updated DKG value to {:?}.",
                    self.approved_aggregate_public_key
                );
            }
            return Ok(());
        };
        if self.state != State::Idle
            || self.signer_id != self.get_dkg_coordinator().0
        {
            // We are not the coordinator or we are in the middle of an operation. Do not attempt to queue DKG
            return Ok(());
        }
        debug!("{self}: Checking if old DKG vote transaction exists in FunaiDB...");
        // Have I already voted, but the vote is still pending in FunaiDB? Check funaidb for the same round number and reward cycle vote transaction
        // Only get the account nonce of THIS signer as we only care about our own votes, not other signer votes
        let signer_address = funai_client.get_signer_address();
        let account_nonces = self.get_account_nonces(funai_client, &[*signer_address]);
        let old_transactions = self.get_signer_transactions(&account_nonces).map_err(|e| {
                warn!("{self}: Failed to get old signer transactions: {e:?}. May trigger DKG unnecessarily");
            }).unwrap_or_default();
        // Check if we have an existing vote transaction for the same round and reward cycle
        for transaction in old_transactions.iter() {
            let params =
                    NakamotoSigners::parse_vote_for_aggregate_public_key(transaction).unwrap_or_else(|| panic!("BUG: {self}: Received an invalid {SIGNERS_VOTING_FUNCTION_NAME} transaction in an already filtered list: {transaction:?}"));
            if Some(params.aggregate_key) == self.coordinator.aggregate_public_key
                && params.voting_round == self.coordinator.current_dkg_id
                && reward_cycle == self.reward_cycle
            {
                debug!("{self}: Not triggering a DKG round. Already have a pending vote transaction.";
                    "txid" => %transaction.txid(),
                    "aggregate_key" => %params.aggregate_key,
                    "voting_round" => params.voting_round
                );
                return Ok(());
            }
        }
        if let Some(aggregate_key) = funai_client.get_vote_for_aggregate_public_key(
            self.coordinator.current_dkg_id,
            self.reward_cycle,
            *funai_client.get_signer_address(),
        )? {
            let Some(round_weight) = funai_client
                .get_round_vote_weight(self.reward_cycle, self.coordinator.current_dkg_id)?
            else {
                // This only will happen if somehow we registered as a signer and were granted no weight which should not really ever happen.
                error!("{self}: already voted for DKG, but no round vote weight found. We either have no voting power or the contract is corrupted.";
                    "voting_round" => self.coordinator.current_dkg_id,
                    "aggregate_key" => %aggregate_key
                );
                return Ok(());
            };
            let threshold_weight = funai_client.get_vote_threshold_weight(self.reward_cycle)?;
            if round_weight < threshold_weight {
                // The threshold weight has not been met yet. We should wait for more votes to arrive.
                // TODO: this should be on a timeout of some kind. We should not wait forever for the threshold to be met.
                // See https://github.com/funai-network/funai-core/issues/4568
                debug!("{self}: Not triggering a DKG round. Weight threshold has not been met yet. Waiting for more votes to arrive.";
                    "voting_round" => self.coordinator.current_dkg_id,
                    "aggregate_key" => %aggregate_key,
                    "round_weight" => round_weight,
                    "threshold_weight" => threshold_weight
                );
                return Ok(());
            }
            debug!("{self}: Vote for DKG failed. Triggering a DKG round.";
                "voting_round" => self.coordinator.current_dkg_id,
                "aggregate_key" => %aggregate_key,
                "round_weight" => round_weight,
                "threshold_weight" => threshold_weight
            );
        } else {
            debug!("{self}: Triggering a DKG round.");
        }
        if self.commands.front() != Some(&Command::Dkg) {
            info!("{self} is the current coordinator and must trigger DKG. Queuing DKG command...");
            self.commands.push_front(Command::Dkg);
        } else {
            debug!("{self}: DKG command already queued...");
        }
        Ok(())
    }

    /// Process the event
    pub fn process_event(
        &mut self,
        funai_client: &FunaiClient,
        event: Option<&SignerEvent>,
        res: Sender<Vec<OperationResult>>,
        current_reward_cycle: u64,
    ) -> Result<(), ClientError> {
        debug!("{self}: Processing event: {event:?}");
        match event {
            Some(SignerEvent::BlockValidationResponse(block_validate_response)) => {
                debug!("{self}: Received a block proposal result from the funai node...");
                self.handle_block_validate_response(
                    funai_client,
                    block_validate_response,
                    res,
                    current_reward_cycle,
                )
            }
            Some(SignerEvent::SignerMessages(signer_set, messages)) => {
                if *signer_set != self.funaidb.get_signer_set() {
                    debug!("{self}: Received a signer message for a reward cycle that does not belong to this signer. Ignoring...");
                    return Ok(());
                }
                debug!(
                    "{self}: Received {} messages from the other signers...",
                    messages.len()
                );
                let coordinator_pubkey = self.get_dkg_coordinator().1;
                self.handle_signer_messages(
                    funai_client,
                    res,
                    messages,
                    &coordinator_pubkey,
                    current_reward_cycle,
                );
            }
            Some(SignerEvent::MinerMessages(miner_endpoint, blocks, messages, miner_key)) => {
                if let Some(miner_key) = miner_key {
                    let miner_key = PublicKey::try_from(miner_key.to_bytes_compressed().as_slice())
                        .expect("FATAL: could not convert from FunaiPublicKey to PublicKey");
                    self.miner_key = Some(miner_key);
                };
                if current_reward_cycle != self.reward_cycle {
                    // There is not point in processing blocks if we are not the current reward cycle (we can never actually contribute to signing these blocks)
                    debug!("{self}: Received a proposed block, but this signer's reward cycle is not the current one ({current_reward_cycle}). Ignoring...");
                    return Ok(());
                }
                debug!(
                    "{self}: Received {} block proposals and {} messages from the miner",
                    blocks.len(),
                    messages.len();
                    "miner_key" => ?miner_key,
                );
                let coordinator_pubkey = self.get_signing_coordinator(current_reward_cycle).1;
                self.handle_signer_messages(
                    funai_client,
                    res,
                    messages,
                    &coordinator_pubkey,
                    current_reward_cycle,
                );
                self.handle_proposed_blocks(miner_endpoint, funai_client, blocks);
            }
            Some(SignerEvent::StatusCheck) => {
                debug!("{self}: Received a status check event.")
            }
            Some(SignerEvent::NewBurnBlock(height)) => {
                debug!("{self}: Receved a new burn block event for block height {height}")
            }
            Some(SignerEvent::InferTaskMessage(task)) => {
                debug!("{self}: Received an inference task message.");
                if let Some(sender) = &self.inference_task_sender {
                    // Re-wrap in SignerEvent because InferenceService expects SignerEvent
                    let event = SignerEvent::InferTaskMessage(task.clone());
                    // Use blocking_send or try_send since we are in a sync context
                    if let Err(e) = sender.try_send(event) {
                        error!("{self}: Failed to send inference task to service: {e}");
                    } else {
                        info!("{self}: Forwarded inference task {} to service", task.task_id);
                    }
                } else {
                    debug!("{self}: No inference task sender configured. Ignoring task.");
                }
            }
            None => {
                // No event. Do nothing.
                debug!("{self}: No event received")
            }
        }
        Ok(())
    }
}

