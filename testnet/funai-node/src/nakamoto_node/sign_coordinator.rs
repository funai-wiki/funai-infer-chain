// Copyright (C) 2024 Funai Open Internet Foundation
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

use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use hashbrown::{HashMap, HashSet};
use libsigner::{
    BlockResponse, MessageSlotID, SignerEntries, SignerEvent, SignerMessage, SignerSession, FunaiDBSession,
};
use funai::burnchains::Burnchain;
use funai::chainstate::burn::db::sortdb::SortitionDB;
use funai::chainstate::burn::BlockSnapshot;
use funai::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState, NakamotoBlockVote};
use funai::chainstate::funai::boot::{NakamotoSignerEntry, RewardSet, MINERS_NAME, SIGNERS_NAME};
use funai::chainstate::funai::events::FunaiDBChunksEvent;
use funai::chainstate::funai::{Error as ChainstateError, ThresholdSignature};
use funai::libfunaidb::FunaiDBChunkData;
use funai::net::funaidb::FunaiDBs;
use funai::util_lib::boot::boot_code_id;
use funai_common::codec::FunaiMessageCodec;
use funai_common::types::chainstate::{FunaiPrivateKey, FunaiPublicKey};
use wsts::common::PolyCommitment;
use wsts::curve::ecdsa;
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::coordinator::{Config as CoordinatorConfig, Coordinator};
use wsts::state_machine::PublicKeys;
use wsts::v2::Aggregator;

use super::Error as NakamotoNodeError;
use crate::event_dispatcher::STACKER_DB_CHANNEL;
use crate::Config;

/// How long should the coordinator poll on the event receiver before
/// waking up to check timeouts?
static EVENT_RECEIVER_POLL: Duration = Duration::from_millis(50);

pub struct SignCoordinator {
    coordinator: FireCoordinator<Aggregator>,
    message_key: Scalar,
    receiver: Option<Receiver<FunaiDBChunksEvent>>,
    wsts_public_keys: PublicKeys,
    is_mainnet: bool,
    miners_session: FunaiDBSession,
    signing_round_timeout: Duration,
    reward_cycle: u64,
}

impl SignCoordinator {
    /// * `reward_set` - the active reward set data, used to construct the signer
    ///    set parameters.
    /// * `message_key` - the signing key that the coordinator will use to sign messages
    ///    broadcasted to the signer set. this should be the miner's registered key.
    /// * `aggregate_public_key` - the active aggregate key for this cycle
    pub fn new(
        reward_set: &RewardSet,
        reward_cycle: u64,
        message_key: Scalar,
        aggregate_public_key: Point,
        funaidb_conn: &FunaiDBs,
        config: &Config,
    ) -> Result<Self, ChainstateError> {
        let is_mainnet = config.is_mainnet();
        let Some(ref reward_set_signers) = reward_set.signers else {
            error!("Could not initialize WSTS coordinator for reward set without signer");
            return Err(ChainstateError::NoRegisteredSigners(0));
        };

        let rpc_socket = config
            .node
            .get_rpc_loopback()
            .ok_or_else(|| ChainstateError::MinerAborted)?;
        let miners_contract_id = boot_code_id(MINERS_NAME, is_mainnet);
        let miners_session = FunaiDBSession::new(&rpc_socket.to_string(), miners_contract_id);

        let signer_entries = SignerEntries::parse(is_mainnet, reward_set_signers.as_slice())
            .map_err(|e| ChainstateError::InvalidFunaiBlock(format!("Failed to parse signer entries: {:?}", e)))?;

        let num_signers = signer_entries.count_signers().unwrap();
        let num_keys = signer_entries.count_keys().unwrap();
        let threshold = signer_entries.get_signing_threshold().unwrap();
        let dkg_threshold = signer_entries.get_dkg_threshold().unwrap();

        let coord_config = CoordinatorConfig {
            num_signers,
            num_keys,
            threshold,
            signer_key_ids: signer_entries.coordinator_key_ids.clone(),
            signer_public_keys: signer_entries.signer_public_keys.clone(),
            dkg_threshold,
            message_private_key: message_key.clone(),
            ..Default::default()
        };

        let mut coordinator: FireCoordinator<Aggregator> = FireCoordinator::new(coord_config);
        let party_polynomials = get_signer_commitments(
            is_mainnet,
            reward_set_signers.as_slice(),
            funaidb_conn,
            reward_cycle,
            &aggregate_public_key,
        )?;
        
        let poly_vec: Vec<(u32, PolyCommitment)> = party_polynomials.into_iter().collect();
        if let Err(e) = coordinator
            .set_key_and_party_polynomials(aggregate_public_key.clone(), poly_vec)
        {
            warn!("Failed to set a valid set of party polynomials"; "error" => %e);
        };

        let (receiver, replaced_other) = STACKER_DB_CHANNEL.register_miner_coordinator();
        if replaced_other {
            warn!("Replaced the miner/coordinator receiver of a prior thread. Prior thread may have crashed.");
        }

        Ok(Self {
            coordinator,
            message_key,
            receiver: Some(receiver),
            wsts_public_keys: signer_entries.public_keys,
            is_mainnet,
            miners_session,
            signing_round_timeout: config.miner.wait_on_signers.clone(),
            reward_cycle,
        })
    }

    fn get_sign_id(burn_block_height: u64, burnchain: &Burnchain) -> u64 {
        burnchain
            .pox_constants
            .reward_cycle_index(burnchain.first_block_height, burn_block_height)
            .expect("FATAL: tried to initialize WSTS coordinator before first burn block height")
    }

    fn send_signers_message(
        message_key: &Scalar,
        sortdb: &SortitionDB,
        tip: &BlockSnapshot,
        _funaidbs: &FunaiDBs,
        message: SignerMessage,
        is_mainnet: bool,
        miners_session: &mut FunaiDBSession,
        reward_cycle: u64,
    ) -> Result<(), String> {
        let mut msg_bytes = vec![];
        message
            .consensus_serialize(&mut msg_bytes)
            .map_err(|e| format!("Failed to serialize message: {e:?}"))?;

        let mut chunk = FunaiDBChunkData::new(
            1, // message slot
            1, // version
            msg_bytes,
        );
        
        // Miner key is not FunaiPrivateKey, we need to convert or handle signing
        // For now, use a dummy sign or fix this later
        // let _ = chunk.sign(message_key); 

        miners_session
            .put_chunk(&chunk)
            .map_err(|e| format!("Failed to send message to FunaiDB: {e:?}"))?;

        Ok(())
    }

    pub fn begin_sign(
        &mut self,
        block: &NakamotoBlock,
        block_attempt: u64,
        burn_tip: &BlockSnapshot,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        funaidbs: &FunaiDBs,
    ) -> Result<ThresholdSignature, NakamotoNodeError> {
        let sign_id = Self::get_sign_id(burn_tip.block_height, burnchain);
        let sign_iter_id = block_attempt;
        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burn_tip.block_height)
            .expect("FATAL: tried to initialize coordinator before first burn block height");
        self.coordinator.current_sign_id = sign_id;
        self.coordinator.current_sign_iter_id = sign_iter_id;

        let block_bytes = block.serialize_to_vec();
        let nonce_req_msg = self
            .coordinator
            .start_signing_round(&block_bytes, false, None)
            .map_err(|e| {
                NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "Failed to start signing round in FIRE coordinator: {e:?}"
                ))
            })?;
        Self::send_signers_message(
            &self.message_key,
            sortdb,
            burn_tip,
            &funaidbs,
            nonce_req_msg.into(),
            self.is_mainnet,
            &mut self.miners_session,
            self.reward_cycle,
        )
        .map_err(NakamotoNodeError::SigningCoordinatorFailure)?;

        let Some(ref mut receiver) = self.receiver else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Failed to obtain the FunaiDB event receiver".into(),
            ));
        };

        let start_ts = Instant::now();
        let mut collected_filters = HashSet::new();
        while start_ts.elapsed() <= self.signing_round_timeout {
            let event = match receiver.recv_timeout(EVENT_RECEIVER_POLL) {
                Ok(event) => event,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(NakamotoNodeError::SigningCoordinatorFailure(
                        "FunaiDB event receiver disconnected".into(),
                    ))
                }
            };

            let is_signer_event =
                event.contract_id.name.starts_with(SIGNERS_NAME) && event.contract_id.is_boot();
            if !is_signer_event {
                debug!("Ignoring FunaiDB event for non-signer contract"; "contract" => %event.contract_id);
                continue;
            }
            let Ok(signer_event) = SignerEvent::try_from(event).map_err(|e| {
                warn!("Failure parsing FunaiDB event into signer event. Ignoring message."; "err" => ?e);
            }) else {
                continue;
            };
            let SignerEvent::SignerMessages(signer_set, messages) = signer_event else {
                debug!("Received signer event other than a signer message. Ignoring.");
                continue;
            };
            if signer_set != u32::try_from(reward_cycle_id % 2).unwrap() {
                debug!("Received signer event for other reward cycle. Ignoring.");
                continue;
            };
            debug!("Miner/Coordinator: Received messages from signers"; "count" => messages.len());
            let coordinator_pk = ecdsa::PublicKey::new(&self.message_key).map_err(|_e| {
                NakamotoNodeError::MinerSignatureError("Bad signing key for the FIRE coordinator")
            })?;
            
            let packets: Vec<_> = messages
                .into_iter()
                .filter_map(|msg| {
                    match msg {
                        SignerMessage::DkgResults { .. }
                        | SignerMessage::Transactions(_) => None,
                        SignerMessage::BlockResponse(BlockResponse::Filter(filter)) => {
                            warn!("Signers requested selective transaction removal (FILTER): {:?}", filter.invalid_transactions);
                            collected_filters.insert(filter.invalid_transactions);
                            None
                        }
                        SignerMessage::BlockResponse(_) => None,
                        SignerMessage::Packet(packet) => {
                            debug!("Received signers packet: {packet:?}");
                            if !packet.verify(&self.wsts_public_keys, &coordinator_pk) {
                                warn!("Failed to verify FunaiDB packet: {packet:?}");
                                None
                            } else {
                                Some(packet)
                            }
                        }
                    }
                })
                .collect();
            
            let (outbound_msgs, op_results) = self
                .coordinator
                .process_inbound_messages(&packets)
                .unwrap_or_else(|e| {
                    error!(
                        "Miner/Coordinator: Failed to process inbound message packets";
                        "err" => ?e
                    );
                    (vec![], vec![])
                });
            for operation_result in op_results.into_iter() {
                match operation_result {
                    wsts::state_machine::OperationResult::Dkg { .. }
                    | wsts::state_machine::OperationResult::SignTaproot(_)
                    | wsts::state_machine::OperationResult::DkgError(_) => {
                        debug!("Ignoring unrelated operation result");
                    }
                    wsts::state_machine::OperationResult::Sign(signature) => {
                        // check if the signature actually corresponds to our block?
                        let block_sighash = block.header.signer_signature_hash();
                        let mut verified = signature.verify(
                            self.coordinator.aggregate_public_key.as_ref().unwrap(),
                            &block_sighash.0,
                        );
                        
                        if verified {
                            let signature = ThresholdSignature(signature);
                            return Ok(signature);
                        }

                        // Try to verify as a NakamotoBlockVote (accept or reject)
                        use funai_common::util::hash::Sha512Trunc256Sum;
                        
                        // Check for Accept vote
                        let accept_vote = NakamotoBlockVote {
                            signer_signature_hash: block_sighash.clone(),
                            rejected: false,
                            invalid_transactions: None,
                        };
                        let accept_bytes = accept_vote.serialize_to_vec();
                        let accept_hash = Sha512Trunc256Sum::from_data(&accept_bytes);
                        if signature.verify(
                            self.coordinator.aggregate_public_key.as_ref().unwrap(),
                            &accept_hash.0,
                        ) {
                            return Ok(ThresholdSignature(signature));
                        }

                        // Check for Reject vote (without filter)
                        let reject_vote = NakamotoBlockVote {
                            signer_signature_hash: block_sighash.clone(),
                            rejected: true,
                            invalid_transactions: None,
                        };
                        let reject_bytes = reject_vote.serialize_to_vec();
                        let reject_hash = Sha512Trunc256Sum::from_data(&reject_bytes);
                        if signature.verify(
                            self.coordinator.aggregate_public_key.as_ref().unwrap(),
                            &reject_hash.0,
                        ) {
                            warn!("Signers REJECTED the block via NakamotoBlockVote");
                            return Err(NakamotoNodeError::SignerSignatureError(
                                "Signers rejected the block".into(),
                            ));
                        }

                        // Check for Filter votes (with collected filter suggestions)
                        for invalid_txs in collected_filters.iter() {
                            let filter_vote = NakamotoBlockVote {
                                signer_signature_hash: block_sighash.clone(),
                                rejected: true,
                                invalid_transactions: Some(invalid_txs.clone()),
                            };
                            let filter_bytes = filter_vote.serialize_to_vec();
                            let filter_hash = Sha512Trunc256Sum::from_data(&filter_bytes);
                            if signature.verify(
                                self.coordinator.aggregate_public_key.as_ref().unwrap(),
                                &filter_hash.0,
                            ) {
                                warn!("Signers agreed on FILTERING the block: {:?}", invalid_txs);
                                return Err(NakamotoNodeError::SignerFilterError(invalid_txs.clone()));
                            }
                        }
                        
                        let signature = ThresholdSignature(signature);
                        warn!(
                            "Processed signature but didn't validate over the expected block. Returning error.";
                            "signature" => %signature,
                            "block_signer_signature_hash" => %block_sighash
                        );
                        return Err(NakamotoNodeError::SignerSignatureError(
                            "Signature failed to validate over the expected block".into(),
                        ));
                    }
                    wsts::state_machine::OperationResult::SignError(e) => {
                        return Err(NakamotoNodeError::SignerSignatureError(format!(
                            "Signing failed: {e:?}"
                        )))
                    }
                }
            }
            for msg in outbound_msgs {
                match Self::send_signers_message(
                    &self.message_key,
                    sortdb,
                    burn_tip,
                    funaidbs,
                    msg.into(),
                    self.is_mainnet,
                    &mut self.miners_session,
                    self.reward_cycle,
                ) {
                    Ok(()) => {
                        debug!("Miner/Coordinator: sent outbound message.");
                    }
                    Err(e) => {
                        warn!(
                            "Miner/Coordinator: Failed to send message to FunaiDB instance: {e:?}."
                        );
                    }
                };
            }
        }

        Err(NakamotoNodeError::SignerSignatureError(
            "Timed out waiting for group signature".into(),
        ))
    }
}

pub struct NakamotoSigningParams {
    pub num_signers: u32,
    pub num_keys: u32,
    pub threshold: u32,
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
    pub signer_public_keys: HashMap<u32, Point>,
    pub wsts_public_keys: PublicKeys,
}

impl NakamotoSigningParams {
    pub fn parse(
        is_mainnet: bool,
        signers: &[NakamotoSignerEntry],
    ) -> Result<Self, ChainstateError> {
        let mut signer_key_ids = HashMap::new();
        let mut signer_public_keys = HashMap::new();
        let mut wsts_signers = HashMap::new();
        let mut wsts_key_ids = HashMap::new();

        let mut next_key_id = 0;
        let mut weight_end = 1;
        for (i, entry) in signers.iter().enumerate() {
            let signer_id = i as u32;
            let ecdsa_pk = ecdsa::PublicKey::try_from(entry.signing_key.as_slice())
                .map_err(|_| ChainstateError::InvalidFunaiBlock("Bad signer key".into()))?;
            
            let point = Point::try_from(&wsts::curve::point::Compressed::from(ecdsa_pk.to_bytes()))
                .map_err(|_| ChainstateError::InvalidFunaiBlock("Bad signer key".into()))?;

            signer_public_keys.insert(signer_id, point.clone());
            wsts_signers.insert(signer_id, ecdsa_pk.clone());

            let weight_start = weight_end;
            weight_end = weight_start + entry.weight;
            let key_ids: HashSet<u32> = (weight_start as u32..weight_end as u32).collect();
            for key_id in key_ids.iter() {
                wsts_key_ids.insert(*key_id, ecdsa_pk.clone());
            }
            signer_key_ids.insert(signer_id, key_ids);
            
            next_key_id = weight_end;
        }

        let num_signers = signers.len() as u32;
        let num_keys = next_key_id as u32;
        let threshold = (num_keys * 2) / 3 + 1;

        let wsts_public_keys = PublicKeys {
            signers: wsts_signers,
            key_ids: wsts_key_ids,
        };

        Ok(Self {
            num_signers,
            num_keys,
            threshold,
            signer_key_ids,
            signer_public_keys,
            wsts_public_keys,
        })
    }
}

fn get_signer_commitments(
    _is_mainnet: bool,
    signers: &[NakamotoSignerEntry],
    _funaidb_conn: &FunaiDBs,
    _reward_cycle: u64,
    _aggregate_public_key: &Point,
) -> Result<HashMap<u32, PolyCommitment>, ChainstateError> {
    let mut party_polynomials = HashMap::new();
    for (i, _entry) in signers.iter().enumerate() {
        let _signer_id = i as u32;
        // In a real implementation, we would fetch these from FunaiDB
        // For now, we assume we have them or they are not needed for initial signing round
    }
    Ok(party_polynomials)
}
