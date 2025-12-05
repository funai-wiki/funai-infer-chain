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
//
use funailib::chainstate::funai::FunaiTransaction;
use funailib::net::api::postfunaidbchunk::FunaiDBErrorCodes;
use hashbrown::HashMap;
use libsigner::{MessageSlotID, SignerMessage, SignerSession, FunaiDBSession};
use libfunaidb::{FunaiDBChunkAckData, FunaiDBChunkData};
use slog::{slog_debug, slog_warn};
use funai_common::codec::{read_next, FunaiMessageCodec};
use funai_common::types::chainstate::FunaiPrivateKey;
use funai_common::{debug, warn};

use super::ClientError;
use crate::client::retry_with_exponential_backoff;
use crate::config::SignerConfig;
use crate::signer::SignerSlotID;

/// The FunaiDB client for communicating with the .signers contract
pub struct FunaiDB {
    /// The funai-db sessions for each signer set and message type.
    /// Maps message ID to the DB session.
    signers_message_funaidb_sessions: HashMap<MessageSlotID, FunaiDBSession>,
    /// The private key used in all funai node communications
    funai_private_key: FunaiPrivateKey,
    /// A map of a message ID to last chunk version for each session
    slot_versions: HashMap<MessageSlotID, HashMap<SignerSlotID, u32>>,
    /// The signer slot ID -- the index into the signer list for this signer daemon's signing key.
    signer_slot_id: SignerSlotID,
    /// The reward cycle of the connecting signer
    reward_cycle: u64,
    /// The funai-db transaction msg session for the NEXT reward cycle
    next_transaction_session: FunaiDBSession,
}

impl From<&SignerConfig> for FunaiDB {
    fn from(config: &SignerConfig) -> Self {
        Self::new(
            &config.node_host,
            config.funai_private_key,
            config.mainnet,
            config.reward_cycle,
            config.signer_slot_id,
        )
    }
}
impl FunaiDB {
    /// Create a new FunaiDB client
    pub fn new(
        host: &str,
        funai_private_key: FunaiPrivateKey,
        is_mainnet: bool,
        reward_cycle: u64,
        signer_slot_id: SignerSlotID,
    ) -> Self {
        let mut signers_message_funaidb_sessions = HashMap::new();
        for msg_id in MessageSlotID::ALL {
            signers_message_funaidb_sessions.insert(
                *msg_id,
                FunaiDBSession::new(host, msg_id.funai_db_contract(is_mainnet, reward_cycle)),
            );
        }
        let next_transaction_session = FunaiDBSession::new(
            host,
            MessageSlotID::Transactions
                .funai_db_contract(is_mainnet, reward_cycle.wrapping_add(1)),
        );

        Self {
            signers_message_funaidb_sessions,
            funai_private_key,
            slot_versions: HashMap::new(),
            signer_slot_id,
            reward_cycle,
            next_transaction_session,
        }
    }

    /// Sends messages to the .signers funai-db with an exponential backoff retry
    pub fn send_message_with_retry(
        &mut self,
        message: SignerMessage,
    ) -> Result<FunaiDBChunkAckData, ClientError> {
        let msg_id = message.msg_id();
        let message_bytes = message.serialize_to_vec();
        self.send_message_bytes_with_retry(&msg_id, message_bytes)
    }

    /// Sends message (as a raw msg ID and bytes) to the .signers funai-db with an
    ///  exponential backoff retry
    pub fn send_message_bytes_with_retry(
        &mut self,
        msg_id: &MessageSlotID,
        message_bytes: Vec<u8>,
    ) -> Result<FunaiDBChunkAckData, ClientError> {
        let slot_id = self.signer_slot_id;
        loop {
            let mut slot_version = if let Some(versions) = self.slot_versions.get_mut(msg_id) {
                if let Some(version) = versions.get(&slot_id) {
                    *version
                } else {
                    versions.insert(slot_id, 0);
                    1
                }
            } else {
                let mut versions = HashMap::new();
                versions.insert(slot_id, 0);
                self.slot_versions.insert(*msg_id, versions);
                1
            };

            let mut chunk = FunaiDBChunkData::new(slot_id.0, slot_version, message_bytes.clone());
            chunk.sign(&self.funai_private_key)?;

            let Some(session) = self.signers_message_funaidb_sessions.get_mut(msg_id) else {
                panic!("FATAL: would loop forever trying to send a message with ID {}, for which we don't have a session", msg_id);
            };

            debug!(
                "Sending a chunk to funaidb slot ID {slot_id} with version {slot_version} to contract {:?}!\n{chunk:?}",
                &session.funaidb_contract_id
            );

            let send_request = || session.put_chunk(&chunk).map_err(backoff::Error::transient);
            let chunk_ack: FunaiDBChunkAckData = retry_with_exponential_backoff(send_request)?;

            if let Some(versions) = self.slot_versions.get_mut(msg_id) {
                // NOTE: per the above, this is always executed
                versions.insert(slot_id, slot_version.saturating_add(1));
            } else {
                return Err(ClientError::NotConnected);
            }

            if chunk_ack.accepted {
                debug!("Chunk accepted by funaidb: {chunk_ack:?}");
                return Ok(chunk_ack);
            } else {
                warn!("Chunk rejected by funaidb: {chunk_ack:?}");
            }
            if let Some(code) = chunk_ack.code {
                match FunaiDBErrorCodes::from_code(code) {
                    Some(FunaiDBErrorCodes::DataAlreadyExists) => {
                        if let Some(slot_metadata) = chunk_ack.metadata {
                            warn!("Failed to send message to funaidb due to wrong version number. Attempted {}. Expected {}. Retrying...", slot_version, slot_metadata.slot_version);
                            slot_version = slot_metadata.slot_version;
                        } else {
                            warn!("Failed to send message to funaidb due to wrong version number. Attempted {}. Expected unknown version number. Incrementing and retrying...", slot_version);
                        }
                        if let Some(versions) = self.slot_versions.get_mut(msg_id) {
                            // NOTE: per the above, this is always executed
                            versions.insert(slot_id, slot_version.saturating_add(1));
                        } else {
                            return Err(ClientError::NotConnected);
                        }
                    }
                    _ => {
                        warn!("Failed to send message to funaidb: {:?}", chunk_ack);
                        return Err(ClientError::PutChunkRejected(
                            chunk_ack
                                .reason
                                .unwrap_or_else(|| "No reason given".to_string()),
                        ));
                    }
                }
            }
        }
    }

    /// Get the transactions from funaidb for the signers
    fn get_transactions(
        transactions_session: &mut FunaiDBSession,
        signer_ids: &[SignerSlotID],
    ) -> Result<Vec<FunaiTransaction>, ClientError> {
        let send_request = || {
            transactions_session
                .get_latest_chunks(&signer_ids.iter().map(|id| id.0).collect::<Vec<_>>())
                .map_err(backoff::Error::transient)
        };
        let chunk_ack = retry_with_exponential_backoff(send_request)?;
        let mut transactions = Vec::new();
        for (i, chunk) in chunk_ack.iter().enumerate() {
            let signer_id = *signer_ids
                .get(i)
                .expect("BUG: retrieved an unequal amount of chunks to requested chunks");
            let Some(data) = chunk else {
                continue;
            };
            let Ok(message) = read_next::<SignerMessage, _>(&mut &data[..]) else {
                if !data.is_empty() {
                    warn!("Failed to deserialize chunk data into a SignerMessage");
                    debug!(
                        "signer #{signer_id}: Failed chunk ({}): {data:?}",
                        &data.len(),
                    );
                }
                continue;
            };

            let SignerMessage::Transactions(chunk_transactions) = message else {
                warn!("Signer wrote an unexpected type to the transactions slot");
                continue;
            };
            debug!(
                "Retrieved {} transactions from signer ID {}.",
                chunk_transactions.len(),
                signer_id
            );
            transactions.extend(chunk_transactions);
        }
        Ok(transactions)
    }

    /// Get this signer's latest transactions from funaidb
    pub fn get_current_transactions_with_retry(
        &mut self,
    ) -> Result<Vec<FunaiTransaction>, ClientError> {
        let Some(transactions_session) = self
            .signers_message_funaidb_sessions
            .get_mut(&MessageSlotID::Transactions)
        else {
            return Err(ClientError::NotConnected);
        };
        Self::get_transactions(transactions_session, &[self.signer_slot_id])
    }

    /// Get the latest signer transactions from signer ids for the next reward cycle
    pub fn get_next_transactions_with_retry(
        &mut self,
        signer_ids: &[SignerSlotID],
    ) -> Result<Vec<FunaiTransaction>, ClientError> {
        debug!("Getting latest chunks from funaidb for the following signers: {signer_ids:?}",);
        Self::get_transactions(&mut self.next_transaction_session, signer_ids)
    }

    /// Retrieve the signer set this funaidb client is attached to
    pub fn get_signer_set(&self) -> u32 {
        u32::try_from(self.reward_cycle % 2).expect("FATAL: reward cycle % 2 exceeds u32::MAX")
    }

    /// Retrieve the signer slot ID
    pub fn get_signer_slot_id(&mut self) -> SignerSlotID {
        self.signer_slot_id
    }
}

#[cfg(test)]
mod tests {
    use std::thread::spawn;
    use std::time::Duration;

    use funailib::chainstate::funai::{
        TransactionAnchorMode, TransactionAuth, TransactionPayload, TransactionPostConditionMode,
        TransactionSmartContract, TransactionVersion,
    };
    use funailib::util_lib::strings::FunaiString;

    use super::*;
    use crate::client::tests::{generate_signer_config, mock_server_from_config, write_response};
    use crate::config::GlobalConfig;

    #[test]
    fn get_signer_transactions_with_retry_should_succeed() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let signer_config = generate_signer_config(&config, 5, 20);
        let mut funaidb = FunaiDB::from(&signer_config);
        let sk = FunaiPrivateKey::new();
        let tx = FunaiTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0,
            auth: TransactionAuth::from_p2pkh(&sk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "test-contract".into(),
                    code_body: FunaiString::from_str("(/ 1 0)").unwrap(),
                },
                None,
            ),
        };

        let signer_message = SignerMessage::Transactions(vec![tx.clone()]);
        let message = signer_message.serialize_to_vec();

        let signer_slot_ids = vec![SignerSlotID(0), SignerSlotID(1)];
        let h = spawn(move || funaidb.get_next_transactions_with_retry(&signer_slot_ids));
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let transactions = h.join().unwrap().unwrap();
        assert_eq!(transactions, vec![tx]);
    }

    #[test]
    fn send_signer_message_with_retry_should_succeed() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-1.toml").unwrap();
        let signer_config = generate_signer_config(&config, 5, 20);
        let mut funaidb = FunaiDB::from(&signer_config);

        let sk = FunaiPrivateKey::new();
        let tx = FunaiTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0,
            auth: TransactionAuth::from_p2pkh(&sk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "test-contract".into(),
                    code_body: FunaiString::from_str("(/ 1 0)").unwrap(),
                },
                None,
            ),
        };

        let signer_message = SignerMessage::Transactions(vec![tx]);
        let ack = FunaiDBChunkAckData {
            accepted: true,
            reason: None,
            metadata: None,
            code: None,
        };
        let mock_server = mock_server_from_config(&config);
        let h = spawn(move || funaidb.send_message_with_retry(signer_message));
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        let payload = serde_json::to_string(&ack).expect("Failed to serialize ack");
        response_bytes.extend(payload.as_bytes());
        std::thread::sleep(Duration::from_millis(500));
        write_response(mock_server, response_bytes.as_slice());
        assert_eq!(ack, h.join().unwrap().unwrap());
    }
}
