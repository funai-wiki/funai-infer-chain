use std::collections::VecDeque;
use std::time::Instant;

use clarity::vm::costs::ExecutionCost;
use funai::burnchains::bitcoin::BitcoinBlock;
use funai::burnchains::{
    Burnchain, BurnchainBlock, BurnchainBlockHeader, BurnchainStateTransitionOps, Txid,
};
use funai::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use funai::chainstate::burn::operations::leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS;
use funai::chainstate::burn::operations::{
    BlockstackOperationType, DelegateStxOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp,
    StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
use funai::chainstate::burn::BlockSnapshot;
use funai::core::{
    FunaiEpoch, FunaiEpochId, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_EPOCH_2_1, PEER_VERSION_EPOCH_2_2, PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4,
    PEER_VERSION_EPOCH_2_5, PEER_VERSION_EPOCH_3_0, STACKS_EPOCH_MAX,
};
use funai_common::types::chainstate::{BurnchainHeaderHash, PoxId};
use funai_common::util::get_epoch_time_secs;
use funai_common::util::hash::Sha256Sum;

use super::super::operations::BurnchainOpSigner;
use super::super::Config;
use super::{BurnchainController, BurnchainTip, Error as BurnchainControllerError};

/// MocknetController is simulating a simplistic burnchain.
pub struct MocknetController {
    config: Config,
    burnchain: Burnchain,
    db: Option<SortitionDB>,
    chain_tip: Option<BurnchainTip>,
    queued_operations: VecDeque<BlockstackOperationType>,
}

impl MocknetController {
    pub fn generic(config: Config) -> Box<dyn BurnchainController> {
        Box::new(Self::new(config))
    }

    fn new(config: Config) -> Self {
        debug!("Opening Burnchain at {}", &config.get_burn_db_path());
        let burnchain = config.get_burnchain();

        Self {
            config: config,
            burnchain: burnchain,
            db: None,
            queued_operations: VecDeque::new(),
            chain_tip: None,
        }
    }

    fn build_next_block_header(current_block: &BlockSnapshot) -> BurnchainBlockHeader {
        let curr_hash = &current_block.burn_header_hash.to_bytes()[..];
        let next_hash = Sha256Sum::from_data(&curr_hash);

        let block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            current_block.block_height + 1,
            &BurnchainHeaderHash::from_bytes(next_hash.as_bytes()).unwrap(),
            &current_block.burn_header_hash,
            vec![],
            get_epoch_time_secs(),
        ));
        block.header()
    }
}

impl BurnchainController for MocknetController {
    fn sortdb_ref(&self) -> &SortitionDB {
        self.db.as_ref().expect("BUG: did not instantiate burn DB")
    }

    fn sortdb_mut(&mut self) -> &mut SortitionDB {
        match self.db {
            Some(ref mut sortdb) => sortdb,
            None => {
                unreachable!();
            }
        }
    }

    fn get_chain_tip(&self) -> BurnchainTip {
        match &self.chain_tip {
            Some(chain_tip) => chain_tip.clone(),
            None => {
                unreachable!();
            }
        }
    }

    fn get_headers_height(&self) -> u64 {
        match &self.chain_tip {
            Some(chain_tip) => chain_tip.block_snapshot.block_height,
            None => {
                unreachable!();
            }
        }
    }

    fn get_funai_epochs(&self) -> Vec<FunaiEpoch> {
        match &self.config.burnchain.epochs {
            Some(epochs) => epochs.clone(),
            None => vec![
                FunaiEpoch {
                    epoch_id: FunaiEpochId::Epoch20,
                    start_height: 0,
                    end_height: 1,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_0,
                },
                FunaiEpoch {
                    epoch_id: FunaiEpochId::Epoch2_05,
                    start_height: 1,
                    end_height: 2,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_05,
                },
                FunaiEpoch {
                    epoch_id: FunaiEpochId::Epoch21,
                    start_height: 2,
                    end_height: 3,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_1,
                },
                FunaiEpoch {
                    epoch_id: FunaiEpochId::Epoch22,
                    start_height: 3,
                    end_height: 4,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_2,
                },
                FunaiEpoch {
                    epoch_id: FunaiEpochId::Epoch23,
                    start_height: 4,
                    end_height: 5,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_3,
                },
                FunaiEpoch {
                    epoch_id: FunaiEpochId::Epoch24,
                    start_height: 5,
                    end_height: 6,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_4,
                },
                FunaiEpoch {
                    epoch_id: FunaiEpochId::Epoch25,
                    start_height: 6,
                    end_height: STACKS_EPOCH_MAX,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_5,
                },
                // FunaiEpoch {
                //     epoch_id: FunaiEpochId::Epoch30,
                //     start_height: 7,
                //     end_height: STACKS_EPOCH_MAX,
                //     block_limit: ExecutionCost::max_value(),
                //     network_epoch: PEER_VERSION_EPOCH_3_0,
                // },
            ],
        }
    }

    fn start(
        &mut self,
        _ignored_target_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), BurnchainControllerError> {
        // If `config` sets a value, use that. Otherwise, use a default.
        let epoch_vector = self.get_funai_epochs();
        let db = match SortitionDB::connect(
            &self.config.get_burn_db_file_path(),
            0,
            &BurnchainHeaderHash::zero(),
            get_epoch_time_secs(),
            &epoch_vector,
            self.burnchain.pox_constants.clone(),
            None,
            true,
        ) {
            Ok(db) => db,
            Err(_) => panic!("Error while connecting to burnchain db"),
        };
        let block_snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn())
            .expect("FATAL: failed to get canonical chain tip");

        self.db = Some(db);

        let genesis_state = BurnchainTip {
            block_snapshot,
            state_transition: BurnchainStateTransitionOps::noop(),
            received_at: Instant::now(),
        };
        self.chain_tip = Some(genesis_state.clone());
        let block_height = genesis_state.block_snapshot.block_height;
        Ok((genesis_state, block_height))
    }

    fn submit_operation(
        &mut self,
        _epoch_id: FunaiEpochId,
        operation: BlockstackOperationType,
        _op_signer: &mut BurnchainOpSigner,
        _attempt: u64,
    ) -> Option<Txid> {
        let txid = operation.txid();
        self.queued_operations.push_back(operation);
        Some(txid)
    }

    fn sync(
        &mut self,
        _ignored_target_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), BurnchainControllerError> {
        let chain_tip = self.get_chain_tip();

        // Simulating mining
        let next_block_header = Self::build_next_block_header(&chain_tip.block_snapshot);
        let mut ops = vec![];

        while let Some(payload) = self.queued_operations.pop_front() {
            let op = match payload {
                BlockstackOperationType::LeaderKeyRegister(payload) => {
                    BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
                        consensus_hash: payload.consensus_hash,
                        public_key: payload.public_key,
                        memo: payload.memo,
                        txid: payload.txid,
                        vtxindex: payload.vtxindex,
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                    })
                }
                BlockstackOperationType::LeaderBlockCommit(payload) => {
                    BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
                        sunset_burn: 0,
                        block_header_hash: payload.block_header_hash,
                        new_seed: payload.new_seed,
                        parent_block_ptr: payload.parent_block_ptr,
                        parent_vtxindex: payload.parent_vtxindex,
                        key_block_ptr: payload.key_block_ptr,
                        key_vtxindex: payload.key_vtxindex,
                        memo: payload.memo,
                        burn_fee: payload.burn_fee,
                        apparent_sender: payload.apparent_sender,
                        input: payload.input,
                        commit_outs: payload.commit_outs,
                        txid: payload.txid,
                        vtxindex: payload.vtxindex,
                        block_height: next_block_header.block_height,
                        burn_parent_modulus: if next_block_header.block_height > 0 {
                            (next_block_header.block_height - 1) % BURN_BLOCK_MINED_AT_MODULUS
                        } else {
                            BURN_BLOCK_MINED_AT_MODULUS - 1
                        } as u8,
                        burn_header_hash: next_block_header.block_hash,
                    })
                }
                BlockstackOperationType::PreStx(payload) => {
                    BlockstackOperationType::PreStx(PreStxOp {
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                        ..payload
                    })
                }
                BlockstackOperationType::TransferStx(payload) => {
                    BlockstackOperationType::TransferStx(TransferStxOp {
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                        ..payload
                    })
                }
                BlockstackOperationType::StackStx(payload) => {
                    BlockstackOperationType::StackStx(StackStxOp {
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                        ..payload
                    })
                }
                BlockstackOperationType::DelegateStx(payload) => {
                    BlockstackOperationType::DelegateStx(DelegateStxOp {
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                        ..payload
                    })
                }
                BlockstackOperationType::VoteForAggregateKey(payload) => {
                    BlockstackOperationType::VoteForAggregateKey(VoteForAggregateKeyOp {
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                        ..payload
                    })
                }
            };
            ops.push(op);
        }

        // Include txs in a new block
        let (block_snapshot, state_transition) = {
            match self.db {
                None => {
                    unreachable!();
                }
                Some(ref mut burn_db) => {
                    let mut burn_tx =
                        SortitionHandleTx::begin(burn_db, &chain_tip.block_snapshot.sortition_id)
                            .unwrap();
                    let new_chain_tip = burn_tx
                        .process_block_ops(
                            &self.burnchain,
                            &chain_tip.block_snapshot,
                            &next_block_header,
                            ops,
                            None,
                            PoxId::stubbed(),
                            None,
                            0,
                        )
                        .unwrap();
                    burn_tx.commit().unwrap();
                    new_chain_tip
                }
            }
        };

        let state_transition = BurnchainStateTransitionOps {
            accepted_ops: state_transition.accepted_ops,
            consumed_leader_keys: state_transition.consumed_leader_keys,
        };

        // Transmit the new state
        let new_state = BurnchainTip {
            block_snapshot,
            state_transition,
            received_at: Instant::now(),
        };
        self.chain_tip = Some(new_state.clone());

        let block_height = new_state.block_snapshot.block_height;
        Ok((new_state, block_height))
    }

    #[cfg(test)]
    fn bootstrap_chain(&mut self, _num_blocks: u64) {}

    fn connect_dbs(&mut self) -> Result<(), BurnchainControllerError> {
        Ok(())
    }
}
