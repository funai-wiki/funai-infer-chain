use clarity::vm::costs::ExecutionCost;
use funai_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, FunaiWorkScore, TrieHash,
};
use funai_common::util::hash::{to_hex, Hash160, Sha512Trunc256Sum};
use funai_common::util::vrf::VRFProof;

use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::funai::db::{FunaiEpochReceipt, FunaiHeaderInfo};
use crate::chainstate::funai::events::FunaiTransactionReceipt;
use crate::chainstate::funai::{
    CoinbasePayload, FunaiBlockHeader, FunaiTransaction, TokenTransferMemo, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionSpendingCondition, TransactionVersion,
};
use crate::core::FunaiEpochId;

/// Make a block receipt from `tx_receipts` with some dummy values filled for test.
#[cfg(test)]
pub fn make_block_receipt(tx_receipts: Vec<FunaiTransactionReceipt>) -> FunaiEpochReceipt {
    FunaiEpochReceipt {
        header: FunaiHeaderInfo {
            anchored_header: FunaiBlockHeader {
                version: 1,
                total_work: FunaiWorkScore { burn: 1, work: 1 },
                proof: VRFProof::empty(),
                parent_block: BlockHeaderHash([0; 32]),
                parent_microblock: BlockHeaderHash([0; 32]),
                parent_microblock_sequence: 0,
                tx_merkle_root: Sha512Trunc256Sum([0; 32]),
                state_index_root: TrieHash([0; 32]),
                microblock_pubkey_hash: Hash160([0; 20]),
            }
            .into(),
            microblock_tail: None,
            funai_block_height: 1,
            index_root: TrieHash([0; 32]),
            consensus_hash: ConsensusHash([2; 20]),
            burn_header_hash: BurnchainHeaderHash([1; 32]),
            burn_header_height: 2,
            burn_header_timestamp: 2,
            anchored_block_size: 1,
        },
        tx_receipts,
        matured_rewards: vec![],
        matured_rewards_info: None,
        parent_microblocks_cost: ExecutionCost::zero(),
        anchored_block_cost: ExecutionCost::zero(),
        parent_burn_block_hash: BurnchainHeaderHash([0; 32]),
        parent_burn_block_height: 1,
        parent_burn_block_timestamp: 1,
        evaluated_epoch: FunaiEpochId::Epoch20,
        epoch_transition: false,
        signers_updated: false,
    }
}
