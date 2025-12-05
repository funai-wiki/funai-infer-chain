use clarity::vm::analysis::ContractAnalysis;
use clarity::vm::costs::ExecutionCost;
pub use clarity::vm::events::FunaiTransactionEvent;
use clarity::vm::types::{
    AssetIdentifier, PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value,
};
use libfunaidb::FunaiDBChunkData;
use funai_common::codec::FunaiMessageCodec;
use funai_common::types::chainstate::{BlockHeaderHash, FunaiAddress};
use funai_common::util::hash::to_hex;

use crate::burnchains::Txid;
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::funai::{FunaiBlock, FunaiMicroblockHeader, FunaiTransaction};

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionOrigin {
    Funai(FunaiTransaction),
    Burn(BlockstackOperationType),
}

impl From<FunaiTransaction> for TransactionOrigin {
    fn from(o: FunaiTransaction) -> TransactionOrigin {
        TransactionOrigin::Funai(o)
    }
}

impl TransactionOrigin {
    pub fn txid(&self) -> Txid {
        match self {
            TransactionOrigin::Burn(op) => op.txid(),
            TransactionOrigin::Funai(tx) => tx.txid(),
        }
    }
    /// Serialize this origin type to a string that can be stored in
    ///  a database
    pub fn serialize_to_dbstring(&self) -> String {
        match self {
            TransactionOrigin::Burn(op) => format!("BTC({})", op.txid()),
            TransactionOrigin::Funai(tx) => to_hex(&tx.serialize_to_vec()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunaiTransactionReceipt {
    pub transaction: TransactionOrigin,
    pub events: Vec<FunaiTransactionEvent>,
    pub post_condition_aborted: bool,
    pub result: Value,
    pub stx_burned: u128,
    pub contract_analysis: Option<ContractAnalysis>,
    pub execution_cost: ExecutionCost,
    pub microblock_header: Option<FunaiMicroblockHeader>,
    pub tx_index: u32,
    /// This is really a string-formatted CheckError (which can't be clone()'ed)
    pub vm_error: Option<String>,
}

#[derive(Clone)]
pub struct FunaiBlockEventData {
    pub block_hash: BlockHeaderHash,
    pub parent_block_hash: BlockHeaderHash,
    pub parent_microblock_hash: BlockHeaderHash,
    pub parent_microblock_sequence: u16,
}

impl From<FunaiBlock> for FunaiBlockEventData {
    fn from(block: FunaiBlock) -> FunaiBlockEventData {
        FunaiBlockEventData {
            block_hash: block.block_hash(),
            parent_block_hash: block.header.parent_block,
            parent_microblock_hash: block.header.parent_microblock,
            parent_microblock_sequence: block.header.parent_microblock_sequence,
        }
    }
}

impl From<(NakamotoBlock, BlockHeaderHash)> for FunaiBlockEventData {
    fn from(block: (NakamotoBlock, BlockHeaderHash)) -> FunaiBlockEventData {
        FunaiBlockEventData {
            block_hash: block.0.header.block_hash(),
            parent_block_hash: block.1,
            parent_microblock_hash: BlockHeaderHash([0u8; 32]),
            parent_microblock_sequence: 0,
        }
    }
}

/// Event structure for newly-arrived FunaiDB data
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FunaiDBChunksEvent {
    /// The contract ID for the FunaiDB instance
    pub contract_id: QualifiedContractIdentifier,
    /// The chunk data for newly-modified slots
    pub modified_slots: Vec<FunaiDBChunkData>,
    /// The miner endpoint for the FunaiDB instance
    pub miner_endpoint: Option<String>,
}
