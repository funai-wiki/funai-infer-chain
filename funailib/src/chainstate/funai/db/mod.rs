// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Funai Open Internet Foundation
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

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet};
use std::io::prelude::*;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::{fmt, fs, io};

use clarity::vm::analysis::analysis_db::AnalysisDatabase;
use clarity::vm::analysis::run_analysis;
use clarity::vm::ast::ASTRules;
use clarity::vm::clarity::TransactionConnection;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::{
    BurnStateDB, ClarityDatabase, HeadersDB, STXBalance, SqliteConnection, NULL_BURN_STATE_DB,
};
use clarity::vm::events::*;
use clarity::vm::representations::{ClarityName, ContractName};
use clarity::vm::types::TupleData;
use clarity::vm::{SymbolicExpression, Value};
use lazy_static::lazy_static;
use rusqlite::types::ToSql;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, Transaction, NO_PARAMS};
use serde::de::Error as de_Error;
use serde::Deserialize;
use funai_common::codec::{read_next, write_next, FunaiMessageCodec};
use funai_common::types::chainstate::{FunaiAddress, FunaiBlockId, TrieHash};
use funai_common::util;
use funai_common::util::hash::{hex_bytes, to_hex};

use crate::burnchains::bitcoin::address::{BitcoinAddress, LegacyBitcoinAddress};
use crate::burnchains::{Address, Burnchain, BurnchainParameters, PoxConstants};
use crate::chainstate::burn::db::sortdb::{BlockHeaderCache, SortitionDB, SortitionDBConn, *};
use crate::chainstate::burn::operations::{
    DelegateStxOp, StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
use crate::chainstate::burn::{ConsensusHash, ConsensusHashExtensions};
use crate::chainstate::nakamoto::{
    HeaderTypeNames, NakamotoBlock, NakamotoBlockHeader, NakamotoChainState,
    NakamotoStagingBlocksConn, NAKAMOTO_CHAINSTATE_SCHEMA_1,
};
use crate::chainstate::funai::address::FunaiAddressExtensions;
use crate::chainstate::funai::boot::*;
use crate::chainstate::funai::db::accounts::*;
use crate::chainstate::funai::db::blocks::*;
use crate::chainstate::funai::db::unconfirmed::UnconfirmedState;
use crate::chainstate::funai::events::*;
use crate::chainstate::funai::index::marf::{
    MARFOpenOpts, MarfConnection, BLOCK_HASH_TO_HEIGHT_MAPPING_KEY,
    BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF,
};
use crate::chainstate::funai::index::storage::TrieFileStorage;
use crate::chainstate::funai::index::{ClarityMarfTrieId, MARFValue, MarfTrieId};
use crate::chainstate::funai::{
    Error, FunaiBlockHeader, FunaiMicroblockHeader, C32_ADDRESS_VERSION_MAINNET_MULTISIG,
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::clarity_vm::clarity::{
    ClarityBlockConnection, ClarityConnection, ClarityInstance, ClarityReadOnlyConnection,
    Error as clarity_error, PreCommitClarityBlock,
};
use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::*;
use crate::monitoring;
use crate::net::atlas::BNS_CHARS_REGEX;
use crate::net::Error as net_error;
use crate::util_lib::boot::{boot_code_acc, boot_code_addr, boot_code_id, boot_code_tx_auth};
use crate::util_lib::db::{
    query_count, query_row, tx_begin_immediate, tx_busy_handler, DBConn, DBTx, Error as db_error,
    FromColumn, FromRow, IndexDBConn, IndexDBTx,
};

pub mod accounts;
pub mod blocks;
pub mod contracts;
pub mod headers;
pub mod transactions;
pub mod unconfirmed;

lazy_static! {
    pub static ref TRANSACTION_LOG: bool =
        std::env::var("STACKS_TRANSACTION_LOG") == Ok("1".into());
}

/// Fault injection struct for various kinds of faults we'd like to introduce into the system
pub struct FunaiChainStateFaults {
    // if true, then the envar STACKS_HIDE_BLOCKS_AT_HEIGHT will be consulted to get a list of
    // Funai block heights to never propagate or announce.
    pub hide_blocks: bool,
}

impl FunaiChainStateFaults {
    pub fn new() -> Self {
        Self { hide_blocks: false }
    }
}

pub struct FunaiChainState {
    pub mainnet: bool,
    pub chain_id: u32,
    pub clarity_state: ClarityInstance,
    pub nakamoto_staging_blocks_conn: NakamotoStagingBlocksConn,
    pub state_index: MARF<FunaiBlockId>,
    pub blocks_path: String,
    pub clarity_state_index_path: String, // path to clarity MARF
    pub clarity_state_index_root: String, // path to dir containing clarity MARF and side-store
    pub root_path: String,
    pub unconfirmed_state: Option<UnconfirmedState>,
    pub fault_injection: FunaiChainStateFaults,
    marf_opts: Option<MARFOpenOpts>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunaiAccount {
    pub principal: PrincipalData,
    pub nonce: u64,
    pub stx_balance: STXBalance,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MinerPaymentTxFees {
    Epoch2 { anchored: u128, streamed: u128 },
    Nakamoto { parent_fees: u128 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerPaymentSchedule {
    pub address: FunaiAddress,
    pub recipient: PrincipalData,
    pub block_hash: BlockHeaderHash,
    pub consensus_hash: ConsensusHash,
    pub parent_block_hash: BlockHeaderHash,
    pub parent_consensus_hash: ConsensusHash,
    pub coinbase: u128,
    pub tx_fees: MinerPaymentTxFees,
    pub burnchain_commit_burn: u64,
    pub burnchain_sortition_burn: u64,
    pub miner: bool, // is this a schedule payment for the block's miner?
    pub funai_block_height: u64,
    pub vtxindex: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FunaiBlockHeaderTypes {
    Epoch2(FunaiBlockHeader),
    Nakamoto(NakamotoBlockHeader),
}

impl From<FunaiBlockHeader> for FunaiBlockHeaderTypes {
    fn from(value: FunaiBlockHeader) -> Self {
        Self::Epoch2(value)
    }
}

impl From<NakamotoBlockHeader> for FunaiBlockHeaderTypes {
    fn from(value: NakamotoBlockHeader) -> Self {
        Self::Nakamoto(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunaiHeaderInfo {
    /// Funai block header
    pub anchored_header: FunaiBlockHeaderTypes,
    /// Last microblock header (Funai 2.x only; this is None in Funai 3.x)
    pub microblock_tail: Option<FunaiMicroblockHeader>,
    /// Height of this Funai block
    pub funai_block_height: u64,
    /// MARF root hash of the headers DB (not consensus critical)
    pub index_root: TrieHash,
    /// consensus hash of the burnchain block in which this miner was selected to produce this block
    pub consensus_hash: ConsensusHash,
    /// Hash of the burnchain block in which this miner was selected to produce this block
    pub burn_header_hash: BurnchainHeaderHash,
    /// Height of the burnchain block
    pub burn_header_height: u32,
    /// Timestamp of the burnchain block
    pub burn_header_timestamp: u64,
    /// Size of the block corresponding to `anchored_header` in bytes
    pub anchored_block_size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerRewardInfo {
    pub from_block_consensus_hash: ConsensusHash,
    pub from_funai_block_hash: BlockHeaderHash,
    pub from_parent_block_consensus_hash: ConsensusHash,
    pub from_parent_funai_block_hash: BlockHeaderHash,
}

/// This is the block receipt for a Funai block
#[derive(Debug, Clone, PartialEq)]
pub struct FunaiEpochReceipt {
    pub header: FunaiHeaderInfo,
    pub tx_receipts: Vec<FunaiTransactionReceipt>,
    pub matured_rewards: Vec<MinerReward>,
    pub matured_rewards_info: Option<MinerRewardInfo>,
    pub parent_microblocks_cost: ExecutionCost,
    pub anchored_block_cost: ExecutionCost,
    pub parent_burn_block_hash: BurnchainHeaderHash,
    pub parent_burn_block_height: u32,
    pub parent_burn_block_timestamp: u64,
    /// This is the Funai epoch that the block was evaluated in,
    /// which is the Funai epoch that this block's parent was elected
    /// in.
    pub evaluated_epoch: FunaiEpochId,
    pub epoch_transition: bool,
    /// Was .signers updated during this block?
    pub signers_updated: bool,
}

/// Headers we serve over the network
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtendedFunaiHeader {
    pub consensus_hash: ConsensusHash,
    #[serde(
        serialize_with = "ExtendedFunaiHeader_FunaiBlockHeader_serialize",
        deserialize_with = "ExtendedFunaiHeader_FunaiBlockHeader_deserialize"
    )]
    pub header: FunaiBlockHeader,
    pub parent_block_id: FunaiBlockId,
}

/// In ExtendedFunaiHeader, encode the FunaiBlockHeader as a hex string
fn ExtendedFunaiHeader_FunaiBlockHeader_serialize<S: serde::Serializer>(
    header: &FunaiBlockHeader,
    s: S,
) -> Result<S::Ok, S::Error> {
    let bytes = header.serialize_to_vec();
    let header_hex = to_hex(&bytes);
    s.serialize_str(&header_hex.as_str())
}

/// In ExtendedFunaiHeader, encode the FunaiBlockHeader as a hex string
fn ExtendedFunaiHeader_FunaiBlockHeader_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<FunaiBlockHeader, D::Error> {
    let header_hex = String::deserialize(d)?;
    let header_bytes = hex_bytes(&header_hex).map_err(de_Error::custom)?;
    FunaiBlockHeader::consensus_deserialize(&mut &header_bytes[..]).map_err(de_Error::custom)
}

impl FunaiMessageCodec for ExtendedFunaiHeader {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.consensus_hash)?;
        write_next(fd, &self.header)?;
        write_next(fd, &self.parent_block_id)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ExtendedFunaiHeader, codec_error> {
        let ch = read_next(fd)?;
        let bh = read_next(fd)?;
        let pbid = read_next(fd)?;
        Ok(ExtendedFunaiHeader {
            consensus_hash: ch,
            header: bh,
            parent_block_id: pbid,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DBConfig {
    pub version: String,
    pub mainnet: bool,
    pub chain_id: u32,
}

impl DBConfig {
    pub fn supports_epoch(&self, epoch_id: FunaiEpochId) -> bool {
        match epoch_id {
            FunaiEpochId::Epoch10 => true,
            FunaiEpochId::Epoch20 => {
                self.version == "1"
                    || self.version == "2"
                    || self.version == "3"
                    || self.version == "4"
                    || self.version == "5"
            }
            FunaiEpochId::Epoch2_05 => {
                self.version == "2" || self.version == "3" || self.version == "4" || self.version == "5"
            }
            FunaiEpochId::Epoch21 => self.version == "3" || self.version == "4" || self.version == "5",
            FunaiEpochId::Epoch22 => self.version == "3" || self.version == "4" || self.version == "5",
            FunaiEpochId::Epoch23 => self.version == "3" || self.version == "4" || self.version == "5",
            FunaiEpochId::Epoch24 => self.version == "3" || self.version == "4" || self.version == "5",
            FunaiEpochId::Epoch25 => self.version == "3" || self.version == "4" || self.version == "5",
            FunaiEpochId::Epoch30 => self.version == "3" || self.version == "4" || self.version == "5",
        }
    }
}

impl FunaiBlockHeaderTypes {
    pub fn block_hash(&self) -> BlockHeaderHash {
        match &self {
            FunaiBlockHeaderTypes::Epoch2(x) => x.block_hash(),
            FunaiBlockHeaderTypes::Nakamoto(x) => x.block_hash(),
        }
    }

    pub fn is_first_mined(&self) -> bool {
        match self {
            FunaiBlockHeaderTypes::Epoch2(x) => x.is_first_mined(),
            FunaiBlockHeaderTypes::Nakamoto(x) => x.is_first_mined(),
        }
    }

    pub fn height(&self) -> u64 {
        match self {
            FunaiBlockHeaderTypes::Epoch2(x) => x.total_work.work,
            FunaiBlockHeaderTypes::Nakamoto(x) => x.chain_length,
        }
    }

    /// Get the total spend by miners for this block
    pub fn total_burns(&self) -> u64 {
        match self {
            FunaiBlockHeaderTypes::Epoch2(x) => x.total_work.burn,
            FunaiBlockHeaderTypes::Nakamoto(x) => x.burn_spent,
        }
    }

    pub fn as_funai_epoch2(&self) -> Option<&FunaiBlockHeader> {
        match &self {
            FunaiBlockHeaderTypes::Epoch2(ref x) => Some(x),
            _ => None,
        }
    }

    pub fn as_funai_nakamoto(&self) -> Option<&NakamotoBlockHeader> {
        match &self {
            FunaiBlockHeaderTypes::Nakamoto(ref x) => Some(x),
            _ => None,
        }
    }
}

impl FunaiHeaderInfo {
    pub fn index_block_hash(&self) -> FunaiBlockId {
        let block_hash = self.anchored_header.block_hash();
        FunaiBlockId::new(&self.consensus_hash, &block_hash)
    }

    pub fn regtest_genesis() -> FunaiHeaderInfo {
        let burnchain_params = BurnchainParameters::bitcoin_regtest();
        FunaiHeaderInfo {
            anchored_header: FunaiBlockHeader::genesis_block_header().into(),
            microblock_tail: None,
            funai_block_height: 0,
            index_root: TrieHash([0u8; 32]),
            burn_header_hash: burnchain_params.first_block_hash.clone(),
            burn_header_height: burnchain_params.first_block_height as u32,
            consensus_hash: ConsensusHash::empty(),
            burn_header_timestamp: 0,
            anchored_block_size: 0,
        }
    }

    pub fn genesis(
        root_hash: TrieHash,
        first_burnchain_block_hash: &BurnchainHeaderHash,
        first_burnchain_block_height: u32,
        first_burnchain_block_timestamp: u64,
    ) -> FunaiHeaderInfo {
        FunaiHeaderInfo {
            anchored_header: FunaiBlockHeader::genesis_block_header().into(),
            microblock_tail: None,
            funai_block_height: 0,
            index_root: root_hash,
            burn_header_hash: first_burnchain_block_hash.clone(),
            burn_header_height: first_burnchain_block_height,
            consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            burn_header_timestamp: first_burnchain_block_timestamp,
            anchored_block_size: 0,
        }
    }

    pub fn is_first_mined(&self) -> bool {
        self.anchored_header.is_first_mined()
    }

    pub fn is_epoch_2_block(&self) -> bool {
        matches!(self.anchored_header, FunaiBlockHeaderTypes::Epoch2(_))
    }

    pub fn is_nakamoto_block(&self) -> bool {
        matches!(self.anchored_header, FunaiBlockHeaderTypes::Nakamoto(_))
    }
}

impl FromRow<DBConfig> for DBConfig {
    fn from_row<'a>(row: &'a Row) -> Result<DBConfig, db_error> {
        let version: String = row.get_unwrap("version");
        let mainnet_i64: i64 = row.get_unwrap("mainnet");
        let chain_id_i64: i64 = row.get_unwrap("chain_id");

        let mainnet = mainnet_i64 != 0;
        let chain_id = chain_id_i64 as u32;

        Ok(DBConfig {
            version,
            mainnet,
            chain_id,
        })
    }
}

impl FromRow<FunaiHeaderInfo> for FunaiHeaderInfo {
    fn from_row<'a>(row: &'a Row) -> Result<FunaiHeaderInfo, db_error> {
        let block_height: u64 = u64::from_column(row, "block_height")?;
        let index_root = TrieHash::from_column(row, "index_root")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let burn_header_height: u64 = u64::from_column(row, "burn_header_height")?;
        let burn_header_timestamp = u64::from_column(row, "burn_header_timestamp")?;
        let anchored_block_size_str: String = row.get_unwrap("block_size");
        let anchored_block_size = anchored_block_size_str
            .parse::<u64>()
            .map_err(|_| db_error::ParseError)?;

        let funai_header: FunaiBlockHeaderTypes = {
            let header_type: HeaderTypeNames = row
                .get("header_type")
                .unwrap_or_else(|_e| HeaderTypeNames::Epoch2);
            match header_type {
                HeaderTypeNames::Epoch2 => FunaiBlockHeader::from_row(row)?.into(),
                HeaderTypeNames::Nakamoto => NakamotoBlockHeader::from_row(row)?.into(),
            }
        };

        if block_height != funai_header.height() {
            return Err(db_error::ParseError);
        }

        Ok(FunaiHeaderInfo {
            anchored_header: funai_header,
            microblock_tail: None,
            funai_block_height: block_height,
            index_root,
            consensus_hash,
            burn_header_hash,
            burn_header_height: burn_header_height as u32,
            burn_header_timestamp,
            anchored_block_size,
        })
    }
}

pub type FunaiDBTx<'a> = IndexDBTx<'a, (), FunaiBlockId>;
pub type FunaiDBConn<'a> = IndexDBConn<'a, (), FunaiBlockId>;

pub struct ClarityTx<'a, 'b> {
    block: ClarityBlockConnection<'a, 'b>,
    pub config: DBConfig,
}

impl<'a, 'b> ClarityConnection for ClarityTx<'a, 'b> {
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase),
    {
        ClarityConnection::with_clarity_db_readonly_owned(&mut self.block, to_do)
    }

    fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase) -> R,
    {
        self.block.with_analysis_db_readonly(to_do)
    }

    fn get_epoch(&self) -> FunaiEpochId {
        self.block.get_epoch()
    }
}

impl<'a, 'b> ClarityTx<'a, 'b> {
    pub fn cost_so_far(&self) -> ExecutionCost {
        self.block.cost_so_far()
    }

    pub fn get_epoch(&self) -> FunaiEpochId {
        self.block.get_epoch()
    }

    /// Set the ClarityTx's cost tracker.
    /// Returns the replaced cost tracker.
    fn set_cost_tracker(&mut self, new_tracker: LimitedCostTracker) -> LimitedCostTracker {
        self.block.set_cost_tracker(new_tracker)
    }

    /// Returns the block limit for the block being created.
    pub fn block_limit(&self) -> Option<ExecutionCost> {
        self.block.block_limit()
    }

    /// Run `todo` in this ClarityTx with `new_tracker`.
    /// Returns the result of `todo` and the `new_tracker`
    pub fn with_temporary_cost_tracker<F, R>(
        &mut self,
        new_tracker: LimitedCostTracker,
        todo: F,
    ) -> (R, LimitedCostTracker)
    where
        F: FnOnce(&mut ClarityTx) -> R,
    {
        let original_tracker = self.set_cost_tracker(new_tracker);
        let result = todo(self);
        let new_tracker = self.set_cost_tracker(original_tracker);
        (result, new_tracker)
    }

    pub fn seal(&mut self) -> TrieHash {
        self.block.seal()
    }

    #[cfg(test)]
    pub fn commit_block(self) -> () {
        self.block.commit_block();
    }

    pub fn commit_mined_block(
        self,
        block_hash: &FunaiBlockId,
    ) -> Result<ExecutionCost, clarity_error> {
        Ok(self.block.commit_mined_block(block_hash)?.get_total())
    }

    pub fn commit_to_block(
        self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> () {
        let index_block_hash = FunaiBlockHeader::make_index_block_hash(consensus_hash, block_hash);
        self.block.commit_to_block(&index_block_hash);
    }

    pub fn precommit_to_block(
        self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> PreCommitClarityBlock<'a> {
        let index_block_hash = FunaiBlockId::new(consensus_hash, block_hash);
        self.block.precommit_to_block(index_block_hash)
    }

    pub fn commit_unconfirmed(self) -> () {
        self.block.commit_unconfirmed();
    }

    pub fn rollback_block(self) -> () {
        self.block.rollback_block()
    }

    pub fn rollback_unconfirmed(self) -> () {
        self.block.rollback_unconfirmed()
    }

    pub fn reset_cost(&mut self, cost: ExecutionCost) -> () {
        self.block.reset_block_cost(cost);
    }

    pub fn connection(&mut self) -> &mut ClarityBlockConnection<'a, 'b> {
        &mut self.block
    }

    pub fn increment_ustx_liquid_supply(&mut self, incr_by: u128) {
        self.connection()
            .as_transaction(|tx| {
                tx.with_clarity_db(|db| {
                    db.increment_ustx_liquid_supply(incr_by)
                        .map_err(|e| e.into())
                })
            })
            .expect("FATAL: `ust-liquid-supply` overflowed");
    }
}

pub struct ChainstateTx<'a> {
    pub config: DBConfig,
    pub blocks_path: String,
    pub tx: FunaiDBTx<'a>,
    pub root_path: String,
}

impl<'a> ChainstateTx<'a> {
    pub fn new(
        tx: FunaiDBTx<'a>,
        blocks_path: String,
        root_path: String,
        config: DBConfig,
    ) -> ChainstateTx<'a> {
        ChainstateTx {
            config,
            blocks_path,
            tx,
            root_path,
        }
    }

    pub fn get_blocks_path(&self) -> &String {
        &self.blocks_path
    }

    pub fn commit(self) -> Result<(), db_error> {
        self.tx.commit()
    }

    pub fn get_config(&self) -> &DBConfig {
        &self.config
    }

    pub fn log_transactions_processed(
        &self,
        block_id: &FunaiBlockId,
        events: &[FunaiTransactionReceipt],
    ) {
        if *TRANSACTION_LOG {
            let insert =
                "INSERT INTO transactions (txid, index_block_hash, tx_hex, result) VALUES (?, ?, ?, ?)";
            for tx_event in events.iter() {
                let txid = tx_event.transaction.txid();
                let tx_hex = tx_event.transaction.serialize_to_dbstring();
                let result = tx_event.result.to_string();
                let params: &[&dyn ToSql] = &[&txid, block_id, &tx_hex, &result];
                if let Err(e) = self.tx.tx().execute(insert, params) {
                    warn!("Failed to log TX: {}", e);
                }
            }
        }
        for tx_event in events.iter() {
            let txid = tx_event.transaction.txid();
            if let Err(e) = monitoring::log_transaction_processed(&txid, &self.root_path) {
                warn!("Failed to monitor TX processed: {:?}", e; "txid" => %txid);
            }
        }
    }
}

impl<'a> Deref for ChainstateTx<'a> {
    type Target = FunaiDBTx<'a>;
    fn deref(&self) -> &FunaiDBTx<'a> {
        &self.tx
    }
}

impl<'a> DerefMut for ChainstateTx<'a> {
    fn deref_mut(&mut self) -> &mut FunaiDBTx<'a> {
        &mut self.tx
    }
}

pub const CHAINSTATE_VERSION: &'static str = "5";

const CHAINSTATE_INITIAL_SCHEMA: &'static [&'static str] = &[
    "PRAGMA foreign_keys = ON;",
    r#"
    -- Anchored funai block headers
    CREATE TABLE block_headers(
        version INTEGER NOT NULL,
        total_burn TEXT NOT NULL,       -- converted to/from u64
        total_work TEXT NOT NULL,       -- converted to/from u64
        proof TEXT NOT NULL,
        parent_block TEXT NOT NULL,             -- hash of parent Funai block
        parent_microblock TEXT NOT NULL,
        parent_microblock_sequence INTEGER NOT NULL,
        tx_merkle_root TEXT NOT NULL,
        state_index_root TEXT NOT NULL,
        microblock_pubkey_hash TEXT NOT NULL,
        
        block_hash TEXT NOT NULL,                   -- NOTE: this is *not* unique, since two burn chain forks can commit to the same Funai block.
        index_block_hash TEXT UNIQUE NOT NULL,      -- NOTE: this is the hash of the block hash and consensus hash of the burn block that selected it, 
                                                    -- and is guaranteed to be globally unique (across all Funai forks and across all PoX forks).
                                                    -- index_block_hash is the block hash fed into the MARF index.

        -- internal use only
        block_height INTEGER NOT NULL,
        index_root TEXT NOT NULL,                    -- root hash of the internal, not-consensus-critical MARF that allows us to track chainstate /fork metadata
        consensus_hash TEXT UNIQUE NOT NULL,         -- all consensus hashes are guaranteed to be unique
        burn_header_hash TEXT NOT NULL,              -- burn header hash corresponding to the consensus hash (NOT guaranteed to be unique, since we can have 2+ blocks per burn block if there's a PoX fork)
        burn_header_height INT NOT NULL,             -- height of the burnchain block header that generated this consensus hash
        burn_header_timestamp INT NOT NULL,          -- timestamp from burnchain block header that generated this consensus hash
        parent_block_id TEXT NOT NULL,               -- NOTE: this is the parent index_block_hash

        cost TEXT NOT NULL,
        block_size TEXT NOT NULL,       -- converted to/from u64
        affirmation_weight INTEGER NOT NULL,

        PRIMARY KEY(consensus_hash,block_hash)
    );"#,
    r#"
    -- scheduled payments
    -- no designated primary key since there can be duplicate entries
    CREATE TABLE payments(
        address TEXT NOT NULL,              -- miner that produced this block and microblock stream
        block_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        parent_block_hash TEXT NOT NULL,
        parent_consensus_hash TEXT NOT NULL,
        coinbase TEXT NOT NULL,             -- encodes u128
        tx_fees_anchored TEXT NOT NULL,     -- encodes u128
        tx_fees_streamed TEXT NOT NULL,     -- encodes u128
        stx_burns TEXT NOT NULL,            -- encodes u128
        burnchain_commit_burn INT NOT NULL,
        burnchain_sortition_burn INT NOT NULL,
        miner INT NOT NULL,
        
        -- internal use
        funai_block_height INTEGER NOT NULL,
        index_block_hash TEXT NOT NULL,     -- NOTE: can't enforce UNIQUE here, because there will be multiple entries per block
        vtxindex INT NOT NULL               -- user burn support vtxindex
    );"#,
    r#"
    -- users who supported miners
    CREATE TABLE user_supporters(
        address TEXT NOT NULL,
        support_burn INT NOT NULL,
        block_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,

        PRIMARY KEY(address,block_hash,consensus_hash)
    );"#,
    r#"
    CREATE TABLE db_config(
        version TEXT NOT NULL,
        mainnet INTEGER NOT NULL,
        chain_id INTEGER NOT NULL
    );"#,
    r#"
    -- Staging microblocks -- preprocessed microblocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_microblocks(anchored_block_hash TEXT NOT NULL,     -- this is the hash of the parent anchored block
                                     consensus_hash TEXT NOT NULL,          -- this is the hash of the burn chain block that holds the parent anchored block's block-commit
                                     index_block_hash TEXT NOT NULL,        -- this is the anchored block's index hash
                                     microblock_hash TEXT NOT NULL,
                                     parent_hash TEXT NOT NULL,             -- previous microblock
                                     index_microblock_hash TEXT NOT NULL,   -- this is the hash of consensus_hash and microblock_hash
                                     sequence INT NOT NULL,
                                     processed INT NOT NULL,
                                     orphaned INT NOT NULL,
                                     PRIMARY KEY(anchored_block_hash,consensus_hash,microblock_hash)
    );"#,
    r#"
    -- Staging microblocks data
    CREATE TABLE staging_microblocks_data(block_hash TEXT NOT NULL,
                                          block_data BLOB NOT NULL,
                                          PRIMARY KEY(block_hash)
    );"#,
    r#"
    -- Invalidated staging microblocks data
    CREATE TABLE invalidated_microblocks_data(block_hash TEXT NOT NULL,
                                              block_data BLOB NOT NULL,
                                              PRIMARY KEY(block_hash)
    );"#,
    r#"
    -- Staging blocks -- preprocessed blocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_blocks(anchored_block_hash TEXT NOT NULL,
                                parent_anchored_block_hash TEXT NOT NULL,
                                consensus_hash TEXT NOT NULL,
                                -- parent_consensus_hash is the consensus hash of the sortition that chose the parent Funai block.
                                parent_consensus_hash TEXT NOT NULL,
                                parent_microblock_hash TEXT NOT NULL,
                                parent_microblock_seq INT NOT NULL,
                                microblock_pubkey_hash TEXT NOT NULL,
                                height INT NOT NULL,
                                attachable INT NOT NULL,            -- set to 1 if this block's parent is processed; 0 if not
                                orphaned INT NOT NULL,              -- set to 1 if this block can never be attached
                                processed INT NOT NULL,
                                commit_burn INT NOT NULL,
                                sortition_burn INT NOT NULL,
                                index_block_hash TEXT NOT NULL,           -- used internally; hash of consensus hash and anchored_block_hash
                                download_time INT NOT NULL,               -- how long the block was in-flight
                                arrival_time INT NOT NULL,                -- when this block was stored
                                processed_time INT NOT NULL,              -- when this block was processed
                                PRIMARY KEY(anchored_block_hash,consensus_hash)
    );"#,
    r#"
    CREATE TABLE transactions(
        id INTEGER PRIMARY KEY,
        txid TEXT NOT NULL,
        index_block_hash TEXT NOT NULL,
        tx_hex TEXT NOT NULL,
        result TEXT NOT NULL,
        UNIQUE (txid,index_block_hash)
    );"#,
];

const CHAINSTATE_SCHEMA_2: &'static [&'static str] = &[
    // new in epoch 2.05 (schema version 2)
    // table of blocks that applied an epoch transition
    r#"
    CREATE TABLE epoch_transitions(
        block_id TEXT PRIMARY KEY
    );"#,
    r#"
    UPDATE db_config SET version = "2";
    "#,
];

const CHAINSTATE_SCHEMA_3: &'static [&'static str] = &[
    // new in epoch 2.1 (schema version 3)
    // track mature miner rewards paid out, so we can report them in Clarity.
    r#"
    -- table for MinerRewards.
    -- For each block within in a fork, there will be exactly two miner records:
    -- * one that records the coinbase, anchored tx fee, and confirmed streamed tx fees, and
    -- * one that records only the produced streamed tx fees.
    -- The latter is determined once this block's stream gets subsequently confirmed.
    -- You query this table by passing both the parent and the child block hashes, since both the 
    -- parent and child blocks determine the full reward for the parent block.
    CREATE TABLE matured_rewards(
        address TEXT NOT NULL,      -- address of the miner who produced the block
        recipient TEXT,             -- who received the reward (if different from the miner)
        vtxindex INTEGER NOT NULL,  -- will be 0 if this is the miner, >0 if this is a user burn support
        coinbase TEXT NOT NULL,
        tx_fees_anchored TEXT NOT NULL,
        tx_fees_streamed_confirmed TEXT NOT NULL,
        tx_fees_streamed_produced TEXT NOT NULL,

        -- fork identifier 
        child_index_block_hash TEXT NOT NULL,
        parent_index_block_hash TEXT NOT NULL,
        
        -- 1 if this is a parent reward (streamed fees only), 0 if child reward (coinbase + fees)
        is_parent INTEGER NOT NULL DEFAULT 0,

        -- vtxindex uniquely identifies the reward recipient: 0 for miner, 1+ for inference nodes
        -- is_parent distinguishes parent (streamed fees) from child (coinbase) rewards for same vtxindex
        PRIMARY KEY(parent_index_block_hash,child_index_block_hash,vtxindex,is_parent)
    );"#,
    r#"
    -- Add a `recipient` column so that in Funai 2.1, the block reward can be sent to someone besides the miner (e.g. a contract).
    -- If NULL, then the payment goes to the `address`.
    ALTER TABLE payments ADD COLUMN recipient TEXT;
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS index_matured_rewards_by_vtxindex ON matured_rewards(parent_index_block_hash,child_index_block_hash,vtxindex);
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS index_parent_block_id_by_block_id ON block_headers(index_block_hash,parent_block_id);
    "#,
    // table to map index block hashes to the txids of on-burnchain funai operations that were
    // proessed
    r#"
    CREATE TABLE burnchain_txids(
        index_block_hash TEXT PRIMARY KEY,
        -- this is a JSON-encoded list of txids
        txids TEXT NOT NULL
    );"#,
    r#"
    UPDATE db_config SET version = "3";
    "#,
];

// Fix for UNIQUE constraint violation when multiple inference nodes receive the same reward amount.
// The PRIMARY KEY was (parent_index_block_hash, child_index_block_hash, coinbase) which conflicts
// when two inference nodes get the same coinbase value.
// 
// We need to use vtxindex to distinguish between different reward recipients, but we also need
// to distinguish between parent and child rewards for the same vtxindex (e.g., miner has both
// a parent reward and a child reward with vtxindex=0).
//
// Solution: Add an is_parent column and use PRIMARY KEY (parent_index_block_hash, child_index_block_hash, vtxindex, is_parent)
const CHAINSTATE_SCHEMA_5: &'static [&'static str] = &[
    r#"
    -- Create new table with correct PRIMARY KEY using vtxindex and is_parent
    CREATE TABLE matured_rewards_new(
        address TEXT NOT NULL,
        recipient TEXT,
        vtxindex INTEGER NOT NULL,
        coinbase TEXT NOT NULL,
        tx_fees_anchored TEXT NOT NULL,
        tx_fees_streamed_confirmed TEXT NOT NULL,
        tx_fees_streamed_produced TEXT NOT NULL,
        child_index_block_hash TEXT NOT NULL,
        parent_index_block_hash TEXT NOT NULL,
        is_parent INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(parent_index_block_hash,child_index_block_hash,vtxindex,is_parent)
    );"#,
    r#"
    -- Copy data from old table, deriving is_parent from coinbase (parent rewards have coinbase=0)
    INSERT INTO matured_rewards_new 
        SELECT address, recipient, vtxindex, coinbase, tx_fees_anchored, 
               tx_fees_streamed_confirmed, tx_fees_streamed_produced,
               child_index_block_hash, parent_index_block_hash,
               CASE WHEN CAST(coinbase AS INTEGER) = 0 THEN 1 ELSE 0 END as is_parent
        FROM matured_rewards;"#,
    r#"
    -- Drop old table
    DROP TABLE matured_rewards;"#,
    r#"
    -- Rename new table to original name
    ALTER TABLE matured_rewards_new RENAME TO matured_rewards;"#,
    r#"
    -- Recreate the index
    CREATE INDEX IF NOT EXISTS index_matured_rewards_by_vtxindex ON matured_rewards(parent_index_block_hash,child_index_block_hash,vtxindex);"#,
    r#"
    UPDATE db_config SET version = "5";
    "#,
];

const CHAINSTATE_INDEXES: &'static [&'static str] = &[
    "CREATE INDEX IF NOT EXISTS index_block_hash_to_primary_key ON block_headers(index_block_hash,consensus_hash,block_hash);",
    "CREATE INDEX IF NOT EXISTS block_headers_hash_index ON block_headers(block_hash,block_height);",
    "CREATE INDEX IF NOT EXISTS block_index_hash_index ON block_headers(index_block_hash,consensus_hash,block_hash);",
    "CREATE INDEX IF NOT EXISTS block_headers_burn_header_height ON block_headers(burn_header_height);",
    "CREATE INDEX IF NOT EXISTS index_payments_block_hash_consensus_hash_vtxindex ON payments(block_hash,consensus_hash,vtxindex ASC);",
    "CREATE INDEX IF NOT EXISTS index_payments_index_block_hash_vtxindex ON payments(index_block_hash,vtxindex ASC);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_processed ON staging_microblocks(processed);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_orphaned ON staging_microblocks(orphaned);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash ON staging_microblocks(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash_processed ON staging_microblocks(index_block_hash,processed);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash_orphaned ON staging_microblocks(index_block_hash,orphaned);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_microblock_hash ON staging_microblocks(microblock_hash);",
    "CREATE INDEX IF NOT EXISTS processed_funai_blocks ON staging_blocks(processed,anchored_block_hash,consensus_hash);",
    "CREATE INDEX IF NOT EXISTS orphaned_funai_blocks ON staging_blocks(orphaned,anchored_block_hash,consensus_hash);",
    "CREATE INDEX IF NOT EXISTS parent_blocks ON staging_blocks(parent_anchored_block_hash);",
    "CREATE INDEX IF NOT EXISTS parent_consensus_hashes ON staging_blocks(parent_consensus_hash);",
    "CREATE INDEX IF NOT EXISTS index_block_hashes ON staging_blocks(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS height_funai_blocks ON staging_blocks(height);",
    "CREATE INDEX IF NOT EXISTS txid_tx_index ON transactions(txid);",
    "CREATE INDEX IF NOT EXISTS index_block_hash_tx_index ON transactions(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS index_block_header_by_affirmation_weight ON block_headers(affirmation_weight);",
    "CREATE INDEX IF NOT EXISTS index_block_header_by_height_and_affirmation_weight ON block_headers(block_height,affirmation_weight);",
    "CREATE INDEX IF NOT EXISTS index_headers_by_consensus_hash ON block_headers(consensus_hash);",
];

pub use funai_common::consts::MINER_REWARD_MATURITY;

// fraction (out of 100) of the coinbase a user will receive for reporting a microblock stream fork
pub const POISON_MICROBLOCK_COMMISSION_FRACTION: u128 = 5;

#[derive(Debug, Clone)]
pub struct ChainstateAccountBalance {
    pub address: String,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateAccountLockup {
    pub address: String,
    pub amount: u64,
    pub block_height: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateBNSNamespace {
    pub namespace_id: String,
    pub importer: String,
    pub buckets: String,
    pub base: u64,
    pub coeff: u64,
    pub nonalpha_discount: u64,
    pub no_vowel_discount: u64,
    pub lifetime: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateBNSName {
    pub fully_qualified_name: String,
    pub owner: String,
    pub zonefile_hash: String,
}

impl ChainstateAccountLockup {
    pub fn new(address: FunaiAddress, amount: u64, block_height: u64) -> ChainstateAccountLockup {
        ChainstateAccountLockup {
            address: address.to_string(),
            amount,
            block_height,
        }
    }
}

pub struct ChainStateBootData {
    pub first_burnchain_block_hash: BurnchainHeaderHash,
    pub first_burnchain_block_height: u32,
    pub first_burnchain_block_timestamp: u32,
    pub initial_balances: Vec<(PrincipalData, u64)>,
    pub pox_constants: PoxConstants,
    pub post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx) -> ()>>,
    pub get_bulk_initial_lockups:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateAccountLockup>>>>,
    pub get_bulk_initial_balances:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateAccountBalance>>>>,
    pub get_bulk_initial_namespaces:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateBNSNamespace>>>>,
    pub get_bulk_initial_names:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateBNSName>>>>,
}

impl ChainStateBootData {
    pub fn new(
        burnchain: &Burnchain,
        initial_balances: Vec<(PrincipalData, u64)>,
        post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx) -> ()>>,
    ) -> ChainStateBootData {
        ChainStateBootData {
            first_burnchain_block_hash: burnchain.first_block_hash.clone(),
            first_burnchain_block_height: burnchain.first_block_height as u32,
            first_burnchain_block_timestamp: burnchain.first_block_timestamp,
            initial_balances,
            pox_constants: burnchain.pox_constants.clone(),
            post_flight_callback,
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_namespaces: None,
            get_bulk_initial_names: None,
        }
    }
}

impl FunaiChainState {
    fn instantiate_db(
        mainnet: bool,
        chain_id: u32,
        marf_path: &str,
        migrate: bool,
    ) -> Result<MARF<FunaiBlockId>, Error> {
        let mut marf = FunaiChainState::open_index(marf_path)?;
        let mut dbtx = FunaiDBTx::new(&mut marf, ());

        {
            let tx = dbtx.tx();

            for cmd in CHAINSTATE_INITIAL_SCHEMA {
                tx.execute_batch(cmd)?;
            }
            tx.execute(
                "INSERT INTO db_config (version,mainnet,chain_id) VALUES (?1,?2,?3)",
                &[
                    &"1".to_string(),
                    &(if mainnet { 1 } else { 0 }) as &dyn ToSql,
                    &chain_id as &dyn ToSql,
                ],
            )?;

            if migrate {
                FunaiChainState::apply_schema_migrations(&tx, mainnet, chain_id)?;
            }

            FunaiChainState::add_indexes(&tx)?;
        }

        dbtx.instantiate_index()?;
        dbtx.commit()?;
        Ok(marf)
    }

    /// Load the chainstate DBConfig, given the path to the chainstate root
    pub fn get_db_config_from_path(chainstate_root_path: &str) -> Result<DBConfig, db_error> {
        let index_pathbuf =
            FunaiChainState::header_index_root_path(PathBuf::from(chainstate_root_path));
        let index_path = index_pathbuf
            .to_str()
            .ok_or_else(|| db_error::ParseError)?
            .to_string();

        let marf = FunaiChainState::open_index(&index_path)?;
        FunaiChainState::load_db_config(marf.sqlite_conn())
    }

    pub fn load_db_config(conn: &DBConn) -> Result<DBConfig, db_error> {
        let config = query_row::<DBConfig, _>(conn, "SELECT * FROM db_config LIMIT 1", NO_PARAMS)?;
        Ok(config.expect("BUG: no db_config installed"))
    }

    fn apply_schema_migrations<'a>(
        tx: &DBTx<'a>,
        mainnet: bool,
        chain_id: u32,
    ) -> Result<(), Error> {
        let mut db_config =
            FunaiChainState::load_db_config(tx).expect("CORRUPTION: no db_config found");

        if db_config.mainnet != mainnet {
            error!(
                "Invalid chain state database: expected mainnet = {}, got {}",
                mainnet, db_config.mainnet
            );
            return Err(Error::InvalidChainstateDB);
        }

        if db_config.chain_id != chain_id {
            error!(
                "Invalid chain ID: expected {}, got {}",
                chain_id, db_config.chain_id
            );
            return Err(Error::InvalidChainstateDB);
        }

        if db_config.version != CHAINSTATE_VERSION {
            while db_config.version != CHAINSTATE_VERSION {
                match db_config.version.as_str() {
                    "1" => {
                        // migrate to 2
                        info!("Migrating chainstate schema from version 1 to 2");
                        for cmd in CHAINSTATE_SCHEMA_2.iter() {
                            tx.execute_batch(cmd)?;
                        }
                    }
                    "2" => {
                        // migrate to 3
                        info!("Migrating chainstate schema from version 2 to 3");
                        for cmd in CHAINSTATE_SCHEMA_3.iter() {
                            tx.execute_batch(cmd)?;
                        }
                    }
                    "3" => {
                        // migrate to nakamoto 1
                        info!("Migrating chainstate schema from version 3 to 4: nakamoto support");
                        for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_1.iter() {
                            tx.execute_batch(cmd)?;
                        }
                    }
                    "4" => {
                        // migrate to 5: fix matured_rewards PRIMARY KEY to use vtxindex instead of coinbase
                        info!("Migrating chainstate schema from version 4 to 5: fix matured_rewards primary key");
                        for cmd in CHAINSTATE_SCHEMA_5.iter() {
                            tx.execute_batch(cmd)?;
                        }
                    }
                    _ => {
                        error!(
                            "Invalid chain state database: expected version = {}, got {}",
                            CHAINSTATE_VERSION, db_config.version
                        );
                        return Err(Error::InvalidChainstateDB);
                    }
                }
                db_config =
                    FunaiChainState::load_db_config(tx).expect("CORRUPTION: no db_config found");
            }
        }
        Ok(())
    }

    fn add_indexes<'a>(tx: &DBTx<'a>) -> Result<(), Error> {
        for cmd in CHAINSTATE_INDEXES {
            tx.execute_batch(cmd)?;
        }
        Ok(())
    }

    fn open_db(
        mainnet: bool,
        chain_id: u32,
        index_path: &str,
    ) -> Result<MARF<FunaiBlockId>, Error> {
        let create_flag = fs::metadata(index_path).is_err();

        if create_flag {
            // instantiate!
            FunaiChainState::instantiate_db(mainnet, chain_id, index_path, true)
        } else {
            let mut marf = FunaiChainState::open_index(index_path)?;
            let tx = marf.storage_tx()?;
            FunaiChainState::apply_schema_migrations(&tx, mainnet, chain_id)?;
            FunaiChainState::add_indexes(&tx)?;
            tx.commit()?;
            Ok(marf)
        }
    }

    #[cfg(test)]
    pub fn open_db_without_migrations(
        mainnet: bool,
        chain_id: u32,
        index_path: &str,
    ) -> Result<MARF<FunaiBlockId>, Error> {
        let create_flag = fs::metadata(index_path).is_err();

        if create_flag {
            // instantiate!
            FunaiChainState::instantiate_db(mainnet, chain_id, index_path, false)
        } else {
            let mut marf = FunaiChainState::open_index(index_path)?;
            let tx = marf.storage_tx()?;
            FunaiChainState::add_indexes(&tx)?;
            tx.commit()?;
            Ok(marf)
        }
    }

    pub fn open_index(marf_path: &str) -> Result<MARF<FunaiBlockId>, db_error> {
        test_debug!("Open MARF index at {}", marf_path);
        let mut open_opts = MARFOpenOpts::default();
        open_opts.external_blobs = true;
        let marf = MARF::from_path(marf_path, open_opts).map_err(|e| db_error::IndexError(e))?;
        Ok(marf)
    }

    /// Idempotent `mkdir -p`
    fn mkdirs(path: &PathBuf) -> Result<(), Error> {
        match fs::metadata(path) {
            Ok(md) => {
                if !md.is_dir() {
                    error!("Not a directory: {:?}", path);
                    return Err(Error::DBError(db_error::ExistsError));
                }
                Ok(())
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::DBError(db_error::IOError(e)));
                }
                fs::create_dir_all(path).map_err(|e| Error::DBError(db_error::IOError(e)))
            }
        }
    }

    fn parse_genesis_address(addr: &str, mainnet: bool) -> PrincipalData {
        // Typical entries are BTC encoded addresses that need converted to STX
        let mut funai_address = match LegacyBitcoinAddress::from_b58(&addr) {
            Ok(addr) => FunaiAddress::from_legacy_bitcoin_address(&addr),
            // A few addresses (from legacy placeholder accounts) are already STX addresses
            _ => match FunaiAddress::from_string(addr) {
                Some(addr) => addr,
                None => panic!("Failed to parsed genesis address {}", addr),
            },
        };
        // Convert a given address to the currently running network mode (mainnet vs testnet).
        // All addresses from the Funai 1.0 import data should be mainnet, but we'll handle either case.
        funai_address.version = if mainnet {
            match funai_address.version {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                C32_ADDRESS_VERSION_TESTNET_MULTISIG => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                _ => funai_address.version,
            }
        } else {
            match funai_address.version {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                C32_ADDRESS_VERSION_MAINNET_MULTISIG => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
                _ => funai_address.version,
            }
        };
        let principal: PrincipalData = funai_address.into();
        return principal;
    }

    /// Install the boot code into the chain history.
    fn install_boot_code(
        chainstate: &mut FunaiChainState,
        mainnet: bool,
        boot_data: &mut ChainStateBootData,
    ) -> Result<Vec<FunaiTransactionReceipt>, Error> {
        info!("Building genesis block");

        let tx_version = if mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let boot_code_address = boot_code_addr(mainnet);

        let boot_code_auth = boot_code_tx_auth(boot_code_address);

        let mut boot_code_account = boot_code_acc(boot_code_address, 0);

        let mut initial_liquid_ustx = 0u128;
        let mut receipts = vec![];

        {
            let mut clarity_tx = chainstate.genesis_block_begin(
                &NULL_BURN_STATE_DB,
                &BURNCHAIN_BOOT_CONSENSUS_HASH,
                &BOOT_BLOCK_HASH,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            let boot_code = if mainnet {
                *boot::STACKS_BOOT_CODE_MAINNET
            } else {
                *boot::STACKS_BOOT_CODE_TESTNET
            };
            for (boot_code_name, boot_code_contract) in boot_code.iter() {
                debug!(
                    "Instantiate boot code contract '{}' ({} bytes)...",
                    boot_code_name,
                    boot_code_contract.len()
                );

                let smart_contract = TransactionPayload::SmartContract(
                    TransactionSmartContract {
                        name: ContractName::try_from(boot_code_name.to_string())
                            .expect("FATAL: invalid boot-code contract name"),
                        code_body: FunaiString::from_str(boot_code_contract)
                            .expect("FATAL: invalid boot code body"),
                    },
                    None,
                );

                let boot_code_smart_contract = FunaiTransaction::new(
                    tx_version.clone(),
                    boot_code_auth.clone(),
                    smart_contract,
                );

                let tx_receipt = clarity_tx.connection().as_transaction(|clarity| {
                    FunaiChainState::process_transaction_payload(
                        clarity,
                        &boot_code_smart_contract,
                        &boot_code_account,
                        ASTRules::PrecheckSize,
                        None,
                    )
                })?;
                receipts.push(tx_receipt);

                boot_code_account.nonce += 1;
            }

            let mut allocation_events: Vec<FunaiTransactionEvent> = vec![];
            if boot_data.initial_balances.len() > 0 {
                warn!(
                    "Seeding {} balances coming from the config",
                    boot_data.initial_balances.len()
                );
            }
            for (address, amount) in boot_data.initial_balances.iter() {
                clarity_tx.connection().as_transaction(|clarity| {
                    FunaiChainState::account_genesis_credit(clarity, address, (*amount).into())
                });
                initial_liquid_ustx = initial_liquid_ustx
                    .checked_add(*amount as u128)
                    .expect("FATAL: liquid STX overflow");
                let mint_event = FunaiTransactionEvent::STXEvent(STXEventType::STXMintEvent(
                    STXMintEventData {
                        recipient: address.clone(),
                        amount: *amount as u128,
                    },
                ));
                allocation_events.push(mint_event);
            }

            clarity_tx.connection().as_transaction(|clarity| {
                // Balances
                if let Some(get_balances) = boot_data.get_bulk_initial_balances.take() {
                    info!("Importing accounts from Funai 1.0");
                    let mut balances_count = 0;
                    let initial_balances = get_balances();
                    for balance in initial_balances {
                        balances_count = balances_count + 1;
                        let stx_address =
                            FunaiChainState::parse_genesis_address(&balance.address, mainnet);
                        FunaiChainState::account_genesis_credit(
                            clarity,
                            &stx_address,
                            balance.amount.into(),
                        );
                        initial_liquid_ustx = initial_liquid_ustx
                            .checked_add(balance.amount as u128)
                            .expect("FATAL: liquid STX overflow");
                        let mint_event = FunaiTransactionEvent::STXEvent(
                            STXEventType::STXMintEvent(STXMintEventData {
                                recipient: stx_address,
                                amount: balance.amount.into(),
                            }),
                        );
                        allocation_events.push(mint_event);
                    }
                    info!("Seeding {} balances coming from chain dump", balances_count);
                }

                // Lockups
                if let Some(get_schedules) = boot_data.get_bulk_initial_lockups.take() {
                    info!("Initializing chain with lockups");
                    let mut lockups_per_block: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
                    let initial_lockups = get_schedules();
                    for schedule in initial_lockups {
                        let stx_address =
                            FunaiChainState::parse_genesis_address(&schedule.address, mainnet);
                        let value = Value::Tuple(
                            TupleData::from_data(vec![
                                ("recipient".into(), Value::Principal(stx_address)),
                                ("amount".into(), Value::UInt(schedule.amount.into())),
                            ])
                            .unwrap(),
                        );
                        match lockups_per_block.entry(schedule.block_height) {
                            Entry::Occupied(schedules) => {
                                schedules.into_mut().push(value);
                            }
                            Entry::Vacant(entry) => {
                                let schedules = vec![value];
                                entry.insert(schedules);
                            }
                        };
                    }

                    let lockup_contract_id = boot_code_id("lockup", mainnet);
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            for (block_height, schedule) in lockups_per_block.into_iter() {
                                let key = Value::UInt(block_height.into());
                                let value = Value::cons_list(schedule, &epoch).unwrap();
                                db.insert_entry_unknown_descriptor(
                                    &lockup_contract_id,
                                    "lockups",
                                    key,
                                    value,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }

                // BNS Namespace
                let bns_contract_id = boot_code_id("bns", mainnet);
                if let Some(get_namespaces) = boot_data.get_bulk_initial_namespaces.take() {
                    info!("Initializing chain with namespaces");
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            let initial_namespaces = get_namespaces();
                            for entry in initial_namespaces {
                                let namespace = {
                                    if !BNS_CHARS_REGEX.is_match(&entry.namespace_id) {
                                        panic!("Invalid namespace characters");
                                    }
                                    let buffer = entry.namespace_id.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid namespace")
                                };

                                let importer = {
                                    let address = FunaiChainState::parse_genesis_address(
                                        &entry.importer,
                                        mainnet,
                                    );
                                    Value::Principal(address)
                                };

                                let revealed_at = Value::UInt(0);
                                let launched_at = Value::UInt(0);
                                let lifetime = Value::UInt(entry.lifetime.into());
                                let price_function = {
                                    let base = Value::UInt(entry.base.into());
                                    let coeff = Value::UInt(entry.coeff.into());
                                    let nonalpha_discount =
                                        Value::UInt(entry.nonalpha_discount.into());
                                    let no_vowel_discount =
                                        Value::UInt(entry.no_vowel_discount.into());
                                    let buckets: Vec<_> = entry
                                        .buckets
                                        .split(';')
                                        .map(|e| Value::UInt(e.parse::<u64>().unwrap().into()))
                                        .collect();
                                    assert_eq!(buckets.len(), 16);

                                    TupleData::from_data(vec![
                                        (
                                            "buckets".into(),
                                            Value::cons_list(buckets, &epoch).unwrap(),
                                        ),
                                        ("base".into(), base),
                                        ("coeff".into(), coeff),
                                        ("nonalpha-discount".into(), nonalpha_discount),
                                        ("no-vowel-discount".into(), no_vowel_discount),
                                    ])
                                    .unwrap()
                                };

                                let namespace_props = Value::Tuple(
                                    TupleData::from_data(vec![
                                        ("revealed-at".into(), revealed_at),
                                        ("launched-at".into(), Value::some(launched_at).unwrap()),
                                        ("lifetime".into(), lifetime),
                                        ("namespace-import".into(), importer),
                                        ("can-update-price-function".into(), Value::Bool(true)),
                                        ("price-function".into(), Value::Tuple(price_function)),
                                    ])
                                    .unwrap(),
                                );

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "namespaces",
                                    namespace,
                                    namespace_props,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }

                // BNS Names
                if let Some(get_names) = boot_data.get_bulk_initial_names.take() {
                    info!("Initializing chain with names");
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            let initial_names = get_names();
                            for entry in initial_names {
                                let components: Vec<_> =
                                    entry.fully_qualified_name.split('.').collect();
                                assert_eq!(components.len(), 2);

                                let namespace = {
                                    let namespace_str = components[1];
                                    if !BNS_CHARS_REGEX.is_match(&namespace_str) {
                                        panic!("Invalid namespace characters");
                                    }
                                    let buffer = namespace_str.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid namespace")
                                };

                                let name = {
                                    let name_str = components[0].to_string();
                                    if !BNS_CHARS_REGEX.is_match(&name_str) {
                                        panic!("Invalid name characters");
                                    }
                                    let buffer = name_str.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid name")
                                };

                                let fqn = Value::Tuple(
                                    TupleData::from_data(vec![
                                        ("namespace".into(), namespace),
                                        ("name".into(), name),
                                    ])
                                    .unwrap(),
                                );

                                let owner_address =
                                    FunaiChainState::parse_genesis_address(&entry.owner, mainnet);

                                let zonefile_hash = {
                                    if entry.zonefile_hash.len() == 0 {
                                        Value::buff_from(vec![]).unwrap()
                                    } else {
                                        let buffer = Hash160::from_hex(&entry.zonefile_hash)
                                            .expect("Invalid zonefile_hash");
                                        Value::buff_from(buffer.to_bytes().to_vec()).unwrap()
                                    }
                                };

                                let expected_asset_type =
                                    db.get_nft_key_type(&bns_contract_id, "names")?;
                                db.set_nft_owner(
                                    &bns_contract_id,
                                    "names",
                                    &fqn,
                                    &owner_address,
                                    &expected_asset_type,
                                    &epoch,
                                )?;

                                let registered_at = Value::UInt(0);
                                let name_props = Value::Tuple(
                                    TupleData::from_data(vec![
                                        (
                                            "registered-at".into(),
                                            Value::some(registered_at).unwrap(),
                                        ),
                                        ("imported-at".into(), Value::none()),
                                        ("revoked-at".into(), Value::none()),
                                        ("zonefile-hash".into(), zonefile_hash),
                                    ])
                                    .unwrap(),
                                );

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "name-properties",
                                    fqn.clone(),
                                    name_props,
                                    &epoch,
                                )?;

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "owner-name",
                                    Value::Principal(owner_address),
                                    fqn,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }
                info!("Saving Genesis block. This could take a while");
            });

            let allocations_tx = FunaiTransaction::new(
                tx_version.clone(),
                boot_code_auth,
                TransactionPayload::TokenTransfer(
                    PrincipalData::Standard(boot_code_address.into()),
                    0,
                    TokenTransferMemo([0u8; 34]),
                ),
            );
            let allocations_receipt = FunaiTransactionReceipt::from_stx_transfer(
                allocations_tx,
                allocation_events,
                Value::okay_true(),
                ExecutionCost::zero(),
            );
            receipts.push(allocations_receipt);

            if let Some(callback) = boot_data.post_flight_callback.take() {
                callback(&mut clarity_tx);
            }

            // Setup burnchain parameters for pox contract
            let pox_constants = &boot_data.pox_constants;
            let contract = boot_code_id("pox", mainnet);
            let sender = PrincipalData::from(contract.clone());
            let params = vec![
                Value::UInt(boot_data.first_burnchain_block_height as u128),
                Value::UInt(pox_constants.prepare_length as u128),
                Value::UInt(pox_constants.reward_cycle_length as u128),
                Value::UInt(pox_constants.pox_rejection_fraction as u128),
            ];
            clarity_tx.connection().as_transaction(|conn| {
                conn.run_contract_call(
                    &sender,
                    None,
                    &contract,
                    "set-burnchain-parameters",
                    &params,
                    |_, _| false,
                )
                .expect("Failed to set burnchain parameters in PoX contract");
            });

            clarity_tx
                .connection()
                .as_transaction(|tx| {
                    tx.with_clarity_db(|db| {
                        db.increment_ustx_liquid_supply(initial_liquid_ustx)
                            .map_err(|e| e.into())
                    })
                })
                .expect("FATAL: `ustx-liquid-supply` overflowed");

            clarity_tx.commit_to_block(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
        }

        // verify that genesis root hash is as expected
        {
            let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
                let index_block_hash = FunaiBlockHeader::make_index_block_hash(
                    &FIRST_BURNCHAIN_CONSENSUS_HASH,
                    &FIRST_STACKS_BLOCK_HASH,
                );
                marf.get_root_hash_at(&index_block_hash).unwrap()
            });

            info!("Computed Clarity state genesis"; "root_hash" => %genesis_root_hash);

            if mainnet {
                assert_eq!(
                    &genesis_root_hash.to_string(),
                    MAINNET_2_0_GENESIS_ROOT_HASH,
                    "Incorrect root hash for genesis block computed. expected={} computed={}",
                    MAINNET_2_0_GENESIS_ROOT_HASH,
                    genesis_root_hash
                )
            }
        }

        {
            // add a block header entry for the boot code
            let mut tx = chainstate.index_tx_begin()?;
            let parent_hash = FunaiBlockId::sentinel();
            let first_index_hash = FunaiBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );

            test_debug!(
                "Boot code headers index_put_begin {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_root_hash =
                tx.put_indexed_all(&parent_hash, &first_index_hash, &vec![], &vec![])?;

            test_debug!(
                "Boot code headers index_commit {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_tip_info = FunaiHeaderInfo::genesis(
                first_root_hash,
                &boot_data.first_burnchain_block_hash,
                boot_data.first_burnchain_block_height,
                boot_data.first_burnchain_block_timestamp as u64,
            );

            FunaiChainState::insert_funai_block_header(
                &mut tx,
                &parent_hash,
                &first_tip_info,
                &ExecutionCost::zero(),
                0,
            )?;
            tx.commit()?;
        }

        debug!("Finish install boot code");
        Ok(receipts)
    }

    pub fn open(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(FunaiChainState, Vec<FunaiTransactionReceipt>), Error> {
        FunaiChainState::open_and_exec(mainnet, chain_id, path_str, None, marf_opts)
    }

    /// Re-open the chainstate -- i.e. to get a new handle to it using an existing chain state's
    /// parameters
    pub fn reopen(&self) -> Result<(FunaiChainState, Vec<FunaiTransactionReceipt>), Error> {
        FunaiChainState::open(
            self.mainnet,
            self.chain_id,
            &self.root_path,
            self.marf_opts.clone(),
        )
    }

    /// Re-open the chainstate DB
    pub fn reopen_db(&self) -> Result<DBConn, Error> {
        let path = PathBuf::from(self.root_path.clone());
        let header_index_root_path = FunaiChainState::header_index_root_path(path);
        let header_index_root = header_index_root_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let state_index =
            FunaiChainState::open_db(self.mainnet, self.chain_id, &header_index_root)?;
        Ok(state_index.into_sqlite_conn())
    }

    pub fn blocks_path(mut path: PathBuf) -> PathBuf {
        path.push("blocks");
        path
    }

    pub fn vm_state_path(mut path: PathBuf) -> PathBuf {
        path.push("vm");
        path
    }

    pub fn vm_state_index_root_path(path: PathBuf) -> PathBuf {
        let mut ret = FunaiChainState::vm_state_path(path);
        ret.push("clarity");
        ret
    }

    pub fn vm_state_index_marf_path(path: PathBuf) -> PathBuf {
        let mut ret = FunaiChainState::vm_state_index_root_path(path);
        ret.push("marf.sqlite");
        ret
    }

    pub fn header_index_root_path(path: PathBuf) -> PathBuf {
        let mut ret = FunaiChainState::vm_state_path(path);
        ret.push("index.sqlite");
        ret
    }

    pub fn make_chainstate_dirs(path_str: &str) -> Result<(), Error> {
        let path = PathBuf::from(path_str);
        FunaiChainState::mkdirs(&path)?;

        let blocks_path = FunaiChainState::blocks_path(path.clone());
        FunaiChainState::mkdirs(&blocks_path)?;

        let vm_state_path = FunaiChainState::vm_state_path(path.clone());
        FunaiChainState::mkdirs(&vm_state_path)?;
        Ok(())
    }

    pub fn open_and_exec(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        boot_data: Option<&mut ChainStateBootData>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(FunaiChainState, Vec<FunaiTransactionReceipt>), Error> {
        FunaiChainState::make_chainstate_dirs(path_str)?;
        let path = PathBuf::from(path_str);
        let blocks_path = FunaiChainState::blocks_path(path.clone());
        let blocks_path_root = blocks_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let clarity_state_index_root_path =
            FunaiChainState::vm_state_index_root_path(path.clone());
        let clarity_state_index_root = clarity_state_index_root_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let clarity_state_index_marf_path =
            FunaiChainState::vm_state_index_marf_path(path.clone());
        let clarity_state_index_marf = clarity_state_index_marf_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let header_index_root_path = FunaiChainState::header_index_root_path(path.clone());
        let header_index_root = header_index_root_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let nakamoto_staging_blocks_path =
            FunaiChainState::static_get_nakamoto_staging_blocks_path(path.clone())?;
        let nakamoto_staging_blocks_conn =
            FunaiChainState::open_nakamoto_staging_blocks(&nakamoto_staging_blocks_path, true)?;

        let init_required = match fs::metadata(&clarity_state_index_marf) {
            Ok(_) => false,
            Err(_) => true,
        };

        let state_index = FunaiChainState::open_db(mainnet, chain_id, &header_index_root)?;

        let vm_state = MarfedKV::open(
            &clarity_state_index_root,
            Some(&FunaiBlockHeader::make_index_block_hash(
                &MINER_BLOCK_CONSENSUS_HASH,
                &MINER_BLOCK_HEADER_HASH,
            )),
            marf_opts.clone(),
        )
        .map_err(|e| Error::ClarityError(e.into()))?;

        let clarity_state = ClarityInstance::new(mainnet, chain_id, vm_state);

        let mut chainstate = FunaiChainState {
            mainnet: mainnet,
            chain_id: chain_id,
            clarity_state: clarity_state,
            nakamoto_staging_blocks_conn,
            state_index: state_index,
            blocks_path: blocks_path_root,
            clarity_state_index_path: clarity_state_index_marf,
            clarity_state_index_root: clarity_state_index_root,
            root_path: path_str.to_string(),
            unconfirmed_state: None,
            fault_injection: FunaiChainStateFaults::new(),
            marf_opts: marf_opts,
        };

        let mut receipts = vec![];
        match (init_required, boot_data) {
            (true, Some(boot_data)) => {
                let mut res =
                    FunaiChainState::install_boot_code(&mut chainstate, mainnet, boot_data)?;
                receipts.append(&mut res);
            }
            (true, None) => {
                panic!(
                    "FunaiChainState initialization is required, but boot_data was not passed."
                );
            }
            (false, _) => {}
        }

        Ok((chainstate, receipts))
    }

    pub fn config(&self) -> DBConfig {
        DBConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            version: CHAINSTATE_VERSION.to_string(),
        }
    }

    /// Begin a transaction against the (indexed) funai chainstate DB.
    /// Does not create a Clarity instance.
    pub fn index_tx_begin<'a>(&'a mut self) -> Result<FunaiDBTx<'a>, Error> {
        Ok(FunaiDBTx::new(&mut self.state_index, ()))
    }

    pub fn index_conn<'a>(&'a self) -> Result<FunaiDBConn<'a>, Error> {
        Ok(FunaiDBConn::new(&self.state_index, ()))
    }

    /// Begin a transaction against the underlying DB
    /// Does not create a Clarity instance, and does not affect the MARF.
    pub fn db_tx_begin<'a>(&'a mut self) -> Result<DBTx<'a>, Error> {
        self.state_index.storage_tx().map_err(Error::DBError)
    }

    /// Simultaneously begin a transaction against both the headers and blocks.
    /// Used when considering a new block to append the chain state.
    pub fn chainstate_tx_begin<'a>(
        &'a mut self,
    ) -> Result<(ChainstateTx<'a>, &'a mut ClarityInstance), Error> {
        let config = self.config();
        let blocks_path = self.blocks_path.clone();
        let clarity_instance = &mut self.clarity_state;
        let inner_tx = FunaiDBTx::new(&mut self.state_index, ());

        let chainstate_tx =
            ChainstateTx::new(inner_tx, blocks_path, self.root_path.clone(), config);

        Ok((chainstate_tx, clarity_instance))
    }

    // NOTE: used for testing in the funai testnet code.
    // DO NOT CALL FROM PRODUCTION
    pub fn clarity_eval_read_only(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &FunaiBlockId,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Value {
        let result = self.clarity_state.eval_read_only(
            parent_id_bhh,
            &HeadersDBConn(self.state_index.sqlite_conn()),
            burn_dbconn,
            contract,
            code,
            ASTRules::PrecheckSize,
        );
        result.unwrap()
    }

    /// Checked eval-read-only
    pub fn eval_read_only(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &FunaiBlockId,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Result<Value, clarity_error> {
        self.clarity_state.eval_read_only(
            parent_id_bhh,
            &HeadersDBConn(self.state_index.sqlite_conn()),
            burn_dbconn,
            contract,
            code,
            ASTRules::PrecheckSize,
        )
    }

    /// Execute a public function in `contract` from a read-only DB context
    ///  Any mutations that occur will be rolled-back before returning, regardless of
    ///  an okay or error result.
    pub fn eval_fn_read_only(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &FunaiBlockId,
        contract: &QualifiedContractIdentifier,
        function: &str,
        args: &[Value],
    ) -> Result<Value, clarity_error> {
        let headers_db = HeadersDBConn(self.state_index.sqlite_conn());
        let mut conn = self.clarity_state.read_only_connection_checked(
            parent_id_bhh,
            &headers_db,
            burn_dbconn,
        )?;

        let args: Vec<_> = args
            .iter()
            .map(|x| SymbolicExpression::atom_value(x.clone()))
            .collect();

        let result = conn.with_readonly_clarity_env(
            self.mainnet,
            self.chain_id,
            ClarityVersion::latest(),
            contract.clone().into(),
            None,
            LimitedCostTracker::Free,
            |env| {
                env.execute_contract(
                    contract, function, &args,
                    // read-only is set to `false` so that non-read-only functions
                    //  can be executed. any transformation is rolled back.
                    false,
                )
            },
        )?;

        Ok(result)
    }

    pub fn db(&self) -> &DBConn {
        self.state_index.sqlite_conn()
    }

    /// Begin processing an epoch's transactions within the context of a chainstate transaction
    pub fn chainstate_block_begin<'a, 'b>(
        chainstate_tx: &'b ChainstateTx<'b>,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        let conf = chainstate_tx.config.clone();
        FunaiChainState::inner_clarity_tx_begin(
            conf,
            chainstate_tx,
            clarity_instance,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin a transaction against the Clarity VM, _outside of_ the context of a chainstate
    /// transaction.  Used by the miner for producing blocks.
    pub fn block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        FunaiChainState::inner_clarity_tx_begin(
            conf,
            &self.state_index,
            &mut self.clarity_state,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin a transaction against the Clarity VM for initiating the genesis block
    ///  the genesis block is special cased because it must be evaluated _before_ the
    ///  cost contract is loaded in the boot code.
    pub fn genesis_block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and funai block header hash together, since the funai block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            FunaiChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            FunaiBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing genesis Funai block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_genesis_block(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    pub fn with_clarity_marf<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut MARF<FunaiBlockId>) -> R,
    {
        self.clarity_state.with_marf(f)
    }

    /// Run to_do on the state of the Clarity VM at the given chain tip.
    /// Returns Some(x: R) if the given parent_tip exists.
    /// Returns None if not
    pub fn with_read_only_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_tip: &FunaiBlockId,
        to_do: F,
    ) -> Option<R>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        match NakamotoChainState::get_block_header(self.db(), parent_tip) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return None;
            }
            Err(e) => {
                warn!("Failed to query for {}: {:?}", parent_tip, &e);
                return None;
            }
        }
        let mut conn = match self.clarity_state.read_only_connection_checked(
            parent_tip,
            &self.state_index,
            burn_dbconn,
        ) {
            Ok(x) => Some(x),
            Err(e) => {
                warn!("Failed to load read only connection"; "err" => %e);
                None
            }
        }?;
        let result = to_do(&mut conn);
        Some(result)
    }

    /// Run to_do on the unconfirmed Clarity VM state
    pub fn with_read_only_unconfirmed_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        to_do: F,
    ) -> Result<Option<R>, Error>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        if let Some(ref unconfirmed) = self.unconfirmed_state.as_ref() {
            if !unconfirmed.is_readable() {
                return Ok(None);
            }
        }

        let mut unconfirmed_state_opt = self.unconfirmed_state.take();
        let res = if let Some(ref mut unconfirmed_state) = unconfirmed_state_opt {
            let mut conn = unconfirmed_state
                .clarity_inst
                .read_only_connection_checked(
                    &unconfirmed_state.unconfirmed_chain_tip,
                    &self.state_index,
                    burn_dbconn,
                )?;
            let result = to_do(&mut conn);
            Some(result)
        } else {
            None
        };
        self.unconfirmed_state = unconfirmed_state_opt;
        Ok(res)
    }

    /// Run to_do on the unconfirmed Clarity VM state if the tip refers to the unconfirmed state;
    /// otherwise run to_do on the confirmed state of the Clarity VM. If the tip doesn't exist,
    /// then return None.
    pub fn maybe_read_only_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_tip: &FunaiBlockId,
        to_do: F,
    ) -> Result<Option<R>, Error>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        let unconfirmed = if let Some(ref unconfirmed_state) = self.unconfirmed_state {
            *parent_tip == unconfirmed_state.unconfirmed_chain_tip
                && unconfirmed_state.is_readable()
        } else {
            false
        };

        if unconfirmed {
            self.with_read_only_unconfirmed_clarity_tx(burn_dbconn, to_do)
        } else {
            Ok(self.with_read_only_clarity_tx(burn_dbconn, parent_tip, to_do))
        }
    }

    fn get_parent_index_block(
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
    ) -> FunaiBlockId {
        if *parent_block == BOOT_BLOCK_HASH {
            // begin boot block
            FunaiBlockId::sentinel()
        } else if *parent_block == FIRST_STACKS_BLOCK_HASH {
            // begin first-ever block
            FunaiBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            // subsequent block
            FunaiBlockHeader::make_index_block_hash(parent_consensus_hash, parent_block)
        }
    }

    /// Begin an unconfirmed VM transaction, if there's no other open transaction for it.
    pub fn chainstate_begin_unconfirmed<'a, 'b>(
        conf: DBConfig,
        headers_db: &'b dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        tip: &FunaiBlockId,
    ) -> ClarityTx<'a, 'b> {
        let inner_clarity_tx = clarity_instance.begin_unconfirmed(tip, headers_db, burn_dbconn);
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Open a Clarity transaction against this chainstate's unconfirmed state, if it exists.
    pub fn begin_unconfirmed<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
    ) -> Option<ClarityTx<'a, 'a>> {
        let conf = self.config();
        if let Some(ref mut unconfirmed) = self.unconfirmed_state {
            if !unconfirmed.is_writable() {
                debug!("Unconfirmed state is not writable; cannot begin unconfirmed Clarity Tx");
                return None;
            }

            Some(FunaiChainState::chainstate_begin_unconfirmed(
                conf,
                &self.state_index,
                &mut unconfirmed.clarity_inst,
                burn_dbconn,
                &unconfirmed.confirmed_chain_tip,
            ))
        } else {
            debug!("Unconfirmed state is not instantiated; cannot begin unconfirmed Clarity Tx");
            None
        }
    }

    /// Create a Clarity VM database transaction
    fn inner_clarity_tx_begin<'a, 'b>(
        conf: DBConfig,
        headers_db: &'b dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        // mix consensus hash and funai block header hash together, since the funai block hash
        // it not guaranteed to be globally unique (but the pair is)
        let parent_index_block =
            FunaiChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            FunaiBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing Funai block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_block(
            &parent_index_block,
            &new_index_block,
            headers_db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Create a Clarity VM transaction connection for testing in 2.1
    #[cfg(test)]
    pub fn test_genesis_block_begin_2_1<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and funai block header hash together, since the funai block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            FunaiChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            FunaiBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing test genesis Funai block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_test_genesis_block_2_1(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Create a Clarity VM transaction connection for testing in 2.05
    #[cfg(test)]
    pub fn test_genesis_block_begin_2_05<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and funai block header hash together, since the funai block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            FunaiChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            FunaiBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing test genesis Funai block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_test_genesis_block(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Get the appropriate MARF index hash to use to identify a chain tip, given a block header
    pub fn get_index_hash(
        consensus_hash: &ConsensusHash,
        header_hash: &BlockHeaderHash,
    ) -> FunaiBlockId {
        if consensus_hash == &FIRST_BURNCHAIN_CONSENSUS_HASH {
            FunaiBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            FunaiBlockId::new(consensus_hash, header_hash)
        }
    }

    /// Record the microblock public key hash for a block into the MARF'ed Clarity DB
    pub fn insert_microblock_pubkey_hash(
        clarity_tx: &mut ClarityTx,
        height: u32,
        mblock_pubkey_hash: &Hash160,
    ) -> Result<(), Error> {
        clarity_tx
            .connection()
            .as_transaction(|tx| {
                tx.with_clarity_db(|ref mut db| {
                    db.insert_microblock_pubkey_hash_height(mblock_pubkey_hash, height)
                        .expect("FATAL: failed to store microblock public key hash to Clarity DB");
                    Ok(())
                })
            })
            .expect("FATAL: failed to store microblock public key hash");
        Ok(())
    }

    /// Get the block height at which a microblock public key hash was used, if any
    pub fn has_microblock_pubkey_hash(
        clarity_tx: &mut ClarityTx,
        mblock_pubkey_hash: &Hash160,
    ) -> Result<Option<u32>, Error> {
        let height_opt = clarity_tx
            .connection()
            .with_clarity_db_readonly::<_, Result<_, ()>>(|ref mut db| {
                let height_opt = db
                    .get_microblock_pubkey_hash_height(mblock_pubkey_hash)
                    .expect("FATAL: failed to query microblock public key hash");
                Ok(height_opt)
            })
            .expect("FATAL: failed to query microblock public key hash");
        Ok(height_opt)
    }

    /// Get the burnchain txids for a given index block hash
    fn get_burnchain_txids_for_block(
        conn: &Connection,
        index_block_hash: &FunaiBlockId,
    ) -> Result<Vec<Txid>, Error> {
        let sql = "SELECT txids FROM burnchain_txids WHERE index_block_hash = ?1";
        let args: &[&dyn ToSql] = &[index_block_hash];

        let txids = conn
            .query_row(sql, args, |r| {
                let txids_json: String = r.get_unwrap(0);
                let txids: Vec<Txid> = serde_json::from_str(&txids_json)
                    .expect("FATAL: database corruption: could not parse TXID JSON");

                Ok(txids)
            })
            .optional()?
            .unwrap_or(vec![]);

        Ok(txids)
    }

    /// Get the txids of the burnchain operations applied in the past N Funai blocks.
    pub fn get_burnchain_txids_in_ancestors(
        conn: &Connection,
        index_block_hash: &FunaiBlockId,
        count: u64,
    ) -> Result<HashSet<Txid>, Error> {
        let mut ret = HashSet::new();
        let ancestors = FunaiChainState::get_ancestor_index_hashes(conn, index_block_hash, count)?;
        for ancestor in ancestors.into_iter() {
            let txids = FunaiChainState::get_burnchain_txids_for_block(conn, &ancestor)?;
            for txid in txids.into_iter() {
                ret.insert(txid);
            }
        }
        Ok(ret)
    }

    /// Store all on-burnchain STX operations' txids by index block hash
    pub fn store_burnchain_txids(
        tx: &DBTx,
        index_block_hash: &FunaiBlockId,
        burn_stack_stx_ops: Vec<StackStxOp>,
        burn_transfer_stx_ops: Vec<TransferStxOp>,
        burn_delegate_stx_ops: Vec<DelegateStxOp>,
        burn_vote_for_aggregate_key_ops: Vec<VoteForAggregateKeyOp>,
    ) -> Result<(), Error> {
        let mut txids: Vec<_> = burn_stack_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        let mut xfer_txids = burn_transfer_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        txids.append(&mut xfer_txids);

        let mut delegate_txids = burn_delegate_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        txids.append(&mut delegate_txids);

        let mut vote_txids =
            burn_vote_for_aggregate_key_ops
                .into_iter()
                .fold(vec![], |mut txids, op| {
                    txids.push(op.txid);
                    txids
                });

        txids.append(&mut vote_txids);

        let txids_json =
            serde_json::to_string(&txids).expect("FATAL: could not serialize Vec<Txid>");
        let sql = "INSERT INTO burnchain_txids (index_block_hash, txids) VALUES (?1, ?2)";
        let args: &[&dyn ToSql] = &[index_block_hash, &txids_json];
        tx.execute(sql, args)?;
        Ok(())
    }

    /// Append a Funai block to an existing Funai block, and grant the miner the block reward.
    /// Return the new Funai header info.
    pub fn advance_tip<'a>(
        headers_tx: &mut FunaiDBTx<'a>,
        parent_tip: &FunaiBlockHeader,
        parent_consensus_hash: &ConsensusHash,
        new_tip: &FunaiBlockHeader,
        new_consensus_hash: &ConsensusHash,
        new_burn_header_hash: &BurnchainHeaderHash,
        new_burnchain_height: u32,
        new_burnchain_timestamp: u64,
        microblock_tail_opt: Option<FunaiMicroblockHeader>,
        block_reward: &MinerPaymentSchedule,
        mature_miner_payouts: Option<(MinerReward, Vec<MinerReward>, MinerReward, MinerRewardInfo)>, // (miner, [users], parent, matured rewards)
        anchor_block_cost: &ExecutionCost,
        anchor_block_size: u64,
        applied_epoch_transition: bool,
        burn_stack_stx_ops: Vec<StackStxOp>,
        burn_transfer_stx_ops: Vec<TransferStxOp>,
        burn_delegate_stx_ops: Vec<DelegateStxOp>,
        burn_vote_for_aggregate_key_ops: Vec<VoteForAggregateKeyOp>,
        affirmation_weight: u64,
    ) -> Result<FunaiHeaderInfo, Error> {
        if new_tip.parent_block != FIRST_STACKS_BLOCK_HASH {
            // not the first-ever block, so linkage must occur
            assert_eq!(new_tip.parent_block, parent_tip.block_hash());
        }

        assert_eq!(
            parent_tip
                .total_work
                .work
                .checked_add(1)
                .expect("Block height overflow"),
            new_tip.total_work.work
        );

        let parent_hash =
            FunaiChainState::get_index_hash(parent_consensus_hash, &parent_tip.block_hash());

        // store each indexed field
        test_debug!(
            "Headers index_put_begin {}-{}",
            &parent_hash,
            &new_tip.index_block_hash(new_consensus_hash)
        );
        let root_hash = headers_tx.put_indexed_all(
            &parent_hash,
            &new_tip.index_block_hash(new_consensus_hash),
            &vec![],
            &vec![],
        )?;
        let index_block_hash = new_tip.index_block_hash(&new_consensus_hash);
        test_debug!(
            "Headers index_indexed_all finished {}-{}",
            &parent_hash,
            &index_block_hash,
        );

        let new_tip_info = FunaiHeaderInfo {
            anchored_header: new_tip.clone().into(),
            microblock_tail: microblock_tail_opt,
            index_root: root_hash,
            funai_block_height: new_tip.total_work.work,
            consensus_hash: new_consensus_hash.clone(),
            burn_header_hash: new_burn_header_hash.clone(),
            burn_header_height: new_burnchain_height,
            burn_header_timestamp: new_burnchain_timestamp,
            anchored_block_size: anchor_block_size,
        };

        FunaiChainState::insert_funai_block_header(
            headers_tx.deref_mut(),
            &parent_hash,
            &new_tip_info,
            anchor_block_cost,
            affirmation_weight,
        )?;
        FunaiChainState::insert_miner_payment_schedule(headers_tx.deref_mut(), block_reward)?;
        FunaiChainState::store_burnchain_txids(
            headers_tx.deref(),
            &index_block_hash,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            burn_delegate_stx_ops,
            burn_vote_for_aggregate_key_ops,
        )?;

        if let Some((miner_payout, user_payouts, parent_payout, reward_info)) = mature_miner_payouts
        {
            let rewarded_miner_block_id = FunaiBlockHeader::make_index_block_hash(
                &reward_info.from_block_consensus_hash,
                &reward_info.from_funai_block_hash,
            );
            let rewarded_parent_miner_block_id = FunaiBlockHeader::make_index_block_hash(
                &reward_info.from_parent_block_consensus_hash,
                &reward_info.from_parent_funai_block_hash,
            );

            FunaiChainState::insert_matured_child_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &miner_payout,
            )?;
            for user_payout in user_payouts.into_iter() {
                FunaiChainState::insert_matured_child_user_reward(
                    headers_tx.deref_mut(),
                    &rewarded_parent_miner_block_id,
                    &rewarded_miner_block_id,
                    &user_payout,
                )?;
            }
            FunaiChainState::insert_matured_parent_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &parent_payout,
            )?;
        }

        if applied_epoch_transition {
            debug!("Block {} applied an epoch transition", &index_block_hash);
            let sql = "INSERT INTO epoch_transitions (block_id) VALUES (?)";
            let args: &[&dyn ToSql] = &[&index_block_hash];
            headers_tx.deref_mut().execute(sql, args)?;
        }

        debug!(
            "Advanced to new tip! {}/{}",
            new_consensus_hash,
            new_tip.block_hash()
        );
        Ok(new_tip_info)
    }
}

#[cfg(test)]
pub mod test {
    use std::{env, fs};

    use clarity::vm::test_util::TEST_BURN_STATE_DB;
    use funai_genesis::GenesisData;

    use super::*;
    use crate::chainstate::funai::db::*;
    use crate::chainstate::funai::*;
    use crate::util_lib::boot::boot_code_test_addr;

    pub fn instantiate_chainstate(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
    ) -> FunaiChainState {
        instantiate_chainstate_with_balances(mainnet, chain_id, test_name, vec![])
    }

    pub fn instantiate_chainstate_with_balances(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
        balances: Vec<(FunaiAddress, u64)>,
    ) -> FunaiChainState {
        let path = chainstate_path(test_name);
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            }
            Err(_) => {}
        };

        let initial_balances = balances
            .into_iter()
            .map(|(addr, balance)| (PrincipalData::from(addr), balance))
            .collect();

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: None,
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::testnet_default(),
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_names: None,
            get_bulk_initial_namespaces: None,
        };

        FunaiChainState::open_and_exec(mainnet, chain_id, &path, Some(&mut boot_data), None)
            .unwrap()
            .0
    }

    pub fn open_chainstate(mainnet: bool, chain_id: u32, test_name: &str) -> FunaiChainState {
        let path = chainstate_path(test_name);
        FunaiChainState::open(mainnet, chain_id, &path, None)
            .unwrap()
            .0
    }

    pub fn chainstate_path(test_name: &str) -> String {
        format!("/tmp/blockstack-test-chainstate-{}", test_name)
    }

    #[test]
    fn test_instantiate_chainstate() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());

        // verify that the boot code is there
        let mut conn = chainstate.block_begin(
            &TEST_BURN_STATE_DB,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &MINER_BLOCK_CONSENSUS_HASH,
            &MINER_BLOCK_HEADER_HASH,
        );

        for (boot_contract_name, _) in STACKS_BOOT_CODE_TESTNET.iter() {
            let boot_contract_id = QualifiedContractIdentifier::new(
                boot_code_test_addr().into(),
                ContractName::try_from(boot_contract_name.to_string()).unwrap(),
            );
            let contract_res =
                FunaiChainState::get_contract(&mut conn, &boot_contract_id).unwrap();
            assert!(contract_res.is_some());
        }
    }

    #[test]
    fn test_chainstate_sampled_genesis_consistency() {
        // Test root hash for the test chainstate data set
        let mut boot_data = ChainStateBootData {
            initial_balances: vec![],
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::testnet_default(),
            post_flight_callback: None,
            get_bulk_initial_lockups: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_lockups().map(|item| {
                    ChainstateAccountLockup {
                        address: item.address,
                        amount: item.amount,
                        block_height: item.block_height,
                    }
                }))
            })),
            get_bulk_initial_balances: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_balances().map(|item| {
                    ChainstateAccountBalance {
                        address: item.address,
                        amount: item.amount,
                    }
                }))
            })),
            get_bulk_initial_namespaces: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_namespaces().map(|item| {
                    ChainstateBNSNamespace {
                        namespace_id: item.namespace_id,
                        importer: item.importer,
                        buckets: item.buckets,
                        base: item.base as u64,
                        coeff: item.coeff as u64,
                        nonalpha_discount: item.nonalpha_discount as u64,
                        no_vowel_discount: item.no_vowel_discount as u64,
                        lifetime: item.lifetime as u64,
                    }
                }))
            })),
            get_bulk_initial_names: Some(Box::new(|| {
                Box::new(
                    GenesisData::new(true)
                        .read_names()
                        .map(|item| ChainstateBNSName {
                            fully_qualified_name: item.fully_qualified_name,
                            owner: item.owner,
                            zonefile_hash: item.zonefile_hash,
                        }),
                )
            })),
        };

        let path = chainstate_path(function_name!());
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            }
            Err(_) => {}
        };

        let mut chainstate =
            FunaiChainState::open_and_exec(false, 0x80000000, &path, Some(&mut boot_data), None)
                .unwrap()
                .0;

        let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
            let index_block_hash = FunaiBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash).unwrap()
        });

        // If the genesis data changed, then this test will fail.
        // Just update the expected value
        assert_eq!(
            genesis_root_hash.to_string(),
            "c771616ff6acb710051238c9f4a3c48020a6d70cda637d34b89f2311a7e27886"
        );
    }

    #[test]
    fn test_chainstate_full_genesis_consistency() {
        if env::var("CIRCLE_CI_TEST") != Ok("1".into()) {
            return;
        }

        // Test root hash for the final chainstate data set
        let mut boot_data = ChainStateBootData {
            initial_balances: vec![],
            first_burnchain_block_hash: BurnchainHeaderHash::from_hex(
                BITCOIN_MAINNET_FIRST_BLOCK_HASH,
            )
            .unwrap(),
            first_burnchain_block_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT as u32,
            first_burnchain_block_timestamp: BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP,
            pox_constants: PoxConstants::mainnet_default(),
            post_flight_callback: None,
            get_bulk_initial_lockups: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_lockups().map(|item| {
                    ChainstateAccountLockup {
                        address: item.address,
                        amount: item.amount,
                        block_height: item.block_height,
                    }
                }))
            })),
            get_bulk_initial_balances: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_balances().map(|item| {
                    ChainstateAccountBalance {
                        address: item.address,
                        amount: item.amount,
                    }
                }))
            })),
            get_bulk_initial_namespaces: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_namespaces().map(|item| {
                    ChainstateBNSNamespace {
                        namespace_id: item.namespace_id,
                        importer: item.importer,
                        buckets: item.buckets,
                        base: item.base as u64,
                        coeff: item.coeff as u64,
                        nonalpha_discount: item.nonalpha_discount as u64,
                        no_vowel_discount: item.no_vowel_discount as u64,
                        lifetime: item.lifetime as u64,
                    }
                }))
            })),
            get_bulk_initial_names: Some(Box::new(|| {
                Box::new(
                    GenesisData::new(false)
                        .read_names()
                        .map(|item| ChainstateBNSName {
                            fully_qualified_name: item.fully_qualified_name,
                            owner: item.owner,
                            zonefile_hash: item.zonefile_hash,
                        }),
                )
            })),
        };

        let path = chainstate_path(function_name!());
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            }
            Err(_) => {}
        };

        let mut chainstate =
            FunaiChainState::open_and_exec(true, 0x000000001, &path, Some(&mut boot_data), None)
                .unwrap()
                .0;

        let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
            let index_block_hash = FunaiBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash).unwrap()
        });

        // If the genesis data changed, then this test will fail.
        // Just update the expected value
        assert_eq!(
            format!("{}", genesis_root_hash),
            MAINNET_2_0_GENESIS_ROOT_HASH
        );
    }
}
