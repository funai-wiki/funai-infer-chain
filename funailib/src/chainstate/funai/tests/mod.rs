// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Funai Open Internet Foundation
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

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::{fs, io};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::types::*;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use funai_common::address::*;
use funai_common::consts::FIRST_BURNCHAIN_CONSENSUS_HASH;
use funai_common::types::chainstate::SortitionId;
use funai_common::util::sleep_ms;
use funai_common::util::vrf::{VRFProof, VRFPublicKey};

use crate::burnchains::tests::*;
use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::*;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::Error as CoordinatorError;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::funai::db::blocks::test::store_staging_block;
use crate::chainstate::funai::db::test::*;
use crate::chainstate::funai::db::*;
use crate::chainstate::funai::miner::*;
use crate::chainstate::funai::{
    Error as ChainstateError, C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::cost_estimates::metrics::UnitMetric;
use crate::cost_estimates::UnitEstimator;
use crate::net::test::*;
use crate::util_lib::boot::boot_code_addr;
use crate::util_lib::db::Error as db_error;

pub mod accounting;
pub mod block_construction;
pub mod chain_histories;

pub const COINBASE: u128 = 500 * 1_000_000;

pub fn coinbase_total_at(funai_height: u64) -> u128 {
    if funai_height > MINER_REWARD_MATURITY {
        COINBASE * ((funai_height - MINER_REWARD_MATURITY) as u128)
    } else {
        0
    }
}

pub fn path_join(dir: &str, path: &str) -> String {
    // force path to be relative
    let tail = if !path.starts_with("/") {
        path.to_string()
    } else {
        String::from_utf8(path.as_bytes()[1..].to_vec()).unwrap()
    };

    let p = PathBuf::from(dir);
    let res = p.join(PathBuf::from(tail));
    res.to_str().unwrap().to_string()
}

// copy src to dest
pub fn copy_dir(src_dir: &str, dest_dir: &str) -> Result<(), io::Error> {
    eprintln!("Copy directory {} to {}", src_dir, dest_dir);

    let mut dir_queue = VecDeque::new();
    dir_queue.push_back("/".to_string());

    while dir_queue.len() > 0 {
        let next_dir = dir_queue.pop_front().unwrap();
        let next_src_dir = path_join(&src_dir, &next_dir);
        let next_dest_dir = path_join(&dest_dir, &next_dir);

        eprintln!("mkdir {}", &next_dest_dir);
        fs::create_dir_all(&next_dest_dir)?;

        for dirent_res in fs::read_dir(&next_src_dir)? {
            let dirent = dirent_res?;
            let path = dirent.path();
            let md = fs::metadata(&path)?;
            if md.is_dir() {
                let frontier = path_join(&next_dir, &dirent.file_name().to_str().unwrap());
                eprintln!("push {}", &frontier);
                dir_queue.push_back(frontier);
            } else {
                let dest_path = path_join(&next_dest_dir, &dirent.file_name().to_str().unwrap());
                eprintln!("copy {} to {}", &path.to_str().unwrap(), &dest_path);
                fs::copy(path, dest_path)?;
            }
        }
    }
    Ok(())
}

// one point per round
pub struct TestMinerTracePoint {
    pub fork_snapshots: HashMap<usize, BlockSnapshot>, // map miner ID to snapshot
    pub funai_blocks: HashMap<usize, FunaiBlock>,    // map miner ID to funai block
    pub microblocks: HashMap<usize, Vec<FunaiMicroblock>>, // map miner ID to microblocks
    pub block_commits: HashMap<usize, LeaderBlockCommitOp>, // map miner ID to block commit
    pub miner_node_map: HashMap<usize, String>,        // map miner ID to the node it worked on
}

impl TestMinerTracePoint {
    pub fn new() -> TestMinerTracePoint {
        TestMinerTracePoint {
            fork_snapshots: HashMap::new(),
            funai_blocks: HashMap::new(),
            microblocks: HashMap::new(),
            block_commits: HashMap::new(),
            miner_node_map: HashMap::new(),
        }
    }

    pub fn add(
        &mut self,
        miner_id: usize,
        node_name: String,
        fork_snapshot: BlockSnapshot,
        funai_block: FunaiBlock,
        microblocks: Vec<FunaiMicroblock>,
        block_commit: LeaderBlockCommitOp,
    ) -> () {
        self.fork_snapshots.insert(miner_id, fork_snapshot);
        self.funai_blocks.insert(miner_id, funai_block);
        self.microblocks.insert(miner_id, microblocks);
        self.block_commits.insert(miner_id, block_commit);
        self.miner_node_map.insert(miner_id, node_name);
    }

    pub fn get_block_snapshot(&self, miner_id: usize) -> Option<BlockSnapshot> {
        self.fork_snapshots.get(&miner_id).cloned()
    }

    pub fn get_funai_block(&self, miner_id: usize) -> Option<FunaiBlock> {
        self.funai_blocks.get(&miner_id).cloned()
    }

    pub fn get_microblocks(&self, miner_id: usize) -> Option<Vec<FunaiMicroblock>> {
        self.microblocks.get(&miner_id).cloned()
    }

    pub fn get_block_commit(&self, miner_id: usize) -> Option<LeaderBlockCommitOp> {
        self.block_commits.get(&miner_id).cloned()
    }

    pub fn get_node_name(&self, miner_id: usize) -> Option<String> {
        self.miner_node_map.get(&miner_id).cloned()
    }

    pub fn get_miner_ids(&self) -> Vec<usize> {
        let mut miner_ids = HashSet::new();
        for miner_id in self.fork_snapshots.keys() {
            miner_ids.insert(*miner_id);
        }
        for miner_id in self.funai_blocks.keys() {
            miner_ids.insert(*miner_id);
        }
        for miner_id in self.microblocks.keys() {
            miner_ids.insert(*miner_id);
        }
        for miner_id in self.block_commits.keys() {
            miner_ids.insert(*miner_id);
        }
        let mut ret = vec![];
        for miner_id in miner_ids.iter() {
            ret.push(*miner_id);
        }
        ret
    }
}

pub struct TestMinerTrace {
    pub points: Vec<TestMinerTracePoint>,
    pub burn_node: TestBurnchainNode,
    pub miners: Vec<TestMiner>,
}

impl TestMinerTrace {
    pub fn new(
        burn_node: TestBurnchainNode,
        miners: Vec<TestMiner>,
        points: Vec<TestMinerTracePoint>,
    ) -> TestMinerTrace {
        TestMinerTrace {
            points: points,
            burn_node: burn_node,
            miners: miners,
        }
    }

    /// how many blocks represented here?
    pub fn get_num_blocks(&self) -> usize {
        let mut num_blocks = 0;
        for p in self.points.iter() {
            for miner_id in p.funai_blocks.keys() {
                if p.funai_blocks.get(miner_id).is_some() {
                    num_blocks += 1;
                }
            }
        }
        num_blocks
    }

    /// how many sortitions represented here?
    pub fn get_num_sortitions(&self) -> usize {
        let mut num_sortitions = 0;
        for p in self.points.iter() {
            for miner_id in p.fork_snapshots.keys() {
                if p.fork_snapshots.get(miner_id).is_some() {
                    num_sortitions += 1;
                }
            }
        }
        num_sortitions
    }

    /// how many rounds did this trace go for?
    pub fn rounds(&self) -> usize {
        self.points.len()
    }

    /// what are the chainstate directories?
    pub fn get_test_names(&self) -> Vec<String> {
        let mut all_test_names = HashSet::new();
        for p in self.points.iter() {
            for miner_id in p.miner_node_map.keys() {
                if let Some(test_name) = p.miner_node_map.get(miner_id) {
                    if !all_test_names.contains(test_name) {
                        all_test_names.insert(test_name.to_owned());
                    }
                }
            }
        }
        let mut ret = vec![];
        for name in all_test_names.drain() {
            ret.push(name.to_owned());
        }
        ret
    }
}

pub struct TestFunaiNode {
    pub chainstate: FunaiChainState,
    pub prev_keys: Vec<LeaderKeyRegisterOp>, // _all_ keys generated
    pub key_ops: HashMap<VRFPublicKey, usize>, // map VRF public keys to their locations in the prev_keys array
    pub anchored_blocks: Vec<FunaiBlock>,
    pub microblocks: Vec<Vec<FunaiMicroblock>>,
    pub nakamoto_blocks: Vec<Vec<NakamotoBlock>>,
    pub commit_ops: HashMap<BlockHeaderHash, usize>,
    pub nakamoto_commit_ops: HashMap<FunaiBlockId, usize>,
    pub test_name: String,
    forkable: bool,
}

impl TestFunaiNode {
    pub fn new(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
        mut initial_balance_recipients: Vec<FunaiAddress>,
    ) -> TestFunaiNode {
        initial_balance_recipients.sort();
        let initial_balances = initial_balance_recipients
            .into_iter()
            .map(|addr| (addr, 10_000_000_000))
            .collect();
        let chainstate =
            instantiate_chainstate_with_balances(mainnet, chain_id, test_name, initial_balances);
        TestFunaiNode {
            chainstate: chainstate,
            prev_keys: vec![],
            key_ops: HashMap::new(),
            anchored_blocks: vec![],
            microblocks: vec![],
            nakamoto_blocks: vec![],
            commit_ops: HashMap::new(),
            nakamoto_commit_ops: HashMap::new(),
            test_name: test_name.to_string(),
            forkable: true,
        }
    }

    pub fn open(mainnet: bool, chain_id: u32, test_name: &str) -> TestFunaiNode {
        let chainstate = open_chainstate(mainnet, chain_id, test_name);
        TestFunaiNode {
            chainstate: chainstate,
            prev_keys: vec![],
            key_ops: HashMap::new(),
            anchored_blocks: vec![],
            microblocks: vec![],
            nakamoto_blocks: vec![],
            commit_ops: HashMap::new(),
            nakamoto_commit_ops: HashMap::new(),
            test_name: test_name.to_string(),
            forkable: true,
        }
    }

    pub fn from_chainstate(chainstate: FunaiChainState) -> TestFunaiNode {
        TestFunaiNode {
            chainstate: chainstate,
            prev_keys: vec![],
            key_ops: HashMap::new(),
            anchored_blocks: vec![],
            microblocks: vec![],
            nakamoto_blocks: vec![],
            commit_ops: HashMap::new(),
            nakamoto_commit_ops: HashMap::new(),
            test_name: "".to_string(),
            forkable: false,
        }
    }

    // NOTE: can't do this if instantiated via from_chainstate()
    pub fn fork(&self, new_test_name: &str) -> TestFunaiNode {
        if !self.forkable {
            panic!("Tried to fork an unforkable chainstate instance");
        }

        match fs::metadata(&chainstate_path(new_test_name)) {
            Ok(_) => {
                fs::remove_dir_all(&chainstate_path(new_test_name)).unwrap();
            }
            Err(_) => {}
        }

        copy_dir(
            &chainstate_path(&self.test_name),
            &chainstate_path(new_test_name),
        )
        .unwrap();
        let chainstate = open_chainstate(
            self.chainstate.mainnet,
            self.chainstate.chain_id,
            new_test_name,
        );
        TestFunaiNode {
            chainstate: chainstate,
            prev_keys: self.prev_keys.clone(),
            key_ops: self.key_ops.clone(),
            anchored_blocks: self.anchored_blocks.clone(),
            microblocks: self.microblocks.clone(),
            nakamoto_blocks: self.nakamoto_blocks.clone(),
            commit_ops: self.commit_ops.clone(),
            nakamoto_commit_ops: self.nakamoto_commit_ops.clone(),
            test_name: new_test_name.to_string(),
            forkable: true,
        }
    }

    pub fn next_burn_block(
        sortdb: &mut SortitionDB,
        fork: &mut TestBurnchainFork,
    ) -> TestBurnchainBlock {
        let burn_block = {
            let ic = sortdb.index_conn();
            fork.next_block(&ic)
        };
        burn_block
    }

    pub fn add_key_register(
        &mut self,
        block: &mut TestBurnchainBlock,
        miner: &mut TestMiner,
    ) -> LeaderKeyRegisterOp {
        let key_register_op = block.add_leader_key_register(miner);
        self.prev_keys.push(key_register_op.clone());
        self.key_ops
            .insert(key_register_op.public_key.clone(), self.prev_keys.len() - 1);
        key_register_op
    }

    pub fn add_key_register_op(&mut self, op: &LeaderKeyRegisterOp) -> () {
        self.prev_keys.push(op.clone());
        self.key_ops
            .insert(op.public_key.clone(), self.prev_keys.len() - 1);
    }

    pub fn add_block_commit(
        sortdb: &SortitionDB,
        burn_block: &mut TestBurnchainBlock,
        miner: &mut TestMiner,
        block_hash: &BlockHeaderHash,
        burn_amount: u64,
        key_op: &LeaderKeyRegisterOp,
        parent_block_snapshot: Option<&BlockSnapshot>,
    ) -> LeaderBlockCommitOp {
        let block_commit_op = {
            let ic = sortdb.index_conn();
            let parent_snapshot = burn_block.parent_snapshot.clone();
            burn_block.add_leader_block_commit(
                &ic,
                miner,
                block_hash,
                burn_amount,
                key_op,
                Some(&parent_snapshot),
                parent_block_snapshot,
            )
        };
        block_commit_op
    }

    pub fn get_last_key(&self, miner: &TestMiner) -> LeaderKeyRegisterOp {
        let last_vrf_pubkey = miner.last_VRF_public_key().unwrap();
        let idx = *self.key_ops.get(&last_vrf_pubkey).unwrap();
        self.prev_keys[idx].clone()
    }

    pub fn get_last_anchored_block(&self, miner: &TestMiner) -> Option<FunaiBlock> {
        let mut num_commits = miner.num_block_commits();
        if num_commits == 0 {
            return None;
        }

        while num_commits > 0 {
            num_commits -= 1;
            match miner.block_commit_at(num_commits) {
                None => {
                    continue;
                }
                Some(block_commit_op) => {
                    match self.commit_ops.get(&block_commit_op.block_header_hash) {
                        None => {
                            continue;
                        }
                        Some(idx) => {
                            return Some(self.anchored_blocks[*idx].clone());
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_last_accepted_anchored_block(
        &self,
        sortdb: &SortitionDB,
        miner: &TestMiner,
    ) -> Option<FunaiBlock> {
        for bc in miner.block_commits.iter().rev() {
            let consensus_hash = match SortitionDB::get_block_snapshot(
                sortdb.conn(),
                &SortitionId::stubbed(&bc.burn_header_hash),
            )
            .unwrap()
            {
                Some(sn) => sn.consensus_hash,
                None => {
                    continue;
                }
            };

            if FunaiChainState::has_stored_block(
                &self.chainstate.db(),
                &self.chainstate.blocks_path,
                &consensus_hash,
                &bc.block_header_hash,
            )
            .unwrap()
                && !FunaiChainState::is_block_orphaned(
                    &self.chainstate.db(),
                    &consensus_hash,
                    &bc.block_header_hash,
                )
                .unwrap()
            {
                match self.commit_ops.get(&bc.block_header_hash) {
                    None => {
                        continue;
                    }
                    Some(idx) => {
                        return Some(self.anchored_blocks[*idx].clone());
                    }
                }
            }
        }
        return None;
    }

    pub fn get_microblock_stream(
        &self,
        miner: &TestMiner,
        block_hash: &BlockHeaderHash,
    ) -> Option<Vec<FunaiMicroblock>> {
        match self.commit_ops.get(block_hash) {
            None => None,
            Some(idx) => Some(self.microblocks[*idx].clone()),
        }
    }

    pub fn get_anchored_block(&self, block_hash: &BlockHeaderHash) -> Option<FunaiBlock> {
        match self.commit_ops.get(block_hash) {
            None => None,
            Some(idx) => Some(self.anchored_blocks[*idx].clone()),
        }
    }

    pub fn get_last_winning_snapshot(
        ic: &SortitionDBConn,
        fork_tip: &BlockSnapshot,
        miner: &TestMiner,
    ) -> Option<BlockSnapshot> {
        for commit_op in miner.block_commits.iter().rev() {
            match SortitionDB::get_block_snapshot_for_winning_funai_block(
                ic,
                &fork_tip.sortition_id,
                &commit_op.block_header_hash,
            )
            .unwrap()
            {
                Some(sn) => {
                    return Some(sn);
                }
                None => {}
            }
        }
        return None;
    }

    pub fn get_miner_balance(clarity_tx: &mut ClarityTx, addr: &FunaiAddress) -> u128 {
        clarity_tx.with_clarity_db_readonly(|db| {
            db.get_account_stx_balance(&StandardPrincipalData::from(addr.clone()).into())
                .unwrap()
                .amount_unlocked()
        })
    }

    pub fn make_tenure_commitment(
        &mut self,
        sortdb: &SortitionDB,
        burn_block: &mut TestBurnchainBlock,
        miner: &mut TestMiner,
        funai_block: &FunaiBlock,
        microblocks: &Vec<FunaiMicroblock>,
        burn_amount: u64,
        miner_key: &LeaderKeyRegisterOp,
        parent_block_snapshot_opt: Option<&BlockSnapshot>,
    ) -> LeaderBlockCommitOp {
        self.anchored_blocks.push(funai_block.clone());
        self.microblocks.push(microblocks.clone());

        test_debug!(
            "Miner {}: Commit to funai block {} (work {},{})",
            miner.id,
            funai_block.block_hash(),
            funai_block.header.total_work.burn,
            funai_block.header.total_work.work
        );

        // send block commit for this block
        let block_commit_op = TestFunaiNode::add_block_commit(
            sortdb,
            burn_block,
            miner,
            &funai_block.block_hash(),
            burn_amount,
            miner_key,
            parent_block_snapshot_opt,
        );

        test_debug!(
            "Miner {}: Block commit transaction builds on {},{} (parent snapshot is {:?})",
            miner.id,
            block_commit_op.parent_block_ptr,
            block_commit_op.parent_vtxindex,
            &parent_block_snapshot_opt
        );
        self.commit_ops.insert(
            block_commit_op.block_header_hash.clone(),
            self.anchored_blocks.len() - 1,
        );
        block_commit_op
    }

    /// Mine a single Funai block and a microblock stream.
    /// Produce its block-commit.
    pub fn mine_funai_block<F>(
        &mut self,
        sortdb: &SortitionDB,
        miner: &mut TestMiner,
        burn_block: &mut TestBurnchainBlock,
        miner_key: &LeaderKeyRegisterOp,
        parent_funai_block: Option<&FunaiBlock>,
        burn_amount: u64,
        block_assembler: F,
    ) -> (FunaiBlock, Vec<FunaiMicroblock>, LeaderBlockCommitOp)
    where
        F: FnOnce(
            FunaiBlockBuilder,
            &mut TestMiner,
            &SortitionDB,
        ) -> (FunaiBlock, Vec<FunaiMicroblock>),
    {
        let proof = miner
            .make_proof(
                &miner_key.public_key,
                &burn_block.parent_snapshot.sortition_hash,
            )
            .expect(&format!(
                "FATAL: no private key for {}",
                miner_key.public_key.to_hex()
            ));

        let (builder, parent_block_snapshot_opt) = match parent_funai_block {
            None => {
                // first funai block
                let builder = FunaiBlockBuilder::first(
                    miner.id,
                    &burn_block.parent_snapshot.consensus_hash,
                    &burn_block.parent_snapshot.burn_header_hash,
                    burn_block.parent_snapshot.block_height as u32,
                    burn_block.parent_snapshot.burn_header_timestamp,
                    &proof,
                    &miner.next_microblock_privkey(),
                );
                (builder, None)
            }
            Some(parent_funai_block) => {
                // building off an existing funai block
                let parent_funai_block_snapshot = {
                    let ic = sortdb.index_conn();
                    let parent_funai_block_snapshot =
                        SortitionDB::get_block_snapshot_for_winning_funai_block(
                            &ic,
                            &burn_block.parent_snapshot.sortition_id,
                            &parent_funai_block.block_hash(),
                        )
                        .unwrap()
                        .unwrap();
                    let burned_last =
                        SortitionDB::get_block_burn_amount(&ic, &burn_block.parent_snapshot)
                            .unwrap();
                    parent_funai_block_snapshot
                };

                let parent_chain_tip = FunaiChainState::get_anchored_block_header_info(
                    self.chainstate.db(),
                    &parent_funai_block_snapshot.consensus_hash,
                    &parent_funai_block.header.block_hash(),
                )
                .unwrap()
                .unwrap();

                let new_work = FunaiWorkScore {
                    burn: parent_funai_block_snapshot.total_burn,
                    work: parent_funai_block
                        .header
                        .total_work
                        .work
                        .checked_add(1)
                        .expect("FATAL: funai block height overflow"),
                };

                test_debug!(
                    "Work in {} {}: {},{}",
                    burn_block.block_height,
                    burn_block.parent_snapshot.burn_header_hash,
                    new_work.burn,
                    new_work.work
                );
                let builder = FunaiBlockBuilder::from_parent(
                    miner.id,
                    &parent_chain_tip,
                    &new_work,
                    &proof,
                    &miner.next_microblock_privkey(),
                );
                (builder, Some(parent_funai_block_snapshot))
            }
        };

        test_debug!(
            "Miner {}: Assemble funai block from {}",
            miner.id,
            miner.origin_address().unwrap().to_string()
        );

        let (funai_block, microblocks) = block_assembler(builder, miner, sortdb);
        let block_commit_op = self.make_tenure_commitment(
            sortdb,
            burn_block,
            miner,
            &funai_block,
            &microblocks,
            burn_amount,
            miner_key,
            parent_block_snapshot_opt.as_ref(),
        );

        (funai_block, microblocks, block_commit_op)
    }
}

/// Return Some(bool) to indicate whether or not the anchored block was accepted into the queue.
/// Return None if the block was not submitted at all.
pub fn preprocess_funai_block_data(
    node: &mut TestFunaiNode,
    burn_node: &mut TestBurnchainNode,
    fork_snapshot: &BlockSnapshot,
    funai_block: &FunaiBlock,
    funai_microblocks: &Vec<FunaiMicroblock>,
    block_commit_op: &LeaderBlockCommitOp,
) -> Option<bool> {
    let block_hash = funai_block.block_hash();

    let ic = burn_node.sortdb.index_conn();
    let ch_opt = SortitionDB::get_block_commit_parent(
        &ic,
        block_commit_op.parent_block_ptr.into(),
        block_commit_op.parent_vtxindex.into(),
        &fork_snapshot.sortition_id,
    )
    .unwrap();
    let parent_block_consensus_hash = match ch_opt {
        Some(parent_commit) => {
            let db_handle = SortitionHandleConn::open_reader(
                &ic,
                &SortitionId::stubbed(&block_commit_op.burn_header_hash),
            )
            .unwrap();
            let sn = db_handle
                .get_block_snapshot(&parent_commit.burn_header_hash)
                .unwrap()
                .unwrap();
            sn.consensus_hash
        }
        None => {
            // only allowed if this is the first-ever block in the funai fork
            assert_eq!(block_commit_op.parent_block_ptr, 0);
            assert_eq!(block_commit_op.parent_vtxindex, 0);
            assert!(funai_block.header.is_first_mined());

            FIRST_BURNCHAIN_CONSENSUS_HASH.clone()
        }
    };

    let commit_snapshot = match SortitionDB::get_block_snapshot_for_winning_funai_block(
        &ic,
        &fork_snapshot.sortition_id,
        &block_hash,
    )
    .unwrap()
    {
        Some(sn) => sn,
        None => {
            test_debug!("Block commit did not win sorition: {:?}", block_commit_op);
            return None;
        }
    };

    // "discover" this funai block
    test_debug!(
        "\n\nPreprocess Funai block {}/{} ({})",
        &commit_snapshot.consensus_hash,
        &block_hash,
        FunaiBlockHeader::make_index_block_hash(&commit_snapshot.consensus_hash, &block_hash)
    );
    let block_res = node
        .chainstate
        .preprocess_anchored_block(
            &ic,
            &commit_snapshot.consensus_hash,
            &funai_block,
            &parent_block_consensus_hash,
            5,
        )
        .unwrap();

    // "discover" this funai microblock stream
    for mblock in funai_microblocks.iter() {
        test_debug!(
            "Preprocess Funai microblock {}-{} (seq {})",
            &block_hash,
            mblock.block_hash(),
            mblock.header.sequence
        );
        match node.chainstate.preprocess_streamed_microblock(
            &commit_snapshot.consensus_hash,
            &funai_block.block_hash(),
            mblock,
        ) {
            Ok(_) => {}
            Err(_) => {
                return Some(false);
            }
        }
    }

    Some(block_res)
}

/// Verify that the funai block's state root matches the state root in the chain state
pub fn check_block_state_index_root(
    chainstate: &mut FunaiChainState,
    consensus_hash: &ConsensusHash,
    funai_header: &FunaiBlockHeader,
) -> bool {
    let index_block_hash =
        FunaiBlockHeader::make_index_block_hash(consensus_hash, &funai_header.block_hash());
    let mut state_root_index =
        FunaiChainState::open_index(&chainstate.clarity_state_index_path).unwrap();
    let state_root = state_root_index
        .borrow_storage_backend()
        .read_block_root_hash(&index_block_hash)
        .unwrap();
    test_debug!(
        "checking {}/{} state root: expecting {}, got {}",
        consensus_hash,
        &funai_header.block_hash(),
        &funai_header.state_index_root,
        &state_root
    );
    state_root == funai_header.state_index_root
}

/// Verify that the miner got the expected block reward
pub fn check_mining_reward(
    clarity_tx: &mut ClarityTx,
    miner: &mut TestMiner,
    block_height: u64,
    prev_block_rewards: &Vec<Vec<MinerPaymentSchedule>>,
) -> bool {
    let mut block_rewards = HashMap::new();
    let mut stream_rewards = HashMap::new();
    let mut heights = HashMap::new();
    let mut confirmed = HashSet::new();
    for (i, reward_list) in prev_block_rewards.iter().enumerate() {
        for reward in reward_list.iter() {
            let ibh = FunaiBlockHeader::make_index_block_hash(
                &reward.consensus_hash,
                &reward.block_hash,
            );
            if reward.coinbase > 0 {
                block_rewards.insert(ibh.clone(), reward.clone());
            }
            if let MinerPaymentTxFees::Epoch2 { streamed, .. } = &reward.tx_fees {
                if *streamed > 0 {
                    stream_rewards.insert(ibh.clone(), reward.clone());
                }
            }
            heights.insert(ibh.clone(), i);
            confirmed.insert((
                FunaiBlockHeader::make_index_block_hash(
                    &reward.parent_consensus_hash,
                    &reward.parent_block_hash,
                ),
                i,
            ));
        }
    }

    // what was the miner's total spend?
    let miner_nonce = clarity_tx.with_clarity_db_readonly(|db| {
        db.get_account_nonce(&StandardPrincipalData::from(miner.origin_address().unwrap()).into())
            .unwrap()
    });

    let mut spent_total = 0;
    for (nonce, spent) in miner.spent_at_nonce.iter() {
        if *nonce < miner_nonce {
            spent_total += *spent;
        }
    }

    let mut total: u128 = 10_000_000_000 - spent_total;
    test_debug!(
        "Miner {} has spent {} in total so far",
        &miner.origin_address().unwrap(),
        spent_total
    );

    if block_height >= MINER_REWARD_MATURITY {
        for (i, prev_block_reward) in prev_block_rewards.iter().enumerate() {
            if i as u64 > block_height - MINER_REWARD_MATURITY {
                break;
            }
            let mut found = false;
            for recipient in prev_block_reward {
                if recipient.address == miner.origin_address().unwrap() {
                    let (anchored, streamed) = match &recipient.tx_fees {
                        MinerPaymentTxFees::Epoch2 { anchored, streamed } => (anchored, streamed),
                        _ => panic!("Expected Epoch2 style miner rewards"),
                    };
                    let reward = recipient.coinbase + anchored + (3 * streamed / 5);

                    test_debug!(
                        "Miner {} received a reward {} = {} + {} + {} at block {}",
                        &recipient.address.to_string(),
                        reward,
                        recipient.coinbase,
                        anchored,
                        (3 * streamed / 5),
                        i
                    );
                    total += reward;
                    found = true;
                }
            }
            if !found {
                test_debug!(
                    "Miner {} received no reward at block {}",
                    miner.origin_address().unwrap(),
                    i
                );
            }
        }

        for (parent_block, confirmed_block_height) in confirmed.into_iter() {
            if confirmed_block_height as u64 > block_height - MINER_REWARD_MATURITY {
                continue;
            }
            if let Some(ref parent_reward) = stream_rewards.get(&parent_block) {
                if parent_reward.address == miner.origin_address().unwrap() {
                    let streamed = match &parent_reward.tx_fees {
                        MinerPaymentTxFees::Epoch2 { streamed, .. } => streamed,
                        _ => panic!("Expected Epoch2 style miner reward"),
                    };
                    let parent_streamed = (2 * streamed) / 5;
                    let parent_ibh = FunaiBlockHeader::make_index_block_hash(
                        &parent_reward.consensus_hash,
                        &parent_reward.block_hash,
                    );
                    test_debug!(
                        "Miner {} received a produced-stream reward {} from {} confirmed at {}",
                        miner.origin_address().unwrap().to_string(),
                        parent_streamed,
                        heights.get(&parent_ibh).unwrap(),
                        confirmed_block_height
                    );
                    total += parent_streamed;
                }
            }
        }
    }

    let amount = TestFunaiNode::get_miner_balance(clarity_tx, &miner.origin_address().unwrap());
    if amount == 0 {
        test_debug!(
            "Miner {} '{}' has no mature funds in this fork",
            miner.id,
            miner.origin_address().unwrap().to_string()
        );
        return total == 0;
    } else {
        if amount != total {
            test_debug!("Amount {} != {}", amount, total);
            return false;
        }
        return true;
    }
}

pub fn get_last_microblock_header(
    node: &TestFunaiNode,
    miner: &TestMiner,
    parent_block_opt: Option<&FunaiBlock>,
) -> Option<FunaiMicroblockHeader> {
    let last_microblocks_opt = match parent_block_opt {
        Some(ref block) => node.get_microblock_stream(&miner, &block.block_hash()),
        None => None,
    };

    let last_microblock_header_opt = match last_microblocks_opt {
        Some(last_microblocks) => {
            if last_microblocks.len() == 0 {
                None
            } else {
                let l = last_microblocks.len() - 1;
                Some(last_microblocks[l].header.clone())
            }
        }
        None => None,
    };

    last_microblock_header_opt
}

pub fn get_all_mining_rewards(
    chainstate: &mut FunaiChainState,
    tip: &FunaiHeaderInfo,
    block_height: u64,
) -> Vec<Vec<MinerPaymentSchedule>> {
    let mut ret = vec![];
    let mut tx = chainstate.index_tx_begin().unwrap();

    for i in 0..block_height {
        let block_rewards =
            FunaiChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, tip, i)
                .unwrap();
        ret.push(block_rewards);
    }

    ret
}

pub fn make_coinbase(miner: &mut TestMiner, burnchain_height: usize) -> FunaiTransaction {
    make_coinbase_with_nonce(miner, burnchain_height, miner.get_nonce(), None)
}

pub fn make_coinbase_to_contract(
    miner: &mut TestMiner,
    burnchain_height: usize,
    contract: QualifiedContractIdentifier,
) -> FunaiTransaction {
    make_coinbase_with_nonce(
        miner,
        burnchain_height,
        miner.get_nonce(),
        Some(PrincipalData::Contract(contract)),
    )
}

pub fn make_coinbase_with_nonce(
    miner: &mut TestMiner,
    burnchain_height: usize,
    nonce: u64,
    recipient: Option<PrincipalData>,
) -> FunaiTransaction {
    // make a coinbase for this miner
    let mut tx_coinbase = FunaiTransaction::new(
        TransactionVersion::Testnet,
        miner.as_transaction_auth().unwrap(),
        TransactionPayload::Coinbase(
            CoinbasePayload([(burnchain_height % 256) as u8; 32]),
            recipient,
            None,
        ),
    );
    tx_coinbase.chain_id = 0x80000000;
    tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
    tx_coinbase.auth.set_origin_nonce(nonce);

    let mut tx_signer = FunaiTransactionSigner::new(&tx_coinbase);
    miner.sign_as_origin(&mut tx_signer);
    let tx_coinbase_signed = tx_signer.get_tx().unwrap();
    tx_coinbase_signed
}

pub fn make_smart_contract(
    miner: &mut TestMiner,
    burnchain_height: usize,
    funai_block_height: usize,
) -> FunaiTransaction {
    make_smart_contract_with_version(
        miner,
        miner.get_nonce(),
        burnchain_height,
        funai_block_height,
        None,
        None,
    )
}

pub fn make_smart_contract_with_version(
    miner: &mut TestMiner,
    nonce: u64,
    burnchain_height: usize,
    funai_block_height: usize,
    version: Option<ClarityVersion>,
    fee: Option<u64>,
) -> FunaiTransaction {
    // make a smart contract
    let contract = "
    (define-data-var bar int 0)
    (define-public (get-bar) (ok (var-get bar)))
    (define-public (set-bar (x int) (y int))
      (begin (var-set bar (/ x y)) (ok (var-get bar))))";

    test_debug!(
        "Make smart contract block at hello-world-{}-{}",
        burnchain_height,
        funai_block_height
    );

    let mut tx_contract = FunaiTransaction::new(
        TransactionVersion::Testnet,
        miner.as_transaction_auth().unwrap(),
        TransactionPayload::new_smart_contract(
            &format!("hello-world-{}-{}", burnchain_height, funai_block_height),
            &contract.to_string(),
            version,
        )
        .unwrap(),
    );

    tx_contract.chain_id = 0x80000000;
    tx_contract.auth.set_origin_nonce(nonce);

    if miner.test_with_tx_fees {
        tx_contract.set_tx_fee(fee.unwrap_or(123));
        miner
            .spent_at_nonce
            .insert(nonce, fee.unwrap_or(123).into());
    } else {
        tx_contract.set_tx_fee(fee.unwrap_or(0));
    }

    let mut tx_signer = FunaiTransactionSigner::new(&tx_contract);
    miner.sign_as_origin(&mut tx_signer);
    let tx_contract_signed = tx_signer.get_tx().unwrap();

    tx_contract_signed
}

/// paired with make_smart_contract
pub fn make_contract_call(
    miner: &mut TestMiner,
    burnchain_height: usize,
    funai_block_height: usize,
    arg1: i128,
    arg2: i128,
) -> FunaiTransaction {
    let addr = miner.origin_address().unwrap();
    let mut tx_contract_call = FunaiTransaction::new(
        TransactionVersion::Testnet,
        miner.as_transaction_auth().unwrap(),
        TransactionPayload::new_contract_call(
            addr.clone(),
            &format!("hello-world-{}-{}", burnchain_height, funai_block_height),
            "set-bar",
            vec![Value::Int(arg1), Value::Int(arg2)],
        )
        .unwrap(),
    );

    tx_contract_call.chain_id = 0x80000000;
    tx_contract_call.auth.set_origin_nonce(miner.get_nonce());

    if miner.test_with_tx_fees {
        tx_contract_call.set_tx_fee(456);
        miner.spent_at_nonce.insert(miner.get_nonce(), 456);
    } else {
        tx_contract_call.set_tx_fee(0);
    }

    let mut tx_signer = FunaiTransactionSigner::new(&tx_contract_call);
    miner.sign_as_origin(&mut tx_signer);
    let tx_contract_call_signed = tx_signer.get_tx().unwrap();
    tx_contract_call_signed
}

/// make a token transfer
pub fn make_token_transfer(
    miner: &mut TestMiner,
    burnchain_height: usize,
    nonce: Option<u64>,
    recipient: &FunaiAddress,
    amount: u64,
    memo: &TokenTransferMemo,
) -> FunaiTransaction {
    let addr = miner.origin_address().unwrap();
    let mut tx_stx_transfer = FunaiTransaction::new(
        TransactionVersion::Testnet,
        miner.as_transaction_auth().unwrap(),
        TransactionPayload::TokenTransfer((*recipient).clone().into(), amount, (*memo).clone()),
    );

    tx_stx_transfer.chain_id = 0x80000000;
    tx_stx_transfer
        .auth
        .set_origin_nonce(nonce.unwrap_or(miner.get_nonce()));
    tx_stx_transfer.set_tx_fee(0);

    let mut tx_signer = FunaiTransactionSigner::new(&tx_stx_transfer);
    miner.sign_as_origin(&mut tx_signer);
    let tx_stx_transfer_signed = tx_signer.get_tx().unwrap();
    tx_stx_transfer_signed
}

// TODO: merge with vm/tests/integrations.rs.
// Distinct here because we use a different testnet ID
pub fn make_user_contract_publish(
    sender: &FunaiPrivateKey,
    nonce: u64,
    tx_fee: u64,
    contract_name: &str,
    contract_content: &str,
) -> FunaiTransaction {
    let name = ContractName::from(contract_name);
    let code_body = FunaiString::from_string(&contract_content.to_string()).unwrap();

    let payload = TransactionSmartContract { name, code_body };

    sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
}

pub fn make_versioned_user_contract_publish(
    sender: &FunaiPrivateKey,
    nonce: u64,
    tx_fee: u64,
    contract_name: &str,
    contract_content: &str,
    version: ClarityVersion,
) -> FunaiTransaction {
    let name = ContractName::from(contract_name);
    let code_body = FunaiString::from_string(&contract_content.to_string()).unwrap();

    let payload = TransactionPayload::SmartContract(
        TransactionSmartContract { name, code_body },
        Some(version),
    );

    sign_standard_singlesig_tx(payload, sender, nonce, tx_fee)
}

pub fn make_user_contract_call(
    sender: &FunaiPrivateKey,
    nonce: u64,
    tx_fee: u64,
    contract_addr: &FunaiAddress,
    contract_name: &str,
    contract_function: &str,
    args: Vec<Value>,
) -> FunaiTransaction {
    let mut tx_contract_call = FunaiTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(sender).unwrap(),
        TransactionPayload::new_contract_call(
            contract_addr.clone(),
            contract_name,
            contract_function,
            args,
        )
        .unwrap(),
    );

    tx_contract_call.chain_id = 0x80000000;
    tx_contract_call.auth.set_origin_nonce(nonce);
    tx_contract_call.auth.set_tx_fee(tx_fee);
    tx_contract_call.post_condition_mode = TransactionPostConditionMode::Allow;

    let mut tx_signer = FunaiTransactionSigner::new(&tx_contract_call);
    tx_signer.sign_origin(sender).unwrap();
    let tx_contract_call_signed = tx_signer.get_tx().unwrap();
    tx_contract_call_signed
}

pub fn make_user_funai_transfer(
    sender: &FunaiPrivateKey,
    nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> FunaiTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
}

pub fn make_user_coinbase(sender: &FunaiPrivateKey, nonce: u64, tx_fee: u64) -> FunaiTransaction {
    let payload = TransactionPayload::Coinbase(CoinbasePayload([0; 32]), None, None);
    sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
}

pub fn make_user_poison_microblock(
    sender: &FunaiPrivateKey,
    nonce: u64,
    tx_fee: u64,
    payload: TransactionPayload,
) -> FunaiTransaction {
    sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
}

pub fn sign_standard_singlesig_tx(
    payload: TransactionPayload,
    sender: &FunaiPrivateKey,
    nonce: u64,
    tx_fee: u64,
) -> FunaiTransaction {
    let mut spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(FunaiPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");
    spending_condition.set_nonce(nonce);
    spending_condition.set_tx_fee(tx_fee);
    let auth = TransactionAuth::Standard(spending_condition);
    let mut unsigned_tx = FunaiTransaction::new(TransactionVersion::Testnet, auth, payload);

    unsigned_tx.chain_id = 0x80000000;
    unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;

    let mut tx_signer = FunaiTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(sender).unwrap();

    tx_signer.get_tx().unwrap()
}

pub fn get_funai_account(peer: &mut TestPeer, addr: &PrincipalData) -> FunaiAccount {
    let account = peer
        .with_db_state(|ref mut sortdb, ref mut chainstate, _, _| {
            let (consensus_hash, block_bhh) =
                SortitionDB::get_canonical_funai_chain_tip_hash(sortdb.conn()).unwrap();
            let funai_block_id =
                FunaiBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);
            let acct = chainstate
                .with_read_only_clarity_tx(&sortdb.index_conn(), &funai_block_id, |clarity_tx| {
                    FunaiChainState::get_account(clarity_tx, addr)
                })
                .unwrap();
            Ok(acct)
        })
        .unwrap();
    account
}

pub fn instantiate_and_exec(
    mainnet: bool,
    chain_id: u32,
    test_name: &str,
    balances: Vec<(FunaiAddress, u64)>,
    post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx) -> ()>>,
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
        post_flight_callback,
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
