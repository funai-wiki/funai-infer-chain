use funai_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use funai_common::consts::{
    BITCOIN_REGTEST_FIRST_BLOCK_HASH, BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
    BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use funai_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, FunaiAddress, FunaiBlockId,
    FunaiPrivateKey, FunaiPublicKey, VRFSeed,
};
use funai_common::types::{FunaiEpochId, PEER_VERSION_EPOCH_2_0};

use crate::vm::ast::ASTRules;
use crate::vm::costs::ExecutionCost;
use crate::vm::database::{BurnStateDB, HeadersDB};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{PrincipalData, ResponseData, StandardPrincipalData, TupleData, Value};
use crate::vm::{execute as vm_execute, execute_on_network as vm_execute_on_network, FunaiEpoch};

pub struct UnitTestBurnStateDB {
    pub epoch_id: FunaiEpochId,
    pub ast_rules: ASTRules,
}
pub struct UnitTestHeaderDB {}

pub const TEST_HEADER_DB: UnitTestHeaderDB = UnitTestHeaderDB {};
pub const TEST_BURN_STATE_DB: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: FunaiEpochId::Epoch20,
    ast_rules: ASTRules::Typical,
};
pub const TEST_BURN_STATE_DB_205: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: FunaiEpochId::Epoch2_05,
    ast_rules: ASTRules::PrecheckSize,
};
pub const TEST_BURN_STATE_DB_21: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: FunaiEpochId::Epoch21,
    ast_rules: ASTRules::PrecheckSize,
};

pub fn generate_test_burn_state_db(epoch_id: FunaiEpochId) -> UnitTestBurnStateDB {
    match epoch_id {
        FunaiEpochId::Epoch10 => {
            panic!("Epoch 1.0 not testable");
        }
        FunaiEpochId::Epoch20 => UnitTestBurnStateDB {
            epoch_id,
            ast_rules: ASTRules::Typical,
        },
        FunaiEpochId::Epoch2_05
        | FunaiEpochId::Epoch21
        | FunaiEpochId::Epoch22
        | FunaiEpochId::Epoch23
        | FunaiEpochId::Epoch24
        | FunaiEpochId::Epoch25
        | FunaiEpochId::Epoch30 => UnitTestBurnStateDB {
            epoch_id,
            ast_rules: ASTRules::PrecheckSize,
        },
    }
}

pub fn execute(s: &str) -> Value {
    vm_execute(s).unwrap().unwrap()
}

pub fn execute_on_network(s: &str, use_mainnet: bool) -> Value {
    vm_execute_on_network(s, use_mainnet).unwrap().unwrap()
}

pub fn symbols_from_values(vec: Vec<Value>) -> Vec<SymbolicExpression> {
    vec.into_iter()
        .map(|value| SymbolicExpression::atom_value(value))
        .collect()
}

pub fn is_committed(v: &Value) -> bool {
    eprintln!("is_committed?: {}", v);

    match v {
        Value::Response(ref data) => data.committed,
        _ => false,
    }
}

pub fn is_err_code(v: &Value, e: u128) -> bool {
    eprintln!("is_err_code?: {}", v);
    match v {
        Value::Response(ref data) => !data.committed && *data.data == Value::UInt(e),
        _ => false,
    }
}

pub fn is_err_code_i128(v: &Value, e: i128) -> bool {
    eprintln!("is_err_code?: {}", v);
    match v {
        Value::Response(ref data) => !data.committed && *data.data == Value::Int(e),
        _ => false,
    }
}

impl From<&FunaiPrivateKey> for StandardPrincipalData {
    fn from(o: &FunaiPrivateKey) -> StandardPrincipalData {
        let stacks_addr = FunaiAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![FunaiPublicKey::from_private(o)],
        )
        .unwrap();
        StandardPrincipalData::from(stacks_addr)
    }
}

impl From<&FunaiPrivateKey> for PrincipalData {
    fn from(o: &FunaiPrivateKey) -> PrincipalData {
        PrincipalData::Standard(StandardPrincipalData::from(o))
    }
}

impl From<&FunaiPrivateKey> for Value {
    fn from(o: &FunaiPrivateKey) -> Value {
        Value::from(StandardPrincipalData::from(o))
    }
}

impl HeadersDB for UnitTestHeaderDB {
    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &FunaiBlockId,
    ) -> Option<BurnchainHeaderHash> {
        if *id_bhh == FunaiBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            let first_block_hash =
                BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
            Some(first_block_hash)
        } else {
            None
        }
    }
    fn get_vrf_seed_for_block(&self, _bhh: &FunaiBlockId) -> Option<VRFSeed> {
        None
    }
    fn get_funai_block_header_hash_for_block(
        &self,
        id_bhh: &FunaiBlockId,
    ) -> Option<BlockHeaderHash> {
        if *id_bhh == FunaiBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(FIRST_STACKS_BLOCK_HASH)
        } else {
            None
        }
    }
    fn get_burn_block_time_for_block(&self, id_bhh: &FunaiBlockId) -> Option<u64> {
        if *id_bhh == FunaiBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP as u64)
        } else {
            // for non-genesis blocks, just pick a u64 value that will increment in most
            // unit tests as blocks are built (most unit tests construct blocks using
            // incrementing high order bytes)
            Some(1 + 10 * (id_bhh.as_bytes()[0] as u64))
        }
    }
    fn get_burn_block_height_for_block(&self, id_bhh: &FunaiBlockId) -> Option<u32> {
        if *id_bhh == FunaiBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT as u32)
        } else {
            Some(1 + id_bhh.as_bytes()[0] as u32)
        }
    }
    fn get_miner_address(&self, _id_bhh: &FunaiBlockId) -> Option<FunaiAddress> {
        None
    }

    fn get_consensus_hash_for_block(&self, id_bhh: &FunaiBlockId) -> Option<ConsensusHash> {
        if *id_bhh == FunaiBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(FIRST_BURNCHAIN_CONSENSUS_HASH)
        } else {
            None
        }
    }

    fn get_burnchain_tokens_spent_for_block(&self, id_bhh: &FunaiBlockId) -> Option<u128> {
        // if the block is defined at all, then return a constant
        self.get_burn_block_height_for_block(id_bhh).map(|_| 2000)
    }

    fn get_burnchain_tokens_spent_for_winning_block(&self, id_bhh: &FunaiBlockId) -> Option<u128> {
        // if the block is defined at all, then return a constant
        self.get_burn_block_height_for_block(id_bhh).map(|_| 1000)
    }

    fn get_tokens_earned_for_block(&self, id_bhh: &FunaiBlockId) -> Option<u128> {
        // if the block is defined at all, then return a constant
        self.get_burn_block_height_for_block(id_bhh).map(|_| 3000)
    }
}

impl BurnStateDB for UnitTestBurnStateDB {
    fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
        None
    }

    fn get_burn_header_hash(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        None
    }

    fn get_funai_epoch(&self, _height: u32) -> Option<FunaiEpoch> {
        Some(FunaiEpoch {
            epoch_id: self.epoch_id,
            start_height: 0,
            end_height: u64::MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        })
    }

    fn get_funai_epoch_by_epoch_id(&self, _epoch_id: &FunaiEpochId) -> Option<FunaiEpoch> {
        self.get_funai_epoch(0)
    }

    fn get_v1_unlock_height(&self) -> u32 {
        u32::MAX
    }

    fn get_v2_unlock_height(&self) -> u32 {
        u32::MAX
    }

    fn get_v3_unlock_height(&self) -> u32 {
        u32::MAX
    }

    fn get_pox_3_activation_height(&self) -> u32 {
        u32::MAX
    }

    fn get_pox_4_activation_height(&self) -> u32 {
        u32::MAX
    }

    fn get_pox_prepare_length(&self) -> u32 {
        1
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        1
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        1
    }
    fn get_burn_start_height(&self) -> u32 {
        0
    }
    fn get_sortition_id_from_consensus_hash(
        &self,
        _consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        None
    }
    fn get_ast_rules(&self, _height: u32) -> ASTRules {
        self.ast_rules
    }
    fn get_pox_payout_addrs(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        Some((
            vec![TupleData::from_data(vec![
                ("version".into(), Value::buff_from(vec![0u8]).unwrap()),
                ("hashbytes".into(), Value::buff_from(vec![0u8; 20]).unwrap()),
            ])
            .unwrap()],
            123,
        ))
    }
}
