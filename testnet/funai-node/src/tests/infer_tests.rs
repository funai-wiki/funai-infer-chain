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

//! Integration tests for inference transactions
//! 
//! These tests verify the behavior of inference transactions in various scenarios:
//! - Single successful inference transaction
//! - Single failing inference transaction (empty output_hash)
//! - Multiple inference transactions with mixed success/failure
//! - Block processing with failed inference transactions

use clarity::vm::types::PrincipalData;
use funai::chainstate::funai::{FunaiPrivateKey, FunaiTransaction};
use funai_common::codec::FunaiMessageCodec;
use funai_common::types::chainstate::FunaiAddress;

use crate::tests::{
    make_failing_infer_tx, make_successful_infer_tx, make_infer_tx, to_addr, SK_1, SK_2, SK_3,
};

/// Test helper: create a node principal for testing
fn test_node_principal() -> PrincipalData {
    let sk = FunaiPrivateKey::from_hex(SK_2).unwrap();
    PrincipalData::Standard(to_addr(&sk).into())
}

/// Test: Verify that a failing inference transaction (empty output_hash) 
/// can be created and serialized correctly
#[test]
fn test_create_failing_infer_tx() {
    let sender_sk = FunaiPrivateKey::from_hex(SK_1).unwrap();
    let node_principal = test_node_principal();
    
    let tx_bytes = make_failing_infer_tx(
        &sender_sk,
        0,      // nonce
        1000,   // tx_fee
        50000,  // amount
        "What is 2+2?",
        "math context",
        &node_principal,
        "gpt-4",
    );
    
    // Verify transaction can be deserialized
    let tx = FunaiTransaction::consensus_deserialize(&mut &tx_bytes[..])
        .expect("Failed to deserialize failing infer tx");
    
    // Verify it's an Infer transaction
    let txid = tx.txid();
    match tx.payload {
        funai::chainstate::funai::TransactionPayload::Infer(
            _from, amount, _input, _context, _node, _model, ref output_hash
        ) => {
            assert_eq!(amount, 50000);
            // The output_hash should be empty (indicating failure)
            assert!(output_hash.to_string().is_empty(), "Output hash should be empty for failing tx");
        }
        _ => panic!("Expected Infer transaction payload"),
    }
    
    println!("Successfully created failing infer tx: {}", txid);
}

/// Test: Verify that a successful inference transaction (with output_hash) 
/// can be created and serialized correctly
#[test]
fn test_create_successful_infer_tx() {
    let sender_sk = FunaiPrivateKey::from_hex(SK_1).unwrap();
    let node_principal = test_node_principal();
    
    let tx_bytes = make_successful_infer_tx(
        &sender_sk,
        0,      // nonce
        1000,   // tx_fee
        50000,  // amount
        "What is 2+2?",
        "math context",
        &node_principal,
        "gpt-4",
    );
    
    // Verify transaction can be deserialized
    let tx = FunaiTransaction::consensus_deserialize(&mut &tx_bytes[..])
        .expect("Failed to deserialize successful infer tx");
    
    // Verify it's an Infer transaction with non-empty output_hash
    let txid = tx.txid();
    match tx.payload {
        funai::chainstate::funai::TransactionPayload::Infer(
            _from, amount, _input, _context, _node, _model, ref output_hash
        ) => {
            assert_eq!(amount, 50000);
            // The output_hash should NOT be empty (indicating success)
            assert!(!output_hash.to_string().is_empty(), "Output hash should not be empty for successful tx");
        }
        _ => panic!("Expected Infer transaction payload"),
    }
    
    println!("Successfully created successful infer tx: {}", txid);
}

/// Test: Create multiple infer transactions with mixed success/failure
#[test]
fn test_create_mixed_infer_txs() {
    let sender_sk = FunaiPrivateKey::from_hex(SK_1).unwrap();
    let node_principal = test_node_principal();
    
    // Create 3 successful and 2 failing transactions
    let mut txs = Vec::new();
    
    // Successful tx 1
    txs.push((
        "success_1",
        make_successful_infer_tx(&sender_sk, 0, 1000, 10000, "query1", "ctx1", &node_principal, "model1"),
    ));
    
    // Failing tx 1
    txs.push((
        "fail_1",
        make_failing_infer_tx(&sender_sk, 1, 1000, 20000, "query2", "ctx2", &node_principal, "model1"),
    ));
    
    // Successful tx 2
    txs.push((
        "success_2",
        make_successful_infer_tx(&sender_sk, 2, 1000, 30000, "query3", "ctx3", &node_principal, "model2"),
    ));
    
    // Failing tx 2
    txs.push((
        "fail_2",
        make_failing_infer_tx(&sender_sk, 3, 1000, 40000, "query4", "ctx4", &node_principal, "model2"),
    ));
    
    // Successful tx 3
    txs.push((
        "success_3",
        make_successful_infer_tx(&sender_sk, 4, 1000, 50000, "query5", "ctx5", &node_principal, "model3"),
    ));
    
    // Verify all transactions can be deserialized
    for (name, tx_bytes) in &txs {
        let tx = FunaiTransaction::consensus_deserialize(&mut &tx_bytes[..])
            .expect(&format!("Failed to deserialize tx: {}", name));
        println!("Created tx {}: {}", name, tx.txid());
    }
    
    println!("Successfully created {} mixed infer transactions", txs.len());
}

/// Test: Verify txid calculation is consistent for infer transactions
/// The txid should mask the node_principal and output_hash fields
#[test]
fn test_infer_tx_txid_masking() {
    let sender_sk = FunaiPrivateKey::from_hex(SK_1).unwrap();
    let node_principal_1 = test_node_principal();
    
    // Create a different node principal
    let sk3 = FunaiPrivateKey::from_hex(SK_3).unwrap();
    let node_principal_2 = PrincipalData::Standard(to_addr(&sk3).into());
    
    // Create two transactions with different node_principal but same other fields
    let tx_bytes_1 = make_infer_tx(
        &sender_sk, 0, 1000, 50000,
        "same query", "same context",
        &node_principal_1, "same_model",
        "hash1",
    );
    
    let tx_bytes_2 = make_infer_tx(
        &sender_sk, 0, 1000, 50000,
        "same query", "same context",
        &node_principal_2, "same_model",
        "hash2",  // Different hash
    );
    
    let tx1 = FunaiTransaction::consensus_deserialize(&mut &tx_bytes_1[..]).unwrap();
    let tx2 = FunaiTransaction::consensus_deserialize(&mut &tx_bytes_2[..]).unwrap();
    
    // The txids should be the same because node_principal and output_hash are masked
    assert_eq!(
        tx1.txid(), tx2.txid(),
        "Txids should be equal when only node_principal and output_hash differ"
    );
    
    println!("Txid masking works correctly: {}", tx1.txid());
}

// ============================================================================
// Integration tests that require a running node (marked with #[ignore])
// Run these with: cargo test --package funai-node --test '*' -- --ignored
// ============================================================================

/// Integration test: Submit multiple infer transactions to a mocknet node
/// and verify that failing ones are handled correctly
#[test]
#[ignore]
fn integration_test_mixed_infer_txs_in_block() {
    // This test requires a running mocknet node
    // TODO: Implement full integration test with node setup
    
    // Expected behavior:
    // 1. Submit 3 successful + 2 failing infer transactions
    // 2. All 5 transactions should be included in a block
    // 3. Successful transactions should:
    //    - Transfer 90% of amount to node_principal
    //    - Transfer 10% of amount to miner
    // 4. Failing transactions should:
    //    - NOT transfer any amount
    //    - Have vm_error set in the receipt
    //    - Still be included in the block
    
    println!("Integration test placeholder - requires mocknet node");
}
