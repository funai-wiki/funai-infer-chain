# Nakamoto Inference Reward Distribution

This document describes how block rewards (coinbase) and inference fees are distributed to inference nodes in the Nakamoto epoch, including the role of Signer validation.

## Overview

In Nakamoto, inference nodes earn rewards through two independent mechanisms:

1. **Immediate fee distribution** — A direct STX transfer from the user's `amount` at the time the Infer transaction is processed on-chain.
2. **Coinbase (block reward) distribution** — A share of the tenure's coinbase reward, scheduled when the next tenure begins and paid out after a maturity period.

Both mechanisms require that the inference was completed successfully (i.e., the transaction's `output_hash` is non-empty). Additionally, Signer validation acts as a gatekeeper *before* transactions reach the chain.

## Key Differences Between Epoch 2.0 and Nakamoto

| Aspect | Epoch 2.0 | Nakamoto |
|--------|-----------|----------|
| Blocks per tenure | 1 | Multiple |
| Coinbase location | Every block | Only the tenure-start block |
| Infer tx location | Same block as coinbase | Any block in the tenure |
| Coinbase scan scope | Current block only | Previous tenure's blocks + current tenure-start block |
| Block production speed | ~10 min (Bitcoin-bound) | Seconds (within a tenure) |

## Three Validation Gates

An Infer transaction must pass through three successive gates for the inference node to receive full rewards:

```
Gate 1: Signer Validation (off-chain, pre-signing)
  │
  ├── PASS → Transaction stays in the block
  └── FAIL → FILTER message sent; transaction removed from block if consensus reached
                → Node receives NOTHING (tx not on chain)

Gate 2: On-Chain Processing (output_hash check)
  │
  ├── output_hash non-empty → Immediate fee transfer executed
  │     → 90% of amount → inference node
  │     → 10% of amount → miner
  └── output_hash empty → No transfer; user loses only the tx fee
                → Node receives NOTHING from this tx

Gate 3: Coinbase Distribution (next tenure start)
  │
  ├── output_hash non-empty → Participates in coinbase split proportionally by amount
  └── output_hash empty → Excluded from coinbase split
```

## Gate 1: Signer Validation (Detail)

When a miner proposes a block containing Infer transactions, each Signer independently validates every Infer transaction through four checks:

### Check 1: Retrieve Inference Result
The Signer queries the miner's node for the inference result via `get_infer_res_with_retry()`. If the result cannot be retrieved, the transaction is marked invalid.

### Check 2: Node Principal Match
The `node_principal` in the transaction payload must match the `inference_node_id` returned in the inference result. A mismatch means the wrong node processed the request.

### Check 3: Inference Status
The inference result status must be `Success`. If the inference failed or timed out, the transaction is marked invalid.

### Check 4: Local Re-Inference and Token Overlap
This is the most critical check. The Signer:
1. Sends the same prompt to its local inference verifier
2. Compares the output tokens from its local result with the inference node's output tokens
3. Requires that the number of overlapping tokens ≥ `max(len_local, len_node) - 2`

This ensures the inference node produced a legitimate result consistent with what the model should output.

### Signer Response Behavior
- If all checks pass: the Signer votes to **accept** the block.
- If any check fails: the Signer sends a **FILTER** message listing the invalid transaction IDs, but **still votes to accept** the block (failed Infer txs do not block the entire block).
- If the Signer set reaches threshold consensus on a FILTER, the miner receives a `SignerFilterError`, removes the flagged transactions from the mempool, and **re-mines a new block** without them.

## Gate 2: Immediate Fee Distribution (Detail)

For each Infer transaction that makes it on-chain, the processing logic in `transactions.rs` checks the `output_hash` field in the transaction payload:

```
if output_hash is non-empty AND valid hex:
    status = Success
    → Transfer 90% of amount from user to node_principal
    → Transfer 10% of amount from user to miner
else:
    status = Failure
    → No transfers; return error receipt
    → User loses only the transaction fee
```

This check is **purely deterministic** — it only examines the `output_hash` string in the transaction payload. It does NOT re-run inference or contact any external service, ensuring consensus across all nodes.

## Gate 3: Coinbase (Block Reward) Distribution (Detail)

### When It Happens

Coinbase distribution is calculated in `calculate_scheduled_tenure_reward()` when a **new tenure begins**. At that point, the previous tenure is fully complete, so all its blocks and transactions are known.

### What Gets Scanned

The function scans for Infer transactions with non-empty `output_hash` in:
1. The **current tenure-start block** (which may contain Infer txs alongside the coinbase)
2. **All blocks from the previous tenure** (loaded via `get_all_blocks_in_tenure()` from the staging blocks DB)

### How the Coinbase Is Split

```
If qualifying Infer transactions are found:
    miner_share  = 10% of total_coinbase
    nodes_share  = 90% of total_coinbase

    For each qualifying Infer tx:
        node_reward = nodes_share × (tx.amount / total_infer_amount)

If no qualifying Infer transactions found:
    miner gets 100% of total_coinbase
```

Where `total_coinbase = base_coinbase_at_height + accumulated_rewards_from_missed_sortitions`.

### Maturity Period

Scheduled rewards do not pay out immediately. They mature after `MINER_REWARD_MATURITY` tenures (currently set to 2):

```
Tenure N:   Rewards scheduled → insert_miner_payment_schedule()
                               → insert_inference_payment_schedule() (for each node)
Tenure N+1: Waiting...
Tenure N+2: Tenure N's rewards mature and are paid out
```

### Fee Attribution

In Nakamoto, transaction fees are attributed with a one-tenure delay: the miner of Tenure N receives the accumulated transaction fees from Tenure N-1 (because Tenure N's total fees are unknown until it ends).

## Worked Example

### Setup

Tenure N contains 3 blocks with 5 Infer transactions:

| Block | Tx | amount | node | Signer Result | output_hash | On-Chain? |
|-------|-----|--------|------|---------------|-------------|-----------|
| B1 (start) | tx1 | 9,000,000 | Node_A | ✅ Pass | `"4dece1c6..."` | Yes |
| B2 | tx2 | 5,000,000 | Node_B | ❌ Token overlap insufficient | `"cc6de427..."` | **No** (FILTER removed) |
| B2 | tx3 | 3,000,000 | Node_A | ✅ Pass | `"a1b2c3d4..."` | Yes |
| B3 | tx4 | 7,000,000 | Node_C | ❌ Inference failed | `""` | Yes (but hash empty) |
| B3 | tx5 | 6,000,000 | Node_B | ✅ Pass | `"f5e6d7c8..."` | Yes |

### Immediate Fee Distribution (at block processing time)

| Tx | output_hash | Result |
|----|-------------|--------|
| tx1 | non-empty | Node_A receives 8,100,000 / Miner receives 900,000 |
| tx2 | removed from chain | Nothing |
| tx3 | non-empty | Node_A receives 2,700,000 / Miner receives 300,000 |
| tx4 | empty | **No transfer** — user loses tx fee only |
| tx5 | non-empty | Node_B receives 5,400,000 / Miner receives 600,000 |

### Coinbase Distribution (when Tenure N+1 starts)

Qualifying transactions (on-chain AND output_hash non-empty): tx1, tx3, tx5

```
total_infer_amount = 9,000,000 + 3,000,000 + 6,000,000 = 18,000,000
total_coinbase     = 1,000,000,000 (example)

miner_share = 10% = 100,000,000
nodes_share = 90% = 900,000,000

Node_A (tx1): 900,000,000 × 9,000,000 / 18,000,000 = 450,000,000
Node_A (tx3): 900,000,000 × 3,000,000 / 18,000,000 = 150,000,000
Node_B (tx5): 900,000,000 × 6,000,000 / 18,000,000 = 300,000,000
```

### Final Summary

| Participant | Immediate Fees | Coinbase Reward | Total |
|-------------|---------------|-----------------|-------|
| **Node_A** | 10,800,000 | 600,000,000 | **610,800,000** |
| **Node_B** | 5,400,000 | 300,000,000 | **305,400,000** |
| **Node_C** | 0 | 0 | **0** |
| **Miner** | 1,800,000 | 100,000,000 | **101,800,000** |

- **Node_A**: Two successful inferences → receives both immediate fees and the largest coinbase share.
- **Node_B**: tx2 was filtered by Signers (no rewards); tx5 passed → receives rewards for tx5 only.
- **Node_C**: Inference failed (empty output_hash) → receives nothing.
- **Miner**: Receives 10% of both immediate fees and coinbase.

## Source Code References

| Component | File | Function |
|-----------|------|----------|
| Coinbase calculation & split | `funailib/src/chainstate/nakamoto/tenure.rs` | `calculate_scheduled_tenure_reward()` |
| Inference payment schedule insertion | `funailib/src/chainstate/nakamoto/mod.rs` | `append_block()` (after `advance_tip`) |
| On-chain Infer tx processing | `funailib/src/chainstate/funai/db/transactions.rs` | `process_transaction()` (Infer arm) |
| Signer validation of Infer txs | `funai-signer/src/signer.rs` | `handle_block_validate_response()` and the Infer validation loop |
| Miner FILTER handling | `testnet/funai-node/src/nakamoto_node/miner.rs` | `run_tenure()` (SignerFilterError arm) |
| Miner address lookup (non-tenure-start) | `funailib/src/chainstate/nakamoto/mod.rs` | `append_block()` (staging DB lookup) |
| Reward maturity | `funailib/src/chainstate/nakamoto/tenure.rs` | `get_matured_miner_reward_schedules()` |
| All blocks in tenure query | `funailib/src/chainstate/nakamoto/staging_blocks.rs` | `get_all_blocks_in_tenure()` |
