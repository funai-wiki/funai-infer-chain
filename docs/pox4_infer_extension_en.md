# PoX-4 Contract Extension (Inference Node Registry & Stake)

> This extension is **appended** to the end of `pox-4.clar` without modifying any existing PoX-4 variables or functions, guaranteeing that historical on-chain state and Stacker logic remain untouched.  
> All new identifiers are prefixed with `infer-` / `INFER_`, and use a dedicated error-code range `u200–u209` to avoid namespace collisions.

---

## 1. New Features at a Glance
| Feature | Public Interfaces | Data Structures | Description |
|---------|-------------------|-----------------|-------------|
| Inference-node registration | `infer-register-node`, `infer-update-models` | `infer-nodes` | Node announces 33-byte pubkey and up to 10 supported model IDs |
| Node queries | `infer-get-node`, `infer-node-supports?` | — | Read-only helpers returning node info / model support |
| Task routing | `infer-submit-task` | `infer-tasks` | User → node mapping with model, fee and status (`INFER_STATUS_*`) |
| Lightweight staking | `infer-stake-stx`, `infer-increase-stake`, `infer-extend-lock`, `infer-unlock-stx` | `infer-stake`, `infer-total-staked` | Node locks STX as collateral; supports top-up, lock extension & unlock |

---

## 2. Key Parameters
| Constant | Default | Purpose |
|----------|---------|---------|
| `INFER_MIN_STAKE_USTX` | `u10000000` (100 STX) | Minimum stake amount |
| `INFER_MIN_LOCK_PERIOD` | `u2100` | Shortest lock period (≈1 PoX reward cycle) |
| `INFER_MAX_LOCK_PERIOD` | `12 × MIN_LOCK_PERIOD` | Longest lock period |
| `INFER_MAX_MODELS` | `u10` | Max models per node |

---

## 3. Compatibility & Safety
1. **State Isolation**  
   All new `define-map` / `define-data-var` names are unique; calls never touch original PoX-4 state.
2. **Error-code Isolation**  
   Original PoX codes are `< u100`; new module uniformly uses `u200+` to eliminate ambiguity.
3. **Upgrade Procedure**  
   Simply publish the updated `pox-4.clar` (with the appended code) at Epoch 2.4. Existing contract IDs and function signatures stay the same, so dApps and Stackers experience a seamless upgrade.

---

## 4. Interface Examples

### Node registration
```clarity
(infer-register-node 0x021234… (list 2 0x64656570 0x6c6c616d61))
```

### Task submission
```clarity
(infer-submit-task 0xdeadbeef0001 'STXYZ… 0x6c6c616d61 u1000000)
```

### Stake 200 STX for two cycles
```clarity
(infer-stake-stx 0x6e6f64652d6964 u20000000 (* u2 INFER_MIN_LOCK_PERIOD))
```

---

> With this extension, PoX-4 retains its original Stacking mission while natively supporting AI inference-node registration, task routing and economic collateral—providing a trusted on-chain foundation for Layer-2 inference services. 