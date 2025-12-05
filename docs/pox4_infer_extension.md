# PoX-4 合约扩展说明（Inference Node Registry & Stake）

> 本扩展直接追加到 `pox-4.clar` 末尾，不更改 **任何** 既有 PoX-4 变量或函数，确保链上历史状态和 Stackers 逻辑完全不受影响。  
> 新增代码全部使用 `infer-` / `INFER_` 前缀及独立错误码区段 `u200–u209`，与原命名空间隔离。

---

## 1. 新功能概览
| 功能 | 公共接口 | 数据结构 | 说明 |
|------|----------|----------|------|
| 推理节点注册 | `infer-register-node` `infer-update-models` | `infer-nodes` | 节点声明 33 字节公钥及支持模型列表（≤10） |
| 节点查询 | `infer-get-node` `infer-node-supports?` | — | 读接口，仅返回节点信息或模型支持与否 |
| 推理任务路由 | `infer-submit-task` | `infer-tasks` | 用户提交任务 → 绑定节点 / 模型 / 费用；记录状态枚举 `INFER_STATUS_*` |
| 质押（Stake） | `infer-stake-stx` `infer-increase-stake` `infer-extend-lock` `infer-unlock-stx` | `infer-stake`, `infer-total-staked` | 节点锁仓 STX 作为服务抵押；支持增加金额 / 延长锁期 / 到期解锁 |

---

## 2. 关键参数
| 常量 | 默认值 | 用途 |
|------|--------|------|
| `INFER_MIN_STAKE_USTX` | `u10000000` (100 STX) | 质押最小金额 |
| `INFER_MIN_LOCK_PERIOD` | `u2100` | 最短质押周期（≈1 PoX 奖励周期） |
| `INFER_MAX_LOCK_PERIOD` | `12 × MIN_LOCK_PERIOD` | 最长质押周期 |
| `INFER_MAX_MODELS` | `u10` | 节点可声明的模型数量上限 |

---

## 3. 兼容性与安全性
1. **状态隔离**  
   所有新增 `define-map` / `define-data-var` 与 PoX-4 原结构无重名，调用路径不会触及原有锁仓逻辑。
2. **错误码隔离**  
   原 PoX 错误码 `< u100`，新模块统一使用 `u200+`，避免歧义。
3. **升级部署**  
   仅需在 Epoch 2.4 发布更新后的 `pox-4.clar`（包含附加代码）。历史链状态与函数存根保持不变，调用旧接口的 dApp 与 Stacker 体验无感知升级。

---

## 4. 接口示例

### 节点注册
```clarity
(infer-register-node 0x021234… (list 2 0x64656570 0x6c6c616d61))
```

### 任务提交
```clarity
(infer-submit-task 0xdeadbeef0001 'STXYZ… 0x6c6c616d61 u1000000)
```

### 质押 200 STX，锁 2 个周期
```clarity
(infer-stake-stx 0x6e6f64652d6964 u20000000 (* u2 INFER_MIN_LOCK_PERIOD))
```

---

> 通过以上扩展，PoX-4 在保持原有 Stacking 职责的同时，原生支持 AI 推理节点的注册、任务路由与经济抵押，为二层推理服务提供了链上可信基础。 