<p align="left">
  <a href="https://github.com/funai-wiki/funai-infer-chain/blob/master/docs/resource/e6a63b32f7849.png">
    <img alt="FunAI" src="https://github.com/funai-wiki/funai-infer-chain/blob/bridge/docs/resource/e6a63b32f7849.png" width="250" />
  </a>
</p>

# FunAI InferChain

Overview

FUN AI is a decentralized peer-to-peer (P2P) AI-generated content (AIGC) computation system that eliminates reliance on centralized AI giants. It enables users to run open-source large models (e.g., Llama 3) on personal GPUs (e.g., NVIDIA 4090), ensuring privacy, low costs, and community participation. The system uses a two-layer architecture with Proof-of-Work (PoW) and Proof-of-Inference (POI) consensus mechanisms, powered by the $FAI token (21 million total supply, zero pre-mining).This project is built on FunAI network. 
 
 • Goal: Provide a fair, open AI network addressing privacy, cost, and manipulation issues.

Core Features

 • Decentralized P2P inference with privacy protection via blockchain and disk recycling.
 
 • Supports any open-source large model with multi-model compatibility.
 
 • Incentivizes participation with $FAI rewards for inference and verification nodes.

Architecture

 • Ledger Layer: Uses Bitcoin-style PoW for security and transaction recording.
 
 • Inference Layer: Employs POI with inference and verification nodes.
 
 • Communication: Enabled by the Clarity virtual machine.

Workflow

 • Users submit inference tasks; nodes process and broadcast results.
 
 • Inference nodes are elected via $FAI bids and verifiable random functions (VRF).
 
 • Verification nodes (top $FAI stakers) validate results and distribute rewards.

Incentives

 • Ledger Layer: 1.5 $FAI per block.
 
 • Inference Layer: 3.5 $FAI per block.
 
 • Rewards halve every 21 million blocks.

## Building

### 1. Download and install Rust

_For building on Windows, follow the rustup installer instructions at https://rustup.rs/._

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup component add rustfmt
```

- When building the [`master`](https://github.com/funai-wiki/funai-infer-chain/blob/master/) branch, ensure you are using the latest stable release:

```bash
rustup update
```

### 2. Clone the source repository:

```bash
git clone --depth=1 https://github.com/funai-wiki/funai-infer-chain.git
cd funai-infer-chain
```

### 3. Build the project

```bash
# Fully optimized release build
cargo build --release
# Faster but less optimized build. Necessary if < 16 GB RAM
cargo build --profile release-lite
```

_Note on building_: you may set `RUSTFLAGS` to build binaries for your native cpu:

```
RUSTFLAGS="-Ctarget-cpu=native"
```

or uncomment these lines in `./cargo/config`:

```
# [build]
# rustflags = ["-Ctarget-cpu=native"]
```

## Testing

**Run the tests:**

```bash
cargo test testnet  -- --test-threads=1
```

**Run all unit tests in parallel using [nextest](https://nexte.st/):**

_Warning, this typically takes a few minutes_

```bash
cargo nextest run
```

## Run the testnet

You can observe the state machine in action locally by running:

```bash
cd testnet/funai-node
cargo run --bin infer-node -- start --config ./conf/testnet-follower-conf.toml
```

_On Windows, many tests will fail if the line endings aren't `LF`. Please ensure that you are have git's `core.autocrlf` set to `input` when you clone the repository to avoid any potential issues. This is due to the Clarity language currently being sensitive to line endings._

Additional testnet documentation is available [here](./docs/testnet.md)

## Docker

### Build infer-node
- **Release-lite (recommended)**:
  ```bash
  docker build -t infer-node:latest -f Dockerfile .
  ```

### Build infer-signer
```bash
docker build -t infer-signer:latest -f Dockerfile.signer .
```

### Run infer-node
```bash
docker run -d \
  --name infer-node \
  -p 20443:20443 \
  -p 20444:20444 \
  -v /usr/local/data/llm_chain_local/testnet:/usr/local/data/llm_chain_local/testnet \
  infer-node:latest
```
- Default config in image: `/etc/infer-chain/fai-testnet-miner-conf.toml` (not_commit version copied).
- Env vars already set: `STACKS_LOG_INFO=1`, `BLOCKSTACK_DB_TRACE=0`.
- If you prefer storing data under home: `mkdir -p ~/infer-chain-data/node` then mount `-v ~/infer-chain-data/node:/usr/local/data/llm_chain_local/testnet`.

### Run infer-signer
```bash
docker run -d \
  --name infer-signer \
  -p 30000:30000 \
  -v /usr/local/data/llm_signer_local/testnet:/usr/local/data/llm_signer_local/testnet \
  infer-signer:latest
```
- Default config: `/etc/infer-chain/fai-testnet-signer-config.toml`; for persistence you can mount `~/infer-chain-data/signer:/usr/local/data/llm_signer_local/testnet`.

### Build tips
- Slow first build is normal; you can use BuildKit cache:
  ```
  mkdir -p .docker-cache
  docker buildx build --progress=plain \
    --cache-from type=local,src=.docker-cache \
    --cache-to   type=local,dest=.docker-cache,mode=max \
    -t infer-node:latest -f Dockerfile .
  ```
- Signer BuildKit cache example:
  ```
  mkdir -p .docker-cache
  docker buildx build --progress=plain \
    --cache-from type=local,src=.docker-cache \
    --cache-to   type=local,dest=.docker-cache,mode=max \
    -t infer-signer:latest -f Dockerfile.signer .
  ```
- For fastest iteration use `Dockerfile.dev` (no optimizations).

## FunAI Mining

Please refer to this document for mining: [funai-mining](https://github.com/funai-wiki/funai-infer-chain/blob/master/funai-mining.md)

## Release Process

The release process for the funai blockchain is [defined here](./docs/release-process.md)

## Copyright and License

The code and documentation copyright are attributed to funai.org.

This code is released under the [GPL v3 license](https://www.gnu.org/licenses/quick-guide-gplv3.en.html), and the docs are released under the [Creative Commons license](https://creativecommons.org/).
