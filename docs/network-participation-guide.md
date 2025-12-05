# Stacks Network Participation Guide

This document provides detailed instructions on how four roles (Miner, Signer, User, Infer Node) can join the Stacks network and participate in the entire process.

---

## Table of Contents

1. [Miner](#1-miner)
2. [Signer](#2-signer)
3. [User](#3-user)
4. [Infer Node](#4-infer-node)
5. [Network Interaction Flow](#5-network-interaction-flow)
6. [Common Issues](#6-common-issues)
7. [Security Recommendations](#7-security-recommendations)
8. [Monitoring and Maintenance](#8-monitoring-and-maintenance)
9. [Summary](#9-summary)
10. [Reference Resources](#10-reference-resources)
11. [Core Code for Blockchain and AI Integration](#11-core-code-for-blockchain-and-ai-integration)

---

## 1. Miner

### 1.1 Role Responsibilities

- Package transactions into blocks
- Process inference transactions (Infer transactions)
- Collaborate with Signer for block signing
- Maintain blockchain state

### 1.2 Prerequisites

- **Hardware Requirements**:
  - CPU: At least 4 cores
  - Memory: At least 4GB
  - Disk: At least 1TB (for blockchain data)
  - Network: Stable internet connection

- **Software Requirements**:
  - Linux operating system (Ubuntu 20.04+ recommended)
  - Rust toolchain
  - Bitcoin node (main chain)
  - Node.js and npm (for Stacks CLI)

### 1.3 Installation Steps

#### Step 1: Install Dependencies

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y build-essential jq netcat nodejs git autoconf \
  libboost-system-dev libboost-filesystem-dev libboost-thread-dev \
  libboost-chrono-dev libevent-dev libzmq5 libtool m4 automake pkg-config

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup component add rustfmt
```

#### Step 2: Install Bitcoin Node

```bash
# Clone Bitcoin source code (FunAI branch)
git clone --depth 1 --branch funai https://github.com/funai-wiki/bitcoin.git /tmp/mainchain
cd /tmp/mainchain

# Compile and install
sh contrib/install_db4.sh .
./autogen.sh
export BDB_PREFIX="/tmp/bitcoin/db4"
./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" \
  BDB_CFLAGS="-I${BDB_PREFIX}/include" \
  --disable-gui-tests --enable-static --without-miniupnpc \
  --with-pic --enable-cxx \
  --with-boost-libdir=/usr/lib/x86_64-linux-gnu
make -j2
sudo make install
```

#### Step 3: Configure Bitcoin Node

```bash
# Create configuration directory
sudo mkdir -p /etc/mainchain
sudo mkdir -p /main-chain

# Create configuration file
sudo bash -c 'cat <<EOF> /etc/mainchain/mainchain.conf
server=1
datadir=/main-chain
rpcuser=mainchainuser
rpcpassword=mainchainpass
rpcallowip=0.0.0.0/0
bind=0.0.0.0:8333
rpcbind=0.0.0.0:8332
dbcache=512
banscore=1
rpcthreads=256
rpcworkqueue=256
rpctimeout=100
txindex=1
EOF'

# Create user and permissions
sudo useradd mainchain
sudo chown -R mainchain:mainchain /main-chain/

# Create systemd service
sudo bash -c 'cat <<EOF> /etc/systemd/system/mainchain.service
[Unit]
Description=Mainchain daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/mainchaind -daemon \
  -pid=/run/mainchaind/mainchaind.pid \
  -conf=/etc/mainchain/mainchain.conf
Type=forking
PIDFile=/run/mainchaind/mainchaind.pid
Restart=on-failure
TimeoutStopSec=600
User=mainchain
Group=mainchain
RuntimeDirectory=mainchaind
RuntimeDirectoryMode=0710
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF'

# Start service
sudo systemctl daemon-reload
sudo systemctl enable mainchain.service
sudo systemctl start mainchain.service
```

#### Step 4: Install Stacks CLI

```bash
# Clone Stacks.js
git clone --depth 1 --branch funai https://github.com/funai-wiki/stacks.js.git /tmp/stacks_cli
cd /tmp/stacks_cli

# Install dependencies and build
npm install -g lerna
npm run build
```

#### Step 5: Generate Key Pair

```bash
# Generate key pair (save the output!)
cd /tmp/stacks_cli
./node_modules/.bin/stx make_keychain 2>/dev/null | jq

# Output example:
# {
#   "mnemonic": "...",
#   "keyInfo": {
#     "privateKey": "a1c7d36e014ef2e3e7c7f63adcd373bf289f352371b9cf8daee8a6fa9f2d4f5601",
#     "publicKey": "02968cbc30be49e82706907ec63042f66f17882536db1a7700fd35ef6fce402234",
#     "address": "SP2ZMFRFWCD0MWQZVSV8CCHB44M1C0EFSYD3VA2BV",
#     "btcAddress": "1JSQB9BqYMpPrSXPDBn95bA5MHWkGH4K9R",
#     "wif": "L2eC3LwxyUatyugxLjivwwvjrfTSRfnokzHzLyyaeCyyQTeNXVHE",
#     "index": 0
#   }
# }
```

**Important**: Save the `privateKey`, `btcAddress`, and `wif` values!

#### Step 6: Configure Bitcoin Wallet

```bash
# Create wallet
curl --user mainchainuser:mainchainpass \
  --data-binary '{"jsonrpc": "2.0", "id": "curltest", "method": "createwallet", \
  "params": {"wallet_name":"miner","avoid_reuse":true,"descriptors":false,"load_on_startup":true}}' \
  -H 'content-type: application/json' http://localhost:8332/

# Restart service
sudo systemctl restart mainchain

# Import key (replace <btcAddress> and <wif>)
mainchain-cli -rpcconnect=localhost -rpcport=8332 \
  -rpcuser=mainchainuser -rpcpassword=mainchainpass \
  importmulti '[{ "scriptPubKey": { "address": "<btcAddress>" }, \
  "timestamp":"now", "keys": [ "<wif>" ]}]' '{"rescan": true}'

# Verify import
mainchain-cli -rpcconnect=localhost -rpcport=8332 \
  -rpcuser=mainchainuser -rpcpassword=mainchainpass \
  getaddressinfo <btcAddress>
```

**Note**: You need to fund this Bitcoin address to pay for mining fees.

#### Step 7: Build Stacks Node

```bash
# Clone source code
git clone https://github.com/funai-wiki/stacks-core.git $HOME/infer-chain
cd $HOME/infer-chain/testnet/stacks-node

# Build
cargo build --features monitoring_prom,slog_json --release --bin infer-node

# Install
sudo cp -a $HOME/infer-chain/target/release/infer-node /usr/local/bin/infer-node
```

#### Step 8: Configure Miner

```bash
# Create configuration directory
sudo mkdir -p /etc/infer-chain
sudo mkdir -p /infer-chain

# Create configuration file (replace <privateKey> and <bootstrap_node>)
sudo bash -c 'cat <<EOF> /etc/infer-chain/miner.toml
[node]
working_dir = "/infer-chain"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
bootstrap_node = "<bootstrap_node>"
seed = "<privateKey>"
local_peer_seed = "<privateKey>"
miner = true
mine_microblocks = true
wait_time_for_microblocks = 10000
miner_endpoint = "http://127.0.0.1:20443"

[burnchain]
chain = "bitcoin"
mode = "mainnet"
peer_host = "127.0.0.1"
username = "mainchainuser"
password = "mainchainpass"
rpc_port = 8332
peer_port = 8333
wallet_name = "miner"

[connection_options]
block_proposal_token = "123456"

[miner]
first_attempt_time_ms = 5000
subsequent_attempt_time_ms = 180000
microblock_attempt_time_ms = 30000
mining_key = "<privateKey>"

[fee_estimation]
cost_estimator = "naive_pessimistic"
fee_estimator = "scalar_fee_rate"
cost_metric = "proportion_dot_product"
log_error = true
enabled = true
EOF'
```

#### Step 9: Configure Signer Event Listening (Optional, required for Nakamoto mode)

```bash
# If running in Nakamoto mode, add event listening configuration
sudo bash -c 'cat <<EOF>> /etc/infer-chain/miner.toml
[[events_observer]]
endpoint = "127.0.0.1:30000"
retry_count = 255
include_data_events = false
events_keys = ["*","stackerdb","block_proposal"]
EOF'
```

#### Step 10: Create systemd Service

```bash
# Create user
sudo useradd infer
sudo chown -R infer:infer /infer-chain/

# Create service file
sudo bash -c 'cat <<EOF> /etc/systemd/system/infer.service
[Unit]
Description=Stacks Blockchain Miner
Requires=mainchain.service
After=mainchain.service
ConditionFileIsExecutable=/usr/local/bin/infer-node
ConditionPathExists=/infer-chain/

[Service]
ExecStart=/bin/sh -c "/usr/local/bin/infer-node start --config=/etc/infer-chain/miner.toml >> /infer-chain/miner.log 2>&1"
ExecStartPost=/bin/sh -c "umask 022; sleep 2 && pgrep -f \"/usr/local/bin/infer-node start --config=/etc/infer-chain/miner.toml\" > /run/infer-chain/infer.pid"
ExecStopPost=/bin/sh -c "if [ -f \"/run/infer-chain/infer.pid\" ]; then rm -f /run/infer-chain/infer.pid; fi"
Type=simple
PIDFile=/run/infer-chain/infer.pid
Restart=on-failure
TimeoutStopSec=600
KillSignal=SIGTERM
User=infer
Group=infer
RuntimeDirectory=infer-chain
RuntimeDirectoryMode=0710
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF'

# Start service
sudo systemctl daemon-reload
sudo systemctl enable infer.service
sudo systemctl start infer.service
```

#### Step 11: Verify Running Status

```bash
# View logs
sudo tail -f /infer-chain/miner.log

# Check service status
sudo systemctl status infer.service

# Check RPC connection
curl http://localhost:20443/v2/info
```

### 1.4 Participation Flow

1. **Sync Blockchain**: Miner automatically syncs to the latest block after startup
2. **Receive Transactions**: Receive transactions from mempool, including inference transactions
3. **Process Inference Transactions**: 
   - Receive user inference requests
   - Submit tasks to local LLM service (if configured)
   - Wait for inference results
4. **Package Blocks**: Package transactions into blocks
5. **Collaborate with Signer**: In Nakamoto mode, Signer signature is required to produce blocks
6. **Submit Blocks**: Submit signed blocks to the network

---

## 2. Signer

### 2.1 Role Responsibilities

- Participate in Distributed Key Generation (DKG)
- Sign blocks and transactions
- Verify inference results
- Maintain StackerDB state

### 2.2 Prerequisites

- **Hardware Requirements**:
  - CPU: At least 2 cores
  - Memory: At least 2GB
  - Disk: At least 10GB

- **Software Requirements**:
  - Rust toolchain
  - Connection to Stacks node
  - Stacked STX (become a Stacker)

### 2.3 Installation Steps

#### Step 1: Stack STX

Before becoming a Signer, you must first Stack STX:

```bash
# Use Stacks CLI to Stack STX
cd /tmp/stacks_cli
./node_modules/.bin/stx stack <stx_amount> <cycle_length> <btcAddress> <privateKey>

# Example:
./node_modules/.bin/stx stack 1000000000 1 1JSQB9BqYMpPrSXPDBn95bA5MHWkGH4K9R \
  a1c7d36e014ef2e3e7c7f63adcd373bf289f352371b9cf8daee8a6fa9f2d4f5601
```

**Description**:
- `stx_amount`: Amount of STX to Stack (micro-STX, 1 STX = 1,000,000 micro-STX)
- `cycle_length`: Stack cycle length (usually 1)
- `btcAddress`: Bitcoin address
- `privateKey`: Stacks private key

#### Step 2: Build Signer

```bash
# Enter signer directory
cd $HOME/infer-chain/stacks-signer

# Build
cargo build --release --bin infer-signer

# Install (optional)
sudo cp target/release/infer-signer /usr/local/bin/infer-signer
```

#### Step 3: Configure Signer

```bash
# Create configuration file (replace corresponding values)
sudo bash -c 'cat <<EOF> /etc/infer-chain/signer.toml
# Stacks node address
node_host = "127.0.0.1:20443"

# Signer event receiving endpoint
endpoint = "0.0.0.0:30000"

# Network type: mainnet or testnet
network = "mainnet"

# Database path
db_path = "/etc/infer-chain/signer.db"

# Authentication password (same as block_proposal_token in miner.toml)
auth_password = "123456"

# Stacks private key (same as used when Stacking)
stacks_private_key = "<privateKey>"

# Supported model list (for inference verification)
support_models = ["deepseek", "llama"]
EOF'
```

#### Step 4: Start Signer

```bash
# Run directly
STACKS_LOG_INFO=1 /usr/local/bin/infer-signer run --config /etc/infer-chain/signer.toml

# Or run in background with nohup
STACKS_LOG_INFO=1 nohup /usr/local/bin/infer-signer run \
  --config /etc/infer-chain/signer.toml >> /etc/infer-chain/signer.log 2>&1 &
```

#### Step 5: Create systemd Service (Optional)

```bash
sudo bash -c 'cat <<EOF> /etc/systemd/system/infer-signer.service
[Unit]
Description=Stacks Signer
After=network.target

[Service]
ExecStart=/usr/local/bin/infer-signer run --config /etc/infer-chain/signer.toml
Restart=on-failure
RestartSec=10
User=infer
Group=infer

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl daemon-reload
sudo systemctl enable infer-signer.service
sudo systemctl start infer-signer.service
```

### 2.4 Participation Flow

1. **Register to Reward Cycle**: 
   - Signer automatically detects current reward cycle
   - If STX is Stacked, automatically registers to reward set

2. **Participate in DKG (Distributed Key Generation)**:
   - Collaborate with other Signers to generate aggregate public key
   - Gain signing capability after DKG completion

3. **Receive Block Proposals**:
   - Receive block proposal events from Miner
   - Verify transactions in blocks (including inference transactions)

4. **Verify Inference Results**:
   - For inference transactions, call local inference service to verify results
   - Use signatures to verify the legitimacy of inference requests

5. **Sign Blocks**:
   - If verification passes, sign the block
   - Send signature back to Miner

6. **Maintain State**:
   - Regularly update state in StackerDB
   - Synchronize with other Signers

---

## 3. User

### 3.1 Role Responsibilities

- Submit inference requests
- Pay inference fees
- Query inference results

### 3.2 Prerequisites

- **Software Requirements**:
  - Node.js and npm
  - Stacks CLI (stx)
  - Connection to Stacks network node (can be a public node)

- **Account Requirements**:
  - Own STX tokens (for paying transaction fees)
  - Own Stacks address and private key

### 3.3 Installation Steps

#### Step 1: Install Stacks CLI

```bash
# Clone Stacks.js
git clone --depth 1 --branch funai https://github.com/funai-wiki/stacks.js.git $HOME/stacks_cli
cd $HOME/stacks_cli

# Install dependencies and build
npm install -g lerna
npm run build
```

#### Step 2: Generate or Import Keys

```bash
# Generate new key pair
cd $HOME/stacks_cli
./node_modules/.bin/stx make_keychain 2>/dev/null | jq

# Or use existing private key (if available)
# Private key format: 64 or 65 byte hexadecimal string
```

**Save the `privateKey` and `address` from the output!**

#### Step 3: Obtain STX Tokens

- Purchase STX from exchanges
- Get from faucet (testnet)
- Earn as block rewards as a Miner

### 3.4 Usage Flow

#### Submit Inference Request

```bash
# Use stx infer command to submit inference request
cd $HOME/stacks_cli
./node_modules/.bin/stx infer \
  --address <your_stacks_address> \
  --userInput "Is the Earth round?" \
  --context "{}" \
  --fee <fee_in_microstx> \
  --nonce <nonce> \
  --payment_key <your_private_key> \
  -I "http://<node_host>:20443"

# Example:
./node_modules/.bin/stx infer \
  --address SP2ZMFRFWCD0MWQZVSV8CCHB44M1C0EFSYD3VA2BV \
  --userInput "Is the Earth round?" \
  --context "{}" \
  --fee 206 \
  --nonce 0 \
  --payment_key a1c7d36e014ef2e3e7c7f63adcd373bf289f352371b9cf8daee8a6fa9f2d4f5601 \
  -I "http://34.143.166.224:20443"
```

**Parameter Description**:
- `--address`: Your Stacks address
- `--userInput`: Inference question/prompt
- `--context`: Context information (JSON format string)
- `--fee`: Transaction fee (micro-STX)
- `--nonce`: Transaction nonce (obtain from account information)
- `--payment_key`: Your private key
- `-I`: Stacks node RPC address

#### Query Account Information

```bash
# Query account balance and nonce
curl http://<node_host>:20443/v2/accounts/<your_address>

# Or use stx command
./node_modules/.bin/stx balance <your_address> -I http://<node_host>:20443
```

#### Query Inference Results

```bash
# Query inference results via RPC
curl http://<node_host>:20443/v2/infer_result/<txid>

# Or use stx command (if supported)
```

### 3.5 Complete Workflow

1. **Preparation Phase**:
   - Install Stacks CLI
   - Generate or import key pair
   - Obtain STX tokens

2. **Query Account Status**:
   ```bash
   curl http://<node_host>:20443/v2/accounts/<your_address>
   ```
   - Get current balance
   - Get current nonce

3. **Submit Inference Request**:
   ```bash
   ./node_modules/.bin/stx infer \
     --address <address> \
     --userInput "Your question" \
     --context "{}" \
     --fee <fee> \
     --nonce <nonce> \
     --payment_key <private_key> \
     -I "http://<node_host>:20443"
   ```
   - Returns transaction ID (txid)

4. **Wait for Processing**:
   - Transaction enters mempool
   - Miner packages transaction
   - Infer Node processes inference
   - Signer verifies results

5. **Query Results**:
   ```bash
   curl http://<node_host>:20443/v2/infer_result/<txid>
   ```
   - Check status: Created, InProgress, Success, Failure
   - Get inference output (if successful)

---

## 4. Infer Node

### 4.1 Role Responsibilities

- Run Large Language Models (LLM)
- Process inference requests
- Return inference results
- Communicate with Miner and Signer

### 4.2 Prerequisites

- **Hardware Requirements**:
  - GPU: NVIDIA GPU (4090 or higher recommended)
  - VRAM: At least 16GB (depends on model size)
  - CPU: Multi-core CPU
  - Memory: At least 32GB
  - Disk: At least 100GB (for model files)

- **Software Requirements**:
  - CUDA toolkit
  - Python 3.8+
  - PyTorch or other deep learning frameworks
  - Model files (such as Llama, DeepSeek, etc.)

### 4.3 Installation Steps

#### Step 1: Install CUDA and Python Environment

```bash
# Install CUDA (according to your GPU and system version)
# Refer to NVIDIA official documentation

# Install Python and pip
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv

# Create virtual environment
python3 -m venv ~/infer-env
source ~/infer-env/bin/activate
```

#### Step 2: Install Inference Service Dependencies

```bash
# Install PyTorch (select according to CUDA version)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# Install other dependencies
pip install transformers accelerate sentencepiece
pip install fastapi uvicorn
pip install requests
```

#### Step 3: Download Model

```bash
# Create model directory
mkdir -p ~/models

# Download model (using Llama as example)
# Note: Need to download model from Hugging Face or other sources
# Ensure sufficient disk space
```

#### Step 4: Create Inference Service

Create `~/infer-service.py`:

```python
#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import uvicorn
import os
from k256 import ecdsa
import hashlib
import time
import json

app = FastAPI()

# Load model
MODEL_PATH = os.getenv("MODEL_PATH", "~/models/llama-7b")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    torch_dtype=torch.float16,
    device_map="auto"
)

# Private key (obtained from environment variable, used for signing responses)
PRIVATE_KEY = os.getenv("STX_PRIVATE_KEY", "")

class GenerateRequest(BaseModel):
    prompt: str

class GenerateResponse(BaseModel):
    text: str
    first_top_logprobs: list = []

@app.post("/generate")
async def generate(request: GenerateRequest, 
                   x_address: str = None,
                   x_signature: str = None,
                   x_timestamp: str = None):
    """
    Process inference request
    
    If signature headers are provided, verify signature
    """
    # Verify signature (if provided)
    if x_address and x_signature and x_timestamp:
        # Signature verification logic
        # ...
        pass
    
    # Execute inference
    inputs = tokenizer(request.prompt, return_tensors="pt").to(model.device)
    
    with torch.no_grad():
        outputs = model.generate(
            inputs.input_ids,
            max_length=512,
            temperature=0.7,
            do_sample=True,
            top_p=0.9
        )
    
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Extract top logprobs (for verification)
    # ...
    
    return GenerateResponse(
        text=generated_text,
        first_top_logprobs=[]
    )

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

#### Step 5: Configure Environment Variables

```bash
# Create environment variable file
cat <<EOF> ~/.infer-env
export MODEL_PATH=~/models/llama-7b
export STX_PRIVATE_KEY=<your_private_key>
export CUDA_VISIBLE_DEVICES=0
EOF

source ~/.infer-env
```

#### Step 6: Start Inference Service

```bash
# Activate virtual environment
source ~/infer-env/bin/activate

# Start service
python3 ~/infer-service.py

# Or run in background with nohup
nohup python3 ~/infer-service.py >> ~/infer-service.log 2>&1 &
```

#### Step 7: Create systemd Service (Optional)

```bash
sudo bash -c 'cat <<EOF> /etc/systemd/system/infer-node.service
[Unit]
Description=Inference Node Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME
EnvironmentFile=$HOME/.infer-env
ExecStart=$HOME/infer-env/bin/python3 $HOME/infer-service.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl daemon-reload
sudo systemctl enable infer-node.service
sudo systemctl start infer-node.service
```

### 4.4 Register to Network

#### Method 1: Auto-discovery via Miner

If Miner is configured with inference service endpoint, it will automatically discover locally running inference nodes.

#### Method 2: Register via API

```bash
# Register inference node to Miner
curl -X POST http://<miner_host>:20443/api/v1/inference/nodes/register \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "node-001",
    "endpoint": "http://<your_ip>:8000",
    "public_key": "<your_public_key>",
    "supported_models": ["llama", "deepseek"],
    "performance_score": 0.95
  }'
```

### 4.5 Participation Flow

1. **Start Service**:
   - Load model to GPU
   - Start HTTP service (port 8000)

2. **Receive Inference Requests**:
   - Miner or Signer sends inference requests
   - Requests contain `prompt` and optional signature information

3. **Verify Request** (if signature provided):
   - Verify `X-Address`, `X-Signature`, `X-Timestamp` headers
   - Ensure request comes from legitimate source

4. **Execute Inference**:
   - Use model to generate response
   - Calculate top logprobs (for verification)

5. **Return Results**:
   - Return generated text
   - Return top logprobs (for Signer verification)

6. **Heartbeat Maintenance**:
   - Regularly send heartbeat to Miner
   - Report node status and performance

---

## 5. Network Interaction Flow

### 5.1 Complete Inference Flow

```
User → Miner → Infer Node → Signer → Miner → User
  |      |         |          |        |       |
  |      |         |          |        |       +-- Query results
  |      |         |          |        +-- Package results into block
  |      |         |          +-- Verify inference results
  |      |         +-- Execute inference
  |      +-- Receive transaction, assign task
  +-- Submit inference request
```

### 5.2 Detailed Steps

1. **User Submits Request**:
   - User uses `stx infer` command to submit inference request
   - Transaction enters Miner's mempool

2. **Miner Processing**:
   - Miner receives inference transaction
   - Assigns task to Infer Node (or processes locally)
   - Waits for inference results

3. **Infer Node Processing**:
   - Receives inference request (with signature verification)
   - Executes model inference
   - Returns results and verification information

4. **Signer Verification**:
   - Receives block proposal
   - Verifies inference transaction results
   - Calls local inference service for cross-verification
   - If verification passes, signs block

5. **Miner Produces Block**:
   - Collects sufficient Signer signatures
   - Submits block to network
   - Transaction is confirmed

6. **User Queries Results**:
   - User uses txid to query inference results
   - Gets final output

---

## 6. Common Issues

### 6.1 Miner Related Issues

**Q: Miner cannot connect to Bitcoin node**
- Check if Bitcoin node is running
- Verify RPC username and password
- Check firewall settings

**Q: Miner cannot produce blocks**
- Check if STX is Stacked (Nakamoto mode requires Signer)
- Verify Signer is running normally
- Check network connection

**Q: Querying stacker_set returns `PoXAnchorBlockRequired` error**
```json
{
  "err_msg": "Could not read reward set. Prepare phase may not have started for this cycle yet. Cycle = 23, Err = PoXAnchorBlockRequired",
  "response": "error"
}
```

This is a **normal state**, not an error. It indicates:
- The Prepare phase of the current reward cycle has not started yet
- Need to wait for PoX anchor block to be selected and confirmed
- In Nakamoto mode, each reward cycle requires an anchor block for initialization

**Solution**:
1. **Wait for Prepare phase to start**:
   - Prepare phase will start before the reward cycle begins
   - Need to wait for network to select and confirm anchor block

2. **Check current status**:
   ```bash
   # Query current reward cycle information
   curl http://127.0.0.1:20443/v2/pox/info
   
   # Query current block height
   curl http://127.0.0.1:20443/v2/info
   ```

3. **Check logs**:
   ```bash
   # View Miner logs, search for anchor block related information
   sudo tail -f /infer-chain/miner.log | grep -i "anchor"
   ```

4. **Wait for conditions to be met**:
   - Wait for sufficient Stackers to participate in PoX
   - Wait for network to select anchor block
   - Wait for Prepare phase to complete

**Note**: This error will appear in the following situations:
- Network just started, not enough PoX participants yet
- Current reward cycle has not entered Prepare phase yet
- Anchor block has not been selected and confirmed yet

This is a node waiting state, usually automatically resolved when the next reward cycle begins.

### 6.2 Signer Related Issues

**Q: Signer cannot register to reward cycle**
- Confirm STX is Stacked
- Check if Stack has taken effect
- Verify private key is correct
- If `PoXAnchorBlockRequired` is returned, need to wait for Prepare phase of current reward cycle to complete

**Q: Signer cannot verify inference results**
- Check if local inference service is running
- Verify `STX_PRIVATE_KEY` environment variable
- Check network connection

### 6.3 User Related Issues

**Q: Transaction rejected**
- Check if account balance is sufficient
- Verify nonce is correct
- Check if transaction fee is sufficient

**Q: Cannot query inference results**
- Confirm transaction has been confirmed
- Check if txid is correct
- Verify node RPC is accessible

### 6.4 Infer Node Related Issues

**Q: Inference service cannot start**
- Check if GPU and CUDA are correctly installed
- Verify model files exist
- Check if port 8000 is occupied

**Q: Slow inference speed**
- Check GPU usage
- Consider using quantized models
- Optimize batch size

### 6.5 PoX and Reward Cycle Related Issues

**Q: What is PoX Anchor Block?**

PoX (Proof of Transfer) Anchor Block is a special block that must be selected before each reward cycle begins in Nakamoto mode. It is used for:
- Initializing reward set
- Determining signer set
- Starting Prepare phase

**Q: What are the phases of reward cycle?**

Each reward cycle includes the following phases:
1. **Prepare Phase**:
   - Select anchor block
   - Calculate reward set
   - Initialize signer set
   - If this phase hasn't started yet, querying `stacker_set` will return `PoXAnchorBlockRequired`

2. **Reward Phase**:
   - Distribute rewards
   - Signers participate in signing
   - Miner needs Signer signatures to produce blocks

**Q: How to query current reward cycle status?**

```bash
# Query PoX information
curl http://127.0.0.1:20443/v2/pox/info

# Query stacker_set for specific cycle (if Prepare phase is completed)
curl http://127.0.0.1:20443/v2/stacker_set/<cycle_number>

# Query current node information
curl http://127.0.0.1:20443/v2/info
```

**Q: How to determine if Prepare phase is completed?**

1. **Via logs**:
   ```bash
   sudo tail -f /infer-chain/miner.log | grep -i "anchor\|prepare\|reward"
   ```
   Look for similar information:
   - "Anchor block selected"
   - "PoX reward set loaded"
   - "Prepare phase completed"

2. **Via API**:
   ```bash
   # If PoXAnchorBlockRequired is no longer returned, Prepare phase is completed
   curl http://127.0.0.1:20443/v2/stacker_set/<cycle_number>
   ```

3. **Check Signer logs**:
   ```bash
   tail -f /etc/infer-chain/signer.log | grep -i "reward\|cycle"
   ```

**Q: How long to wait?**

- **Normal situation**: Usually need to wait for current reward cycle to end, Prepare phase of next cycle to start
- **Network just started**: May need to wait multiple cycles until sufficient Stackers participate
- **Recommendation**: Regularly check logs and API to understand current status

---

## 7. Security Recommendations

1. **Private Key Security**:
   - Never share private keys
   - Use environment variables to store private keys
   - Regularly backup keys

2. **Network Security**:
   - Use firewall to restrict access
   - Use HTTPS (if possible)
   - Regularly update software

3. **Node Security**:
   - Run in isolated network
   - Use non-root user to run services
   - Regularly monitor logs

---

## 8. Monitoring and Maintenance

### 8.1 Log Viewing

```bash
# Miner logs
sudo tail -f /infer-chain/miner.log

# Signer logs
tail -f /etc/infer-chain/signer.log

# Infer Node logs
tail -f ~/infer-service.log
```

### 8.2 Health Checks

```bash
# Miner health check
curl http://localhost:20443/v2/info

# Infer Node health check
curl http://localhost:8000/health
```

### 8.3 Performance Monitoring

- Monitor CPU, memory, disk usage
- Monitor network bandwidth
- Monitor GPU usage (Infer Node)
- Monitor transaction processing speed

---

## 9. Summary

This document provides detailed instructions on how four roles can join the Stacks network:

- **Miner**: Responsible for packaging transactions and producing blocks
- **Signer**: Responsible for verifying and signing blocks
- **User**: Submits inference requests and queries results
- **Infer Node**: Executes actual inference computation

Each role has its specific responsibilities and configuration requirements. By following the steps in this document, you can successfully join the network and participate in the entire process.

---

## 10. Reference Resources

- [Stacks Official Documentation](https://docs.stacks.co)
- [FunAI Mining Guide](./funai-mining.md)
- [Stacks Signer README](../stacks-signer/README.md)
- [Inference Service Documentation](../stacks-signer/INFERENCE_SERVICE.md)

---

## 11. Core Code for Blockchain and AI Integration

This section specifically lists the key code locations for "Blockchain + AI Inference" integration, making it easy to jump directly to implementation details from the table of contents:

- **Off-chain LLM Inference and On-chain Task Status (`libllm`)**
  - `libllm/src/lib.rs`: Encapsulates local LLM inference interfaces (`infer` / `infer_check` / `random_question`), makes requests to local `http://127.0.0.1:8000/generate` service, and records the correspondence between each inference task and on-chain `txid` through SQLite (`infer_chain` / `query`, etc.).

- **Stacks Node Exposed Inference Result Query Interface**
  - `stackslib/src/net/api/getinferresult.rs`: Implements `/v2/infer_res/{txid}` HTTP API, wrapping inference results from `libllm` into standard RPC responses.
  - `stackslib/src/net/api/mod.rs`: Registers `RPCInferResultRequestHandler`, attaching inference result queries to the node's HTTP service.

- **Inference Transaction Execution Path in Blockchain**
  - `stackslib/src/chainstate/stacks/transaction.rs`: Defines inference-related transaction types (Infer transactions) and their processing logic entry points.
  - `stackslib/src/chainstate/stacks/miner.rs`: In the block production flow, checks inference task status (e.g., `InferTaskNotSuccess` branch), deciding whether to write inference results into blocks or reject transactions.

- **Signer and Inference Node Scheduling (AI Verification Layer)**
  - `stacks-signer/src/inference_service.rs`: Defines structures such as `InferTask`, `InferenceNode`, `InferenceService`, responsible for queuing, distribution, timeout control, and result write-back of inference tasks.
  - `stacks-signer/src/inference_api.rs`: Provides HTTP API between Miner/Signer and inference nodes (node registration, heartbeat, task claiming, result submission, statistics query, etc.), serving as the main interaction interface between blockchain and AI inference nodes.
  - `stacks-signer/src/signer.rs`, `stacks-signer/src/runloop.rs`: Triggers local inference verification in the block verification flow, binding Signer's signing authority with AI verification results.

- **Inference-Related Events and SDK Encapsulation**
  - `libsigner/src/events.rs`, `libsigner/src/libsigner.rs`: Define events and types such as `SubmitInferTask`, `InferModelType`, for reuse by Signer and upper-layer services.
  - `stacks-signer/src/client/stacks_client.rs`: Client encapsulation for Signer-side access to Stacks nodes (including inference-related RPC).
