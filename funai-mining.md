# Infer Blockchain Miner

## Prerequisites

### VM setup

The VM will not need a lot of resources to run a miner - the most resources will be consumed during blockchain sync. \
A single CPU system with at least 4GB of memory should be more than sufficient - as well as roughly 1TB of total disk space

**Note: `mainchainuser` and `mainchainpass` are used for bitcoin RPC auth in this doc. Change as appropriate**

1. Separate disks for chainstates and OS
    - mount a dedicated disk for bitcoin at `/main-chain` of 10GB
    - mount a dedicated disk for stacks-blockchain at `/infer-chain` of at least 10GB
    - root volume `/` of at least 25GB
2. Combined Disk for all data
    - root volume `/` of at least 25GB

```bash
$ sudo mkdir -p /main-chain
$ sudo mkdir -p /infer-chain
$ sudo mkdir -p /etc/main-chain
$ sudo mkdir -p /etc/infer-chain
```

### Install required packages

```bash
$ curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash -
$ sudo apt-get update -y && sudo apt-get install -y build-essential jq netcat nodejs git autoconf libboost-system-dev libboost-filesystem-dev libboost-thread-dev libboost-chrono-dev libevent-dev libzmq5 libtool m4 automake pkg-config libtool libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-program-options-dev libboost-test-dev libboost-thread-dev libboost-iostreams-dev
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source $HOME/.cargo/env
```

### If using mounted disks

mount the disks to each filesystem created above - edit `/etc/fstab` to automount these disks at boot.

```
/dev/xvdb1 /main-chain xfs rw,relatime,attr2,inode64,noquota
/dev/xvdc1 /infer-chain xfs rw,relatime,attr2,inode64,noquota
```

## Install Mainchain

Choose either method, but bitcoin is required here. Building from source ensures you know what code you are running, but will a while to compile.

### Source Install

```
$ git clone --depth 1 --branch funai https://github.com/funai-wiki/bitcoin.git /tmp/mainchain && cd /tmp/mainchain
$ sh contrib/install_db4.sh .
$ ./autogen.sh
$ export BDB_PREFIX="/tmp/bitcoin/db4" && ./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include" \
  --disable-gui-tests \
  --enable-static \
  --without-miniupnpc \
  --with-pic \
  --enable-cxx \
  --with-boost-libdir=/usr/lib/x86_64-linux-gnu
$ make -j2
$ sudo make install
```

### Mainchain Config

```
$ sudo bash -c 'cat <<EOF> /etc/mainchain/mainchain.conf
server=1
#disablewallet=1
datadir=/bitcoin
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
```

### Add mainchain user and configure dirs

```
$ sudo useradd mainchain
$ sudo chown -R mainchain:mainchain /mainchain/
```

### Install mainchain.service unit

```
$ sudo bash -c 'cat <<EOF> /etc/systemd/system/mainchain.service
[Unit]
Description=Mainchain daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/mainchaind -daemon \
                            -pid=/run/mainchaind/mainchaind.pid \
                            -conf=/etc/mainchain/mainchain.conf

# Process management
####################
Type=forking
PIDFile=/run/mainchaind/mainchaind.pid
Restart=on-failure
TimeoutStopSec=600
# Directory creation and permissions
####################################
# Run as mainchain:mainchain
User=mainchain
Group=mainchain
RuntimeDirectory=mainchaind
RuntimeDirectoryMode=0710
# Hardening measures
####################
# Provide a private /tmp and /var/tmp.
PrivateTmp=true
# Mount /usr, /boot/ and /etc read-only for the process.
ProtectSystem=full
# Deny access to /home, /root and /run/user
ProtectHome=true
# Disallow the process and all of its children to gain
# new privileges through execve().
NoNewPrivileges=true
# Use a new /dev namespace only populated with API pseudo devices
# such as /dev/null, /dev/zero and /dev/random.
PrivateDevices=true

[Install]
WantedBy=multi-user.target

EOF'
```

### Enable service and start mainchain

```
$ sudo systemctl daemon-reload
$ sudo systemctl enable mainchain.service
$ sudo systemctl start mainchain.service
```

**now we wait a few minutes until mainchain syncs to chain tip**

```
$ sudo tail -f /mainchain/debug.log
$ mainchain-cli \
  -rpcconnect=localhost \
  -rpcport=8332 \
  -rpcuser=mainchainuser \
  -rpcpassword=mainchainpass \
getblockchaininfo | jq .blocks
```

### Install Stacks CLI

```
$ git clone --depth 1 --branch funai https://github.com/funai-wiki/stacks.js.git /tmp/stacks_cli && cd /tmp/stacks_cli
$ npm install -g lerna
$ npm run build
```

It will generate the cli binary 'stx' in the dir ./node_modules/.bin

### Generate keychain

**save this output in a safe place!**

```bash
$ ./node_modules/.bin/stx make_keychain 2>/dev/null | jq
{
  "mnemonic": "banner best super roast chief nominee romance choice chef artefact shrug wave ritual brass vacuum witness fringe ticket install obvious coffee around aunt ice",
  "keyInfo": {
    "privateKey": "a1c7d36e014ef2e3e7c7f63adcd373bf289f352371b9cf8daee8a6fa9f2d4f5601",
    "publicKey": "02968cbc30be49e82706907ec63042f66f17882536db1a7700fd35ef6fce402234",
    "address": "SP2ZMFRFWCD0MWQZVSV8CCHB44M1C0EFSYD3VA2BV",
    "btcAddress": "1JSQB9BqYMpPrSXPDBn95bA5MHWkGH4K9R",
    "wif": "L2eC3LwxyUatyugxLjivwwvjrfTSRfnokzHzLyyaeCyyQTeNXVHE",
    "index": 0
  }
}
```

### Create mainchain wallet and import it into this instance

We'll be using the wallet values from the previous `npx` command, "btcAddress" and "wif"

```bash
$curl \
--user mainchainuser:mainchainpass \
--data-binary '{"jsonrpc": "2.0", "id": "curltest", "method": "createwallet", "params": {"wallet_name":"miner","avoid_reuse":true,"descriptors":false,"load_on_startup":true}}' \
-H 'content-type: application/json' http://localhost:8332/

$ sudo systemctl restart mainchain
$ mainchain-cli \
  -rpcconnect=localhost \
  -rpcport=8332 \
  -rpcuser=mainchainuser \
  -rpcpassword=mainchainpass \
importmulti '[{ "scriptPubKey": { "address": "<npx btcAddress>" }, "timestamp":"now", "keys": [ "<npx wif>" ]}]' '{"rescan": true}'
$ mainchain-cli \
  -rpcconnect=localhost \
  -rpcport=8332 \
  -rpcuser=mainchainuser \
  -rpcpassword=mainchainpass \
getaddressinfo <npx btcAddress>

```

Once imported, the wallet will need to be funded with some mainchain token.

## infer-chain

### Build and install infer-chain from source (via script)

```bash
$ cd $HOME && cat <<EOF> $HOME/build-stacks.sh
#!/bin/sh
CURDIR=\$(pwd)
DEST=/usr/local/bin/infer-node
GIT_DIR=\$HOME/infer-chain
if [ ! -d \${GIT_DIR} ]; then
  git clone https://github.com/funai-wiki/stacks-core.git \${GIT_DIR}
else
  git -C \${GIT_DIR} pull -r
fi
cd \${GIT_DIR}/testnet/infer-node
cargo build --features monitoring_prom,slog_json --release --bin infer-node
if [ "\$?" -eq "0" ]; then
  if [ -f \${DEST} ]; then
    sudo rm -f \${DEST}
  fi
  echo "Copying stacks-node to $DEST using sudo"
  sudo cp -a \${GIT_DIR}/target/release/infer-node \${DEST}
fi
cd \${CURDIR}
EOF
$ sh $HOME/build-stacks.sh
```

### Build and install infer-chain from source

```bash
$ git clone https://github.com/funai-wiki/stacks-core.git $HOME/infer-chain
$ cd $HOME/infer-chain/testnet/stacks-node
$ cargo build --features monitoring_prom,slog_json --release --bin infer-node
$ sudo cp -a $HOME/infer-chain/target/release/infer-node /usr/local/bin/infer-node
```

```bash
$ sudo bash -c 'cat <<EOF> /etc/infer-chain/follower.toml
[node]
working_dir = "/infer-chain"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
bootstrap_node = "03c830906d80795257ae211fac6ed786a131ec43f3b05e5efc8ce607a1a2c16b5b@34.143.166.224:20444"
miner_endpoint = "http://127.0.0.1:20443"

[burnchain]
chain = "bitcoin"
mode = "mainnet"
peer_host = "127.0.0.1"
username = "mainchainuser"
password = "mainchainpass"
rpc_port = 8332
peer_port = 8333
EOF'
```

**replace `seed` and `local_peer_seed` with the `privateKey` value from the previous `npx` command**

```bash
$ sudo bash -c 'cat <<EOF> /etc/infer-chain/miner.toml
[node]
working_dir = "/infer-chain"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
bootstrap_node = "03c830906d80795257ae211fac6ed786a131ec43f3b05e5efc8ce607a1a2c16b5b@34.143.166.224:20444"
seed = "<npx privateKey>"
local_peer_seed = "<npx privateKey>"
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
mining_key = "<npx privateKey>"

[fee_estimation]
cost_estimator = "naive_pessimistic"
fee_estimator = "scalar_fee_rate"
cost_metric = "proportion_dot_product"
log_error = true
enabled = true
EOF'
```

### Add infer user and configure dirs

```bash
$ sudo useradd infer
$ sudo chown -R infer:infer /infer-chain/
```

### Install infer.service unit

```bash
$ sudo bash -c 'cat <<EOF> /etc/systemd/system/infer.service
[Unit]
Description=Stacks Blockchain
Requires=mainchain.service
After=mainchain.service
ConditionFileIsExecutable=/usr/local/bin/infer-node
ConditionPathExists=/infer-chain/

[Service]
ExecStart=/bin/sh -c "/usr/local/bin/infer-node start --config=/etc/infer-chain/follower.toml >> /infer-chain/follower.log 2>&1"
ExecStartPost=/bin/sh -c "umask 022; sleep 2 && pgrep -f \"/usr/local/bin/infer-node start --config=/etc/infer-chain/follower.toml\" > /run/infer-chain/infer.pid"
ExecStopPost=/bin/sh -c "if [ -f \"/run/stacks-blockchain/infer.pid\" ]; then rm -f /run/infer-chain/infer.pid; fi"

# Process management
####################
Type=simple
PIDFile=/run/infer-chain/infer.pid
Restart=on-failure
TimeoutStopSec=600
KillSignal=SIGTERM

# Directory creation and permissions
####################################
# Run as mainchain:mainchain
User=infer
Group=infer
RuntimeDirectory=infer-chain
RuntimeDirectoryMode=0710

# Hardening measures
####################
# Provide a private /tmp and /var/tmp.
PrivateTmp=true
# Mount /usr, /boot/ and /etc read-only for the process.
ProtectSystem=full
# Deny access to /home, /root and /run/user
ProtectHome=true
# Disallow the process and all of its children to gain
# new privileges through execve().
NoNewPrivileges=true
# Use a new /dev namespace only populated with API pseudo devices
# such as /dev/null, /dev/zero and /dev/random.
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF'

```

### Enable service and start stacks

```
$ sudo systemctl daemon-reload
$ sudo systemctl enable infer.service
$ sudo systemctl start infer.service
```

### Deploy large models

Please refer to this document to deploy large models on stack-node nodes.

https://www.yuque.com/u28951601/at1c64/qfvoklw0ethwcbdg?singleDoc#

### Stack stx

Before becoming a stacker, you need to obtain STX by purchasing or being a miner. Stake STX through STX CLI to become a stacker and earn a layer of network tokens.

```
$./node_modules/.bin/stx stack <stx amount> <cycle length> <npx btcAddress> <npx privateKey>
e.g
$ stx stack 1000000000 1 1JSQB9BqYMpPrSXPDBn95bA5MHWkGH4K9R a1c7d36e014ef2e3e7c7f63adcd373bf289f352371b9cf8daee8a6fa9f2d4f5601
```

After stacking takes effect, you can run the stacker node as follows.

### Build infer-signer from source

```
$ cd stacks-core/stacks-signer
$ cargo build --release --bin infer-signer
$ sudo bash -c 'cat <<EOF> /etc/infer-chain/signer.toml
# The IP address and port where your Stacks node can be accessed.
# The port 20443 is the default RPC endpoint for Stacks nodes.
# Note that you must use an IP address - DNS hosts are not supported at this time.
# This should be the IP address accessible via Docker, usually via a network.
node_host = "127.0.0.1:20443"

# This is the location where the signer will expose an RPC endpoint for
# receiving events from your Stacks node.
endpoint = "0.0.0.0:30000"

# Either “testnet” or “mainnet”
network = "mainnet"

# this is a file path where your signer will persist data. If using Docker,
# this must be within a volume, so that data can be persisted across restarts
db_path = "/etc/infer-chain/signer.db"

# an authentication token that is used for some HTTP requests made from the
# signer to your Stacks node. You’ll need to use this later on when configur$ng
# your Stacks node. You create this field yourself, rather than it being generated
# with your private key.
auth_password = "<the block_proposal_token in the miner.toml>"

# This is the privateKey field from the keys you generated in the
# previous step.
stacks_private_key = "<npx privateKey>"
EOF'
$ STACKS_LOG_INFO=1 nohup ./target/release/infer-signer run --config /etc/infer-chain/signer.toml >> ./signer.log 2>&1 &
```

After the stacker node is running, you need to modify the miner configuration and restart it. 
This is because after nakamoto takes effect, subsequent blocks require the signature and verification of the stacker.

```
$ cat <<EOL>> /etc/infer-chain/miner.toml
[[events_observer]]
endpoint = "127.0.0.1:30000"
retry_count = 255
include_data_events = false
events_keys = ["*","stackerdb","block_proposal"]
EOL
$ systemctl restart infer.service
```

### Submit a infer transaction

```
$ stx infer --address SP2ZMFRFWCD0MWQZVSV8CCHB44M1C0EFSYD3VA2BV --userInput "Is the Earth round?" --context "{}" --fee 206 --nonce 0 --payment_key a1c7d36e014ef2e3e7c7f63adcd373bf289f352371b9cf8daee8a6fa9f2d4f5601 -I "http://34.143.166.224:20443"
```
