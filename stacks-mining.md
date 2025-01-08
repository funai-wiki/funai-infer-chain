# Stacks Blockchain Miner

## Prerequisites

### VM setup

The VM will not need a lot of resources to run a miner - the most resources will be consumed during blockchain sync. \
A single CPU system with at least 4GB of memory should be more than sufficient - as well as roughly 1TB of total disk space

**Note: `btcuser` and `btcpass` are used for bitcoin RPC auth in this doc. Change as appropriate**

1. Separate disks for chainstates and OS
    - mount a dedicated disk for bitcoin at `/bitcoin` of 10GB
    - mount a dedicated disk for stacks-blockchain at `/stacks-blockchain` of at least 10GB
    - root volume `/` of at least 25GB
2. Combined Disk for all data
    - root volume `/` of at least 25GB

```bash
$ sudo mkdir -p /bitcoin
$ sudo mkdir -p /stacks-blockchain
$ sudo mkdir -p /etc/bitcoin
$ sudo mkdir -p /etc/stacks-blockchain
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
/dev/xvdb1 /bitcoin xfs rw,relatime,attr2,inode64,noquota
/dev/xvdc1 /stacks-blockchain xfs rw,relatime,attr2,inode64,noquota
```

## Install Bitcoin

Choose either method, but bitcoin is required here. Building from source ensures you know what code you are running, but will a while to compile.

### Source Install

```
$ git clone --depth 1 --branch funai https://github.com/funai-wiki/bitcoin.git /tmp/bitcoin && cd /tmp/bitcoin
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

### Bitcoin Config

```
$ sudo bash -c 'cat <<EOF> /etc/bitcoin/bitcoin.conf
server=1
#disablewallet=1
datadir=/bitcoin
rpcuser=btcuser
rpcpassword=btcpass
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

### Add bitcoin user and configure dirs

```
$ sudo useradd bitcoin
$ sudo chown -R bitcoin:bitcoin /bitcoin/
```

### Install bitcoin.service unit

```
$ sudo bash -c 'cat <<EOF> /etc/systemd/system/bitcoin.service
[Unit]
Description=Bitcoin daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/bitcoind -daemon \
                            -pid=/run/bitcoind/bitcoind.pid \
                            -conf=/etc/bitcoin/bitcoin.conf

# Process management
####################
Type=forking
PIDFile=/run/bitcoind/bitcoind.pid
Restart=on-failure
TimeoutStopSec=600
# Directory creation and permissions
####################################
# Run as bitcoin:bitcoin
User=bitcoin
Group=bitcoin
RuntimeDirectory=bitcoind
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

### Enable service and start bitcoin

```
$ sudo systemctl daemon-reload
$ sudo systemctl enable bitcoin.service
$ sudo systemctl start bitcoin.service
```

**now we wait a few days until bitcoin syncs to chain tip**

```
$ sudo tail -f /bitcoin/debug.log
$ bitcoin-cli \
  -rpcconnect=localhost \
  -rpcport=8332 \
  -rpcuser=btcuser \
  -rpcpassword=btcpass \
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
  "mnemonic": "frown lens very suit ocean trigger animal flip retire dose various mobile record emerge torch client sorry shy party session until planet member exclude",
  "keyInfo": {
    "privateKey": "ooxeemeitar4ahw0ca8anu4thae7aephahshae1pahtae5oocahthahho4ahn7eici",
    "address": "STTXOG3AIHOHNAEH5AU6IEX9OOTOH8SEIWEI5IJ9",
    "btcAddress": "Ook6goo1Jee5ZuPualeiqu9RiN8wooshoo",
    "wif": "rohCie2ein2chaed9kaiyoo6zo1aeQu1yae4phooShov2oosh4ox",
    "index": 0
  }
}
```

### Create bitcoin wallet and import it into this instance

We'll be using the wallet values from the previous `npx` command, "btcAddress" and "wif"

```bash
$curl \
--user btcuser:btcpass \
--data-binary '{"jsonrpc": "2.0", "id": "curltest", "method": "createwallet", "params": {"wallet_name":"miner","avoid_reuse":true,"descriptors":false,"load_on_startup":true}}' \
-H 'content-type: application/json' http://localhost:8332/

$ sudo systemctl restart bitcoin
$ bitcoin-cli \
  -rpcconnect=localhost \
  -rpcport=8332 \
  -rpcuser=btcuser \
  -rpcpassword=btcpass \
importmulti '[{ "scriptPubKey": { "address": "<npx btcAddress>" }, "timestamp":"now", "keys": [ "<npx wif>" ]}]' '{"rescan": true}'
$ bitcoin-cli \
  -rpcconnect=localhost \
  -rpcport=8332 \
  -rpcuser=btcuser \
  -rpcpassword=btcpass \
getaddressinfo <npx btcAddress>

```

Once imported, the wallet will need to be funded with some bitcoin.

## stacks-blockchain

### Build and install stacks-blockchain from source (via script)

```bash
$ cd $HOME && cat <<EOF> $HOME/build-stacks.sh
#!/bin/sh
CURDIR=\$(pwd)
DEST=/usr/local/bin/stacks-node
GIT_DIR=\$HOME/stacks-blockchain
if [ ! -d \${GIT_DIR} ]; then
  git clone https://github.com/funai-wiki/stacks-core.git \${GIT_DIR}
else
  git -C \${GIT_DIR} pull -r
fi
cd \${GIT_DIR}/testnet/stacks-node
cargo build --features monitoring_prom,slog_json --release --bin stacks-node
if [ "\$?" -eq "0" ]; then
  if [ -f \${DEST} ]; then
    sudo rm -f \${DEST}
  fi
  echo "Copying stacks-node to $DEST using sudo"
  sudo cp -a \${GIT_DIR}/target/release/stacks-node \${DEST}
fi
cd \${CURDIR}
EOF
$ sh $HOME/build-stacks.sh
```

### Build and install stacks-blockchain from source

```bash
$ git clone https://github.com/blockstack/stacks-blockchain.git $HOME/stacks-blockchain
$ cd $HOME/stacks-blockchain/testnet/stacks-node
$ cargo build --features monitoring_prom,slog_json --release --bin stacks-node
$ sudo cp -a $HOME/stacks-blockchain/target/release/stacks-node /usr/local/bin/stacks-node
```

```bash
$ sudo bash -c 'cat <<EOF> /etc/stacks-blockchain/follower.toml
[node]
working_dir = "/stacks-blockchain"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
bootstrap_node = "03c830906d80795257ae211fac6ed786a131ec43f3b05e5efc8ce607a1a2c16b5b@34.143.166.224:20444"
miner_endpoint = "http://127.0.0.1:20443"

[burnchain]
chain = "bitcoin"
mode = "mainnet"
peer_host = "127.0.0.1"
username = "btcuser"
password = "btcpass"
rpc_port = 8332
peer_port = 8333
EOF'
```

**replace `seed` and `local_peer_seed` with the `privateKey` value from the previous `npx` command**

```bash
$ sudo bash -c 'cat <<EOF> /etc/stacks-blockchain/miner.toml
[node]
working_dir = "/stacks-blockchain"
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
username = "btcuser"
password = "btcpass"
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

### Add stacks user and configure dirs

```bash
$ sudo useradd stacks
$ sudo chown -R stacks:stacks /stacks-blockchain/
```

### Install stacks.service unit

```bash
$ sudo bash -c 'cat <<EOF> /etc/systemd/system/stacks.service
[Unit]
Description=Stacks Blockchain
Requires=bitcoin.service
After=bitcoin.service
ConditionFileIsExecutable=/usr/local/bin/stacks-node
ConditionPathExists=/stacks-blockchain/

[Service]
ExecStart=/bin/sh -c "/usr/local/bin/stacks-node start --config=/etc/stacks-blockchain/follower.toml >> /stacks-blockchain/follower.log 2>&1"
ExecStartPost=/bin/sh -c "umask 022; sleep 2 && pgrep -f \"/usr/local/bin/stacks-node start --config=/etc/stacks-blockchain/follower.toml\" > /run/stacks-blockchain/stacks.pid"
ExecStopPost=/bin/sh -c "if [ -f \"/run/stacks-blockchain/stacks.pid\" ]; then rm -f /run/stacks-blockchain/stacks.pid; fi"

# Process management
####################
Type=simple
PIDFile=/run/stacks-blockchain/stacks.pid
Restart=on-failure
TimeoutStopSec=600
KillSignal=SIGTERM

# Directory creation and permissions
####################################
# Run as bitcoin:bitcoin
User=stacks
Group=stacks
RuntimeDirectory=stacks-blockchain
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
$ sudo systemctl enable stacks.service
$ sudo systemctl start stacks.service
```

### Deploy large models

Please refer to this document to deploy large models on stack-node nodes.

https://www.yuque.com/u28951601/at1c64/qfvoklw0ethwcbdg?singleDoc#

### Stack stx

Before becoming a stacker, you need to obtain STX by purchasing or being a miner. Stake STX through STX CLI to become a stacker and earn a layer of network tokens.

```
$./node_modules/.bin/stx stack <stx amount> <cycle length> <npx btcAddress> <npx privateKey>
e.g
$ stx stack 1000000000 1 Ook6goo1Jee5ZuPualeiqu9RiN8wooshoo ooxeemeitar4ahw0ca8anu4thae7aephahshae1pahtae5oocahthahho4ahn7eici
```

After stacking takes effect, you can run the stacker node as follows.

### Build stacks-signer from source

```
$ cd stacks-core/stacks-signer
$ cargo build --release
$ sudo bash -c 'cat <<EOF> /etc/stacks-blockchain/signer.toml
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
db_path = "/data/llm_signer_local/signer.db"

# an authentication token that is used for some HTTP requests made from the
# signer to your Stacks node. You’ll need to use this later on when configur$ng
# your Stacks node. You create this field yourself, rather than it being generated
# with your private key.
auth_password = "<the block_proposal_token in the miner.toml>"

# This is the privateKey field from the keys you generated in the
# previous step.
stacks_private_key = "<npx privateKey>"
EOF'
$ STACKS_LOG_INFO=1 nohup ./target/release/stacks-signer run --config /etc/stacks-blockchain/signer.toml >> ./signer.log 2>&1 &
```

After the stacker node is running, you need to modify the miner configuration and restart it. 
This is because after nakamoto takes effect, subsequent blocks require the signature and verification of the stacker.

```
$ cat <<EOL>> /etc/stacks-blockchain/miner.toml
[[events_observer]]
endpoint = "127.0.0.1:30000"
retry_count = 255
include_data_events = false
events_keys = ["*","stackerdb","block_proposal"]
EOL
$ systemctl restart stacks.service
```