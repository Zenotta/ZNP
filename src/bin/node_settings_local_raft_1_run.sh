#!/bin/sh

echo " "
echo "//-----------------------------//"
echo "Building nodes"
echo "//-----------------------------//"
echo " "
#cargo build --bins --release
if [ "$?" != "0" ]
then
    exit 1
fi
echo " "
echo "//-----------------------------//"
echo "Delete databases"
echo "//-----------------------------//"
echo " "
if [ "$1" != "no_rm" ]
then
    echo "delete dbs"
    rm -rf src/db/db/test.* src/wallet/wallet/test.*
fi
echo " "
echo "//-----------------------------//"
echo "Running nodes for node_settings_local_raft.toml"
echo "//-----------------------------//"
echo " "

if [ "$1" = "set_log" ]
then
    echo set log storage: $2, compute: $3, miner: $4, user: $5.
    STORAGE_LOG=$2
    COMPUTE_LOG=$3
    MINER_LOG=$4
    USER_LOG=$5
else
    STORAGE_LOG=debug
    COMPUTE_LOG=debug
    MINER_LOG=debug
    USER_LOG=debug
fi

if [ "$2" = "ca_nodes" ]
then
    USE_CA_NODES=1
fi


RUST_LOG="$STORAGE_LOG,raft=warn" target/release/node storage --config=src/bin/node_settings_local_raft_1.toml > storage_0.log 2>&1 &
s0=$!
RUST_LOG="$COMPUTE_LOG" target/release/node compute --config=src/bin/node_settings_local_raft_1.toml > compute_0.log 2>&1 &
c0=$!

if [ "$USE_CA_NODES" = "1" ]
then
    RUST_LOG="$MINER_LOG" target/release/node miner --config=src/bin/node_settings_local_raft_1.toml --address "127.0.0.1:12520" --with_user_address="127.0.0.1:12521" --tls_certificate_override="$(cat <src/bin/tls_data/miner101.bundle.pem)" --tls_private_key_override="$(cat <src/bin/tls_data/miner101.key)" --api_port=12522> miner_0.log 2>&1 &
    m0=$!
    RUST_LOG="$USER_LOG" target/release/node user --config=src/bin/node_settings_local_raft_1.toml --address "127.0.0.1:12540" --tls_certificate_override="$(cat <src/bin/tls_data/user101.bundle.pem)" --tls_private_key_override="$(cat <src/bin/tls_data/user101.key)" > user_0.log 2>&1 &
    u0=$!
else
    RUST_LOG="$MINER_LOG" target/release/node miner --config=src/bin/node_settings_local_raft_1.toml --with_user_index=1 --api_port=12522> miner_0.log 2>&1 &
    m0=$!
    RUST_LOG="$USER_LOG" target/release/node user --config=src/bin/node_settings_local_raft_1.toml > user_0.log 2>&1 &
    u0=$!
fi

echo $s0 $c0 $m0 $u0
trap 'echo Kill All $s0 $c0 $m0 $u0; kill $s0 $c0 $m0 $u0' INT
tail -f storage_0.log
