#!/bin/sh

echo " "
echo "//-----------------------------//"
echo "Building nodes"
echo "//-----------------------------//"
echo " "
cargo build --bins --release
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
    COMPUTE_LOG=warn
    MINER_LOG=warn
    USER_LOG=debug
fi

RUST_LOG="$STORAGE_LOG,raft=warn" target/release/node storage > storage_0.log 2>&1 &
s0=$!
RUST_LOG="$COMPUTE_LOG" target/release/node compute > compute_0.log 2>&1 &
c0=$!
RUST_LOG="$MINER_LOG" target/release/node miner --with_user_index=1 --api_port=3010 > miner_0.log 2>&1 &
m0=$!
RUST_LOG="$USER_LOG" target/release/node user > user_0.log 2>&1 &
u0=$!

echo $s0 $c0 $m0 $u0
trap 'echo Kill All $s0 $c0 $m0 $u0; kill $s0 $c0 $m0 $u0' INT
tail -f storage_0.log
