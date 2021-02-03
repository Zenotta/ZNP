#!/bin/sh

echo " "
echo "//-----------------------------//"
echo "Building nodes"
echo "//-----------------------------//"
echo " "
cargo build --bins --release
echo " "
echo "//-----------------------------//"
echo "Delete databases"
echo "//-----------------------------//"
echo " "
rm -rf src/db/db/test.* src/wallet/wallet/test.*
echo " "
echo "//-----------------------------//"
echo "Running nodes for node_settings_local_raft_3.toml"
echo "//-----------------------------//"
echo " "
RUST_LOG="debug,raft=warn" target/release/storage --config=src/bin/node_settings_local_raft_3.toml --index=2 > storage_2.log 2>&1 &
s2=$!
RUST_LOG="debug,raft=warn" target/release/storage --config=src/bin/node_settings_local_raft_3.toml --index=1 > storage_1.log 2>&1 &
s1=$!
RUST_LOG="debug,raft=warn" target/release/storage --config=src/bin/node_settings_local_raft_3.toml > storage_0.log 2>&1 &
s0=$!
RUST_LOG="warn" target/release/compute --config=src/bin/node_settings_local_raft_3.toml --index=2 > compute_2.log 2>&1 &
c2=$!
RUST_LOG="warn" target/release/compute --config=src/bin/node_settings_local_raft_3.toml --index=1 > compute_1.log 2>&1 &
c1=$!
RUST_LOG="warn" target/release/compute --config=src/bin/node_settings_local_raft_3.toml > compute_0.log 2>&1 &
c0=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --index=8 --compute_index=2 --compute_connect > miner_8.log 2>&1 &
m8=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --index=7 --compute_index=2 --compute_connect > miner_7.log 2>&1 &
m7=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --index=6 --compute_index=2 --compute_connect > miner_6.log 2>&1 &
m6=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --index=5 --compute_index=1 --compute_connect > miner_5.log 2>&1 &
m5=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --index=4 --compute_index=1 --compute_connect > miner_4.log 2>&1 &
m4=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --index=3 --compute_index=1 --compute_connect > miner_3.log 2>&1 &
m3=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --index=2 --compute_index=0 --compute_connect > miner_2.log 2>&1 &
m2=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --index=1 --compute_index=0 --compute_connect > miner_1.log 2>&1 &
m1=$!
RUST_LOG="warn" target/release/miner --config=src/bin/node_settings_local_raft_3.toml  --compute_connect > miner_0.log 2>&1 &
m0=$!
RUST_LOG="debug" target/release/user  --config=src/bin/node_settings_local_raft_3.toml --compute_connect > user_0.log 2>&1 &
u0=$!

echo $s2 $s1 $s0 $c2 $c1 $c0 $m8 $m7 $m6 $m5 $m4 $m3 $m2 $m1 $m0 $u0
trap 'echo Kill All $s2 $s1 $s0 $c2 $c1 $c0 $m8 $m7 $m6 $m5 $m4 $m3 $m2 $m1 $m0 $u0; kill $s2 $s1 $s0 $c2 $c1 $c0 $m8 $m7 $m6 $m5 $m4 $m3 $m2 $m1 $m0 $u0' INT
tail -f storage_1.log
