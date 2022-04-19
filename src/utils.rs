use crate::comms_handler::Node;
use crate::configurations::{UnicornFixedInfo, UtxoSetSpec, WalletTxSpec};
use crate::constants::{BLOCK_PREPEND, MINING_DIFFICULTY, NETWORK_VERSION, REWARD_ISSUANCE_VAL};
use crate::interfaces::{
    BlockchainItem, BlockchainItemMeta, DruidDroplet, ProofOfWork, StoredSerializingBlock,
};
use crate::wallet::WalletDb;
use bincode::serialize;
use futures::future::join_all;
use naom::constants::TOTAL_TOKENS;
use naom::crypto::sha3_256;
use naom::crypto::sign_ed25519::{self as sign, PublicKey, SecretKey, Signature};
use naom::primitives::{
    asset::{Asset, TokenAmount},
    block::{build_hex_txs_hash, Block, BlockHeader},
    transaction::{OutPoint, Transaction, TxConstructor, TxIn, TxOut},
};
use naom::script::{lang::Script, StackEntry};
use naom::utils::transaction_utils::{
    construct_address, construct_create_tx, construct_payment_tx_ins, construct_tx_core,
    construct_tx_hash, construct_tx_in_signable_asset_hash, construct_tx_in_signable_hash,
    get_tx_out_with_out_point, get_tx_out_with_out_point_cloned,
};
use rand::{self, Rng};
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task;
use tokio::time::Instant;
use tracing::{trace, warn};

pub type RoutesPoWInfo = Arc<Mutex<BTreeMap<String, usize>>>;
pub type ApiKeys = Arc<Mutex<HashSet<String>>>;
pub type LocalEventSender = MpscTracingSender<LocalEvent>;
pub type LocalEventReceiver = mpsc::Receiver<LocalEvent>;

/// Local command event to nodes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalEvent {
    CoordinatedShutdown(u64),
    Exit(&'static str),
    Ignore,
}

/// Event response processing
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseResult {
    Exit,
    Continue,
}

pub struct MpscTracingSender<T> {
    sender: mpsc::Sender<T>,
}

impl<T> MpscTracingSender<T> {
    pub fn new(sender: mpsc::Sender<T>) -> Self {
        Self { sender }
    }
}

impl<T> Clone for MpscTracingSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<T> From<mpsc::Sender<T>> for MpscTracingSender<T> {
    fn from(sender: mpsc::Sender<T>) -> Self {
        Self { sender }
    }
}

impl<T> MpscTracingSender<T> {
    pub async fn send(&mut self, value: T, tag: &str) -> Result<(), mpsc::error::SendError<T>> {
        use mpsc::error::SendError;
        use mpsc::error::TrySendError;

        match self.sender.try_send(value) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(value)) => {
                trace!("send_tracing({}) full: waiting", tag);
                let start = Instant::now();
                let result = self.sender.send(value).await;
                let elapsed = Instant::now() - start;
                if elapsed < Duration::from_millis(2) {
                    trace!("send_tracing({}) done: waited({:?})", tag, elapsed);
                } else {
                    warn!("send_tracing({}) done: waited({:?})", tag, elapsed);
                }
                result
            }
            Err(TrySendError::Closed(value)) => Err(SendError(value)),
        }
    }
}

/// A running tasks or end result
#[derive(Debug)]
pub enum RunningTaskOrResult<T> {
    None,
    Running(task::JoinHandle<T>),
    Completed(Result<T, task::JoinError>),
}

impl<T> Default for RunningTaskOrResult<T> {
    fn default() -> Self {
        Self::None
    }
}

impl<T> RunningTaskOrResult<T> {
    /// Wait for the handle to complete or wait forever
    pub async fn wait(&mut self) {
        *self = if let RunningTaskOrResult::Running(task) = self {
            Self::Completed(task.await)
        } else {
            std::future::pending().await
        }
    }

    /// Return completed result or None if no completed task
    pub fn completed_result(&self) -> Option<&Result<T, task::JoinError>> {
        if let Self::Completed(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

/// Channel for low volume local events
pub struct LocalEventChannel {
    pub tx: LocalEventSender,
    pub rx: LocalEventReceiver,
}

impl Default for LocalEventChannel {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel(10);
        Self { tx: tx.into(), rx }
    }
}

impl fmt::Debug for LocalEventChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

/// A trivial error to output
#[derive(PartialEq, Eq)]
pub struct StringError(pub String);

impl Error for StringError {
    fn description(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Deserialization of a BlockchainItem
pub enum DeserializedBlockchainItem {
    // Data, block_num, tx_len
    CurrentBlock(StoredSerializingBlock, u64, u32),
    // Data, block_num, tx_num
    CurrentTx(Transaction, u64, u32),
    // Data
    VersionErr(u32),
    // Data
    SerializationErr(bincode::Error),
}

impl DeserializedBlockchainItem {
    pub fn from_item(item: &BlockchainItem) -> Self {
        if item.version != NETWORK_VERSION {
            return Self::VersionErr(item.version);
        }
        match item.item_meta {
            BlockchainItemMeta::Block { block_num, tx_len } => {
                match bincode::deserialize::<StoredSerializingBlock>(&item.data) {
                    Ok(b) => Self::CurrentBlock(b, block_num, tx_len),
                    Err(e) => Self::SerializationErr(e),
                }
            }
            BlockchainItemMeta::Tx { block_num, tx_num } => {
                match bincode::deserialize::<Transaction>(&item.data) {
                    Ok(b) => Self::CurrentTx(b, block_num, tx_num),
                    Err(e) => Self::SerializationErr(e),
                }
            }
        }
    }
}

/// Install a global tracing subscriber that listens for events and
/// filters based on the value of the [`RUST_LOG` environment variable],
/// if one is not already set.
///
/// Default to OFF so if not environment varialbe is provided no log is emitted.
pub fn tracing_log_try_init() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let dirs = std::env::var(tracing_subscriber::EnvFilter::DEFAULT_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "off".to_owned());

    let builder = tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::new(dirs));

    builder.try_init()
}

/// Attempts to connect to all peers
///
/// ### Arguments
///
/// * `node`     - Node attempting to connect to peers.
/// * `peers`    - Vec of socket addresses of peers
/// * `close_rx` - Receiver for close event or None to finish when all connected
pub async fn loop_connnect_to_peers_async(
    mut node: Node,
    peers: Vec<SocketAddr>,
    mut close_rx: Option<oneshot::Receiver<()>>,
) {
    loop {
        for peer in node.unconnected_peers(&peers).await {
            trace!(?peer, "Try to connect to");
            if let Err(e) = node.connect_to(peer).await {
                trace!(?peer, ?e, "Try to connect to failed");
            } else {
                trace!(?peer, "Try to connect to succeeded");
            }
        }

        let delay_retry = tokio::time::sleep(Duration::from_millis(500));
        if let Some(close_rx) = &mut close_rx {
            tokio::select! {
                _ = delay_retry => (),
                _ = close_rx => return,
            };
        } else {
            if node.unconnected_peers(&peers).await.is_empty() {
                return;
            }
            delay_retry.await;
        }
    }
}

/// check connected to all peers
///
/// ### Arguments
///
/// * `node`     - Node attempting to connect to peers.
/// * `peers`    - Vec of socket addresses of peers
pub async fn loop_wait_connnect_to_peers_async(node: Node, peers: Vec<SocketAddr>) {
    while !node.unconnected_peers(&peers).await.is_empty() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Gets the locally set list of sanctioned addresses
///
/// ### Arguments
///
/// * `path`         - Path to the sanction list
/// * `jurisdiction` - Jurisdiction to fetch sanctioned addresses for
pub fn get_sanction_addresses(path: String, jurisdiction: &str) -> Vec<String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let mut buff = String::new();
    file.read_to_string(&mut buff).unwrap();

    let sancs: serde_json::value::Value = serde_json::from_str(&buff).unwrap();

    match sancs[jurisdiction].as_array() {
        Some(v) => (*v
            .iter()
            .map(|i| i.as_str().unwrap().to_string())
            .collect::<Vec<String>>())
        .to_vec(),
        None => Vec::new(),
    }
}

/// Creates a "fake" transaction to save to the local wallet
/// for testing. The transaction will contain 4 tokens
///
/// NOTE: This is a test util function
/// ### Arguments
///
/// * `wallet_db`    - &WalletDb object. Reference to a wallet database
pub async fn create_and_save_fake_to_wallet(
    wallet_db: &WalletDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let (final_address, address_keys) = wallet_db.generate_payment_address().await;
    let (receiver_addr, _) = wallet_db.generate_payment_address().await;

    let (t_hash, _payment_tx) = create_valid_transaction(
        "00000",
        0,
        &receiver_addr,
        &address_keys.public_key,
        &address_keys.secret_key,
    );
    let tx_out_p = OutPoint::new(t_hash, 0);
    let payment_to_save = Asset::token_u64(4000);
    let payments = vec![(tx_out_p.clone(), payment_to_save, final_address)];
    wallet_db
        .save_usable_payments_to_wallet(payments)
        .await
        .unwrap();

    Ok(())
}

/// Address to be used in Proof of Work
///
/// ### Arguments
///
/// * `addr`    - Socket address of used in the proof of work
pub fn format_parition_pow_address(addr: SocketAddr) -> String {
    format!("{}", addr)
}

/// Calculates the reward for the next block, to be placed within the coinbase tx
///
/// ### Argeumtsn
///
/// * `current_circulation` - Current circulation of all tokens
pub fn calculate_reward(current_circulation: TokenAmount) -> TokenAmount {
    TokenAmount((TOTAL_TOKENS - current_circulation.0) >> REWARD_ISSUANCE_VAL)
}

/// Gets the total amount of tokens for all present coinbase transactions,
/// assuming that they have all received the same amount of reward
///
/// ### Arguments
///
/// * `coinbase_tx` - Coinbase transactions
pub fn get_total_coinbase_tokens(coinbase_tx: &BTreeMap<String, Transaction>) -> TokenAmount {
    let mut total = TokenAmount(0);
    for tx_ind in coinbase_tx.values() {
        total += tx_ind.outputs.iter().map(|x| x.value.token_amount()).sum();
    }
    total
}

/// Concatenates a merkle hash and a coinbase hash to produce a single hash output
///
/// ### Arguments
///
/// * `header     ` - Header to update
/// * `merkle_hash` - Nonce to use
/// * `cb_tx_hash`  - Mining transaction hash
pub fn apply_mining_tx(mut header: BlockHeader, nonce: Vec<u8>, tx_hash: String) -> BlockHeader {
    header.nonce_and_mining_tx_hash = (nonce, tx_hash);
    header
}

/// Generates a random sequence of values for a nonce
pub fn generate_pow_nonce() -> Vec<u8> {
    generate_random_num(16)
}

/// Generates a random num for use for proof of work
pub fn generate_pow_random_num() -> Vec<u8> {
    generate_random_num(10)
}

/// Generates a garbage random num for use in network testing
pub fn generate_random_num(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen_range(1, 200)).collect()
}

/// Generates a ProofOfWork for a given address
///
/// ### Arguments
///
/// * `peer`      - Peer to send PoW to
/// * `address`   - Given address to generate the ProofOfWork
/// * `rand_num`  - A random number used to generate the ProofOfWork in an Option<Vec<u8>>
pub fn generate_pow_for_address(
    peer: SocketAddr,
    address: String,
    rand_num: Option<Vec<u8>>,
) -> task::JoinHandle<(ProofOfWork, SocketAddr)> {
    task::spawn_blocking(move || {
        let mut pow = ProofOfWork {
            address,
            nonce: generate_pow_nonce(),
        };

        while !validate_pow_for_address(&pow, &rand_num.as_ref()) {
            pow.nonce = generate_pow_nonce();
        }

        (pow, peer)
    })
}

/// Validate Proof of Work an address with a random number
pub fn validate_pow_for_address(pow: &ProofOfWork, rand_num: &Option<&Vec<u8>>) -> bool {
    let mut pow_body = pow.address.as_bytes().to_vec();
    pow_body.extend(rand_num.iter().flat_map(|r| r.iter()).copied());
    pow_body.extend(&pow.nonce);

    validate_pow(&pow_body).is_some()
}

/// Generate Proof of Work for a block with a mining transaction
///
/// ### Arguments
///
/// * `header`   - The header for PoW
pub fn generate_pow_for_block(mut header: BlockHeader) -> BlockHeader {
    header.nonce_and_mining_tx_hash.0 = generate_pow_nonce();
    while !validate_pow_block(&header) {
        header.nonce_and_mining_tx_hash.0 = generate_pow_nonce();
    }
    header
}

/// Verify block is valid & consistent: Can be fully verified from PoW hash.
/// Verify that PoW hash is valid: sufficient leading 0.
/// Return the hex encoded hash with prefix
///
/// ### Arguments
///
/// * `block`   - The block to extract hash from
pub fn construct_valid_block_pow_hash(block: &Block) -> Result<String, StringError> {
    if build_hex_txs_hash(&block.transactions) != block.header.txs_merkle_root_and_hash.1 {
        trace!(
            "Transactions inconsistent with header: {:?}",
            &block.transactions
        );
        return Err(StringError(
            "Transactions inconsistent with header".to_owned(),
        ));
    }

    let hash_digest = validate_pow_block_hash(&block.header).ok_or_else(|| {
        StringError("Only block passing validate_pow_block are accepted".to_owned())
    })?;

    let mut hash_digest = hex::encode(hash_digest);
    hash_digest.insert(0, BLOCK_PREPEND as char);
    Ok(hash_digest)
}

/// Validate Proof of Work for a block with a mining transaction
///
/// ### Arguments
///
/// * `header`   - The header for PoW
pub fn validate_pow_block(header: &BlockHeader) -> bool {
    validate_pow_block_hash(header).is_some()
}

/// Validate Proof of Work for a block with a mining transaction returning the PoW hash
///
/// ### Arguments
///
/// * `header`   - The header for PoW
fn validate_pow_block_hash(header: &BlockHeader) -> Option<Vec<u8>> {
    let pow = serialize(header).unwrap();
    validate_pow(&pow)
}

/// Check the hash of given data reach MINING_DIFFICULTY
///
/// ### Arguments
///
/// * `mining_difficulty`    - usize mining difficulty
/// * `pow`                  - &u8 proof of work
pub fn validate_pow_for_diff(mining_difficulty: usize, pow: &[u8]) -> Option<Vec<u8>> {
    let pow_hash = sha3_256::digest(pow).to_vec();
    if pow_hash[0..mining_difficulty].iter().all(|v| *v == 0) {
        Some(pow_hash)
    } else {
        None
    }
}

/// Check the hash of given data reach MINING_DIFFICULTY
///
/// ### Arguments
///
/// * `pow`    - &u8 proof of work
fn validate_pow(pow: &[u8]) -> Option<Vec<u8>> {
    validate_pow_for_diff(MINING_DIFFICULTY, pow)
}

/// Get the paiment info from the given transactions
///
/// ### Arguments
///
/// * `txs`   - The transactions
pub fn get_paiments_for_wallet<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> Vec<(OutPoint, Asset, String)> {
    let utxo_iterator = get_tx_out_with_out_point_cloned(txs);
    get_paiments_for_wallet_from_utxo(utxo_iterator)
}

/// Get the paiment info from the given UTXO set/subset
///
/// ### Arguments
///
/// * `utxo_set`   - The UTXO set/subset
pub fn get_paiments_for_wallet_from_utxo(
    utxos: impl Iterator<Item = (OutPoint, TxOut)>,
) -> Vec<(OutPoint, Asset, String)> {
    utxos
        .map(|(out_p, tx_out)| (out_p, tx_out.value, tx_out.script_public_key.unwrap()))
        .collect()
}

/// Create a valid transaction from given info
pub fn create_valid_transaction(
    t_hash_hex: &str,
    prev_n: i32,
    receiver_addr_hex: &str,
    pub_key: &PublicKey,
    secret_key: &SecretKey,
) -> (String, Transaction) {
    create_valid_transaction_with_ins_outs(
        &[(prev_n, t_hash_hex)],
        &[receiver_addr_hex],
        pub_key,
        secret_key,
        TokenAmount(1),
        None,
    )
}

/// Creates a valid DDE transaction from given info
pub fn create_valid_create_transaction_with_ins_outs(
    drs: Vec<u8>,
    pub_key: PublicKey,
    secret_key: &SecretKey,
) -> (String, Transaction) {
    let create_tx = construct_create_tx(0, drs, pub_key, secret_key, 1);
    let ct_hash = construct_tx_hash(&create_tx);

    (ct_hash, create_tx)
}

/// Create a valid transaction from given info
pub fn create_valid_transaction_with_ins_outs(
    tx_in: &[(i32, &str)],
    receiver_addr_hexs: &[&str],
    pub_key: &PublicKey,
    secret_key: &SecretKey,
    amount: TokenAmount,
    address_version: Option<u64>,
) -> (String, Transaction) {
    let tx_ins = {
        let mut tx_in_cons = Vec::new();
        for (prev_n, t_hash_hex) in tx_in {
            let signable = OutPoint::new(t_hash_hex.to_string(), *prev_n);
            let signable_h = construct_tx_in_signable_hash(&signable);

            let signature = sign::sign_detached(signable_h.as_bytes(), secret_key);
            tx_in_cons.push(TxConstructor {
                previous_out: signable,
                signatures: vec![signature],
                pub_keys: vec![*pub_key],
                address_version,
            });
        }

        construct_payment_tx_ins(tx_in_cons)
    };

    let tx_outs = {
        let mut tx_outs = Vec::new();

        for addr in receiver_addr_hexs {
            tx_outs.push(TxOut {
                value: Asset::Token(amount),
                locktime: 0,
                script_public_key: Some(addr.to_string()),
                drs_block_hash: None,
                drs_tx_hash: None,
            });
        }
        tx_outs
    };

    let payment_tx = construct_tx_core(tx_ins, tx_outs);
    let t_hash = construct_tx_hash(&payment_tx);

    (t_hash, payment_tx)
}

/// Get the string to display for genesis TxIn
///
/// ### Arguments
///
/// * `tx`    - The transaction
pub fn get_genesis_tx_in_display(tx: &Transaction) -> &str {
    if let Some(tx_in) = tx.inputs.first() {
        if let Some(StackEntry::Bytes(v)) = tx_in.script_signature.stack.first() {
            return v;
        }
    }

    ""
}

/// Generate a half_druid value
pub fn generate_half_druid() -> String {
    let (pk, _) = sign::gen_keypair();
    construct_address(&pk)
}

/// Generate utxo_set transactions from seed info
///
/// ### Arguments
///
/// * `seed`      - Set iterated through to generate the transaction set utxo
/// * `tx_in_str` - String to use as genesis transactions TxIn bytes.
pub fn make_utxo_set_from_seed(
    seed: &UtxoSetSpec,
    tx_in_str: &Option<String>,
) -> BTreeMap<String, Transaction> {
    let mut pk_to_address: BTreeMap<String, String> = BTreeMap::new();
    let genesis_tx_in = tx_in_str.clone().map(|tx_in| {
        let mut script_signature = Script::new();
        script_signature.stack.push(StackEntry::Bytes(tx_in));
        TxIn {
            previous_out: None,
            script_signature,
        }
    });
    seed.iter()
        .map(|(tx_hash, tx_out)| {
            let tx = Transaction {
                outputs: tx_out
                    .iter()
                    .map(|out| {
                        let script_public_key =
                            if let Some(addr) = pk_to_address.get(&out.public_key) {
                                addr.clone()
                            } else {
                                let addr = decode_pub_key_as_address(&out.public_key);
                                pk_to_address.insert(out.public_key.clone(), addr.clone());
                                addr
                            };

                        TxOut::new_token_amount(script_public_key, out.amount)
                    })
                    .collect(),
                inputs: genesis_tx_in.clone().into_iter().collect(),
                ..Transaction::default()
            };
            (tx_hash.clone(), tx)
        })
        .collect()
}

/// Generate wallet transactions from seed info
///
/// ### Arguments
///
/// * `seed`    - &WalletTxSpec object containing parameters to generate wallet transactions
pub fn make_wallet_tx_info(
    seed: &WalletTxSpec,
) -> (OutPoint, PublicKey, SecretKey, TokenAmount, Option<u64>) {
    let tx_out_p = decode_wallet_out_point(&seed.out_point);
    let amount = TokenAmount(seed.amount as u64);
    let sk = decode_secret_key(&seed.secret_key).unwrap();
    let pk = decode_pub_key(&seed.public_key).unwrap();
    let version = seed.address_version;

    (tx_out_p, pk, sk, amount, version)
}

/// Decodes a wallet's OutPoint
///
/// ### Arguments
///
/// * `out_point`    - String to be split and decode the wallet OutPoint
pub fn decode_wallet_out_point(out_point: &str) -> OutPoint {
    let mut it = out_point.split('-');
    let n = it.next().unwrap().parse().unwrap();
    let tx_hash = it.next().unwrap().parse().unwrap();
    OutPoint::new(tx_hash, n)
}

/// Decodes the public key as address
///
/// ### Arguments
///
/// * `key`    - key to be decoded to give the public key
pub fn decode_pub_key_as_address(key: &str) -> String {
    construct_address(&decode_pub_key(key).unwrap())
}

/// Decodes the public key
///
/// ### Arguments
///
/// * `key`    - key to be decode
pub fn decode_pub_key(key: &str) -> Result<PublicKey, StringError> {
    if let Ok(key_slice) = hex::decode(key) {
        if let Some(key) = PublicKey::from_slice(&key_slice) {
            return Ok(key);
        }
    }
    Err(StringError(format!("Public key decoding error: {}", key)))
}

/// Decodes a secret key
///
/// ### Arguments
///
/// * `key`    - key to decode
pub fn decode_secret_key(key: &str) -> Result<SecretKey, StringError> {
    if let Ok(key_slice) = hex::decode(key) {
        if let Some(key) = SecretKey::from_slice(&key_slice) {
            return Ok(key);
        }
    }
    Err(StringError(format!("Secret key decoding error: {}", key)))
}

/// Decodes a signature
///
/// ### Arguments
///
/// * `sig`    - Signature to decode
pub fn decode_signature(sig: &str) -> Result<Signature, StringError> {
    if let Ok(sig_slice) = hex::decode(sig) {
        if let Some(sig) = Signature::from_slice(&sig_slice) {
            return Ok(sig);
        }
    }
    Err(StringError(format!("Signature decoding error: {}", sig)))
}

/// Stop listening for connection and disconnect existing ones
/// This will complete sent message in the queues.
///
/// ### Arguments
///
/// * `node_conn` - Node to use for connections
pub async fn shutdown_connections(node_conn: &mut Node) {
    join_all(node_conn.stop_listening().await).await;
    join_all(node_conn.disconnect_all(None).await).await;
}

/// Loop reconnect and test disconnect
///
/// ### Arguments
///
/// * `node_conn`         - Node to use for connections
/// * `addrs_to_connect`  - Addresses to establish connections to
/// * `local_events_tx`   - Channel for local events
pub fn loops_re_connect_disconnect(
    node_conn: Node,
    addrs_to_connect: Vec<SocketAddr>,
    mut local_events_tx: LocalEventSender,
) -> (
    (impl Future<Output = ()>, oneshot::Sender<()>),
    (impl Future<Output = ()>, oneshot::Sender<()>),
) {
    // PERMANENT CONNEXION HANDLING
    let re_connect = {
        let (stop_re_connect_tx, stop_re_connect_rx) = tokio::sync::oneshot::channel::<()>();
        let node_conn = node_conn.clone();
        (
            async move {
                println!("Start connect to requested peers");
                loop_connnect_to_peers_async(node_conn, addrs_to_connect, Some(stop_re_connect_rx))
                    .await;
                println!("Reconnect complete");
            },
            stop_re_connect_tx,
        )
    };

    // TEST DIS-CONNECTION HANDLING
    let disconnect_test = {
        let (stop_re_connect_tx, mut stop_re_connect_rx) = tokio::sync::oneshot::channel::<()>();
        let mut node_conn = node_conn;
        let mut paused = true;
        let mut shutdown_num = None;
        (
            async move {
                println!("Start mode input check");
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(100)) => (),
                        _ = &mut stop_re_connect_rx => break,
                    };

                    paused = pause_and_disconnect_on_path(&mut node_conn, paused).await;
                    shutdown_num =
                        shutdown_on_path(&mut node_conn, &mut local_events_tx, shutdown_num).await;
                }
                println!("Complete mode input check");
            },
            stop_re_connect_tx,
        )
    };
    (re_connect, disconnect_test)
}

/// Check disconnect path and pause/disconnect requested connections.
/// Return the new paused state.
///
/// ### Arguments
///
/// * `node_conn`   - Node to use for connections
/// * `paused`      - Current paused state
async fn pause_and_disconnect_on_path(node_conn: &mut Node, paused: bool) -> bool {
    let disconnect = format!("disconnect_{}", node_conn.address().port());
    let path = std::path::Path::new(&disconnect);
    match (paused, path.exists()) {
        (false, true) => {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            let diconnect_addrs: Vec<_> = content
                .split(&[',', '\n'][..])
                .filter_map(|v| v.parse::<SocketAddr>().ok())
                .collect();

            warn!(
                "disconnect from {:?} all {:?}",
                node_conn.address(),
                diconnect_addrs
            );
            node_conn.set_pause_listening(true).await;
            if diconnect_addrs.is_empty() {
                join_all(node_conn.disconnect_all(None).await).await;
            } else {
                join_all(node_conn.disconnect_all(Some(&diconnect_addrs)).await).await;
            }
            true
        }
        (true, false) => {
            node_conn.set_pause_listening(false).await;
            false
        }
        _ => paused,
    }
}

/// Check given shutdown path and trigger coordinated or immediate shutdown.
/// Return the new shutdown block num.
///
/// ### Arguments
///
/// * `node_conn`       - Node to use for connections
/// * `local_events_tx` - Channel for local events
/// * `shutdown_num`    - Current shutdown state
async fn shutdown_on_path(
    node_conn: &mut Node,
    local_events_tx: &mut LocalEventSender,
    shutdown_num: Option<(u64, bool)>,
) -> Option<(u64, bool)> {
    let shutdown_now_one = format!("shutdown_now_{}", node_conn.address().port());
    let shutdown_now_all = "shutdown_now".to_owned();
    let shutdown_coord_one = format!("shutdown_coordinated_{}", node_conn.address().port());
    let shutdown_coord_all = "shutdown_coordinated".to_owned();

    let now = true;
    let path = Some((std::path::Path::new(&shutdown_now_all), now))
        .filter(|(p, _)| p.exists())
        .or_else(|| Some((std::path::Path::new(&shutdown_coord_all), !now)))
        .filter(|(p, _)| p.exists())
        .or_else(|| Some((std::path::Path::new(&shutdown_now_one), now)))
        .filter(|(p, _)| p.exists())
        .or_else(|| Some((std::path::Path::new(&shutdown_coord_one), !now)))
        .filter(|(p, _)| p.exists());

    if let Some((path, is_now)) = path {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        let block_num = content.trim().parse::<u64>().ok().unwrap_or(0);
        let result = Some((block_num, is_now));

        if shutdown_num != result {
            warn!(
                "shutdown from {:?} at block {:?} now={}",
                node_conn.address(),
                block_num,
                is_now
            );

            let event = if is_now {
                LocalEvent::Exit("Shutdown")
            } else {
                LocalEvent::CoordinatedShutdown(block_num)
            };
            if let Err(e) = local_events_tx.send(event, "file_shutdown").await {
                warn!("Cound not send {:?} ({:?})", event, e);
            }
        }

        result
    } else {
        shutdown_num
    }
}

/// Get all the script_public_key and OutPoint from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_pk_with_out_point<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)>,
) -> impl Iterator<Item = (&'a String, OutPoint)> {
    get_tx_out_with_out_point(txs)
        .filter_map(|(op, txout)| txout.script_public_key.as_ref().map(|spk| (spk, op)))
}

/// Get all the script_public_key and OutPoint from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_pk_with_out_point_cloned<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> impl Iterator<Item = (String, OutPoint)> + 'a {
    get_pk_with_out_point(txs).map(|(spk, op)| (spk.clone(), op))
}

/// Get all the script_public_key and OutPoint from the UTXO set
///
/// ### Arguments
///
/// * `utxo_set` - The UTXO set.
pub fn get_pk_with_out_point_from_utxo_set<'a>(
    utxo_set: impl Iterator<Item = (&'a OutPoint, &'a TxOut)>,
) -> impl Iterator<Item = (&'a String, &'a OutPoint)> {
    utxo_set.filter_map(|(op, txout)| txout.script_public_key.as_ref().map(|spk| (spk, op)))
}

/// Get all the script_public_key and OutPoint from the UTXO set
///
/// ### Arguments
///
/// * `utxo_set` - The UTXO set.
pub fn get_pk_with_out_point_from_utxo_set_cloned<'a>(
    utxo_set: impl Iterator<Item = (&'a OutPoint, &'a TxOut)> + 'a,
) -> impl Iterator<Item = (String, OutPoint)> + 'a {
    get_pk_with_out_point_from_utxo_set(utxo_set).map(|(spk, op)| (spk.clone(), op.clone()))
}

/// Concatenate 2 maps of K V.
///
/// ### Arguments
///
/// * `m1` - First map
/// * `m2` - Second map
pub fn concat_maps<K: Clone + Ord, V: Clone>(
    m1: &BTreeMap<K, V>,
    m2: &BTreeMap<K, V>,
) -> BTreeMap<K, V> {
    m1.iter()
        .chain(m2.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Create a new receipt asset transaction (only used on Compute node)
///
/// ### Arguments
///
/// * `receipt_amount`      - Receipt amount
/// * `script_public_key`   - Public address key
/// * `public key`          - Public key
/// * `signature`           - Signature
pub fn create_receipt_asset_tx_from_sig(
    b_num: u64,
    receipt_amount: u64,
    script_public_key: String,
    public_key: String,
    signature: String,
) -> Result<Transaction, StringError> {
    let tx_out = TxOut::new_receipt_amount(script_public_key, receipt_amount);

    let asset_hash = construct_tx_in_signable_asset_hash(&Asset::Receipt(receipt_amount));

    let public_key = decode_pub_key(&public_key)?;
    let signature = decode_signature(&signature)?;

    let tx_in = TxIn {
        previous_out: None,
        script_signature: Script::new_create_asset(b_num, asset_hash, signature, public_key),
    };

    Ok(construct_tx_core(vec![tx_in], vec![tx_out]))
}

/// Confert to ApiKeys data structure
pub fn to_api_keys(api_keys: Vec<String>) -> ApiKeys {
    Arc::new(Mutex::new(api_keys.into_iter().collect()))
}

/// Confert to ApiKeys data structure
pub fn to_route_pow_infos(route_pow_infos: BTreeMap<String, usize>) -> RoutesPoWInfo {
    Arc::new(Mutex::new(route_pow_infos.into_iter().collect()))
}

/// Check to see if DDE transaction participants match
pub fn check_druid_participants(droplet: &DruidDroplet) -> bool {
    droplet
        .txs
        .iter()
        .all(|(_, tx)| tx.druid_info.as_ref().map(|i| i.participants) == Some(droplet.participants))
}

/// Test UnicornFixedInfo with fast compuation
pub fn get_test_common_unicorn() -> UnicornFixedInfo {
    UnicornFixedInfo{
        modulus: "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151".to_owned(),
        iterations: 2,
        security: 1
    }
}

pub mod rug_integer {
    use rug::Integer;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialisation function for big ints
    pub fn serialize<S>(x: &Integer, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value: String = x.to_string_radix(16);
        value.serialize(s)
    }

    /// Deserialisation function for big ints
    pub fn deserialize<'de, D>(d: D) -> Result<Integer, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: String = Deserialize::deserialize(d)?;
        Integer::from_str_radix(&value, 16).map_err(serde::de::Error::custom)
    }
}
