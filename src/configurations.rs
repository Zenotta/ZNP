use crate::db_utils::SimpleDb;
use crate::wallet::WalletDb;
use naom::primitives::asset::TokenAmount;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;

pub type UtxoSetSpec = BTreeMap<String, Vec<TxOutSpec>>;

/// Configuration info for a node
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct NodeSpec {
    pub address: SocketAddr,
}

/// Configuration info for TLS
#[derive(Default, Clone, Deserialize)]
pub struct TlsSpec {
    /// Trusted names for address (trusted or not)
    pub socket_name_mapping: BTreeMap<SocketAddr, String>,
    /// Trusted certificates available
    pub pem_certificates: BTreeMap<String, String>,
    /// Private keys available to authenticate with
    pub pem_pkcs8_private_keys: BTreeMap<String, String>,
    /// Untrusted names for which to add certificate to root store (If None trust all)
    pub untrusted_names: Option<BTreeSet<String>>,
    /// Node certificate override to use for this node ignoring pem_certificates
    pub pem_certificate_override: Option<String>,
    /// Private key override to use for this node ignoring pem_pkcs8_private_keys
    pub pem_pkcs8_private_key_override: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TlsPrivateInfo {
    pub pem_certs: String,
    pub pem_pkcs8_private_keys: String,
}

impl fmt::Debug for TlsSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TlsSpec({:?}, key({:?}), cert({:?}))",
            &self.socket_name_mapping,
            self.pem_pkcs8_private_key_override,
            self.pem_certificate_override
        )
    }
}

/// Configuration info for a TxOut
#[derive(Debug, Clone, Deserialize)]
pub struct TxOutSpec {
    /// Hex encoded public key to seed script_public_key
    pub public_key: String,
    /// Amount that this TxOut can spend
    #[serde(deserialize_with = "deserialize_token_amount")]
    pub amount: TokenAmount,
}

/// Configuration info for a TxOut
#[derive(Debug, Clone, Deserialize)]
pub struct WalletTxSpec {
    /// OutPoint specification: "n-tx_hash"
    pub out_point: String,
    /// Hex encoded secret key
    pub secret_key: String,
    /// Hex encoded public key
    pub public_key: String,
    /// Amount for the transaction
    pub amount: u64,
}

/// Configuration info for a database
#[derive(Debug, Copy, Clone, Deserialize, PartialEq, Eq)]
pub enum DbMode {
    Live,
    Test(usize),
    InMemory,
}

/// Configuration option for a compute node
#[derive(Debug, Clone, Deserialize)]
pub struct ComputeNodeConfig {
    /// Index of the current node in compute_nodes
    pub compute_node_idx: usize,
    /// Use specific database
    pub compute_db_mode: DbMode,
    /// Configuration for handling TLS
    pub tls_config: TlsSpec,
    /// Initial API keys
    pub api_keys: Vec<String>,
    /// All compute nodes addresses
    pub compute_nodes: Vec<NodeSpec>,
    /// All storage nodes addresses: only use first
    pub storage_nodes: Vec<NodeSpec>,
    /// All user nodes addresses
    pub user_nodes: Vec<NodeSpec>,
    /// Whether compute node will use raft or act independently (0)
    pub compute_raft: usize,
    /// API port
    pub compute_api_port: u16,
    /// API use TLS
    pub compute_api_use_tls: bool,
    /// Timeout for ticking raft
    pub compute_raft_tick_timeout: usize,
    /// Index of the current node in compute_nodes
    pub compute_transaction_timeout: usize,
    /// Transaction hash and TxOut info to use to seed utxo
    pub compute_seed_utxo: UtxoSetSpec,
    /// String to use for genesis block TxIn
    pub compute_genesis_tx_in: Option<String>,
    /// Partition full size
    pub compute_partition_full_size: usize,
    /// Minimum miner pool size
    pub compute_minimum_miner_pool_len: usize,
    /// Node's legal jurisdiction
    pub jurisdiction: String,
    /// Node's address sanction list
    pub sanction_list: Vec<String>,
}

/// Configuration option for a storage node
#[derive(Debug, Clone, Deserialize)]
pub struct StorageNodeConfig {
    /// Index of the current node in compute_nodes
    pub storage_node_idx: usize,
    /// Use specific database
    pub storage_db_mode: DbMode,
    /// Configuration for handling TLS
    pub tls_config: TlsSpec,
    /// Initial API keys
    pub api_keys: Vec<String>,
    /// All compute nodes addresses
    pub compute_nodes: Vec<NodeSpec>,
    /// All storage nodes addresses: only use first
    pub storage_nodes: Vec<NodeSpec>,
    /// All user nodes addresses
    pub user_nodes: Vec<NodeSpec>,
    /// Whether storage node will use raft or act independently (0)
    pub storage_raft: usize,
    /// API port
    pub storage_api_port: u16,
    /// API use TLS
    pub storage_api_use_tls: bool,
    /// Timeout for ticking raft
    pub storage_raft_tick_timeout: usize,
    /// Timeout for generating a new block
    pub storage_block_timeout: usize,
}

/// Configuration option for a storage node
#[derive(Debug, Clone, Deserialize)]
pub struct MinerNodeConfig {
    /// Index of the current node in miner_nodes
    pub miner_node_idx: usize,
    /// Use specific database
    pub miner_db_mode: DbMode,
    /// Configuration for handling TLS
    pub tls_config: TlsSpec,
    /// Initial API keys
    pub api_keys: Vec<String>,
    /// Index of the compute node to use in compute_nodes
    pub miner_compute_node_idx: usize,
    /// Index of the storage node to use in storage_nodes
    pub miner_storage_node_idx: usize,
    /// All compute nodes addresses
    pub compute_nodes: Vec<NodeSpec>,
    /// All storage nodes addresses: only use first
    pub storage_nodes: Vec<NodeSpec>,
    /// All miner nodes addresses
    pub miner_nodes: Vec<NodeSpec>,
    /// All user nodes addresses
    pub user_nodes: Vec<NodeSpec>,
    /// API port
    pub miner_api_port: u16,
    /// API use TLS
    pub miner_api_use_tls: bool,
    /// Option of the passphrase used for encryption
    pub passphrase: Option<String>,
}

/// Configuration option for a user node
#[derive(Debug, Clone, Deserialize)]
pub struct UserNodeConfig {
    /// Index of the current node in user_addrs
    pub user_node_idx: usize,
    /// Use specific database
    pub user_db_mode: DbMode,
    /// Configuration for handling TLS
    pub tls_config: TlsSpec,
    /// Initial API keys
    pub api_keys: Vec<String>,
    /// Index of the compute node to use in compute_nodes
    pub user_compute_node_idx: usize,
    /// Peer node index in user_nodes
    pub peer_user_node_idx: usize,
    /// All compute nodes addresses
    pub compute_nodes: Vec<NodeSpec>,
    /// All storage nodes addresses: only use first
    pub storage_nodes: Vec<NodeSpec>,
    /// All miner nodes addresses
    pub miner_nodes: Vec<NodeSpec>,
    /// All peer user nodes addresses
    pub user_nodes: Vec<NodeSpec>,
    /// API port
    pub user_api_port: u16,
    /// API use TLS
    pub user_api_use_tls: bool,
    /// Wallet seeds
    pub user_wallet_seeds: Vec<Vec<WalletTxSpec>>,
    /// Option of the passphrase used for encryption
    pub passphrase: Option<String>,
    /// Will donate amount to all unkown incomming payment request.
    /// Only enable in test net for the distribution users.
    pub user_auto_donate: u64,
    /// Configuration options for auto generating transactions for test
    pub user_test_auto_gen_setup: UserAutoGenTxSetup,
}

/// Configuration option for a pre-launch node
#[derive(Debug, Clone, Deserialize)]
pub struct PreLaunchNodeConfig {
    /// Type of node to launch
    pub node_type: PreLaunchNodeType,
    /// Index of the current node in compute_nodes
    pub compute_node_idx: usize,
    /// Use specific database
    pub compute_db_mode: DbMode,
    /// Configuration for handling TLS
    pub tls_config: TlsSpec,
    /// Index of the current node in compute_nodes
    pub storage_node_idx: usize,
    /// Use specific database
    pub storage_db_mode: DbMode,
    /// All compute nodes addresses
    pub compute_nodes: Vec<NodeSpec>,
    /// All storage nodes addresses: only use first
    pub storage_nodes: Vec<NodeSpec>,
}

/// Type of node in pre-launch mode
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum PreLaunchNodeType {
    Compute,
    Storage,
}

/// Configuration option for setup of user node
#[derive(Default, Debug, Clone, Deserialize)]
pub struct UserAutoGenTxSetup {
    /// Transaction seeds, for each users
    pub user_initial_transactions: Vec<Vec<WalletTxSpec>>,
    /// How many transaction to group in each requests
    pub user_setup_tx_chunk_size: Option<usize>,
    /// How many TxIn to have for each transactions
    pub user_setup_tx_in_per_tx: Option<usize>,
    /// How many Txin to have for that user at each round
    pub user_setup_tx_max_count: usize,
}

/// Extra params for Node construction
#[derive(Default)]
pub struct ExtraNodeParams {
    pub db: Option<SimpleDb>,
    pub raft_db: Option<SimpleDb>,
    pub wallet_db: Option<SimpleDb>,
    pub shared_wallet_db: Option<WalletDb>,
}

///Hacky deserializer to work around deserializatio error with u128
fn deserialize_token_amount<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<TokenAmount, D::Error> {
    let value: u64 = serde::Deserialize::deserialize(deserializer)?;
    Ok(TokenAmount(value as u64))
}
