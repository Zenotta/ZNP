use crate::db_utils::SimpleDbSpec;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

pub mod constants {
    pub const NETWORK_VERSION: u32 = 0;
    pub const NETWORK_VERSION_SERIALIZED: Option<&[u8]> = None;
    pub const DB_PATH: &str = "src/db/db";
    pub const WALLET_PATH: &str = "src/wallet/wallet";
}

pub mod naom {
    use super::*;

    //
    // Block
    //
    pub type UtxoSet = BTreeMap<OutPoint, TxOut>;
    pub type PublicKey = Vec<u8>;
    pub type SecretKey = Vec<u8>;
    pub type Signature = Vec<u8>;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StoredSerializingBlock {
        pub block: Block,
        pub mining_tx_hash_and_nonces: BTreeMap<u64, (String, Vec<u8>)>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Block {
        pub header: BlockHeader,
        pub transactions: Vec<String>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct BlockHeader {
        pub version: u32,
        pub bits: usize,
        pub nonce: Vec<u8>,
        pub b_num: u64,
        pub seed_value: Vec<u8>, // for commercial
        pub previous_hash: Option<String>,
        pub merkle_root_hash: String,
    }

    //
    // Transaction
    //

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct Transaction {
        pub inputs: Vec<TxIn>,
        pub outputs: Vec<TxOut>,
        pub version: usize,
        pub druid: Option<String>,
        pub druid_participants: Option<usize>,
        pub expect_value: Option<Asset>,
        pub expect_value_amount: Option<TokenAmount>,
    }

    //
    // TxIn
    //

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct TxIn {
        pub previous_out: Option<OutPoint>,
        pub script_signature: Script,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
    pub struct OutPoint {
        pub t_hash: String,
        pub n: i32,
    }

    #[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
    pub struct Script {
        pub stack: Vec<StackEntry>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
    pub enum StackEntry {
        Op(OpCodes),
        Signature(Signature),
        PubKey(PublicKey),
        PubKeyHash(String),
        Num(usize),
        Bytes(String),
    }

    /// Ops code for stack scripts
    #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
    pub enum OpCodes {
        OP_DUP = 0x2b,
        OP_HASH256 = 0x5d,
        OP_EQUALVERIFY = 0x3d,
        OP_CHECKSIG = 0x5f,
    }

    impl Serialize for OpCodes {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            (*self as u32).serialize(s)
        }
    }

    impl<'a> Deserialize<'a> for OpCodes {
        fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
            let value: u32 = Deserialize::deserialize(deserializer)?;
            match value {
                0x2b => Ok(Self::OP_DUP),
                0x5d => Ok(Self::OP_HASH256),
                0x3d => Ok(Self::OP_EQUALVERIFY),
                0x5f => Ok(Self::OP_CHECKSIG),
                v => Err(serde::de::Error::custom(format!(
                    "Unkown OpCodes x{:02X}",
                    v
                ))),
            }
        }
    }

    //
    // TxOut
    //

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct TxOut {
        pub value: Option<Asset>,
        pub amount: TokenAmount,
        pub locktime: u64,
        pub drs_block_hash: Option<String>,
        pub drs_tx_hash: Option<String>,
        pub script_public_key: Option<String>,
    }

    #[derive(
        Deserialize, Serialize, Default, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord,
    )]
    pub struct TokenAmount(pub u64);

    #[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
    pub enum Asset {
        Token(TokenAmount),
        Data(Vec<u8>),
    }
}

pub mod interfaces {
    use super::naom::Transaction;
    use super::*;

    #[derive(Default, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct BlockStoredInfo {
        pub block_hash: String,
        pub block_num: u64,
        pub nonce: Vec<u8>,
        pub merkle_hash: String,
        pub mining_transactions: BTreeMap<String, Transaction>,
    }
}

pub mod raft_store {
    pub const HARDSTATE_KEY: &str = "HardStateKey";
    pub const SNAPSHOT_KEY: &str = "SnaphotKey";
    pub const ENTRY_KEY: &str = "EntryKey";
    pub const LAST_ENTRY_KEY: &str = "LastEntryKey";
}

pub mod compute {
    use super::*;

    pub const REQUEST_LIST_KEY: &str = "RequestListKey";

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::DB_PATH,
        suffix: ".compute",
        columns: &[],
    };
}

pub mod compute_raft {
    use super::naom::*;
    use super::*;

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::DB_PATH,
        suffix: ".compute_raft",
        columns: &[],
    };

    /// Stub AccumulatingBlockStoredInfo that should not be present in upgrade
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct AccumulatingBlockStoredInfo {}

    /// All fields that are consensused between the RAFT group.
    /// These fields need to be written and read from a committed log event.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct ComputeConsensused {
        pub unanimous_majority: usize,
        pub sufficient_majority: usize,
        pub tx_pool: BTreeMap<String, Transaction>,
        pub tx_druid_pool: Vec<BTreeMap<String, Transaction>>,
        pub tx_current_block_previous_hash: Option<String>,
        pub tx_current_block_num: Option<u64>,
        pub current_block: Option<Block>,
        pub current_block_tx: BTreeMap<String, Transaction>,
        pub initial_utxo_txs: Option<BTreeMap<String, Transaction>>,
        pub utxo_set: UtxoSet,
        pub current_block_stored_info:
            BTreeMap<Vec<u8>, (AccumulatingBlockStoredInfo, BTreeSet<u64>)>,
        pub last_committed_raft_idx_and_term: (u64, u64),
        pub current_circulation: TokenAmount,
        pub current_reward: TokenAmount,
    }
}

pub mod storage {
    use super::*;

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::DB_PATH,
        suffix: ".storage",
        columns: &[],
    };
}

pub mod storage_raft {
    use super::*;

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::DB_PATH,
        suffix: ".storage_raft",
        columns: &[],
    };

    /// Stub CompleteBlock that should not be present in upgrade
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CompleteBlock {}

    /// All fields that are consensused between the RAFT group.
    /// These fields need to be written and read from a committed log event.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct StorageConsensused {
        pub sufficient_majority: usize,
        pub current_block_num: u64,
        pub current_block_complete_timeout_peer_ids: BTreeSet<u64>,
        pub current_block_completed_parts: BTreeMap<Vec<u8>, CompleteBlock>,
        pub last_committed_raft_idx_and_term: (u64, u64),
    }
}

pub mod wallet {
    use super::naom::{OutPoint, PublicKey, SecretKey, TokenAmount};
    use super::*;

    pub const KNOWN_ADDRESS_KEY: &str = "a";
    pub const FUND_KEY: &str = "f";

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::WALLET_PATH,
        suffix: "",
        columns: &[],
    };

    pub type WalletSavedTransactions = BTreeMap<OutPoint, TokenAmount>;
    #[derive(Default, Debug, Clone, Serialize, Deserialize)]
    pub struct FundStore {
        pub running_total: TokenAmount,
        pub transactions: WalletSavedTransactions,
        pub spent_transactions: WalletSavedTransactions,
    }

    pub type KnownAddresses = BTreeSet<String>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AddressStore {
        pub public_key: PublicKey,
        pub secret_key: SecretKey,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct TransactionStore {
        pub key_address: String,
    }
}

pub mod convert {
    mod old {
        pub use super::super::*;
    }
    use crate::{
        compute_raft, interfaces, storage_raft,
        wallet::{self, AssetValues},
    };
    use naom::crypto::sign_ed25519::{PublicKey, SecretKey, Signature};
    use naom::primitives::{
        asset::{Asset, DataAsset, TokenAmount},
        block::{Block, BlockHeader},
        transaction::{OutPoint, Transaction, TxIn, TxOut},
    };
    use naom::script::{lang::Script, OpCodes, StackEntry};
    use std::collections::BTreeMap;

    pub fn convert_block(old: old::naom::Block) -> Block {
        Block {
            header: convert_block_header(old.header),
            transactions: old.transactions,
        }
    }

    pub fn convert_block_header(old: old::naom::BlockHeader) -> BlockHeader {
        BlockHeader {
            version: old.version,
            bits: old.bits,
            nonce: old.nonce,
            b_num: old.b_num,
            seed_value: old.seed_value,
            previous_hash: old.previous_hash,
            merkle_root_hash: old.merkle_root_hash,
        }
    }

    pub fn convert_transaction(old: old::naom::Transaction) -> Transaction {
        Transaction {
            inputs: old.inputs.into_iter().map(convert_txin).collect(),
            outputs: old.outputs.into_iter().map(convert_txout).collect(),
            version: old.version,
            druid_info: None,
        }
    }

    pub fn convert_txin(old: old::naom::TxIn) -> TxIn {
        TxIn {
            previous_out: old.previous_out.map(convert_outpoint),
            script_signature: convert_script(old.script_signature),
        }
    }

    pub fn convert_outpoint(old: old::naom::OutPoint) -> OutPoint {
        OutPoint {
            t_hash: old.t_hash,
            n: old.n,
        }
    }

    pub fn convert_script(old: old::naom::Script) -> Script {
        Script {
            stack: old.stack.into_iter().map(convert_stack_entry).collect(),
        }
    }

    pub fn convert_stack_entry(old: old::naom::StackEntry) -> StackEntry {
        match old {
            old::naom::StackEntry::Op(v) => StackEntry::Op(convert_op_code(v)),
            old::naom::StackEntry::Signature(v) => {
                StackEntry::Signature(Signature::from_slice(&v).unwrap())
            }
            old::naom::StackEntry::PubKey(v) => {
                StackEntry::PubKey(PublicKey::from_slice(&v).unwrap())
            }
            old::naom::StackEntry::PubKeyHash(v) => StackEntry::PubKeyHash(v),
            old::naom::StackEntry::Num(v) => StackEntry::Num(v),
            old::naom::StackEntry::Bytes(v) => StackEntry::Bytes(v),
        }
    }

    pub fn convert_op_code(old: old::naom::OpCodes) -> OpCodes {
        match old {
            old::naom::OpCodes::OP_DUP => OpCodes::OP_DUP,
            old::naom::OpCodes::OP_HASH256 => OpCodes::OP_HASH256,
            old::naom::OpCodes::OP_EQUALVERIFY => OpCodes::OP_EQUALVERIFY,
            old::naom::OpCodes::OP_CHECKSIG => OpCodes::OP_CHECKSIG,
        }
    }

    pub fn convert_txout(old: old::naom::TxOut) -> TxOut {
        TxOut {
            value: convert_asset(old.value, old.amount),
            locktime: old.locktime,
            drs_block_hash: None,
            drs_tx_hash: None,
            script_public_key: old.script_public_key,
        }
    }

    pub fn convert_asset(
        old_val: Option<old::naom::Asset>,
        old_amount: old::naom::TokenAmount,
    ) -> Asset {
        match old_val {
            Some(old::naom::Asset::Token(v)) => Asset::Token(convert_token_amount(v)),
            Some(old::naom::Asset::Data(v)) => Asset::Data(DataAsset {
                data: v,
                amount: old_amount.0,
            }),
            None => Asset::Token(convert_token_amount(old_amount)),
        }
    }

    pub fn convert_token_amount(old: old::naom::TokenAmount) -> TokenAmount {
        TokenAmount(old.0)
    }

    pub fn convert_token_to_asset_value(old: old::naom::TokenAmount) -> AssetValues {
        AssetValues::new(convert_token_amount(old), 0)
    }

    pub fn convert_token_to_asset(old: old::naom::TokenAmount) -> Asset {
        Asset::Token(convert_token_amount(old))
    }

    pub fn convert_address_store(old: old::wallet::AddressStore) -> wallet::AddressStore {
        wallet::AddressStore {
            public_key: convert_public_key(old.public_key),
            secret_key: convert_secret_key(old.secret_key),
            address_version: Some(old::constants::NETWORK_VERSION as u64),
        }
    }

    pub fn convert_public_key(old: old::naom::PublicKey) -> PublicKey {
        PublicKey::from_slice(&old).unwrap()
    }

    pub fn convert_secret_key(old: old::naom::SecretKey) -> SecretKey {
        //
        // Format: ring pkcs8_prefix + Private key + pkcs8_separator + Public key
        //

        // Sequence: 0x30
        // Size 83: 0x53
        // Value: remaining byptes
        //
        // Integer: 0x02
        // Size 01: 0x01
        // Value 01: 0x01  (Version)
        //
        // Sequence: 0x30
        // size 05: 0x05
        // Value: 0x06 0x03 0x2b 0x65 0x70 (Algo)
        //
        // OctetString: 0x04
        // Size 34 : 0x22
        // Value: 0x04 0x20 + Private key bytes (nested private key)
        const PKCS8_PREFIX: &[u8] = &[
            0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];

        // ContextSpecificConstructed1: 0xa1
        // Size 35: 0x23
        // Value: remaining byptes
        //
        // BitString: 0x03
        // Size 33: 0x21
        // unused_bits_at_end: 0: 0x00
        // Value: public key bytes
        const PKCS8_SEPARATOR: &[u8] = &[0xa1, 0x23, 0x03, 0x21, 0x00];

        let mut secret_key = PKCS8_PREFIX.to_vec();
        secret_key.extend_from_slice(&old[..32]);
        secret_key.extend_from_slice(PKCS8_SEPARATOR);
        secret_key.extend_from_slice(&old[32..]);

        SecretKey::from_slice(&secret_key).unwrap()
    }

    pub fn convert_saved_wallet_transactions(
        old: old::wallet::WalletSavedTransactions,
    ) -> BTreeMap<OutPoint, Asset> {
        old.into_iter()
            .map(|(k, v)| (convert_outpoint(k), convert_token_to_asset(v)))
            .collect()
    }

    pub fn convert_fund_store(old: old::wallet::FundStore) -> wallet::FundStore {
        wallet::FundStore::new(
            convert_token_to_asset_value(old.running_total),
            convert_saved_wallet_transactions(old.transactions),
            convert_saved_wallet_transactions(old.spent_transactions),
        )
    }

    pub fn convert_compute_consensused_to_import(
        old: old::compute_raft::ComputeConsensused,
        special_handling: Option<compute_raft::SpecialHandling>,
    ) -> compute_raft::ComputeConsensusedImport {
        compute_raft::ComputeConsensusedImport {
            unanimous_majority: old.unanimous_majority,
            sufficient_majority: old.sufficient_majority,
            partition_full_size: Default::default(),
            unicorn_fixed_param: Default::default(),
            tx_current_block_num: old.tx_current_block_num,
            current_block: old.current_block.map(convert_block),
            utxo_set: convert_utxoset(old.utxo_set),
            last_committed_raft_idx_and_term: old.last_committed_raft_idx_and_term,
            current_circulation: convert_token_amount(old.current_circulation),
            special_handling,
        }
    }

    pub fn convert_utxoset(old: old::naom::UtxoSet) -> interfaces::UtxoSet {
        old.into_iter()
            .map(|(op, out)| (convert_outpoint(op), convert_txout(out)))
            .collect()
    }

    pub fn convert_storage_consensused_to_import(
        old: old::storage_raft::StorageConsensused,
        last_block_stored: Option<interfaces::BlockStoredInfo>,
    ) -> storage_raft::StorageConsensusedImport {
        storage_raft::StorageConsensusedImport {
            sufficient_majority: old.sufficient_majority,
            current_block_num: old.current_block_num,
            last_committed_raft_idx_and_term: old.last_committed_raft_idx_and_term,
            last_block_stored,
        }
    }

    pub fn convert_block_stored_info(
        old: old::interfaces::BlockStoredInfo,
    ) -> interfaces::BlockStoredInfo {
        interfaces::BlockStoredInfo {
            block_hash: old.block_hash,
            block_num: old.block_num,
            nonce: old.nonce,
            merkle_hash: old.merkle_hash,
            mining_transactions: convert_transactions(old.mining_transactions),
            shutdown: false,
        }
    }

    pub fn convert_transactions(
        old: BTreeMap<String, old::naom::Transaction>,
    ) -> BTreeMap<String, Transaction> {
        old.into_iter()
            .map(|(k, v)| (k, convert_transaction(v)))
            .collect()
    }
}
pub use convert::*;
