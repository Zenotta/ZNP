use crate::db_utils::SimpleDbSpec;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

pub mod constants {
    pub const NETWORK_VERSION: u32 = 3;
    pub const NETWORK_VERSION_SERIALIZED: Option<&[u8]> = Some(b"3");
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
    pub type Nonce = Vec<u8>;
    pub type Salt = Vec<u8>;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Block {
        pub header: BlockHeader,
        pub transactions: Vec<String>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct BlockHeader {
        pub version: u32,
        pub bits: usize,
        pub nonce_and_mining_tx_hash: (Vec<u8>, String),
        pub b_num: u64,
        pub seed_value: Vec<u8>, // for commercial
        pub previous_hash: Option<String>,
        pub txs_merkle_root_and_hash: (String, String),
    }

    //
    // Transaction
    //

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct Transaction {
        pub inputs: Vec<TxIn>,
        pub outputs: Vec<TxOut>,
        pub version: usize,
        pub druid_info: Option<DdeValues>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct DdeValues {
        pub druid: String,
        pub participants: usize,
        pub expectations: Vec<DruidExpectation>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct DruidExpectation {
        pub from: String,
        pub to: String,
        pub asset: Asset,
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
        OP_CREATE = 0x6d,
        OP_HASH256_V0 = 0x6e,
        OP_HASH256_TEMP = 0x6f,
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
                0x6d => Ok(Self::OP_CREATE),
                0x6e => Ok(Self::OP_HASH256_V0),
                0x6f => Ok(Self::OP_HASH256_TEMP),
                v => Err(serde::de::Error::custom(format!("Unkown OpCodes x{v:02X}"))),
            }
        }
    }

    //
    // TxOut
    //

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct TxOut {
        pub value: Asset,
        pub locktime: u64,
        pub drs_block_hash: Option<String>,
        pub script_public_key: Option<String>,
    }

    #[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
    pub enum Asset {
        Token(TokenAmount),
        Data(DataAsset),
        Receipt(ReceiptAsset),
    }

    #[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
    pub struct ReceiptAsset {
        pub amount: u64,
        pub drs_tx_hash: Option<String>,
        pub metadata: Option<String>,
    }

    #[derive(
        Deserialize, Serialize, Default, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord,
    )]
    pub struct TokenAmount(pub u64);

    #[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
    pub struct DataAsset {
        pub data: Vec<u8>,
        pub amount: u64,
    }
}

pub mod interfaces {
    use super::naom::{Block, Transaction};
    use super::*;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct StoredSerializingBlock {
        pub block: Block,
    }

    #[derive(Default, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct BlockStoredInfo {
        pub block_hash: String,
        pub block_num: u64,
        pub nonce: Vec<u8>,
        pub mining_transactions: BTreeMap<String, Transaction>,
        pub shutdown: bool,
    }
}

pub mod raft_store {
    pub const HARDSTATE_KEY: &str = "HardStateKey";
    pub const SNAPSHOT_DATA_KEY: &str = "SnaphotDataKey";
    pub const SNAPSHOT_META_KEY: &str = "SnaphotMetaKey";
    pub const ENTRY_KEY: &str = "EntryKey";
    pub const LAST_ENTRY_KEY: &str = "LastEntryKey";
}

pub mod compute {
    use super::*;

    /// Key for local miner list
    pub const REQUEST_LIST_KEY: &str = "RequestListKey";
    pub const USER_NOTIFY_LIST_KEY: &str = "UserNotifyListKey";
    pub const RAFT_KEY_RUN: &str = "RaftKeyRun";

    /// Database columns
    pub const DB_COL_INTERNAL: &str = "internal";
    pub const DB_COL_LOCAL_TXS: &str = "local_transactions";

    // New but compatible with 1.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::DB_PATH,
        suffix: ".compute",
        columns: &[DB_COL_INTERNAL, DB_COL_LOCAL_TXS],
    };
}

pub mod compute_raft {
    use super::block_pipeline::*;
    use super::naom::*;
    use super::*;

    // Only serialize the UtxoSet
    pub type TrackedUtxoSet = UtxoSet;

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::DB_PATH,
        suffix: ".compute_raft",
        columns: &[],
    };

    /// Stub AccumulatingBlockStoredInfo that should not be present in upgrade
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct AccumulatingBlockStoredInfo {}

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum SpecialHandling {
        Shutdown,
        FirstUpgradeBlock,
    }

    /// All fields that are consensused between the RAFT group.
    /// These fields need to be written and read from a committed log event.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ComputeConsensused {
        pub unanimous_majority: usize,
        pub sufficient_majority: usize,
        pub partition_full_size: usize,
        pub tx_pool: BTreeMap<String, Transaction>,
        pub tx_druid_pool: Vec<BTreeMap<String, Transaction>>,
        pub tx_current_block_previous_hash: Option<String>,
        pub initial_utxo_txs: Option<BTreeMap<String, Transaction>>,
        pub utxo_set: TrackedUtxoSet,
        pub current_block_stored_info:
            BTreeMap<Vec<u8>, (AccumulatingBlockStoredInfo, BTreeSet<u64>)>,
        pub last_committed_raft_idx_and_term: (u64, u64),
        pub current_circulation: TokenAmount,
        pub block_pipeline: MiningPipelineInfo,
        pub last_mining_transaction_hashes: Vec<String>,
        pub special_handling: Option<SpecialHandling>,
    }
}

pub mod unicorn {
    use super::*;
    use crate::utils::rug_integer;
    use rug::Integer;

    #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
    pub struct Unicorn {
        pub iterations: u64,
        pub security_level: u32,
        #[serde(with = "rug_integer")]
        pub seed: Integer,
        #[serde(with = "rug_integer")]
        pub modulus: Integer,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
    pub struct UnicornFixedParam {
        pub modulus: String,
        pub iterations: u64,
        pub security: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
    pub struct UnicornInfo {
        pub unicorn: Unicorn,
        pub g_value: String,
        #[serde(with = "rug_integer")]
        pub witness: Integer,
    }
}

pub mod raft {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    pub struct RaftContextKey {
        pub proposer_id: u64,
        pub proposer_run: u64,
        pub proposal_id: u64,
    }
}

pub mod block_pipeline {
    use std::net::SocketAddr;

    use super::naom::*;
    use super::unicorn::UnicornInfo;
    use super::*;

    /// Different states of the mining pipeline
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    pub enum MiningPipelineStatus {
        Halted,
        ParticipantOnlyIntake,
        AllItemsIntake,
    }

    /// Participants collection (unsorted: given order, and lookup collection)
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Participants {
        unsorted: Vec<SocketAddr>,
        lookup: BTreeSet<SocketAddr>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct WinningPoWInfo {
        pub nonce: Vec<u8>,
        pub mining_tx: (String, Transaction),
        pub p_value: u8,
        pub d_value: u8,
    }

    /// Rolling info particular to a specific mining pipeline
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MiningPipelineInfo {
        pub participants_intake: BTreeMap<u64, Participants>,
        pub participants_mining: BTreeMap<u64, Participants>,
        pub empty_participants: Participants,
        pub last_winning_hashes: BTreeSet<String>,
        pub all_winning_pow: Vec<(SocketAddr, WinningPoWInfo)>,
        pub unicorn_info: UnicornInfo,
        pub winning_pow: Option<(SocketAddr, WinningPoWInfo)>,
        pub mining_pipeline_status: MiningPipelineStatus,
        pub current_phase_timeout_peer_ids: BTreeSet<u64>,
        pub current_phase_reset_pipeline_peer_ids: BTreeSet<u64>,
        pub unicorn_fixed_param: unicorn::UnicornFixedParam,
        pub current_block_num: Option<u64>,
        pub current_block: Option<Block>,
        pub current_block_tx: BTreeMap<String, Transaction>,
        pub current_reward: TokenAmount,
        pub proposed_keys: BTreeSet<raft::RaftContextKey>,
    }
}

pub mod storage {
    use super::*;

    /// Key storing current proposer run
    pub const RAFT_KEY_RUN: &str = "RaftKeyRun";
    pub const LAST_CONTIGUOUS_BLOCK_KEY: &str = "LastContiguousBlockKey";

    /// Database columns
    pub const DB_COL_INTERNAL: &str = "internal";
    pub const DB_COL_BC_ALL: &str = "block_chain_all";
    pub const DB_COL_BC_NAMED: &str = "block_chain_named";
    pub const DB_COL_BC_META: &str = "block_chain_meta";
    pub const DB_COL_BC_JSON: &str = "block_chain_json";
    pub const DB_COL_BC_V0_5_0: &str = "block_chain_v0.5.0";
    pub const DB_COL_BC_V0_4_0: &str = "block_chain_v0.4.0";
    pub const DB_COL_BC_V0_3_0: &str = "block_chain_v0.3.0";
    pub const DB_COL_BC_V0_2_0: &str = "block_chain_v0.2.0";

    /// Version columns
    pub const DB_COLS_BC: &[(&str, u32)] = &[
        (DB_COL_BC_V0_5_0, 3),
        (DB_COL_BC_V0_4_0, 2),
        (DB_COL_BC_V0_3_0, 1),
        (DB_COL_BC_V0_2_0, 0),
    ];
    pub const DB_POINTER_SEPARATOR: u8 = b':';

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::DB_PATH,
        suffix: ".storage",
        columns: &[
            DB_COL_INTERNAL,
            DB_COL_BC_ALL,
            DB_COL_BC_NAMED,
            DB_COL_BC_META,
            DB_COL_BC_JSON,
            DB_COL_BC_V0_5_0,
            DB_COL_BC_V0_4_0,
            DB_COL_BC_V0_3_0,
            DB_COL_BC_V0_2_0,
        ],
    };
}

pub mod storage_raft {
    use super::interfaces::BlockStoredInfo;
    use super::*;

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::DB_PATH,
        suffix: ".storage_raft",
        columns: &[],
    };

    /// Stub CompleteBlockBuilder that should not be present in upgrade
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CompleteBlockBuilder {}

    /// All fields that are consensused between the RAFT group.
    /// These fields need to be written and read from a committed log event.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct StorageConsensused {
        pub sufficient_majority: usize,
        pub current_block_num: u64,
        pub current_block_completed_parts: BTreeMap<Vec<u8>, CompleteBlockBuilder>,
        pub last_committed_raft_idx_and_term: (u64, u64),
        pub last_block_stored: Option<BlockStoredInfo>,
    }
}

pub mod wallet {
    use super::naom::{
        Asset, Nonce, OutPoint, PublicKey, Salt, SecretKey, TokenAmount, Transaction,
    };
    use super::*;

    pub const KNOWN_ADDRESS_KEY: &str = "a";
    pub const FUND_KEY: &str = "f";
    pub const MASTER_KEY_STORE_KEY: &str = "MasterKeyStore";
    pub const TX_GENERATOR_KEY: &str = "TxGeneratorKey";
    pub const LAST_COINBASE_KEY: &str = "LastCoinbaseKey";
    pub const MINING_ADDRESS_KEY: &str = "MiningAddressKey";

    // New but compatible with 0.2.0
    pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
        db_path: constants::WALLET_PATH,
        suffix: "",
        columns: &[],
    };

    pub type WalletSavedTransactions = BTreeMap<OutPoint, Asset>;

    pub type PendingMap = BTreeMap<String, (Transaction, Vec<(String, OutPoint, TokenAmount)>)>;
    pub type ReadyMap = BTreeMap<String, Vec<(OutPoint, TokenAmount)>>;
    pub type TransactionGenSer = (PendingMap, ReadyMap);

    pub type LastCoinbase = (String, Transaction);

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MasterKeyStore {
        pub salt: Salt,
        pub nonce: Nonce,
        pub enc_master_key: Vec<u8>,
    }

    #[derive(Default, Debug, Clone, Serialize, Deserialize)]
    pub struct FundStore {
        pub running_total: AssetValues,
        pub transactions: BTreeMap<OutPoint, Asset>,
        pub transaction_pages: Vec<BTreeMap<OutPoint, Asset>>, //Vec holding redundent paged version of entries in transactions.
        pub spent_transactions: BTreeMap<OutPoint, Asset>,
    }

    #[derive(Default, Debug, Clone, Serialize, Deserialize)]
    pub struct AssetValues {
        pub tokens: TokenAmount,
        // Note: Receipts from create transactions will have `drs_tx_hash` = `t_hash`
        pub receipts: BTreeMap<String, u64>, /* `drs_tx_hash` - amount */
    }

    pub type KnownAddresses = Vec<String>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AddressStore {
        pub public_key: PublicKey,
        pub secret_key: SecretKey,
        pub address_version: Option<u64>,
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
    use crate::unicorn::UnicornFixedParam;
    use crate::{compute_raft, interfaces, storage_raft, transaction_gen, wallet};
    use naom::crypto::sign_ed25519::{PublicKey, SecretKey, Signature};
    use naom::primitives::asset::{AssetValues, ReceiptAsset};
    use naom::primitives::{
        asset::{Asset, DataAsset, TokenAmount},
        block::{Block, BlockHeader},
        druid::{DdeValues, DruidExpectation},
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
            nonce_and_mining_tx_hash: old.nonce_and_mining_tx_hash,
            b_num: old.b_num,
            seed_value: old.seed_value,
            previous_hash: old.previous_hash,
            txs_merkle_root_and_hash: old.txs_merkle_root_and_hash,
        }
    }

    pub fn convert_transaction(old: old::naom::Transaction) -> Transaction {
        Transaction {
            inputs: old.inputs.into_iter().map(convert_txin).collect(),
            outputs: old.outputs.into_iter().map(convert_txout).collect(),
            version: old.version,
            druid_info: old.druid_info.map(convert_dde_values),
        }
    }

    pub fn convert_dde_values(old: old::naom::DdeValues) -> DdeValues {
        DdeValues {
            druid: old.druid,
            participants: old.participants,
            expectations: old
                .expectations
                .into_iter()
                .map(convert_druid_expectation)
                .collect(),
        }
    }

    pub fn convert_druid_expectation(old: old::naom::DruidExpectation) -> DruidExpectation {
        DruidExpectation {
            from: old.from,
            to: old.to,
            asset: convert_asset(old.asset),
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
            old::naom::StackEntry::Signature(v) => StackEntry::Signature(convert_signature(v)),
            old::naom::StackEntry::PubKey(v) => StackEntry::PubKey(convert_public_key(v)),
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
            old::naom::OpCodes::OP_CREATE => OpCodes::OP_CREATE,
            old::naom::OpCodes::OP_HASH256_V0 => OpCodes::OP_HASH256_V0,
            old::naom::OpCodes::OP_HASH256_TEMP => OpCodes::OP_HASH256_TEMP,
        }
    }

    pub fn convert_txout(old: old::naom::TxOut) -> TxOut {
        TxOut {
            value: convert_asset(old.value),
            locktime: old.locktime,
            drs_block_hash: old.drs_block_hash,
            script_public_key: old.script_public_key,
        }
    }

    pub fn convert_asset(old: old::naom::Asset) -> Asset {
        match old {
            old::naom::Asset::Token(v) => Asset::Token(convert_token_amount(v)),
            old::naom::Asset::Data(v) => Asset::Data(convert_data_asset(v)),
            old::naom::Asset::Receipt(v) => Asset::Receipt(convert_receipt_asset(v)),
        }
    }

    pub fn convert_receipt_asset(old: old::naom::ReceiptAsset) -> ReceiptAsset {
        ReceiptAsset {
            amount: old.amount,
            drs_tx_hash: old.drs_tx_hash,
            metadata: old.metadata,
        }
    }

    /// Keep all existing DRS transaction hash values as is
    pub fn convert_receipt_amount(old: BTreeMap<String, u64>) -> BTreeMap<String, u64> {
        old
    }

    pub fn convert_data_asset(old: old::naom::DataAsset) -> DataAsset {
        DataAsset {
            data: old.data,
            amount: old.amount,
        }
    }

    pub fn convert_token_amount(old: old::naom::TokenAmount) -> TokenAmount {
        TokenAmount(old.0)
    }

    pub fn convert_token_to_asset(old: old::naom::TokenAmount) -> Asset {
        Asset::Token(convert_token_amount(old))
    }

    // TODO: This should get used in upgrade when the key-pair structure changes
    pub fn convert_address_store(old: old::wallet::AddressStore) -> wallet::AddressStore {
        wallet::AddressStore {
            public_key: convert_public_key(old.public_key),
            secret_key: convert_secret_key(old.secret_key),
            address_version: old.address_version,
        }
    }

    pub fn convert_public_key(old: old::naom::PublicKey) -> PublicKey {
        PublicKey::from_slice(&old).unwrap()
    }

    pub fn convert_secret_key(old: old::naom::SecretKey) -> SecretKey {
        SecretKey::from_slice(&old).unwrap()
    }

    pub fn convert_signature(old: old::naom::Signature) -> Signature {
        Signature::from_slice(&old).unwrap()
    }

    pub fn convert_fund_store(old: old::wallet::FundStore) -> wallet::FundStore {
        wallet::FundStore::new(
            convert_asset_values(old.running_total),
            convert_saved_wallet_transactions(old.transactions),
            convert_saved_wallet_transactions_pages(old.transaction_pages),
            convert_saved_wallet_transactions(old.spent_transactions),
        )
    }

    pub fn convert_asset_values(old: old::wallet::AssetValues) -> AssetValues {
        AssetValues {
            tokens: convert_token_amount(old.tokens),
            receipts: convert_receipt_amount(old.receipts),
        }
    }

    pub fn convert_saved_wallet_transactions(
        old: old::wallet::WalletSavedTransactions,
    ) -> BTreeMap<OutPoint, Asset> {
        old.into_iter()
            .map(|(k, v)| (convert_outpoint(k), convert_asset(v)))
            .collect()
    }

    //Creares pages from the frozen transactions
    pub fn convert_saved_wallet_transactions_pages(
        old: Vec<BTreeMap<old::naom::OutPoint, old::naom::Asset>>,
    ) -> Vec<BTreeMap<OutPoint, Asset>> {
        old.iter()
            .map(|page| {
                page.iter()
                    .map(|(k, v)| (convert_outpoint(k.clone()), convert_asset(v.clone())))
                    .collect()
            })
            .collect()
    }

    pub fn convert_compute_consensused_to_import(
        old: old::compute_raft::ComputeConsensused,
        special_handling: Option<compute_raft::SpecialHandling>,
    ) -> compute_raft::ComputeConsensusedImport {
        compute_raft::ComputeConsensusedImport {
            unanimous_majority: old.unanimous_majority,
            sufficient_majority: old.sufficient_majority,
            partition_full_size: old.partition_full_size,
            unicorn_fixed_param: convert_unicorn_fixed_param(
                old.block_pipeline.unicorn_fixed_param,
            ),
            tx_current_block_num: old.block_pipeline.current_block_num,
            current_block: old.block_pipeline.current_block.map(convert_block),
            utxo_set: convert_utxoset(old.utxo_set),
            last_committed_raft_idx_and_term: old.last_committed_raft_idx_and_term,
            current_circulation: convert_token_amount(old.current_circulation),
            special_handling,
        }
    }

    pub fn convert_unicorn_fixed_param(old: old::unicorn::UnicornFixedParam) -> UnicornFixedParam {
        UnicornFixedParam {
            modulus: old.modulus,
            iterations: old.iterations,
            security: old.security,
        }
    }

    pub fn convert_utxoset(old: old::naom::UtxoSet) -> interfaces::UtxoSet {
        old.into_iter()
            .map(|(op, out)| (convert_outpoint(op), convert_txout(out)))
            .collect()
    }

    pub fn convert_storage_consensused_to_import(
        old: old::storage_raft::StorageConsensused,
    ) -> storage_raft::StorageConsensusedImport {
        storage_raft::StorageConsensusedImport {
            sufficient_majority: old.sufficient_majority,
            current_block_num: old.current_block_num,
            last_committed_raft_idx_and_term: old.last_committed_raft_idx_and_term,
            last_block_stored: old.last_block_stored.map(convert_block_stored_info),
        }
    }

    pub fn convert_block_stored_info(
        old: old::interfaces::BlockStoredInfo,
    ) -> interfaces::BlockStoredInfo {
        interfaces::BlockStoredInfo {
            block_hash: old.block_hash,
            block_num: old.block_num,
            nonce: old.nonce,
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

    pub fn convert_last_coinbase(old: (String, old::naom::Transaction)) -> (String, Transaction) {
        (old.0, convert_transaction(old.1))
    }

    pub fn convert_transaction_gen(
        (old_pending, old_ready): old::wallet::TransactionGenSer,
    ) -> transaction_gen::TransactionGenSer {
        let (mut pending, mut ready) = transaction_gen::TransactionGenSer::default();
        for (k, v) in old_ready {
            ready.insert(
                k,
                v.into_iter()
                    .map(|(o, a)| (convert_outpoint(o), convert_token_amount(a)))
                    .collect(),
            );
        }
        for (tx_hash, tx) in old_pending {
            // Best effort regenerate the ready input
            let src =
                tx.1.into_iter()
                    .map(|(v, o, a)| (v, convert_outpoint(o), convert_token_amount(a)))
                    .collect();
            pending.insert(tx_hash, (convert_transaction(tx.0), src));
        }

        (pending, ready)
    }
}

pub use convert::*;
