//! This module provide the upgrade functionality.
//! All necessary data structure/deserialization utilities need to
//! be stored in the frozen_last_version module.

mod frozen_last_version;
#[cfg(test)]
mod tests;
#[cfg(test)]
#[rustfmt::skip]
mod tests_last_version_db;

use crate::configurations::{DbMode, ExtraNodeParams, UnicornFixedInfo};
use crate::constants::{
    BLOCK_PREPEND, DB_PATH, DB_VERSION_KEY, FUND_KEY, NETWORK_VERSION_SERIALIZED, TX_PREPEND,
    WALLET_PATH,
};
use crate::db_utils::{
    new_db_no_check_version, new_db_with_version, SimpleDb, SimpleDbError, SimpleDbSpec,
    SimpleDbWriteBatch, DB_COL_DEFAULT,
};
use crate::miner::LAST_COINBASE_KEY;
use crate::utils::StringError;
use crate::{compute, compute_raft, raft_store, storage, storage_raft, user, wallet};
use bincode::{deserialize, serialize};
use frozen_last_version as old;
use std::error::Error;
use std::fmt;
use tracing::error;

pub const DB_SPEC_INFOS: &[DbSpecInfo] = &[
    DbSpecInfo {
        node_type: "compute",
        db_path: DB_PATH,
        suffix: ".compute",
    },
    DbSpecInfo {
        node_type: "compute",
        db_path: DB_PATH,
        suffix: ".compute_raft",
    },
    DbSpecInfo {
        node_type: "storage",
        db_path: DB_PATH,
        suffix: ".storage",
    },
    DbSpecInfo {
        node_type: "storage",
        db_path: DB_PATH,
        suffix: ".storage_raft",
    },
    DbSpecInfo {
        node_type: "miner",
        db_path: WALLET_PATH,
        suffix: "",
    },
    DbSpecInfo {
        node_type: "user",
        db_path: WALLET_PATH,
        suffix: "",
    },
];

/// Result wrapper for upgrade errors
pub type Result<T> = std::result::Result<T, UpgradeError>;

/// Status info on the upgrade
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeStatus {
    pub last_block_num: Option<u64>,
    pub last_raft_block_num: Option<u64>,
}

/// Configuration passed in to drive upgrade
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeCfg {
    pub raft_len: usize,
    pub compute_partition_full_size: usize,
    pub compute_unicorn_fixed_param: UnicornFixedInfo,
    pub passphrase: String,
}

#[derive(Debug)]
pub struct DbSpecInfo {
    pub node_type: &'static str,
    pub db_path: &'static str,
    pub suffix: &'static str,
}

#[derive(Debug)]
pub enum UpgradeError {
    ConfigError(&'static str),
    DbError(SimpleDbError),
    Serialization(bincode::Error),
    StringError(StringError),
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigError(err) => write!(f, "Config error: {}", err),
            Self::DbError(err) => write!(f, "DB error: {}", err),
            Self::Serialization(err) => write!(f, "Serialization error: {}", err),
            Self::StringError(err) => write!(f, "String error: {}", err),
        }
    }
}

impl Error for UpgradeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConfigError(_) => None,
            Self::DbError(ref e) => Some(e),
            Self::Serialization(ref e) => Some(e),
            Self::StringError(ref e) => Some(e),
        }
    }
}

impl From<SimpleDbError> for UpgradeError {
    fn from(other: SimpleDbError) -> Self {
        Self::DbError(other)
    }
}

impl From<bincode::Error> for UpgradeError {
    fn from(other: bincode::Error) -> Self {
        Self::Serialization(other)
    }
}

impl From<StringError> for UpgradeError {
    fn from(other: StringError) -> Self {
        Self::StringError(other)
    }
}

/// Upgrade DB: New column are added at begining of upgrade and old one removed at the end.
pub fn get_upgrade_compute_db(
    db_mode: DbMode,
    old_dbs: ExtraNodeParams,
) -> Result<ExtraNodeParams> {
    let spec = &old::compute::DB_SPEC;
    let raft_spec = &old::compute_raft::DB_SPEC;
    let version = old::constants::NETWORK_VERSION_SERIALIZED;
    let db = new_db_with_version(db_mode, spec, version, old_dbs.db)?;
    let raft_db = new_db_with_version(db_mode, raft_spec, version, old_dbs.raft_db)?;

    Ok(ExtraNodeParams {
        db: Some(db),
        raft_db: Some(raft_db),
        ..Default::default()
    })
}

/// Upgrade DB: upgrade ready given db  .
pub fn upgrade_compute_db(
    mut dbs: ExtraNodeParams,
    upgrade_cfg: &UpgradeCfg,
) -> Result<(ExtraNodeParams, UpgradeStatus)> {
    let db = dbs.db.as_mut().unwrap();
    let raft_db = dbs.raft_db.as_mut().unwrap();

    let (batch, raft_batch, status) = upgrade_compute_db_batch(
        (db, raft_db),
        (db.batch_writer(), raft_db.batch_writer()),
        upgrade_cfg,
    )?;
    let (batch, raft_batch) = (batch.done(), raft_batch.done());

    db.write(batch)?;
    raft_db.write(raft_batch)?;
    Ok((dbs, status))
}

/// Upgrade DB: all columns new and old are expected to be opened
pub fn upgrade_compute_db_batch<'a>(
    (db, raft_db): (&SimpleDb, &SimpleDb),
    (mut batch, mut raft_batch): (SimpleDbWriteBatch<'a>, SimpleDbWriteBatch<'a>),
    upgrade_cfg: &UpgradeCfg,
) -> Result<(
    SimpleDbWriteBatch<'a>,
    SimpleDbWriteBatch<'a>,
    UpgradeStatus,
)> {
    let mut status = UpgradeStatus::default();
    batch.put_cf(DB_COL_DEFAULT, DB_VERSION_KEY, NETWORK_VERSION_SERIALIZED);
    raft_batch.put_cf(DB_COL_DEFAULT, DB_VERSION_KEY, NETWORK_VERSION_SERIALIZED);
    batch.put_cf(compute::DB_COL_INTERNAL, compute::RAFT_KEY_RUN, key_run()?);

    let column = compute::DB_COL_INTERNAL;
    for (key, value) in db.iter_cf_clone(column) {
        if key == old::compute::REQUEST_LIST_KEY.as_bytes()
            || key == old::compute::USER_NOTIFY_LIST_KEY.as_bytes()
        {
            batch.delete_cf(column, &key);
        } else if key == compute::RAFT_KEY_RUN.as_bytes() {
            // Keep modified
        } else {
            return Err(key_value_error("Unexpected key", &key, &value));
        }
    }

    let column = compute::DB_COL_LOCAL_TXS;
    for (key, _) in db.iter_cf_clone(column) {
        batch.delete_cf(column, &key);
    }

    clean_raft_db(raft_db, &mut raft_batch, |k, v| {
        let mut consensus = old::convert_compute_consensused_to_import(
            tracked_deserialize("ComputeConsensused", k, &v)?,
            Some(compute_raft::SpecialHandling::FirstUpgradeBlock),
        );

        status.last_raft_block_num = consensus.tx_current_block_num;

        // Already mined block it would have been discarded when PoW found.
        consensus.current_block = None;

        let consensus = compute_raft::ComputeConsensused::from_import(consensus)
            .with_peers_len(upgrade_cfg.raft_len)
            .with_partition_full_size(upgrade_cfg.compute_partition_full_size)
            .with_unicorn_fixed_param(upgrade_cfg.compute_unicorn_fixed_param.clone())
            .init_block_pipeline_status();

        Ok(serialize(&consensus)?)
    })?;

    Ok((batch, raft_batch, status))
}

/// Update the database to be as if it had just been upgraded
pub fn upgrade_same_version_compute_db(mut dbs: ExtraNodeParams) -> Result<ExtraNodeParams> {
    let db = dbs.db.as_mut().unwrap();
    let raft_db = dbs.raft_db.as_mut().unwrap();

    let (mut batch, mut raft_batch) = (db.batch_writer(), raft_db.batch_writer());

    let column = compute::DB_COL_INTERNAL;
    for (key, value) in db.iter_cf_clone(column) {
        if key == compute::REQUEST_LIST_KEY.as_bytes()
            || key == compute::USER_NOTIFY_LIST_KEY.as_bytes()
            || key == compute::POW_RANDOM_NUM_KEY.as_bytes()
        {
            batch.delete_cf(column, &key);
        } else if key == compute::RAFT_KEY_RUN.as_bytes() {
            // Keep modified
        } else {
            return Err(key_value_error("Unexpected key", &key, &value));
        }
    }

    let column = compute::DB_COL_LOCAL_TXS;
    for (key, _) in db.iter_cf_clone(column) {
        batch.delete_cf(column, &key);
    }

    clean_same_raft_db(raft_db, &mut raft_batch, |k, v| {
        let mut consensus = compute_raft::ComputeConsensused::into_import(
            tracked_deserialize("ComputeConsensused", k, &v)?,
            Some(compute_raft::SpecialHandling::FirstUpgradeBlock),
        );
        // Version 0.3.0 coordinated shutdown should never have a block in snapshoot
        consensus.current_block = None;
        Ok(serialize(&compute_raft::ComputeConsensused::from_import(
            consensus,
        ))?)
    })?;

    let (batch, raft_batch) = (batch.done(), raft_batch.done());
    db.write(batch)?;
    raft_db.write(raft_batch)?;
    Ok(dbs)
}

/// Upgrade DB: New column are added at begining of upgrade and old one removed at the end.
pub fn get_upgrade_storage_db(
    db_mode: DbMode,
    old_dbs: ExtraNodeParams,
) -> Result<ExtraNodeParams> {
    let spec = &old::storage::DB_SPEC;
    let raft_spec = &old::storage_raft::DB_SPEC;
    let version = old::constants::NETWORK_VERSION_SERIALIZED;
    let mut db = new_db_with_version(db_mode, spec, version, old_dbs.db)?;
    let raft_db = new_db_with_version(db_mode, raft_spec, version, old_dbs.raft_db)?;

    db.upgrade_create_missing_cf(storage::DB_COL_BC_NOW)?;
    Ok(ExtraNodeParams {
        db: Some(db),
        raft_db: Some(raft_db),
        ..Default::default()
    })
}

/// Upgrade DB: upgrade ready given db  .
pub fn upgrade_storage_db(
    mut dbs: ExtraNodeParams,
    upgrade_cfg: &UpgradeCfg,
) -> Result<(ExtraNodeParams, UpgradeStatus)> {
    let db = dbs.db.as_mut().unwrap();
    let raft_db = dbs.raft_db.as_mut().unwrap();

    let (batch, raft_batch, status) = upgrade_storage_db_batch(
        (db, raft_db),
        (db.batch_writer(), raft_db.batch_writer()),
        upgrade_cfg,
    )?;
    let (batch, raft_batch) = (batch.done(), raft_batch.done());

    db.write(batch)?;
    raft_db.write(raft_batch)?;
    Ok((dbs, status))
}

/// Upgrade DB: all columns new and old are expected to be opened
pub fn upgrade_storage_db_batch<'a>(
    (db, raft_db): (&SimpleDb, &SimpleDb),
    (mut batch, mut raft_batch): (SimpleDbWriteBatch<'a>, SimpleDbWriteBatch<'a>),
    upgrade_cfg: &UpgradeCfg,
) -> Result<(
    SimpleDbWriteBatch<'a>,
    SimpleDbWriteBatch<'a>,
    UpgradeStatus,
)> {
    let mut status = UpgradeStatus::default();
    batch.put_cf(DB_COL_DEFAULT, DB_VERSION_KEY, NETWORK_VERSION_SERIALIZED);
    raft_batch.put_cf(DB_COL_DEFAULT, DB_VERSION_KEY, NETWORK_VERSION_SERIALIZED);
    batch.put_cf(storage::DB_COL_INTERNAL, storage::RAFT_KEY_RUN, key_run()?);

    let column = storage::DB_COL_INTERNAL;
    for (key, value) in db.iter_cf_clone(column) {
        if key == storage::RAFT_KEY_RUN.as_bytes()
            || key == storage::LAST_CONTIGUOUS_BLOCK_KEY.as_bytes()
        {
            // Keep modified
        } else {
            return Err(key_value_error("Unexpected key", &key, &value));
        }
    }

    let column = old::storage::DB_COL_BC_V0_3_0;
    for (key, value) in db.iter_cf_clone(column) {
        if is_transaction_key(&key) {
            let _: old::naom::Transaction = tracked_deserialize("Tx deserialize", &key, &value)?;
        } else if is_block_key(&key) {
            let stored_block: old::interfaces::StoredSerializingBlock =
                tracked_deserialize("Block deserialize", &key, &value)?;
            status.last_block_num =
                std::cmp::max(status.last_block_num, Some(stored_block.block.header.b_num));
        } else {
            return Err(key_value_error("Unexpected key", &key, &value));
        }
    }

    clean_raft_db(raft_db, &mut raft_batch, |k, v| {
        let consensus = old::convert_storage_consensused_to_import(tracked_deserialize(
            "StorageConsensused",
            k,
            &v,
        )?);
        status.last_raft_block_num = Some(consensus.current_block_num);

        let consensus = storage_raft::StorageConsensused::from_import(consensus)
            .with_peers_len(upgrade_cfg.raft_len);
        Ok(serialize(&consensus)?)
    })?;

    Ok((batch, raft_batch, status))
}

/// Update the database to be as if it had just been upgraded
pub fn upgrade_same_version_storage_db(mut dbs: ExtraNodeParams) -> Result<ExtraNodeParams> {
    let db = dbs.db.as_mut().unwrap();
    let raft_db = dbs.raft_db.as_mut().unwrap();

    let (batch, mut raft_batch) = (db.batch_writer(), raft_db.batch_writer());

    let column = storage::DB_COL_INTERNAL;
    for (key, value) in db.iter_cf_clone(column) {
        if key == storage::RAFT_KEY_RUN.as_bytes()
            || key == storage::LAST_CONTIGUOUS_BLOCK_KEY.as_bytes()
        {
            // Keep modified
        } else {
            return Err(key_value_error("Unexpected key", &key, &value));
        }
    }

    clean_same_raft_db(raft_db, &mut raft_batch, |k, v| {
        let mut consensus = storage_raft::StorageConsensused::into_import(tracked_deserialize(
            "StorageConsensused",
            k,
            &v,
        )?);
        if let Some(v) = &mut consensus.last_block_stored {
            v.shutdown = false;
        }
        Ok(serialize(&storage_raft::StorageConsensused::from_import(
            consensus,
        ))?)
    })?;

    let (batch, raft_batch) = (batch.done(), raft_batch.done());
    db.write(batch)?;
    raft_db.write(raft_batch)?;
    Ok(dbs)
}

/// Upgrade raft DB
fn clean_raft_db(
    raft_db: &SimpleDb,
    raft_batch: &mut SimpleDbWriteBatch,
    mut convert: impl FnMut(&[u8], Vec<u8>) -> Result<Vec<u8>>,
) -> Result<()> {
    for (key, value) in raft_db.iter_cf_clone(DB_COL_DEFAULT) {
        if key == DB_VERSION_KEY.as_bytes() {
            // Keep as is
        } else if key == old::raft_store::SNAPSHOT_DATA_KEY.as_bytes() {
            let data = convert(&key, value)?;
            raft_batch.put_cf(DB_COL_DEFAULT, raft_store::SNAPSHOT_DATA_KEY, &data);
        } else if !(key.starts_with(old::raft_store::ENTRY_KEY.as_bytes())
            || key == old::raft_store::HARDSTATE_KEY.as_bytes()
            || key == old::raft_store::LAST_ENTRY_KEY.as_bytes()
            || key == old::raft_store::SNAPSHOT_META_KEY.as_bytes()
            || key == old::raft_store::SNAPSHOT_DATA_KEY.as_bytes())
        {
            return Err(key_value_error("Unexpected raft key", &key, &value));
        }
    }
    Ok(())
}

/// Update the raft database to be as if it had just been upgraded
fn clean_same_raft_db(
    raft_db: &SimpleDb,
    raft_batch: &mut SimpleDbWriteBatch,
    convert: impl Fn(&[u8], Vec<u8>) -> Result<Vec<u8>>,
) -> Result<()> {
    for (key, value) in raft_db.iter_cf_clone(DB_COL_DEFAULT) {
        raft_batch.delete_cf(DB_COL_DEFAULT, &key);

        if key == raft_store::SNAPSHOT_META_KEY.as_bytes() || key == DB_VERSION_KEY.as_bytes() {
            raft_batch.put_cf(DB_COL_DEFAULT, &key, &value);
        } else if key == raft_store::SNAPSHOT_DATA_KEY.as_bytes() {
            raft_batch.put_cf(DB_COL_DEFAULT, &key, &convert(&key, value)?);
        } else if !(key.starts_with(raft_store::ENTRY_KEY.as_bytes())
            || key == raft_store::HARDSTATE_KEY.as_bytes()
            || key == raft_store::LAST_ENTRY_KEY.as_bytes())
        {
            return Err(key_value_error("Unexpected raft key", &key, &value));
        }
    }
    Ok(())
}

/// Upgrade DB: New column are added at begining of upgrade and old one removed at the end.
pub fn get_upgrade_wallet_db(db_mode: DbMode, old_dbs: ExtraNodeParams) -> Result<ExtraNodeParams> {
    let spec = &old::wallet::DB_SPEC;
    let version = old::constants::NETWORK_VERSION_SERIALIZED;
    let db = new_db_with_version(db_mode, spec, version, old_dbs.wallet_db)?;
    Ok(ExtraNodeParams {
        wallet_db: Some(db),
        ..Default::default()
    })
}

/// Upgrade DB: upgrade ready given db  .
pub fn upgrade_wallet_db(
    mut dbs: ExtraNodeParams,
    upgrade_cfg: &UpgradeCfg,
) -> Result<(ExtraNodeParams, UpgradeStatus)> {
    let db = dbs.wallet_db.as_mut().unwrap();
    let (batch, status) = upgrade_wallet_db_batch(db, db.batch_writer(), upgrade_cfg)?;
    let batch = batch.done();
    db.write(batch)?;
    Ok((dbs, status))
}

/// Upgrade DB: all columns new and old are expected to be opened
pub fn upgrade_wallet_db_batch<'a>(
    db: &SimpleDb,
    mut batch: SimpleDbWriteBatch<'a>,
    upgrade_cfg: &UpgradeCfg,
) -> Result<(SimpleDbWriteBatch<'a>, UpgradeStatus)> {
    batch.put_cf(DB_COL_DEFAULT, DB_VERSION_KEY, NETWORK_VERSION_SERIALIZED);

    let passphrase = upgrade_cfg.passphrase.as_bytes();
    let masterkey = wallet::get_or_save_master_key_store(db, &mut batch, passphrase);

    for (key, value) in db.iter_cf_clone(DB_COL_DEFAULT) {
        if key == DB_VERSION_KEY.as_bytes() {
            // Keep as is
        } else if key == old::wallet::TX_GENERATOR_KEY.as_bytes() {
            // Upgrade
            let old_gen: old::wallet::TransactionGenSer =
                tracked_deserialize("TransactionGen deserialize", &key, &value)?;

            let data = serialize(&old::convert_transaction_gen(old_gen))?;
            batch.put_cf(DB_COL_DEFAULT, user::TX_GENERATOR_KEY, &data);
        } else if key == old::wallet::LAST_COINBASE_KEY.as_bytes() {
            // Upgrade
            let old_coinbase: old::wallet::LastCoinbase =
                tracked_deserialize("LastCoinbase deserialize", &key, &value)?;

            let data = serialize(&old::convert_last_coinbase(old_coinbase))?;
            batch.put_cf(DB_COL_DEFAULT, LAST_COINBASE_KEY, &data);
        } else if key == old::wallet::MINING_ADDRESS_KEY.as_bytes() {
            // Keep as is
            let _: String = tracked_deserialize("MiningAddress deserialize", &key, &value)?;
        } else if key == old::wallet::MASTER_KEY_STORE_KEY.as_bytes() {
            // Keep as is
            let _: old::wallet::MasterKeyStore =
                tracked_deserialize("MasterKeyStore deserialize", &key, &value)?;
        } else if key == old::wallet::FUND_KEY.as_bytes() {
            // Upgrade
            let old_fundstore: old::wallet::FundStore =
                tracked_deserialize("FundStore deserialize", &key, &value)?;

            let data = serialize(&old::convert_fund_store(old_fundstore))?;
            batch.put_cf(DB_COL_DEFAULT, FUND_KEY, &data);
        } else if key == old::wallet::KNOWN_ADDRESS_KEY.as_bytes() {
            // Keep as is
            let _: old::wallet::KnownAddresses =
                tracked_deserialize("Known Addresses deserialize", &key, &value)?;
        } else if is_wallet_transaction_store_key(&key) {
            // Keep as is
            let _: old::wallet::TransactionStore =
                tracked_deserialize("Tx Store deserialize", &key, &value)?;
        } else if is_wallet_address_store_key(&key) {
            // Keep as is
            let value = wallet::decrypt_store(value, &masterkey);
            let _: old::wallet::AddressStore =
                tracked_deserialize("Addr Store deserialize", &key, &value)?;
        } else {
            return Err(key_value_error("Key not recognized", &key, &value));
        }
    }

    Ok((batch, UpgradeStatus::default()))
}

/// Update the database to be as if it had just been upgraded
pub fn upgrade_same_version_wallet_db(mut dbs: ExtraNodeParams) -> Result<ExtraNodeParams> {
    let _db = dbs.wallet_db.as_mut().unwrap();
    // Wallet after upgrade is the same as in normal operation
    Ok(dbs)
}

/// whether it is a transaction key
pub fn is_transaction_key(key: &[u8]) -> bool {
    // special genesis block transactions had 6 digits and missed prefix
    key.first() == Some(&TX_PREPEND) || key.len() == 6
}

/// Wallet AddressStore key
fn is_wallet_address_store_key(key: &[u8]) -> bool {
    // 0.2.0 was 32, 0.3.0 is 64
    key.len() == 32 || key.len() == 64
}

/// Wallet TransactionStore key
fn is_wallet_transaction_store_key(key: &[u8]) -> bool {
    // special genesis block transactions had 6 digits and missed prefix
    key.len() == 44 || key.len() == 18
}

/// whether it is a block key
pub fn is_block_key(key: &[u8]) -> bool {
    // 0.2.0 was 64, 0.3.0 is 65 with block prepend char
    key.len() == 64 || (key.len() == 65 && key[0] == BLOCK_PREPEND)
}

/// Open a database for dump doing no checks on validity
pub fn get_db_to_dump_no_checks(
    db_mode: DbMode,
    db_info: &DbSpecInfo,
    old_db: Option<SimpleDb>,
) -> Result<SimpleDb> {
    let spec = SimpleDbSpec {
        db_path: db_info.db_path,
        suffix: db_info.suffix,
        columns: &[],
    };
    Ok(new_db_no_check_version(db_mode, &spec, old_db)?)
}

/// Dump the database as string
pub fn dump_db(db: &'_ SimpleDb) -> impl Iterator<Item = String> + '_ {
    db.iter_all_cf_clone()
        .into_iter()
        .flat_map(|(c, it)| it.map(move |(k, v)| (c.clone(), k, v)))
        .map(|(c, k, v)| (c, to_u8_array_literal(&k), v))
        .map(|(c, k, v)| (c, k, to_u8_array_literal(&v)))
        .map(|(c, k, v)| format!("\"{}\", b\"{}\", b\"{}\"", c, k, v))
}

/// Convert to a valid array literal displaying ASCII nicely
fn to_u8_array_literal(value: &[u8]) -> String {
    let mut result = String::with_capacity(value.len());
    for v in value {
        if v.is_ascii_alphanumeric() || v == &b'_' {
            result.push(*v as char);
        } else {
            format!("{result}\\x{:02X}", v);
        }
    }
    result
}

fn key_value_error(info: &str, key: &[u8], value: &[u8]) -> UpgradeError {
    let log_key = to_u8_array_literal(key);
    let log_value = to_u8_array_literal(value);

    let error = format!("{} \"{}\" -> \"{}\"", info, log_key, log_value);
    error!("{}", &error);

    StringError(error).into()
}

fn tracked_deserialize<'a, T: serde::Deserialize<'a>>(
    tag: &str,
    key: &[u8],
    value: &'a [u8],
) -> Result<T> {
    match deserialize(value) {
        Ok(v) => Ok(v),
        Err(e) => Err(key_value_error(&format!("{}: {:?}", tag, e), key, value)),
    }
}

fn key_run() -> Result<Vec<u8>> {
    // Key run not present in v2: Assume it was 0, so it is incremented on start
    let key_run: u64 = 0;
    Ok(serialize(&key_run)?)
}
