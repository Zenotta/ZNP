use crate::configurations::{DbMode, WalletTxSpec};
use crate::constants::{FUND_KEY, KNOWN_ADDRESS_KEY, WALLET_PATH};
use crate::db_utils::{
    self, CustomDbSpec, SimpleDb, SimpleDbError, SimpleDbSpec, SimpleDbWriteBatch, DB_COL_DEFAULT,
};
use crate::utils::{get_paiments_for_wallet, make_wallet_tx_info};
use crate::Rs2JsMsg;
use bincode::{deserialize, serialize};
use hex::FromHexError;
use naom::crypto::pbkdf2 as pwhash;
use naom::crypto::secretbox_chacha20_poly1305 as secretbox;
use naom::crypto::sign_ed25519 as sign;
use naom::crypto::sign_ed25519::{PublicKey, SecretKey};
use naom::primitives::asset::{Asset, TokenAmount};
use naom::primitives::transaction::{OutPoint, Transaction, TxConstructor, TxIn, TxOut};
use naom::utils::transaction_utils::{
    construct_address_for, construct_payment_tx_ins, construct_tx_hash,
    construct_tx_in_signable_hash,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::{error, fmt, io};
use tokio::sync::Mutex as TokioMutex;
use tokio::task;
use tracing::warn;
pub mod fund_store;
pub use fund_store::FundStore;

/// Key for locked coinbase transactions
pub const LOCKED_COINBASE_KEY: &str = "LockedCoinbaseKey";

/// Storage key for a &[u8] of the word 'MasterKeyStore'
pub const MASTER_KEY_STORE_KEY: &str = "MasterKeyStore";

pub const DB_SPEC: SimpleDbSpec = SimpleDbSpec {
    db_path: WALLET_PATH,
    suffix: "",
    columns: &[],
};

/// Result wrapper for WalletDb errors
///
/// TODO: Determine the remaining functions that require the `Result` wrapper for error handling
pub type Result<T> = std::result::Result<T, WalletDbError>;

/// Wrapper for a locked coinbase (tx_hash, locktime)
pub type LockedCoinbase = Option<BTreeMap<String, u64>>;
pub type LockedCoinbaseWithMutex = Arc<TokioMutex<LockedCoinbase>>;

/// Enum for errors that occur during WalletDb operations
#[derive(Debug)]
pub enum WalletDbError {
    IO(io::Error),
    AsyncTask(task::JoinError),
    Serialization(bincode::Error),
    Database(SimpleDbError),
    HexError(FromHexError),
    PassphraseError,
    InsufficientFundsError,
    MasterKeyRetrievalError,
    MasterKeyMissingError,
}

impl fmt::Display for WalletDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(err) => write!(f, "I/O Error: {err}"),
            Self::AsyncTask(err) => write!(f, "Async Error: {err}"),
            Self::Serialization(err) => write!(f, "Serialization Error: {err}"),
            Self::Database(err) => write!(f, "Database Error: {err}"),
            Self::HexError(err) => write!(f, "Hex Error: {err}"),
            Self::PassphraseError => write!(f, "PassphraseError"),
            Self::InsufficientFundsError => write!(f, "InsufficientFundsError"),
            Self::MasterKeyRetrievalError => write!(f, "MasterKeyRetrievalError"),
            Self::MasterKeyMissingError => write!(f, "MasterKeyMissingError"),
        }
    }
}

impl error::Error for WalletDbError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::IO(ref e) => Some(e),
            Self::Serialization(ref e) => Some(e),
            Self::AsyncTask(ref e) => Some(e),
            Self::Database(ref e) => Some(e),
            Self::HexError(ref e) => Some(e),
            Self::PassphraseError => None,
            Self::InsufficientFundsError => None,
            Self::MasterKeyRetrievalError => None,
            Self::MasterKeyMissingError => None,
        }
    }
}

impl From<io::Error> for WalletDbError {
    fn from(other: io::Error) -> Self {
        Self::IO(other)
    }
}

impl From<task::JoinError> for WalletDbError {
    fn from(other: task::JoinError) -> Self {
        Self::AsyncTask(other)
    }
}

impl From<bincode::Error> for WalletDbError {
    fn from(other: bincode::Error) -> Self {
        Self::Serialization(other)
    }
}

impl From<SimpleDbError> for WalletDbError {
    fn from(other: SimpleDbError) -> Self {
        Self::Database(other)
    }
}

impl From<FromHexError> for WalletDbError {
    fn from(other: FromHexError) -> Self {
        Self::HexError(other)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressStore {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
    pub address_version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressStoreHex {
    pub public_key: String,
    pub secret_key: String,
    pub address_version: Option<u64>,
}

impl From<AddressStore> for AddressStoreHex {
    fn from(other: AddressStore) -> Self {
        Self {
            public_key: hex::encode(other.public_key.as_ref()),
            secret_key: hex::encode(other.secret_key.as_ref()),
            address_version: other.address_version,
        }
    }
}

impl AddressStore {
    pub fn try_from_hex_store(hex_store: AddressStoreHex) -> Result<Self> {
        let public_key = hex::decode(hex_store.public_key)?;
        let secret_key = hex::decode(hex_store.secret_key)?;
        Ok(Self {
            public_key: PublicKey::from_slice(&public_key)
                .ok_or(WalletDbError::HexError(FromHexError::InvalidStringLength))?,
            secret_key: SecretKey::from_slice(&secret_key)
                .ok_or(WalletDbError::HexError(FromHexError::InvalidStringLength))?,
            address_version: hex_store.address_version,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStore {
    pub key_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterKeyStore {
    pub salt: pwhash::Salt,
    pub nonce: secretbox::Nonce,
    pub enc_master_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WalletDb {
    db: Arc<Mutex<SimpleDb>>,
    encryption_key: secretbox::Key,
    ui_feedback_tx: Option<tokio::sync::mpsc::Sender<Rs2JsMsg>>,
    locked_coinbase: LockedCoinbaseWithMutex,
    last_generated_address: Option<String>,
    last_locked_coinbase_filter_b_num: Option<u64>,
}

impl WalletDb {
    pub fn new(
        db_mode: DbMode,
        db: Option<SimpleDb>,
        passphrase: Option<String>,
        custom_db_spec: Option<CustomDbSpec>,
    ) -> Result<Self> {
        let mut db = db_utils::new_db(db_mode, &DB_SPEC, db, custom_db_spec);
        let mut batch = db.batch_writer();

        let passphrase = passphrase.as_deref().unwrap_or("").as_bytes();
        let masterkey = get_or_save_master_key_store(&db, &mut batch, passphrase)?;

        let batch = batch.done();
        db.write(batch).unwrap();
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            locked_coinbase: Arc::new(TokioMutex::new(None)),
            encryption_key: masterkey,
            ui_feedback_tx: None,
            last_generated_address: None,
            last_locked_coinbase_filter_b_num: None,
        })
    }

    /// Set the UI feedback channel
    ///
    /// ## Arguments
    /// * `tx` - The channel to send UI feedback messages to
    pub fn set_ui_feedback_tx(&mut self, tx: tokio::sync::mpsc::Sender<Rs2JsMsg>) {
        self.ui_feedback_tx = Some(tx);
    }

    /// Set locked coinbase value
    ///
    /// ## Arguments
    /// * `value` - The locked coinbase value
    pub async fn set_locked_coinbase(&mut self, value: LockedCoinbase) {
        let mut locked_coinbase = self.locked_coinbase.lock().await;
        *locked_coinbase = value;
    }

    /// Get locked coinbase mutex
    #[allow(clippy::type_complexity)]
    pub fn get_locked_coinbase_mutex(&self) -> Arc<TokioMutex<LockedCoinbase>> {
        self.locked_coinbase.clone()
    }

    /// Get locked coinbase value
    pub async fn get_locked_coinbase(&self) -> LockedCoinbase {
        self.locked_coinbase.lock().await.clone()
    }

    /// Test old passphrase and then change to a new passphrase
    ///
    /// ### Arguments
    ///
    /// * `old_passphrase`      - Previous passphrase
    /// * `new_passphrase`      - New passphrase
    ///
    pub async fn change_wallet_passphrase(
        &mut self,
        old_passphrase: String,
        new_passphrase: String,
    ) -> Result<()> {
        self.re_encrypt_master_key(old_passphrase, new_passphrase)
            .await?;
        Ok(())
    }

    /// Test passphrase
    ///
    /// This function is used to test the `WalletDb` passphrase
    /// without unnecessarily exposing the master key
    ///
    /// ### Arguments
    ///
    /// * `passphrase` - Current wallet passphrase
    pub async fn test_passphrase(&self, passphrase: String) -> Result<()> {
        self.get_master_key_store(passphrase).await?;
        Ok(())
    }

    /// Get the last generated address
    pub fn get_last_generated_address(&self) -> Option<String> {
        self.last_generated_address.clone()
    }

    /// Get the master key store using a given passphrase
    ///
    ///  ### Arguments
    ///
    /// * `passphrase` - Current wallet passphrase
    pub async fn get_master_key_store(&self, passphrase: String) -> Result<secretbox::Key> {
        let db = self.db.clone();
        task::spawn_blocking(move || {
            let db = db.lock().unwrap();
            get_master_key_store(&db, passphrase.as_bytes())
        })
        .await?
    }

    /// Re-encrypt the master key with a new passphrase
    ///
    /// ### Arguments
    ///
    /// * `new_passphrase`      - Passphrase for master key store.
    async fn re_encrypt_master_key(
        &self,
        old_passphrase: String,
        new_passphrase: String,
    ) -> Result<()> {
        let db = self.db.clone();
        task::spawn_blocking(move || {
            let mut db = db.lock().unwrap();
            let mut batch = db.batch_writer();
            let master_key = get_master_key_store(&db, old_passphrase.as_bytes())?;
            let salt = pwhash::gen_salt();
            let nonce = secretbox::gen_nonce();
            let pass_key = make_key(new_passphrase.as_bytes(), salt);
            let enc_master_key =
                secretbox::seal(master_key.as_ref().to_vec(), &nonce, &pass_key).unwrap();
            let store = serialize(&MasterKeyStore {
                salt,
                nonce,
                enc_master_key,
            })
            .unwrap();
            batch.put_cf(DB_COL_DEFAULT, MASTER_KEY_STORE_KEY, &store);
            let batch = batch.done();
            db.write(batch).unwrap();
            Ok(())
        })
        .await?
    }

    pub async fn with_seed(mut self, seeds: Vec<WalletTxSpec>) -> Self {
        {
            let fund_store = self.get_fund_store();
            let addresses = self.get_known_addresses();
            if !fund_store.transactions().is_empty()
                || !fund_store.spent_transactions().is_empty()
                || !addresses.is_empty()
            {
                return self;
            }
        }

        for seed in seeds {
            let (tx_out_p, pk, sk, amount, v) = make_wallet_tx_info(&seed);
            let (address, _) = self.store_payment_address(pk, sk, v).await;
            let payments = vec![(tx_out_p, Asset::Token(amount), address, 0)];
            self.save_usable_payments_to_wallet(payments, 0)
                .await
                .unwrap();
        }
        self
    }

    /// Extract persistent storage of a closed raft
    pub async fn take_closed_persistent_store(&mut self) -> SimpleDb {
        self.db.lock().unwrap().take()
    }

    /// Backup persistent storage
    pub async fn backup_persistent_store(&mut self) -> Result<()> {
        self.db.lock().unwrap().file_backup()?;
        Ok(())
    }

    /// Generates a new payment address, saving the related keys to the wallet
    /// TODO: Add static address capability for frequent payments
    pub async fn generate_payment_address(&mut self) -> (String, AddressStore) {
        let (public_key, secret_key) = sign::gen_keypair();
        self.store_payment_address(public_key, secret_key, None)
            .await
    }

    /// Store a new payment address, saving the related keys to the wallet
    pub async fn store_payment_address(
        &mut self,
        public_key: PublicKey,
        secret_key: SecretKey,
        address_version: Option<u64>,
    ) -> (String, AddressStore) {
        let final_address = construct_address_for(&public_key, address_version);
        let address_keys = AddressStore {
            public_key,
            secret_key,
            address_version,
        };

        let save_result = self
            .save_address_to_wallet(final_address.clone(), address_keys.clone())
            .await;
        if save_result.is_err() {
            panic!("Error writing address to wallet");
        }

        self.last_generated_address = Some(final_address.clone());

        (final_address, address_keys)
    }

    /// Saves an address and its ancestor keys to the wallet
    ///
    /// ### Arguments
    ///
    /// * `address` - Address to save to wallet
    /// * `keys`    - Address-related keys to save
    pub async fn save_address_to_wallet(&self, address: String, keys: AddressStore) -> Result<()> {
        let db = self.db.clone();
        let encryption_key = self.encryption_key.clone();
        Ok(task::spawn_blocking(move || {
            // Wallet DB handling
            let mut db = db.lock().unwrap();
            let mut batch = db.batch_writer();

            let mut address_list = get_known_key_address(&db);
            address_list.insert(address.clone());

            // Save to disk
            save_address_store_to_wallet(&mut batch, &address, keys, &encryption_key);
            set_known_key_address(&mut batch, address_list);
            let batch = batch.done();
            db.write(batch).unwrap();
        })
        .await?)
    }

    /// Saves an AddressStore to wallet in a directly encrypted state
    ///
    /// ### Arguments
    ///
    /// * `address` - Address to save to wallet
    /// * `keys`    - Address-related keys in an encrypted state
    pub async fn save_encrypted_address_to_wallet(
        &self,
        address: String,
        keys: Vec<u8>,
    ) -> Result<()> {
        let db = self.db.clone();
        Ok(task::spawn_blocking(move || {
            let mut db = db.lock().unwrap();
            let mut batch = db.batch_writer();

            let mut address_list = get_known_key_address(&db);
            address_list.insert(address.clone());

            batch.put_cf(DB_COL_DEFAULT, address, keys);
            set_known_key_address(&mut batch, address_list);

            let batch = batch.done();
            db.write(batch).unwrap();
        })
        .await?)
    }

    /// Saves an address and the associated transaction with it to the wallet
    ///
    /// ### Arguments
    ///
    /// * `out_p`        - Transaction hash/index
    /// * `key_address`  - Transaction Address
    pub async fn save_transaction_to_wallet(
        &self,
        out_p: OutPoint,
        key_address: String,
    ) -> Result<()> {
        let db = self.db.clone();
        Ok(task::spawn_blocking(move || {
            let mut db = db.lock().unwrap();
            let mut batch = db.batch_writer();

            let store = TransactionStore { key_address };
            save_transaction_to_wallet(&mut batch, &out_p, &store);

            let batch = batch.done();
            db.write(batch).unwrap();
        })
        .await?)
    }

    /// Saves a received payment to the local wallet
    ///
    /// ### Arguments
    ///
    /// * `payments` - Payments OutPoint, amount and receiver key address
    /// * `b_num`    - Current block number
    pub async fn save_usable_payments_to_wallet(
        &mut self,
        payments: Vec<(OutPoint, Asset, String, u64)>,
        current_b_num: u64,
    ) -> Result<Vec<(OutPoint, Asset, String, u64)>> {
        let db = self.db.clone();
        let locked_coinbase = self.get_locked_coinbase().await.unwrap_or_default();
        let (result, locked_db) = task::spawn_blocking(move || {
            let mut db = db.lock().unwrap();
            let mut batch = db.batch_writer();
            let mut fund_store = get_fund_store(&db);
            let mut locked_coinbase = locked_coinbase.clone();
            let addresses = get_known_key_address(&db);

            let usable_payments: Vec<_> = payments
                .into_iter()
                .filter(|(_, _, a, _)| addresses.contains(a))
                .collect();

            for (out_p, asset, key_address, locktime) in &usable_payments {
                let key_address = key_address.clone();
                let store = TransactionStore { key_address };
                let asset_to_store = asset.clone().with_fixed_hash(out_p);
                fund_store.store_tx(out_p.clone(), asset_to_store);
                save_transaction_to_wallet(&mut batch, out_p, &store);
                if *locktime > current_b_num {
                    locked_coinbase.insert(out_p.t_hash.clone(), *locktime);
                }
            }

            set_fund_store(&mut batch, fund_store);

            let batch = batch.done();
            db.write(batch).unwrap();
            (usable_payments, locked_coinbase)
        })
        .await?;
        let locked_coinbase = self.store_locked_coinbase(Some(locked_db)).await;
        self.set_locked_coinbase(locked_coinbase).await;
        Ok(result)
    }

    /// Get `Vec<TxIn>` and `Vec<TxOut>` values for a transaction
    ///
    /// ### Arguments
    ///
    /// * `asset_required`              - The required `Asset`
    /// * `tx_outs`                     - Initial `Vec<TxOut>` value
    pub async fn fetch_tx_ins_and_tx_outs(
        &mut self,
        asset_required: Asset,
        tx_outs: Vec<TxOut>,
    ) -> Result<(Vec<TxIn>, Vec<TxOut>)> {
        self.fetch_tx_ins_and_tx_outs_provided_excess(asset_required, tx_outs, None)
            .await
    }

    /// Get `Vec<TxIn>` and `Vec<TxOut>` values for a transaction that merges
    /// provided input addresses to a new address or an excess address
    ///
    /// ### Arguments
    ///
    /// * `asset_required`              - The required `Asset`
    /// * `tx_outs`                     - Initial `Vec<TxOut>` value
    pub async fn fetch_tx_ins_and_tx_outs_merge_input_addrs(
        &mut self,
        input_addresses: BTreeSet<String>,
        excess_address: Option<String>,
    ) -> Result<(Vec<TxIn>, Vec<TxOut>)> {
        let (tx_cons, asset, tx_used) = self
            .fetch_inputs_for_payment_from_supplied_input_addrs(input_addresses)
            .await
            .unwrap();

        let excess_addr = match excess_address {
            Some(excess_addr) => excess_addr,
            None => self.generate_payment_address().await.0,
        };

        let tx_outs: Vec<TxOut> = vec![TxOut::new_asset(excess_addr, asset)];
        let tx_ins = self.consume_inputs_for_payment(tx_cons, tx_used).await;

        Ok((tx_ins, tx_outs))
    }

    /// Get `Vec<TxIn>` and `Vec<TxOut>` values for a transaction
    ///
    /// ### Arguments
    ///
    /// * `asset_required`              - The required `Asset`
    /// * `tx_outs`                     - Initial `Vec<TxOut>` value
    pub async fn fetch_tx_ins_and_tx_outs_provided_excess(
        &mut self,
        asset_required: Asset,
        mut tx_outs: Vec<TxOut>,
        excess_address: Option<String>,
    ) -> Result<(Vec<TxIn>, Vec<TxOut>)> {
        let (tx_cons, total_amount, tx_used) = self
            .fetch_inputs_for_payment(asset_required.clone())
            .await?;

        if let Some(excess) = total_amount.get_excess(&asset_required) {
            let excess_address = match excess_address {
                Some(address) => address,
                None => self.generate_payment_address().await.0,
            };
            tx_outs.push(TxOut::new_asset(excess_address, excess));
        }

        let tx_ins = self.consume_inputs_for_payment(tx_cons, tx_used).await;

        Ok((tx_ins, tx_outs))
    }

    /// Get `Vec<TxIn>` and `Vec<TxOut>` values for a transaction
    ///
    /// ### Arguments
    ///
    /// * `wallet_db`: Mutable ref of the WalletDB instance
    /// * `txs` - Outpoints and Assets which correspond to addresses in the transaction store
    pub async fn fetch_tx_ins_and_tx_outs_from_supplied_txs(
        &mut self,
        txs: Vec<(OutPoint, Asset)>,
    ) -> Result<(Vec<TxIn>, Asset)> {
        let (tx_cons, total_amount, tx_used) = self
            .fetch_inputs_for_payment_from_supplied_txs(txs)
            .await
            .unwrap();

        tracing::trace!("Total amount collected by store {total_amount:?}");

        let tx_ins = self.consume_inputs_for_payment(tx_cons, tx_used).await;

        Ok((tx_ins, total_amount))
    }

    /// Store payment transaction
    ///
    /// ### Arguments
    ///
    /// * `transaction` - Transaction to be received and saved to wallet
    /// * `b_num` - Block number
    pub async fn store_payment_transaction(&mut self, transaction: Transaction, b_num: u64) {
        let hash = construct_tx_hash(&transaction);
        let payments = get_paiments_for_wallet(Some((&hash, &transaction)).into_iter());
        let our_payments = self
            .save_usable_payments_to_wallet(payments, b_num)
            .await
            .unwrap();
        tracing::debug!("store_payment_transactions: {:?}", our_payments);
    }

    /// Fetches valid TxIns based on the wallet's running total and available unspent
    /// transactions, and total value
    ///
    /// TODO: Replace errors here with Error enum types that the Result can return
    /// TODO: Possibly sort addresses found ascending, so that smaller amounts are consumed
    ///
    /// ### Arguments
    ///
    /// * `asset_required` - Asset needed
    pub async fn fetch_inputs_for_payment(
        &self,
        asset_required: Asset,
    ) -> Result<(Vec<TxConstructor>, Asset, Vec<(OutPoint, String)>)> {
        let db = self.db.clone();
        let encryption_key = self.encryption_key.clone();
        let locked_coinbase = self.get_locked_coinbase().await;
        task::spawn_blocking(move || {
            let db = db.lock().unwrap();
            fetch_inputs_for_payment_from_db(&db, asset_required, &encryption_key, &locked_coinbase)
        })
        .await?
    }

    /// Fetches valid TxIns based on the supplied transactions
    ///
    /// TODO: Replace errors here with Error enum types that the Result can return
    ///
    /// ### Arguments
    ///
    /// * `txs` - Outpoints and Assets which correspond to addresses in the transaction store
    pub async fn fetch_inputs_for_payment_from_supplied_input_addrs(
        &self,
        addresses: BTreeSet<String>,
    ) -> Result<(Vec<TxConstructor>, Asset, Vec<(OutPoint, String)>)> {
        let db = self.db.clone();
        let locked_coinbase = self.get_locked_coinbase().await;
        let encryption_key = self.encryption_key.clone();
        task::spawn_blocking(move || {
            let db = db.lock().unwrap();
            fetch_inputs_for_payment_from_supplied_input_addrs_db(
                &db,
                addresses,
                &encryption_key,
                &locked_coinbase,
            )
        })
        .await?
    }

    /// Fetches valid TxIns based on the supplied transactions
    ///
    /// TODO: Replace errors here with Error enum types that the Result can return
    ///
    /// ### Arguments
    ///
    /// * `txs` - Outpoints and Assets which correspond to addresses in the transaction store
    pub async fn fetch_inputs_for_payment_from_supplied_txs(
        &self,
        txs: Vec<(OutPoint, Asset)>,
    ) -> Result<(Vec<TxConstructor>, Asset, Vec<(OutPoint, String)>)> {
        let db = self.db.clone();
        let encryption_key = self.encryption_key.clone();
        task::spawn_blocking(move || {
            let db = db.lock().unwrap();
            fetch_inputs_from_supplied_txs_for_payment_from_db(&db, txs, &encryption_key)
        })
        .await?
    }

    /// Consume given used transaction and produce TxIns
    ///
    /// ### Arguments
    ///
    /// * `tx_cons`         - TxIn TxConstructors
    /// * `tx_used`         - TxOut used for TxIns
    pub async fn consume_inputs_for_payment(
        &mut self,
        tx_cons: Vec<TxConstructor>,
        tx_used: Vec<(OutPoint, String)>,
    ) -> Vec<TxIn> {
        let db = self.db.clone();
        task::spawn_blocking(move || {
            let mut db = db.lock().unwrap();
            let mut batch = db.batch_writer();
            let mut fund_store = get_fund_store(&db);

            for (out_p, _) in tx_used {
                fund_store.spend_tx(&out_p);
            }
            set_fund_store(&mut batch, fund_store);
            let batch = batch.done();
            db.write(batch).unwrap();

            construct_payment_tx_ins(tx_cons)
        })
        .await
        .unwrap()
    }

    /// Destroy the used transactions with keys purging them from the wallet
    /// Handle the case where same address is reused for multiple transactions
    pub async fn destroy_spent_transactions_and_keys(
        &mut self,
        addresses: Option<BTreeSet<String>>,
    ) -> (BTreeSet<String>, BTreeMap<OutPoint, Asset>) {
        let db = self.db.clone();
        task::spawn_blocking(move || {
            let mut db = db.lock().unwrap();
            destroy_spent_transactions_and_keys(&mut db, addresses)
        })
        .await
        .unwrap()
    }

    /// Get a the serialized value stored at given key
    pub async fn get_db_value(&self, key: &'static str) -> Option<Vec<u8>> {
        let db = self.db.clone();
        task::spawn_blocking(move || db.lock().unwrap().get_cf(DB_COL_DEFAULT, key).unwrap())
            .await
            .unwrap()
    }

    /// Set a the serialized value stored at given key
    pub async fn set_db_value(&self, key: &'static str, value: Vec<u8>) {
        let db = self.db.clone();
        task::spawn_blocking(move || {
            db.lock()
                .unwrap()
                .put_cf(DB_COL_DEFAULT, key, &value)
                .unwrap()
        })
        .await
        .unwrap()
    }

    /// Delete value stored at given key
    pub async fn delete_db_value(&self, key: &'static str) {
        let db = self.db.clone();
        task::spawn_blocking(move || db.lock().unwrap().delete_cf(DB_COL_DEFAULT, key).unwrap())
            .await
            .unwrap()
    }

    /// Get the wallet fund store
    pub fn get_fund_store(&self) -> FundStore {
        get_fund_store(&self.db.lock().unwrap())
    }

    /// Get the wallet fund store with errors
    pub fn get_fund_store_err(&self) -> Result<FundStore> {
        get_fund_store_err(&self.db.lock().unwrap())
    }

    /// Get the wallet address
    pub fn get_transaction_store(&self, out_p: &OutPoint) -> TransactionStore {
        get_transaction_store(&self.db.lock().unwrap(), out_p)
    }

    /// Gets the address store based on a provided key
    ///
    /// ### Arguments
    ///
    ///  * `key_addr` - Key to get the address store for
    pub fn get_address_store(&self, key_addr: &str) -> AddressStore {
        get_address_store(&self.db.lock().unwrap(), key_addr, &self.encryption_key)
    }

    /// Gets the address store based on a provided key, but returns
    /// the result in an encrypted state for external storage
    ///
    /// ### Arguments
    ///
    ///  * `key_addr` - Key to get the address store for
    pub fn get_address_store_encrypted(&self, key_addr: &str) -> Vec<u8> {
        get_address_store_encrypted(&self.db.lock().unwrap(), key_addr)
    }

    /// Get the wallet addresses
    pub fn get_known_addresses(&self) -> Vec<String> {
        get_known_key_address(&self.db.lock().unwrap())
            .into_iter()
            .collect()
    }

    /// Get the wallet transaction address
    pub fn get_transaction_address(&self, out_p: &OutPoint) -> String {
        self.get_transaction_store(out_p).key_address
    }

    /// Load locked coinbase from wallet
    pub async fn load_locked_coinbase(&mut self) -> Result<()> {
        let mut cb = self.locked_coinbase.lock().await;
        let locked_coinbase = self
            .get_db_value(LOCKED_COINBASE_KEY)
            .await
            .map(|v| deserialize(&v))
            .transpose()?;
        *cb = locked_coinbase;
        Ok(())
    }

    /// Add to locked coinbase transactions
    pub async fn store_locked_coinbase(
        &mut self,
        locked_coinbase: LockedCoinbase,
    ) -> LockedCoinbase {
        if let Some(cb) = &locked_coinbase {
            let ser_cb = serialize(cb).unwrap();
            self.set_db_value(LOCKED_COINBASE_KEY, ser_cb).await;
        } else {
            self.delete_db_value(LOCKED_COINBASE_KEY).await;
        }
        locked_coinbase
    }

    /// Filter locked coinbase after receiving new block to mine
    pub async fn filter_locked_coinbase(&mut self, b_num: u64) {
        if b_num <= self.last_locked_coinbase_filter_b_num.unwrap_or_default() {
            return; // We're not ready to filter again
        }
        // Remove all fields where current_block_num >= locktime
        self.last_locked_coinbase_filter_b_num = Some(b_num);
        let mut locked_coinbase = self.get_locked_coinbase().await;
        if let Some(l_coinbase) = locked_coinbase.as_mut() {
            l_coinbase.retain(|_, locktime| b_num < *locktime)
        };
        let value = self.store_locked_coinbase(locked_coinbase).await;
        self.set_locked_coinbase(value).await;
    }
}

/// Get the wallet fund store
pub fn get_fund_store(db: &SimpleDb) -> FundStore {
    match get_fund_store_err(db) {
        Ok(v) => v,
        Err(e) => panic!("Failed to access the wallet database with error: {:?}", e),
    }
}

/// Get the wallet fund store
pub fn get_fund_store_err(db: &SimpleDb) -> Result<FundStore> {
    match db.get_cf(DB_COL_DEFAULT, FUND_KEY) {
        Ok(Some(list)) => Ok(deserialize(&list).unwrap()),
        Ok(None) => Ok(FundStore::default()),
        Err(e) => Err(e.into()),
    }
}

/// Set the wallet fund store
pub fn set_fund_store(db: &mut SimpleDbWriteBatch, fund_store: FundStore) {
    db.put_cf(DB_COL_DEFAULT, FUND_KEY, &serialize(&fund_store).unwrap())
}

/// Get the wallet known address
pub fn get_known_key_address(db: &SimpleDb) -> BTreeSet<String> {
    match db.get_cf(DB_COL_DEFAULT, KNOWN_ADDRESS_KEY) {
        Ok(Some(list)) => deserialize(&list).unwrap(),
        Ok(None) => Default::default(),
        Err(e) => panic!("Error accessing wallet: {:?}", e),
    }
}

/// Set the wallet known address
pub fn set_known_key_address(db: &mut SimpleDbWriteBatch, address_store: BTreeSet<String>) {
    db.put_cf(
        DB_COL_DEFAULT,
        KNOWN_ADDRESS_KEY,
        &serialize(&address_store).unwrap(),
    );
}

/// Gets the wallet AddressStore in an encrypted state for external storage
pub fn get_address_store_encrypted(db: &SimpleDb, key_addr: &str) -> Vec<u8> {
    match db.get_cf(DB_COL_DEFAULT, key_addr) {
        Ok(Some(store)) => store,
        Ok(None) => panic!("Key address not present in wallet: {}", key_addr),
        Err(e) => panic!("Error accessing wallet: {:?}", e),
    }
}

/// Get the wallet AddressStore
pub fn get_address_store(
    db: &SimpleDb,
    key_addr: &str,
    encryption_key: &secretbox::Key,
) -> AddressStore {
    match db.get_cf(DB_COL_DEFAULT, key_addr) {
        Ok(Some(store)) => {
            let decrypted = decrypt_store(store, encryption_key);
            deserialize(&decrypted).unwrap()
        }
        Ok(None) => panic!("Key address not present in wallet: {}", key_addr),
        Err(e) => panic!("Error accessing wallet: {:?}", e),
    }
}

/// Delete AddressStore
pub fn delete_address_store(db: &mut SimpleDbWriteBatch, key_addr: &str) {
    db.delete_cf(DB_COL_DEFAULT, key_addr);
}

/// Save AddressStore
pub fn save_address_store_to_wallet(
    db: &mut SimpleDbWriteBatch,
    key_addr: &str,
    store: AddressStore,
    encryption_key: &secretbox::Key,
) {
    let store = serialize(&store).unwrap();
    let input = encrypt_store(store, encryption_key);
    db.put_cf(DB_COL_DEFAULT, key_addr, &input);
}

/// Get the wallet transaction store
pub fn get_transaction_store(db: &SimpleDb, out_p: &OutPoint) -> TransactionStore {
    match db.get_cf(DB_COL_DEFAULT, serialize(&out_p).unwrap()) {
        Ok(Some(store)) => deserialize(&store).unwrap(),
        Ok(None) => panic!("Transaction not present in wallet: {:?}", out_p),
        Err(e) => panic!("Error accessing wallet: {:?}", e),
    }
}

/// Delete transaction store
pub fn delete_transaction_store(db: &mut SimpleDbWriteBatch, out_p: &OutPoint) {
    let key = serialize(&out_p).unwrap();
    db.delete_cf(DB_COL_DEFAULT, &key);
}

/// Save transaction
pub fn save_transaction_to_wallet(
    db: &mut SimpleDbWriteBatch,
    out_p: &OutPoint,
    store: &TransactionStore,
) {
    let key = serialize(out_p).unwrap();
    let input = serialize(store).unwrap();
    db.put_cf(DB_COL_DEFAULT, &key, &input);
}

// Set a new master key store
pub fn set_new_master_key_store(
    batch: &mut SimpleDbWriteBatch,
    passphrase: &[u8],
) -> secretbox::Key {
    let salt = pwhash::gen_salt();
    let master_key = secretbox::gen_key();
    let nonce = secretbox::gen_nonce();
    let pass_key = make_key(passphrase, salt);
    let enc_master_key = secretbox::seal(master_key.as_ref().to_vec(), &nonce, &pass_key).unwrap();
    let store = serialize(&MasterKeyStore {
        salt,
        nonce,
        enc_master_key,
    })
    .unwrap();
    batch.put_cf(DB_COL_DEFAULT, MASTER_KEY_STORE_KEY, &store);
    master_key
}

/// Get master store key with given passphrase
pub fn get_master_key_store(db: &SimpleDb, passphrase: &[u8]) -> Result<secretbox::Key> {
    let store = db.get_cf(DB_COL_DEFAULT, MASTER_KEY_STORE_KEY)?;
    let store = store.ok_or(WalletDbError::MasterKeyMissingError)?;
    let store: MasterKeyStore = deserialize(&store)?;

    let pass_key = make_key(passphrase, store.salt);
    let master_key = secretbox::open(store.clone().enc_master_key, &store.nonce, &pass_key)
        .ok_or(WalletDbError::PassphraseError)?;
    let key =
        secretbox::Key::from_slice(&master_key).ok_or(WalletDbError::MasterKeyRetrievalError)?;
    Ok(key)
}

/// Get or save master key store
///
/// This function is used during the initial node startup,
/// and should panic on errors.
pub fn get_or_save_master_key_store(
    db: &SimpleDb,
    batch: &mut SimpleDbWriteBatch,
    passphrase: &[u8],
) -> Result<secretbox::Key> {
    match get_master_key_store(db, passphrase) {
        Ok(key) => Ok(key),
        Err(WalletDbError::MasterKeyMissingError) => {
            Ok(set_new_master_key_store(batch, passphrase))
        }
        Err(e) => Err(e),
    }
}

///Creates a secretbox key to be used for encryption and decryption
///
/// ### Arguments
///
/// * `passphrase` - String used as the password when creating the encryption key
/// * `salt` - Salt value added to the passphrase to ensure safe encryption
pub fn make_key(passphrase: &[u8], salt: pwhash::Salt) -> secretbox::Key {
    let mut kb = [0; secretbox::KEY_LEN];
    pwhash::derive_key(&mut kb, passphrase, &salt, pwhash::OPSLIMIT_INTERACTIVE);
    secretbox::Key::from_slice(&kb).unwrap()
}

/// Decrypt a Store value
pub fn decrypt_store(store: Vec<u8>, encryption_key: &secretbox::Key) -> Vec<u8> {
    let (nonce, output) = store.split_at(secretbox::NONCE_LEN);
    let nonce = secretbox::Nonce::from_slice(nonce).unwrap();
    match secretbox::open(output.to_vec(), &nonce, encryption_key) {
        Some(decrypted) => decrypted,
        _ => panic!("Error accessing wallet"),
    }
}

/// Encrypt a Store value
pub fn encrypt_store(store: Vec<u8>, encryption_key: &secretbox::Key) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let mut input: Vec<u8> = nonce.as_ref().to_vec();
    input.append(&mut secretbox::seal(store, &nonce, encryption_key).unwrap());
    input
}

/// Make TxConstructors from stored TxOut
/// Also return the used info for db cleanup
#[allow(clippy::type_complexity)]
pub fn fetch_inputs_for_payment_from_db(
    db: &SimpleDb,
    asset_required: Asset,
    encryption_key: &secretbox::Key,
    locked_coinbase: &LockedCoinbase,
) -> Result<(Vec<TxConstructor>, Asset, Vec<(OutPoint, String)>)> {
    let mut tx_cons = Vec::new();
    let mut tx_used = Vec::new();
    let mut fund_store = get_fund_store(db);
    // We need to filter here, because we are fetching inputs for a transaction
    if let Some(count) = fund_store.filter_locked_coinbase(locked_coinbase) {
        warn!("{count} locked coinbase transaction filtered out");
    }
    let mut amount_made = Asset::default_of_type(&asset_required);

    if !fund_store.running_total().has_enough(&asset_required) {
        return Err(WalletDbError::InsufficientFundsError);
    }

    for (out_p, amount) in fund_store.into_transactions() {
        if amount_made.add_assign(&amount) {
            let (cons, used) = tx_constructor_from_prev_out(db, out_p, encryption_key);
            tx_cons.push(cons);
            tx_used.push(used);
        }
        if let Some(true) = amount_made.is_greater_or_equal_to(&asset_required) {
            break;
        }
    }

    Ok((tx_cons, amount_made, tx_used))
}

/// Make TxConstructors from stored TxOut
/// Also return the used info for db cleanup
#[allow(clippy::type_complexity)]
pub fn fetch_inputs_for_payment_from_supplied_input_addrs_db(
    db: &SimpleDb,
    addresses: BTreeSet<String>,
    encryption_key: &secretbox::Key,
    locked_coinbase: &LockedCoinbase,
) -> Result<(Vec<TxConstructor>, Asset, Vec<(OutPoint, String)>)> {
    // Only use addresses that actually contain assets
    let addresses_to_use = retrieve_non_empty_addresses(addresses, db);
    let mut fund_store = get_fund_store(db);
    // We need to filter here because we are fetching inputs for a transaction
    if let Some(count) = fund_store.filter_locked_coinbase(locked_coinbase) {
        warn!("{count} locked coinbase transaction filtered out");
    }
    let fund_store_txs = fund_store.into_transactions();
    let mut txs_to_use = Vec::new();

    for addr in addresses_to_use {
        fund_store_txs
            .iter()
            .filter(|(out_p, _)| addr == get_transaction_store(db, out_p).key_address)
            .for_each(|(op, asset)| txs_to_use.push((op.clone(), asset.clone())));
    }

    fetch_inputs_from_supplied_txs_for_payment_from_db(db, txs_to_use, encryption_key)
}

/// Make TxConstructors from stored TxOut
/// Also return the used info for db cleanup
#[allow(clippy::type_complexity)]
pub fn fetch_inputs_from_supplied_txs_for_payment_from_db(
    db: &SimpleDb,
    addresses: Vec<(OutPoint, Asset)>,
    encryption_key: &secretbox::Key,
) -> Result<(Vec<TxConstructor>, Asset, Vec<(OutPoint, String)>)> {
    let mut tx_cons = Vec::new();
    let mut tx_used = Vec::new();
    let mut amount_made = Asset::Token(TokenAmount(0)); // TODO: Allow any asset type here

    for (out_p, amount) in addresses {
        if amount_made.add_assign(&amount) {
            let (cons, used) = tx_constructor_from_prev_out(db, out_p, encryption_key);
            tx_cons.push(cons);
            tx_used.push(used);
        }
    }

    Ok((tx_cons, amount_made, tx_used))
}

/// Destroy the used transactions with keys purging them from the wallet
/// Handle the case where same address is reused for multiple transactions
pub fn destroy_spent_transactions_and_keys(
    db: &mut SimpleDb,
    addresses: Option<BTreeSet<String>>,
) -> (BTreeSet<String>, BTreeMap<OutPoint, Asset>) {
    let empty_addr = retrieve_empty_addresses(addresses.unwrap_or_default(), db);
    let mut batch = db.batch_writer();
    let mut fund_store = get_fund_store(db);
    let mut address_store = get_known_key_address(db);

    //
    // Gather data for update
    //

    let spent_txs = fund_store.remove_spent_transactions();

    let remove_key_addresses: BTreeSet<_> = {
        let fund_store_txs = fund_store.transactions();

        let unspent_key_addresses: BTreeSet<_> = fund_store_txs
            .keys()
            .map(|out_p| get_transaction_store(db, out_p).key_address)
            .collect();

        let mut spent_addrs: BTreeSet<_> = spent_txs
            .keys()
            .map(|out_p| get_transaction_store(db, out_p).key_address)
            .filter(|addr| !unspent_key_addresses.contains(addr))
            .collect();

        spent_addrs.extend(empty_addr);
        spent_addrs
    };

    for keys_address in &remove_key_addresses {
        address_store.remove(keys_address);
    }

    //
    // Update database
    //
    set_fund_store(&mut batch, fund_store);
    set_known_key_address(&mut batch, address_store);
    for keys_address in &remove_key_addresses {
        delete_address_store(&mut batch, keys_address);
    }
    for out_p in spent_txs.keys() {
        delete_transaction_store(&mut batch, out_p);
    }

    let batch = batch.done();
    db.write(batch).unwrap();

    (remove_key_addresses, spent_txs)
}

/// Retrieve addresses from a subset that may or may not contain assets
///
/// ## Arguments
/// * `addresses` - The subset of addresses to filter
/// * `db` - The database to use
/// * `look_for_empty` - If true, return addresses that DO NOT contain assets
pub fn retrieve_empty_or_non_empty_addresses(
    mut addresses: BTreeSet<String>,
    db: &SimpleDb,
    look_for_empty: bool,
) -> BTreeSet<String> {
    let fund_store = get_fund_store(db);
    let fund_store_txs = fund_store.transactions();

    let unspent_key_addresses: BTreeSet<_> = fund_store_txs
        .keys()
        .map(|out_p| get_transaction_store(db, out_p).key_address)
        .collect();

    if look_for_empty {
        addresses.retain(|addr| !unspent_key_addresses.contains(addr));
    } else {
        addresses.retain(|addr| unspent_key_addresses.contains(addr));
    }
    addresses
}

/// Retrieve addresses from a subset that DO NOT contain assets from the wallet
pub fn retrieve_empty_addresses(addresses: BTreeSet<String>, db: &SimpleDb) -> BTreeSet<String> {
    retrieve_empty_or_non_empty_addresses(addresses, db, true)
}

/// Retrieve addresses from a subset that contain assets from the wallet
pub fn retrieve_non_empty_addresses(
    addresses: BTreeSet<String>,
    db: &SimpleDb,
) -> BTreeSet<String> {
    retrieve_empty_or_non_empty_addresses(addresses, db, false)
}

/// Make TxConstructor from stored TxOut
/// Also return the used info for db cleanup
pub fn tx_constructor_from_prev_out(
    db: &SimpleDb,
    out_p: OutPoint,
    encryption_key: &secretbox::Key,
) -> (TxConstructor, (OutPoint, String)) {
    let key_address = get_transaction_store(db, &out_p).key_address;
    let needed_store = get_address_store(db, &key_address, encryption_key);

    let hash_to_sign = construct_tx_in_signable_hash(&out_p);
    let signature = sign::sign_detached(hash_to_sign.as_bytes(), &needed_store.secret_key);

    let tx_const = TxConstructor {
        previous_out: out_p.clone(),
        signatures: vec![signature],
        pub_keys: vec![needed_store.public_key],
        address_version: needed_store.address_version,
    };

    (tx_const, (out_p, key_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use naom::utils::transaction_utils::construct_address;

    #[test]
    /// Creating a valid payment address
    fn should_construct_address_valid() {
        let pk = PublicKey::from_slice(&[
            196, 234, 50, 92, 76, 102, 62, 4, 231, 81, 211, 133, 33, 164, 134, 52, 44, 68, 174, 18,
            14, 59, 108, 187, 150, 190, 169, 229, 215, 130, 78, 78,
        ])
        .unwrap();
        let addr = construct_address(&pk);

        assert_eq!(
            addr,
            "fc0aa2394edb0d2df918325d4682c21eacecf173265db7c04623d2a921f3876c".to_string(),
        );
    }

    #[test]
    /// Creating a payment address of 25 bytes
    fn should_construct_address_valid_length() {
        let pk = PublicKey::from_slice(&[
            196, 234, 50, 92, 76, 102, 62, 4, 231, 81, 211, 133, 33, 164, 134, 52, 44, 68, 174, 18,
            14, 59, 108, 187, 150, 190, 169, 229, 215, 130, 78, 78,
        ])
        .unwrap();
        let addr = construct_address(&pk);

        assert_eq!(addr.len(), 64);
    }

    #[tokio::test(flavor = "current_thread")]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: PassphraseError")]
    async fn incorrect_password() {
        //Arrange
        let db = WalletDb::new(
            DbMode::InMemory,
            None,
            Some(String::from("Test Passphrase1")),
            None,
        )
        .unwrap()
        .take_closed_persistent_store()
        .await;

        //Act/Panic - Wrong Passphrase
        let _db = WalletDb::new(
            DbMode::InMemory,
            Some(db),
            Some("Test Passphrase 2".to_owned()),
            None,
        )
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wallet_life_cycle() {
        //
        // Arrange
        //
        let out_p1 = OutPoint::new(String::new(), 1);
        let out_p2 = OutPoint::new(String::new(), 2);
        let amount1 = Asset::token_u64(3);

        let out_p3 = OutPoint::new(String::new(), 3);
        let amount3 = Asset::token_u64(5);

        let out_p4 = OutPoint::new(String::new(), 3);
        let amount4 = Asset::token_u64(6);
        let key_addr_non_existent = "000000".to_owned();

        let out_p_non_pay = OutPoint::new(String::new(), 4);
        let key_addr_non_pay = "".to_owned();

        let amount_out = Asset::token_u64(4);

        //
        // Act
        //
        let mut wallet = WalletDb::new(
            DbMode::InMemory,
            None,
            Some("Test Passphrase".to_owned()),
            None,
        )
        .unwrap();

        // Unlinked keys and transactions
        let (_key_addr_unused, _) = wallet.generate_payment_address().await;
        wallet
            .save_transaction_to_wallet(out_p_non_pay, key_addr_non_pay)
            .await
            .unwrap();

        // Store payments
        let (key_addr1, _) = wallet.generate_payment_address().await;
        let (key_addr2, _) = wallet.generate_payment_address().await;
        let stored_usable = wallet
            .save_usable_payments_to_wallet(
                vec![
                    (out_p1.clone(), amount1.clone(), key_addr1.clone(), 0),
                    (out_p2.clone(), amount1.clone(), key_addr2.clone(), 0),
                    (out_p3, amount3, key_addr2, 0),
                    (out_p4, amount4, key_addr_non_existent, 0),
                ],
                Default::default(),
            )
            .await
            .unwrap();

        // Pay out
        let (tx_cons, fetched_amount, tx_used) =
            wallet.fetch_inputs_for_payment(amount_out).await.unwrap();
        let tx_ins = wallet.consume_inputs_for_payment(tx_cons, tx_used).await;

        // clean up db
        let (destroyed_keys, destroyed_txs) =
            wallet.destroy_spent_transactions_and_keys(None).await;

        //
        // Assert
        //
        assert_eq!(stored_usable.len(), 3);
        assert_eq!(
            fetched_amount,
            Asset::Token(amount1.token_amount() + amount1.token_amount())
        );
        assert_eq!(tx_ins.len(), 2);

        let expected_destroyed_keys: BTreeSet<_> = vec![key_addr1].into_iter().collect();
        assert_eq!(destroyed_keys, expected_destroyed_keys);

        let expected_destroyedkeys: BTreeMap<_, _> =
            vec![(out_p1, amount1.clone()), (out_p2, amount1)]
                .into_iter()
                .collect();
        assert_eq!(destroyed_txs, expected_destroyedkeys);
    }
}
