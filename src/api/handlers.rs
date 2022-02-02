use crate::api::errors;
use crate::comms_handler::Node;
use crate::constants::LAST_BLOCK_HASH_KEY;
use crate::db_utils::SimpleDb;
use crate::interfaces::{
    node_type_as_str, AddressesWithOutPoints, BlockchainItem, BlockchainItemMeta,
    BlockchainItemType, ComputeApi, ComputeApiRequest, DebugData, DruidPool, NodeType,
    OutPointData, StoredSerializingBlock, UserApiRequest, UserRequest, UtxoFetchType,
};
use crate::miner::{BlockPoWReceived, CurrentBlockWithMutex};
use crate::storage::{get_stored_value_from_db, indexed_block_hash_key};
use crate::threaded_call::{self, ThreadedCallSender};
use crate::utils::{decode_pub_key, decode_signature};
use crate::wallet::{WalletDb, WalletDbError};
use crate::ComputeRequest;
use naom::constants::D_DISPLAY_PLACES;
use naom::crypto::sign_ed25519::PublicKey;
use naom::primitives::asset::TokenAmount;
use naom::primitives::druid::DdeValues;
use naom::primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use naom::script::lang::Script;
use naom::utils::transaction_utils::construct_address_for;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str;
use std::sync::{Arc, Mutex};
use tracing::{error, trace};

pub type DbgPaths = Vec<&'static str>;

/// Data entry from the blockchain
#[derive(Debug, Serialize, Deserialize)]
enum BlockchainData {
    Block(StoredSerializingBlock),
    Transaction(Transaction),
}

/// Private/public keypairs, stored with payment address as key.
/// Values are encrypted
#[derive(Debug, Serialize, Deserialize)]
pub struct Addresses {
    pub addresses: BTreeMap<String, Vec<u8>>,
}

/// Information about a wallet to be returned to requester
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletInfo {
    running_total: f64,
    receipt_total: u64,
    addresses: AddressesWithOutPoints,
}

/// Public key addresses received from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyAddresses {
    pub address_list: Vec<String>,
}

/// Encapsulated payment received from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncapsulatedPayment {
    pub address: String,
    pub amount: TokenAmount,
    pub passphrase: String,
}

/// Receipt asset creation structure received from client
///
/// This structure is used to create a receipt asset on EITHER
/// the compute or user node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReceiptAssetData {
    pub receipt_amount: u64,
    pub script_public_key: Option<String>, /* Not used by user Node */
    pub public_key: Option<String>,        /* Not used by user Node */
    pub signature: Option<String>,         /* Not used by user Node */
}

/// Information needed for the creaion of TxIn script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CreateTxInScript {
    Pay2PkH {
        /// Data to sign
        signable_data: String,
        /// Hex encoded signature
        signature: String,
        /// Hex encoded complete public key
        public_key: String,
        /// Optional address version field
        address_version: Option<u64>,
    },
}

/// Information needed for the creaion of TxIn.
/// This API would change if types are modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTxIn {
    /// The previous_out to use
    pub previous_out: Option<OutPoint>,
    /// script info
    pub script_signature: Option<CreateTxInScript>,
}

/// Information necessary for the creation of a Transaction
/// This API would change if types are modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTransaction {
    /// String to sign in each inputs
    pub inputs: Vec<CreateTxIn>,
    pub outputs: Vec<TxOut>,
    pub version: usize,
    pub druid_info: Option<DdeValues>,
}
/// Struct received from client to change passphrase
///
/// Entries will be encrypted with TLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePassphraseData {
    pub old_passphrase: String,
    pub new_passphrase: String,
}

/// Struct received from client to construct address
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct AddressConstructData {
    pub pub_key: Option<Vec<u8>>,
    pub pub_key_hex: Option<String>,
    pub version: Option<u64>,
}

/// Struct received from client to fetch pending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchPendingData {
    pub druid_list: Vec<String>,
}

/// Struct received from client to fetch pending
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchPendingtResult {
    pub pending_transactions: DruidPool,
}

/// A JSON formatted reply.
pub struct JsonReply(Vec<u8>);

impl warp::reply::Reply for JsonReply {
    #[inline]
    fn into_response(self) -> warp::reply::Response {
        use warp::http::header::{HeaderValue, CONTENT_TYPE};
        let mut res = warp::reply::Response::new(self.0.into());
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        res
    }
}

//======= GET HANDLERS =======//

/// Gets the state of the connected wallet and returns it.
/// Returns a `WalletInfo` struct
pub async fn get_wallet_info(wallet_db: WalletDb) -> Result<impl warp::Reply, warp::Rejection> {
    let fund_store = match wallet_db.get_fund_store_err() {
        Ok(fund) => fund,
        Err(_) => return Err(warp::reject::custom(errors::ErrorCannotAccessWallet)),
    };

    let mut addresses = AddressesWithOutPoints::new();
    for (out_point, asset) in fund_store.transactions() {
        addresses
            .entry(wallet_db.get_transaction_address(out_point))
            .or_insert_with(Vec::new)
            .push(OutPointData::new(out_point.clone(), asset.clone()));
    }

    let total = fund_store.running_total();
    let (running_total, receipt_total) = (
        total.tokens.0 as f64 / D_DISPLAY_PLACES,
        total.receipts as u64,
    );
    let send_val = WalletInfo {
        running_total,
        receipt_total,
        addresses,
    };

    Ok(warp::reply::json(&send_val))
}

/// Gets all present keys and sends them out for export
pub async fn get_export_keypairs(wallet_db: WalletDb) -> Result<impl warp::Reply, warp::Rejection> {
    let known_addr = wallet_db.get_known_addresses();
    let mut addresses = BTreeMap::new();

    for addr in known_addr {
        addresses.insert(addr.clone(), wallet_db.get_address_store_encrypted(&addr));
    }

    Ok(warp::reply::json(&Addresses { addresses }))
}

/// Gets a newly generated payment address
pub async fn get_new_payment_address(
    wallet_db: WalletDb,
) -> Result<impl warp::Reply, warp::Rejection> {
    let (address, _) = wallet_db.generate_payment_address().await;

    Ok(warp::reply::json(&address))
}

/// Gets the latest block information
pub async fn get_latest_block(
    db: Arc<Mutex<SimpleDb>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    get_json_reply_stored_value_from_db(db, LAST_BLOCK_HASH_KEY, false)
}

/// Gets the debug info for a speficied node type
///
/// Contains an optional field for an auxiliary `Node`
/// , i.e a Miner node may or may not have additional User
/// node capabilities- providing additional debug data.
pub async fn get_debug_data(
    debug_paths: DbgPaths,
    node: Node,
    aux_node: Option<Node>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let node_type = node_type_as_str(node.get_node_type());
    let node_peers = node.get_peer_list().await;
    let node_api = debug_paths.into_iter().map(|p| p.to_string()).collect();

    let data = match aux_node {
        Some(aux) => {
            let aux_type = node_type_as_str(aux.get_node_type());
            let aux_peers = aux.get_peer_list().await;
            DebugData {
                node_type: format!("{}/{}", node_type, aux_type),
                node_api,
                node_peers: [node_peers, aux_peers].concat(),
            }
        }
        None => DebugData {
            node_type: node_type.to_owned(),
            node_api,
            node_peers,
        },
    };
    Ok(warp::reply::json(&data))
}

/// Get to fetch information about the current mining block
pub async fn get_current_mining_block(
    current_block: CurrentBlockWithMutex,
) -> Result<impl warp::Reply, warp::Rejection> {
    let data: Option<BlockPoWReceived> = current_block.lock().unwrap().clone();
    Ok(warp::reply::json(&data))
}

/// Get all addresses for unspent tokens on the UTXO set
pub async fn get_utxo_addresses(
    mut threaded_calls: ThreadedCallSender<dyn ComputeApi>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let addresses = make_api_threaded_call(
        &mut threaded_calls,
        |c| c.get_committed_utxo_tracked_set().get_all_addresses(),
        "get_utxo_addresses",
    )
    .await?;
    Ok(warp::reply::json(&addresses))
}

//======= POST HANDLERS =======//

/// Post to retrieve an item from the blockchain db by hash key
pub async fn post_blockchain_entry_by_key(
    db: Arc<Mutex<SimpleDb>>,
    key: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    get_json_reply_stored_value_from_db(db, &key, true)
}

/// Post to retrieve block information by number
pub async fn post_block_by_num(
    db: Arc<Mutex<SimpleDb>>,
    block_nums: Vec<u64>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let keys: Vec<_> = block_nums
        .iter()
        .map(|num| indexed_block_hash_key(*num))
        .collect();
    get_json_reply_blocks_from_db(db, keys)
}

/// Post to import new keypairs to the connected wallet
pub async fn post_import_keypairs(
    db: WalletDb,
    keypairs: Addresses,
) -> Result<impl warp::Reply, warp::Rejection> {
    for (addr, address_set) in keypairs.addresses.iter() {
        match db
            .save_encrypted_address_to_wallet(addr.clone(), address_set.clone())
            .await
        {
            Ok(_) => {}
            Err(_e) => {
                return Err(warp::reject::custom(
                    errors::ErrorCannotSaveAddressesToWallet,
                ))
            }
        }
    }

    Ok(warp::reply::json(&"Key/s saved successfully".to_owned()))
}

///Post make a new payment from the connected wallet
pub async fn post_make_payment(
    db: WalletDb,
    peer: Node,
    encapsulated_data: EncapsulatedPayment,
) -> Result<impl warp::Reply, warp::Rejection> {
    let EncapsulatedPayment {
        address,
        amount,
        passphrase,
    } = encapsulated_data;

    let request = match db.test_passphrase(passphrase).await {
        Ok(_) => UserRequest::UserApi(UserApiRequest::MakePayment { address, amount }),
        Err(e) => return Err(wallet_db_error(e)),
    };

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:make_payment error: {:?}", e);
        return Err(warp::reject::custom(errors::ErrorCannotAccessUserNode));
    }

    Ok(warp::reply::json(&"Payment processing".to_owned()))
}

///Post make a new payment from the connected wallet using an ip address
pub async fn post_make_ip_payment(
    db: WalletDb,
    peer: Node,
    encapsulated_data: EncapsulatedPayment,
) -> Result<impl warp::Reply, warp::Rejection> {
    trace!("in the payment");

    let EncapsulatedPayment {
        address,
        amount,
        passphrase,
    } = encapsulated_data;

    let payment_peer: SocketAddr = address
        .parse::<SocketAddr>()
        .map_err(|_| warp::reject::custom(errors::ErrorCannotParseAddress))?;

    let request = match db.test_passphrase(passphrase).await {
        Ok(_) => UserRequest::UserApi(UserApiRequest::MakeIpPayment {
            payment_peer,
            amount,
        }),
        Err(e) => return Err(wallet_db_error(e)),
    };

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:make_payment error: {:?}", e);
        return Err(warp::reject::custom(errors::ErrorCannotAccessUserNode));
    }

    Ok(warp::reply::json(&"Payment processing".to_owned()))
}

///Post make a donation request from the user node at specified ip address
pub async fn post_request_donation(
    peer: Node,
    address: String,
) -> Result<impl warp::Reply, warp::Rejection> {
    trace!("in request donation");

    let paying_peer: SocketAddr = address
        .parse::<SocketAddr>()
        .map_err(|_| warp::reject::custom(errors::ErrorCannotParseAddress))?;

    let request = UserRequest::UserApi(UserApiRequest::RequestDonation { paying_peer });

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:equest_donation error: {:?}", e);
        return Err(warp::reject::custom(errors::ErrorCannotAccessUserNode));
    }

    Ok(warp::reply::json(&"Donation processing".to_owned()))
}

/// Post to update running total of connected wallet
pub async fn post_update_running_total(
    peer: Node,
    addresses: PublicKeyAddresses,
) -> Result<impl warp::Reply, warp::Rejection> {
    let request = UserRequest::UserApi(UserApiRequest::UpdateWalletFromUtxoSet {
        address_list: UtxoFetchType::AnyOf(addresses.address_list),
    });

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:update_running_total error: {:?}", e);
        return Err(warp::reject::custom(errors::ErrorCannotAccessUserNode));
    }

    Ok(warp::reply::json(&"Running total updated".to_owned()))
}

/// Post to fetch the balance for given addresses in UTXO
pub async fn post_fetch_utxo_balance(
    mut threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    addresses: PublicKeyAddresses,
) -> Result<impl warp::Reply, warp::Rejection> {
    let balances = make_api_threaded_call(
        &mut threaded_calls,
        move |c| {
            c.get_committed_utxo_tracked_set()
                .get_balance_for_addresses(&addresses.address_list)
        },
        "post_fetch_utxo_balance",
    )
    .await?;
    Ok(warp::reply::json(&balances))
}

//POST fetch pending transaction from a computet node
pub async fn post_fetch_druid_pending(
    mut threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    fetch_input: FetchPendingData,
) -> Result<impl warp::Reply, warp::Rejection> {
    let pending_transactions = make_api_threaded_call(
        &mut threaded_calls,
        move |c| {
            let pending = c.get_pending_druid_pool();
            (fetch_input.druid_list.iter())
                .filter_map(|k| pending.get_key_value(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<DruidPool>()
        },
        "post_fetch_pending",
    )
    .await?;
    Ok(warp::reply::json(&FetchPendingtResult {
        pending_transactions,
    }))
}

/// Post to create a receipt asset transaction on EITHER Compute or User node type
pub async fn post_create_receipt_asset(
    peer: Node,
    create_receipt_asset_data: CreateReceiptAssetData,
) -> Result<impl warp::Reply, warp::Rejection> {
    let CreateReceiptAssetData {
        receipt_amount,
        script_public_key,
        public_key,
        signature,
    } = create_receipt_asset_data;

    let node_type = peer.get_node_type();

    let all_some = script_public_key.is_some() && public_key.is_some() && signature.is_some();
    let all_none = script_public_key.is_none() && public_key.is_none() && signature.is_none();

    if node_type == NodeType::User && all_none {
        // Create receipt tx on the user node
        let request =
            UserRequest::UserApi(UserApiRequest::SendCreateReceiptRequest { receipt_amount });
        if let Err(e) = peer.inject_next_event(peer.address(), request) {
            error!("route:post_create_receipt_asset error: {:?}", e);
            return Err(warp::reject::custom(errors::ErrorCannotAccessUserNode));
        }
    } else if node_type == NodeType::Compute && all_some {
        // Create receipt tx on the compute node
        let (script_public_key, public_key, signature) = (
            script_public_key.unwrap_or_default(),
            public_key.unwrap_or_default(),
            signature.unwrap_or_default(),
        );

        let request = ComputeRequest::ComputeApi(ComputeApiRequest::SendCreateReceiptRequest {
            receipt_amount,
            script_public_key,
            public_key,
            signature,
        });

        if let Err(e) = peer.inject_next_event(peer.address(), request) {
            error!("route:post_create_receipt_asset error: {:?}", e);
            return Err(warp::reject::custom(errors::ErrorCannotAccessComputeNode));
        }
    } else {
        return Err(warp::reject::custom(errors::ErrorInvalidJSONStructure));
    }
    Ok(warp::reply::json(&"Creating receipt asset".to_owned()))
}

/// Post transactions to compute node
pub async fn post_create_transactions(
    peer: Node,
    data: Vec<CreateTransaction>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let transactions = {
        let mut transactions = Vec::new();
        for tx in data {
            let tx = to_transaction(tx)?;
            transactions.push(tx);
        }
        transactions
    };

    let request = ComputeRequest::ComputeApi(ComputeApiRequest::SendTransactions { transactions });

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:post_create_transactions error: {:?}", e);
        return Err(warp::reject::custom(errors::ErrorCannotAccessComputeNode));
    }

    Ok(warp::reply::json(&"Creating Transactions".to_owned()))
}

// POST to change wallet passphrase
pub async fn post_change_wallet_passphrase(
    mut db: WalletDb,
    passphrase_struct: ChangePassphraseData,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ChangePassphraseData {
        old_passphrase,
        new_passphrase,
    } = passphrase_struct;

    db.change_wallet_passphrase(old_passphrase, new_passphrase)
        .await
        .map_err(wallet_db_error)?;

    Ok(warp::reply::json(
        &"Passphrase changed successfully".to_owned(),
    ))
}

// POST to check for address presence
pub async fn post_blocks_by_tx_hashes(
    db: Arc<Mutex<SimpleDb>>,
    tx_hashes: Vec<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    get_json_reply_block_nums_by_tx_hashes_from_db(db, tx_hashes)
}

//POST create a new payment address from a computet node
pub async fn post_payment_address_construction(
    data: AddressConstructData,
) -> Result<impl warp::Reply, warp::Rejection> {
    let pub_key = data.pub_key;
    let pub_key_hex = data.pub_key_hex;
    let version = data.version;

    let pub_key = pub_key.or_else(|| pub_key_hex.and_then(|k| hex::decode(k).ok()));
    let pub_key = pub_key.filter(|k| !k.is_empty());
    let pub_key = pub_key.and_then(|k| PublicKey::from_slice(&k));

    if let Some(pub_key) = pub_key {
        let data: String = construct_address_for(&pub_key, version);
        return Ok(warp::reply::json(&data));
    }
    Ok(warp::reply::json(&String::from("")))
}

//======= Helpers =======//

/// Filters through wallet errors which are internal vs errors caused by user input
pub fn wallet_db_error(err: WalletDbError) -> warp::Rejection {
    match err {
        WalletDbError::PassphraseError => warp::reject::custom(errors::ErrorInvalidPassphrase),
        _ => warp::reject::custom(errors::InternalError),
    }
}

/// Generic static string warp error
pub fn generic_error(name: &'static str) -> warp::Rejection {
    warp::reject::custom(errors::ErrorGeneric::new(name))
}

/// Expect optional field
pub fn with_opt_field<T>(field: Option<T>, err: &'static str) -> Result<T, warp::Rejection> {
    field.ok_or_else(|| generic_error(err))
}

/// Create a `Transaction` from a `CreateTransaction`
pub fn to_transaction(data: CreateTransaction) -> Result<Transaction, warp::Rejection> {
    let CreateTransaction {
        inputs,
        outputs,
        version,
        druid_info,
    } = data;

    let inputs = {
        let mut tx_ins = Vec::new();
        for i in inputs {
            let previous_out = with_opt_field(i.previous_out, "Invalid previous_out")?;
            let script_signature = with_opt_field(i.script_signature, "Invalid script_signature")?;
            let tx_in = {
                let CreateTxInScript::Pay2PkH {
                    signable_data,
                    signature,
                    public_key,
                    address_version,
                } = script_signature;

                let signature =
                    with_opt_field(decode_signature(&signature).ok(), "Invalid signature")?;
                let public_key =
                    with_opt_field(decode_pub_key(&public_key).ok(), "Invalid public_key")?;

                TxIn {
                    previous_out: Some(previous_out),
                    script_signature: Script::pay2pkh(
                        signable_data,
                        signature,
                        public_key,
                        address_version,
                    ),
                }
            };

            tx_ins.push(tx_in);
        }
        tx_ins
    };

    Ok(Transaction {
        inputs,
        outputs,
        version,
        druid_info,
    })
}

/// Fetches JSON blocks.
fn get_json_reply_stored_value_from_db(
    db: Arc<Mutex<SimpleDb>>,
    key: &str,
    wrap: bool,
) -> Result<impl warp::Reply, warp::Rejection> {
    let item = get_stored_value_from_db(db, key.as_bytes())
        .ok_or_else(|| warp::reject::custom(errors::ErrorNoDataFoundForKey))?;

    match (wrap, item.item_meta.as_type()) {
        (true, BlockchainItemType::Block) => Ok(json_embed_block(item.data_json)),
        (true, BlockchainItemType::Tx) => Ok(json_embed_transaction(item.data_json)),
        (false, _) => Ok(json_embed(&[&item.data_json])),
    }
}

/// Fetches JSON blocks. Blocks which for whatever reason are
/// unretrievable will be replaced with a default (best handling?)
pub fn get_json_reply_blocks_from_db(
    db: Arc<Mutex<SimpleDb>>,
    keys: Vec<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let key_values: Vec<_> = keys
        .into_iter()
        .map(|key| {
            get_stored_value_from_db(db.clone(), key)
                .map(|item| (item.key, item.data_json))
                .unwrap_or_else(|| (b"".to_vec(), b"\"\"".to_vec()))
        })
        .collect();

    // Make JSON tupple with key and Block
    let key_values: Vec<_> = key_values
        .iter()
        .map(|(k, v)| [&b"[\""[..], k, &b"\","[..], v, &b"]"[..]])
        .collect();

    // Make JSON array:
    let mut key_values: Vec<_> = key_values.join(&&b","[..]);
    key_values.insert(0, &b"["[..]);
    key_values.push(&b"]"[..]);

    Ok(json_embed(&key_values))
}

/// Fetches stored block numbers that contain provided `tx_hash` values.
/// Unretrievable transactions will be ignored.
pub fn get_json_reply_block_nums_by_tx_hashes_from_db(
    db: Arc<Mutex<SimpleDb>>,
    tx_hashes: Vec<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let block_nums: Vec<u64> = tx_hashes
        .into_iter()
        .filter_map(
            |tx_hash| match get_stored_value_from_db(db.clone(), tx_hash) {
                Some(BlockchainItem {
                    item_meta: BlockchainItemMeta::Tx { block_num, .. },
                    ..
                }) => Some(block_num),
                _ => None,
            },
        )
        .collect();
    Ok(warp::reply::json(&block_nums))
}

/// Embed block into Block enum
pub fn json_embed_block(value: Vec<u8>) -> JsonReply {
    json_embed(&[b"{\"Block\":", &value, b"}"])
}

/// Embed transaction into Transaction enum
pub fn json_embed_transaction(value: Vec<u8>) -> JsonReply {
    json_embed(&[b"{\"Transaction\":", &value, b"}"])
}

/// Embed JSON into wrapping JSON
pub fn json_embed(value: &[&[u8]]) -> JsonReply {
    JsonReply(value.iter().copied().flatten().copied().collect())
}

/// Threaded call for API
pub async fn make_api_threaded_call<'a, T: ?Sized, R: Send + Sized + 'static>(
    tx: &mut ThreadedCallSender<T>,
    f: impl FnOnce(&mut T) -> R + Send + Sized + 'static,
    tag: &str,
) -> Result<R, warp::Rejection> {
    threaded_call::make_threaded_call(tx, f, tag)
        .await
        .map_err(|e| {
            trace!("make_api_threaded_call error: {} ({})", e, tag);
            warp::reject::custom(errors::InternalError)
        })
}
