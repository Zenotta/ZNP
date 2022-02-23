use crate::api::errors;
use crate::api::responses::{
    api_format_asset, common_error_reply, common_success_reply, json_embed, json_embed_block,
    json_embed_transaction, json_serialize_embed, APIAsset, APICreateResponseContent, CallResponse,
    CallResponseWithData, JsonReply,
};
use crate::comms_handler::Node;
use crate::constants::LAST_BLOCK_HASH_KEY;
use crate::db_utils::SimpleDb;
use crate::interfaces::{
    node_type_as_str, AddressesWithOutPoints, BlockchainItem, BlockchainItemMeta,
    BlockchainItemType, ComputeApi, DebugData, DruidPool, OutPointData, StoredSerializingBlock,
    UserApiRequest, UserRequest, UtxoFetchType,
};
use crate::miner::{BlockPoWReceived, CurrentBlockWithMutex};
use crate::storage::{get_stored_value_from_db, indexed_block_hash_key};
use crate::threaded_call::{self, ThreadedCallSender};
use crate::utils::{decode_pub_key, decode_signature};
use crate::wallet::{WalletDb, WalletDbError};
use naom::constants::D_DISPLAY_PLACES;
use naom::crypto::sign_ed25519::PublicKey;
use naom::primitives::asset::{Asset, TokenAmount};
use naom::primitives::druid::DdeValues;
use naom::primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use naom::script::lang::Script;
use naom::utils::transaction_utils::construct_address_for;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, trace};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReceiptAssetDataUser {
    pub receipt_amount: u64,
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

//======= GET HANDLERS =======//

/// Gets the state of the connected wallet and returns it.
/// Returns a `WalletInfo` struct
pub async fn get_wallet_info(
    wallet_db: WalletDb,
    extra: Option<String>,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse { route, call_id };

    let fund_store = match wallet_db.get_fund_store_err() {
        Ok(fund) => fund,
        Err(_) => return r.into_err(&errors::ErrorCannotAccessWallet),
    };

    let mut addresses = AddressesWithOutPoints::new();
    let txs = match extra.as_deref() {
        Some("spent") => fund_store.spent_transactions(),
        _ => fund_store.transactions(),
    };

    for (out_point, asset) in txs {
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

    r.into_ok(json_serialize_embed(send_val))
}

/// Gets all present keys and sends them out for export
pub async fn get_export_keypairs(
    wallet_db: WalletDb,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let known_addr = wallet_db.get_known_addresses();
    let mut addresses = BTreeMap::new();

    for addr in known_addr {
        addresses.insert(addr.clone(), wallet_db.get_address_store_encrypted(&addr));
    }

    Ok(common_success_reply(
        call_id,
        route,
        json_serialize_embed(addresses),
    ))
}

/// Gets a newly generated payment address
pub async fn get_payment_address(
    wallet_db: WalletDb,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let (address, _) = wallet_db.generate_payment_address().await;

    Ok(common_success_reply(
        call_id,
        route,
        json_serialize_embed(address),
    ))
}

/// Gets the latest block information
pub async fn get_latest_block(
    db: Arc<Mutex<SimpleDb>>,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    get_json_reply_stored_value_from_db(db, LAST_BLOCK_HASH_KEY, false, call_id, route)
}

/// Gets the debug info for a speficied node type
///
/// Contains an optional field for an auxiliary `Node`,
/// i.e a Miner node may or may not have additional User
/// node capabilities- providing additional debug data.
pub async fn get_debug_data<'a>(
    debug_paths: DbgPaths,
    node: Node,
    aux_node: Option<Node>,
    route: &'a str,
    call_id: &'a str,
) -> Result<JsonReply, JsonReply> {
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

    Ok(common_success_reply(
        call_id,
        route,
        json_serialize_embed(data),
    ))
}

/// Get to fetch information about the current mining block
pub async fn get_current_mining_block(
    current_block: CurrentBlockWithMutex,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let data: Option<BlockPoWReceived> = current_block.lock().unwrap().clone();
    Ok(common_success_reply(
        call_id,
        route,
        json_serialize_embed(data),
    ))
}

/// Get all addresses for unspent tokens on the UTXO set
pub async fn get_utxo_addresses(
    mut threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let addresses = make_api_threaded_call(
        &mut threaded_calls,
        |c| c.get_committed_utxo_tracked_set().get_all_addresses(),
        call_id,
        route,
        "Can't access UTXO",
    )
    .await?;

    Ok(common_success_reply(
        call_id,
        route,
        json_serialize_embed(addresses),
    ))
}

//======= POST HANDLERS =======//

/// Post to retrieve an item from the blockchain db by hash key
pub async fn post_blockchain_entry_by_key(
    db: Arc<Mutex<SimpleDb>>,
    key: String,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    get_json_reply_stored_value_from_db(db, &key, true, call_id, route)
}

/// Post to retrieve block information by number
pub async fn post_block_by_num(
    db: Arc<Mutex<SimpleDb>>,
    block_nums: Vec<u64>,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let keys: Vec<_> = block_nums
        .iter()
        .map(|num| indexed_block_hash_key(*num))
        .collect();
    get_json_reply_blocks_from_db(db, keys, route, call_id)
}

/// Post to import new keypairs to the connected wallet
pub async fn post_import_keypairs(
    db: WalletDb,
    keypairs: Addresses,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let response_keys: Vec<String> = keypairs.addresses.keys().cloned().collect();
    let r = CallResponseWithData {
        route,
        call_id,
        data: json_serialize_embed(response_keys),
    };

    for (addr, address_set) in keypairs.addresses.iter() {
        match db
            .save_encrypted_address_to_wallet(addr.clone(), address_set.clone())
            .await
        {
            Ok(_) => {}
            Err(_e) => {
                return r.into_err(&errors::ErrorCannotAccessUserNode);
            }
        }
    }

    r.into_ok()
}

///Post make a new payment from the connected wallet
pub async fn post_make_payment(
    db: WalletDb,
    peer: Node,
    encapsulated_data: EncapsulatedPayment,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let EncapsulatedPayment {
        address,
        amount,
        passphrase,
    } = encapsulated_data;

    let r = CallResponse { route, call_id };

    let request = match db.test_passphrase(passphrase).await {
        Ok(_) => UserRequest::UserApi(UserApiRequest::MakePayment {
            address: address.clone(),
            amount,
        }),
        Err(e) => {
            return r.into_err(&wallet_db_error(e));
        }
    };

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:make_payment error: {:?}", e);
        return r.into_err(&errors::ErrorCannotAccessUserNode);
    }

    r.into_ok(json_serialize_embed(construct_make_payment_map(
        address, amount,
    )))
}

///Post make a new payment from the connected wallet using an ip address
pub async fn post_make_ip_payment(
    db: WalletDb,
    peer: Node,
    encapsulated_data: EncapsulatedPayment,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let EncapsulatedPayment {
        address,
        amount,
        passphrase,
    } = encapsulated_data;

    let r = CallResponse { route, call_id };

    let payment_peer: SocketAddr = match address.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            return r.into_err(&errors::ErrorCannotParseAddress);
        }
    };

    let request = match db.test_passphrase(passphrase).await {
        Ok(_) => UserRequest::UserApi(UserApiRequest::MakeIpPayment {
            payment_peer,
            amount,
        }),
        Err(e) => {
            return r.into_err(&wallet_db_error(e));
        }
    };

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:make_payment error: {:?}", e);
        return r.into_err(&errors::ErrorCannotAccessUserNode);
    }

    r.into_ok(json_serialize_embed(construct_make_payment_map(
        address.clone(),
        amount,
    )))
}

///Post make a donation request from the user node at specified ip address
pub async fn post_request_donation(
    peer: Node,
    address: String,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse { route, call_id };
    let paying_peer: SocketAddr = match address.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            return r.into_err(&errors::ErrorCannotParseAddress);
        }
    };

    let request = UserRequest::UserApi(UserApiRequest::RequestDonation { paying_peer });

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:request_donation error: {:?}", e);
        return r.into_err(&errors::ErrorCannotAccessUserNode);
    }

    r.into_ok(json_serialize_embed("null"))
}

/// Post to update running total of connected wallet
pub async fn post_update_running_total(
    peer: Node,
    addresses: PublicKeyAddresses,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let request = UserRequest::UserApi(UserApiRequest::UpdateWalletFromUtxoSet {
        address_list: UtxoFetchType::AnyOf(addresses.address_list),
    });
    let r = CallResponse { route, call_id };

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:update_running_total error: {:?}", e);
        return r.into_err(&errors::ErrorCannotAccessUserNode);
    }

    r.into_ok(json_serialize_embed("null"))
}

/// Post to fetch the balance for given addresses in UTXO
pub async fn post_fetch_utxo_balance(
    mut threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    addresses: PublicKeyAddresses,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let balances = make_api_threaded_call(
        &mut threaded_calls,
        move |c| {
            c.get_committed_utxo_tracked_set()
                .get_balance_for_addresses(&addresses.address_list)
        },
        call_id,
        route,
        "Cannot fetch UTXO balance",
    )
    .await?;

    Ok(common_success_reply(
        call_id,
        route,
        json_serialize_embed(balances),
    ))
}

//POST fetch pending transaction from a computet node
pub async fn post_fetch_druid_pending(
    mut threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    fetch_input: FetchPendingData,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let pending_transactions = make_api_threaded_call(
        &mut threaded_calls,
        move |c| {
            let pending = c.get_pending_druid_pool();
            (fetch_input.druid_list.iter())
                .filter_map(|k| pending.get_key_value(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<DruidPool>()
        },
        call_id,
        route,
        "Cannot fetch pending transactions",
    )
    .await?;

    Ok(common_success_reply(
        call_id,
        route,
        json_serialize_embed(pending_transactions),
    ))
}

/// Post to create a receipt asset transaction on User node
pub async fn post_create_receipt_asset_user(
    peer: Node,
    receipt_data: CreateReceiptAssetDataUser,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let CreateReceiptAssetDataUser { receipt_amount } = receipt_data;
    let request = UserRequest::UserApi(UserApiRequest::SendCreateReceiptRequest { receipt_amount });
    let r = CallResponse { route, call_id };

    if let Err(e) = peer.inject_next_event(peer.address(), request) {
        error!("route:create_receipt_asset error: {:?}", e);
        return r.into_err(&errors::ErrorCannotAccessUserNode);
    }

    r.into_ok(json_serialize_embed(receipt_amount))
}

/// Post to create a receipt asset transaction on Compute node
pub async fn post_create_receipt_asset(
    mut threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    create_receipt_asset_data: CreateReceiptAssetData,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let CreateReceiptAssetData {
        receipt_amount,
        script_public_key,
        public_key,
        signature,
    } = create_receipt_asset_data;

    let all_some = script_public_key.is_some() && public_key.is_some() && signature.is_some();

    // Response content
    let create_info = APICreateResponseContent::new(
        "receipt".to_string(),
        receipt_amount,
        script_public_key.clone().unwrap_or_default(),
    );

    let r = CallResponseWithData {
        route,
        call_id,
        data: json_serialize_embed(create_info),
    };

    if all_some {
        // Create receipt tx on the compute node
        let (script_public_key, public_key, signature) = (
            script_public_key.unwrap_or_default(),
            public_key.unwrap_or_default(),
            signature.unwrap_or_default(),
        );

        let compute_resp = make_api_threaded_call(
            &mut threaded_calls,
            move |c| {
                c.create_receipt_asset_tx(receipt_amount, script_public_key, public_key, signature)
            },
            call_id,
            route,
            "Cannot access Compute Node",
        )
        .await?;

        match compute_resp {
            Some(resp) => match resp.success {
                true => return r.into_ok(),
                false => return r.into_err(&resp.reason),
            },
            None => return r.into_err(&errors::ErrorCannotAccessComputeNode),
        }
    }

    debug!(
        "route:post_create_receipt_asset error: {:?}",
        "Invalid JSON structure"
    );

    r.into_err(&errors::ErrorInvalidJSONStructure)
}

/// Post transactions to compute node
pub async fn post_create_transactions(
    mut threaded_calls: ThreadedCallSender<dyn ComputeApi>,
    data: Vec<CreateTransaction>,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse { route, call_id };
    let transactions = {
        let mut transactions = Vec::new();
        for tx in data {
            let tx = match to_transaction(tx) {
                Ok(tx) => tx,
                Err(e) => {
                    debug!("route:post_create_transactions error: {:?}", e);
                    return r.into_err(&errors::ErrorInvalidJSONStructure);
                }
            };
            transactions.push(tx);
        }
        transactions
    };

    // Construct response
    let ctx_map = construct_ctx_map(&transactions);

    // Send request to compute node
    let compute_resp = make_api_threaded_call(
        &mut threaded_calls,
        move |c| c.receive_transactions(transactions),
        call_id,
        route,
        "Cannot access Compute Node",
    )
    .await?;

    // If the creation failed for some reason
    if !compute_resp.success {
        debug!(
            "route:post_create_transactions error: {:?}",
            compute_resp.reason
        );
        return r.into_err(&compute_resp.reason);
    }

    r.into_ok(json_serialize_embed(ctx_map))
}

// POST to change wallet passphrase
pub async fn post_change_wallet_passphrase(
    mut db: WalletDb,
    passphrase_struct: ChangePassphraseData,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let ChangePassphraseData {
        old_passphrase,
        new_passphrase,
    } = passphrase_struct;

    let r = CallResponse { route, call_id };

    match db
        .change_wallet_passphrase(old_passphrase, new_passphrase)
        .await
    {
        Ok(_) => r.into_ok(json_serialize_embed("null")),
        Err(e) => r.into_err(&wallet_db_error(e)),
    }
}

// POST to check for transaction presence
pub async fn post_blocks_by_tx_hashes(
    db: Arc<Mutex<SimpleDb>>,
    tx_hashes: Vec<String>,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
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
    Ok(common_success_reply(
        call_id,
        route,
        json_serialize_embed(block_nums),
    ))
}

//POST create a new payment address from a computet node
pub async fn post_payment_address_construction(
    data: AddressConstructData,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
    let pub_key = data.pub_key;
    let pub_key_hex = data.pub_key_hex;
    let version = data.version;
    let r = CallResponse { route, call_id };

    let pub_key = pub_key.or_else(|| pub_key_hex.and_then(|k| hex::decode(k).ok()));
    let pub_key = pub_key.filter(|k| !k.is_empty());
    let pub_key = pub_key.and_then(|k| PublicKey::from_slice(&k));

    if let Some(pub_key) = pub_key {
        let data: String = construct_address_for(&pub_key, version);
        return r.into_ok(json_serialize_embed(data));
    }

    r.into_ok(json_serialize_embed("null"))
}

//======= Helpers =======//

/// Filters through wallet errors which are internal vs errors caused by user input
pub fn wallet_db_error(err: WalletDbError) -> Box<dyn std::fmt::Display> {
    match err {
        WalletDbError::PassphraseError => Box::new(errors::ErrorInvalidPassphrase),
        _ => Box::new(errors::InternalError),
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
    call_id: &str,
    route: &str,
) -> Result<JsonReply, JsonReply> {
    let r = CallResponse { route, call_id };
    let item = get_stored_value_from_db(db, key.as_bytes()).ok_or_else(|| {
        r.clone()
            .into_err(&errors::ErrorNoDataFoundForKey)
            .unwrap_err()
    })?;

    let json_content = match (wrap, item.item_meta.as_type()) {
        (true, BlockchainItemType::Block) => json_embed_block(item.data_json),
        (true, BlockchainItemType::Tx) => json_embed_transaction(item.data_json),
        (false, _) => json_embed(&[&item.data_json]),
    };

    r.into_ok(json_content)
}

/// Fetches JSON blocks. Blocks which for whatever reason are
/// unretrievable will be replaced with a default (best handling?)
pub fn get_json_reply_blocks_from_db(
    db: Arc<Mutex<SimpleDb>>,
    keys: Vec<String>,
    route: &str,
    call_id: &str,
) -> Result<JsonReply, JsonReply> {
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

    Ok(common_success_reply(
        call_id,
        route,
        json_embed(&key_values),
    ))
}

/// Threaded call for API
pub async fn make_api_threaded_call<'a, T: ?Sized, R: Send + Sized + 'static>(
    tx: &mut ThreadedCallSender<T>,
    f: impl FnOnce(&mut T) -> R + Send + Sized + 'static,
    call_id: &str,
    route: &str,
    tag: &'static str,
) -> Result<R, JsonReply> {
    threaded_call::make_threaded_call(tx, f, tag)
        .await
        .map_err(|e| {
            trace!("make_api_threaded_call error: {} ({})", e, tag);
            common_error_reply(call_id, errors::ErrorGeneric::new(tag), route, None)
        })
}

/// Constructs the mapping of output address to asset for `create_transactions`
pub fn construct_ctx_map(transactions: &[Transaction]) -> BTreeMap<String, APIAsset> {
    let mut tx_info = BTreeMap::new();

    for tx in transactions {
        for out in &tx.outputs {
            let address = out.script_public_key.clone().unwrap_or_default();
            let asset = api_format_asset(out.value.clone());

            tx_info.insert(address, asset);
        }
    }

    tx_info
}

/// Constructs the mapping of output address to asset for `make_payment`
pub fn construct_make_payment_map(
    to_address: String,
    amount: TokenAmount,
) -> BTreeMap<String, APIAsset> {
    let mut tx_info = BTreeMap::new();
    tx_info.insert(to_address, api_format_asset(Asset::Token(amount)));
    tx_info
}
