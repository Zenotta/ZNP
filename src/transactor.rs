use crate::comms_handler::Node;
use crate::interfaces::{NodeType, UtxoFetchType, UtxoSet};
use crate::wallet::WalletDb;
use crate::{ComputeRequest, Response};
use async_trait::async_trait;
use naom::primitives::asset::Asset;
use naom::primitives::transaction::{Transaction, TxIn, TxOut};
use std::net::SocketAddr;
use naom::utils::transaction_utils::construct_tx_hash;
use tracing::debug;
use crate::utils::get_paiments_for_wallet;

/// A common trait that can be implemented by nodes as necessary to
/// build transactions from their local wallets.
// TODO: Expand this trait by finding more common ground between UserNode and MinerNode
#[async_trait]
pub trait Transactor {
    type Error;

    /// Get `Vec<TxIn>` and `Vec<TxOut>` values for a transaction
    ///
    /// ### Arguments
    ///
    /// * `asset_required`              - The required `Asset`
    /// * `tx_outs`                     - Initial `Vec<TxOut>` value
    async fn fetch_tx_ins_and_tx_outs(
        wallet_db: &mut WalletDb,
        asset_required: Asset,
        mut tx_outs: Vec<TxOut>,
    ) -> Result<(Vec<TxIn>, Vec<TxOut>), Self::Error> {
        let (tx_cons, total_amount, tx_used) = wallet_db
            .fetch_inputs_for_payment(asset_required.clone())
            .await
            .unwrap();

        if let Some(excess) = total_amount.get_excess(&asset_required) {
            let (excess_address, _) = wallet_db.generate_payment_address().await;
            tx_outs.push(TxOut::new_asset(excess_address, excess));
        }

        let tx_ins = wallet_db.consume_inputs_for_payment(tx_cons, tx_used).await;

        Ok((tx_ins, tx_outs))
    }

    /// Sends the next internal payment transaction to be processed by the connected Compute
    /// node
    ///
    /// ### Arguments
    ///
    /// * `compute_peer` - Compute peer to send the payment tx to
    /// * `transactions` - Transactions to send
    async fn send_transactions_to_compute(
        &mut self,
        compute_peer: SocketAddr,
        transactions: Vec<Transaction>,
    ) -> Result<(), Self::Error>;

    /// Store payment transaction
    ///
    /// ### Arguments
    ///
    /// * `transaction` - Transaction to be received and saved to wallet
    async fn store_payment_transaction(wallet_db: &mut WalletDb, transaction: Transaction) {
        let hash = construct_tx_hash(&transaction);

        let payments = get_paiments_for_wallet(Some((&hash, &transaction)).into_iter());

        let our_payments = wallet_db
            .save_usable_payments_to_wallet(payments)
            .await
            .unwrap();
        debug!("store_payment_transactions: {:?}", our_payments);
    }

    /// Send a request to the compute nodes to receive latest UTXO set
    ///
    /// ### Arguments
    /// * `address_list` - List of addresses for which UTXOs are requested
    async fn send_request_utxo_set(
        node: &mut Node,
        address_list: UtxoFetchType,
        compute_addr: SocketAddr,
        requester_node_type: NodeType,
    ) -> Result<(), Self::Error> {
        node.send(
            compute_addr,
            ComputeRequest::SendUtxoRequest {
                address_list,
                requester_node_type,
            },
        )
        .await
        .unwrap();
        Ok(())
    }

    /// Receive the requested UTXO set/subset from Compute
    ///
    /// ### Arguments
    ///
    /// * `utxo_set` - The requested UTXO set
    fn receive_utxo_set(&mut self, utxo_set: UtxoSet) -> Response;

    /// Updates the local running total with the latest received UTXO set
    async fn update_running_total(&mut self);
}
