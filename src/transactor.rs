use async_trait::async_trait;
use naom::primitives::asset::Asset;
use naom::primitives::transaction::{Transaction, TxIn, TxOut};
use std::net::SocketAddr;

/// A common trait that can be implemented by nodes as necessary to
/// build transactions from their local wallets.
#[async_trait]
pub trait TransactionBuilder {
    type Error;

    /// Get `Vec<TxIn>` and `Vec<TxOut>` values for a transaction
    ///
    /// ### Arguments
    ///
    /// * `asset_required`              - The required `Asset`
    /// * `tx_outs`                     - Initial `Vec<TxOut>` value
    async fn fetch_tx_ins_and_tx_outs(
        &mut self,
        asset_required: Asset,
        mut tx_outs: Vec<TxOut>,
    ) -> Result<(Vec<TxIn>, Vec<TxOut>), Self::Error>;

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
    async fn store_payment_transaction(&mut self, transaction: Transaction);
}
