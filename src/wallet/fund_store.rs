use naom::primitives::asset::{Asset, AssetValues};
use naom::primitives::transaction::OutPoint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A reference to fund stores, where `transactions` contains the hash
/// of the transaction and its holding `AssetValue`
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct FundStore {
    running_total: AssetValues,
    transactions: BTreeMap<OutPoint, Asset>,
    spent_transactions: BTreeMap<OutPoint, Asset>,
}

impl FundStore {
    pub fn new(
        running_total: AssetValues,
        transactions: BTreeMap<OutPoint, Asset>,
        spent_transactions: BTreeMap<OutPoint, Asset>,
    ) -> Self {
        Self {
            running_total,
            transactions,
            spent_transactions,
        }
    }

    pub fn running_total(&self) -> &AssetValues {
        &self.running_total
    }

    pub fn transactions(&self) -> &BTreeMap<OutPoint, Asset> {
        &self.transactions
    }

    pub fn spent_transactions(&self) -> &BTreeMap<OutPoint, Asset> {
        &self.spent_transactions
    }

    pub fn into_transactions(self) -> BTreeMap<OutPoint, Asset> {
        self.transactions
    }

    pub fn remove_spent_transactions(&mut self) -> BTreeMap<OutPoint, Asset> {
        std::mem::take(&mut self.spent_transactions)
    }

    pub fn store_tx(&mut self, out_p: OutPoint, amount: Asset) {
        let asset_to_save = amount.clone().with_fixed_hash(&out_p);
        if let Some(old_amount) = self.transactions.insert(out_p, asset_to_save.clone()) {
            if old_amount != amount {
                panic!("Try to insert existing transaction with different amount");
            }
        } else {
            self.running_total.update_add(&asset_to_save);
        }
    }

    pub fn spend_tx(&mut self, out_p: &OutPoint) {
        if let Some((out_p_v, amount)) = self.transactions.remove_entry(out_p) {
            self.running_total.update_sub(&amount);
            if self.spent_transactions.insert(out_p_v, amount).is_some() {
                panic!("Try to spend already spent transaction {:?}", out_p);
            }
        }
    }
}
