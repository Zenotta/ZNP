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
    transaction_pages: Vec<BTreeMap<OutPoint, Asset>>, //Vec holding redundent paged version of entries in transactions.
    spent_transactions: BTreeMap<OutPoint, Asset>,
}

//Number of transaction entries per page in transaction_pages
pub const ENTRIES_PER_PAGE: usize = 25;

impl FundStore {
    pub fn new(
        running_total: AssetValues,
        transactions: BTreeMap<OutPoint, Asset>,
        transaction_pages: Vec<BTreeMap<OutPoint, Asset>>, //Contains paged version of transactions
        spent_transactions: BTreeMap<OutPoint, Asset>,
    ) -> Self {
        let mut temp_transactions = transaction_pages;
        if temp_transactions.is_empty() {
            temp_transactions.push(BTreeMap::new());
        }

        Self {
            running_total,
            transactions,
            transaction_pages: temp_transactions,
            spent_transactions,
        }
    }

    pub fn running_total(&self) -> &AssetValues {
        &self.running_total
    }

    pub fn transactions(&self) -> &BTreeMap<OutPoint, Asset> {
        &self.transactions
    }

    /// Filters out locked coinbase transactions, updating the running total.
    ///
    /// Returns amount of filtered out coinbase transactions due to locktime
    ///
    /// # Arguments
    /// * `locked_coinbase` - A vector of tuples containing the transaction hash and the block height at which it is locked
    pub fn filter_locked_coinbase(
        &mut self,
        locked_coinbase: Option<&Vec<(String, u64)>>,
    ) -> Option<u64> {
        let mut out_points_locked = Vec::new();
        if let Some(locked_coinbase) = locked_coinbase {
            for (t_hash, _) in locked_coinbase {
                out_points_locked = self
                    .transactions
                    .keys()
                    .cloned()
                    .filter(|out_p| out_p.t_hash == t_hash.clone())
                    .collect::<Vec<OutPoint>>();

                out_points_locked.iter().for_each(|out_p| {
                    if let Some(asset_locked) = self.transactions.remove(out_p) {
                        self.running_total.update_sub(&asset_locked)
                    }
                });
            }
        }
        if out_points_locked.is_empty() {
            None
        } else {
            Some(out_points_locked.len() as u64)
        }
    }

    /// Returns a page (or nearest page) with tranasactions
    pub fn transaction_pages(&self, page: usize) -> &BTreeMap<OutPoint, Asset> {
        if let Some(page_ref) = self.transaction_pages.get(page) {
            return page_ref;
        } else if page > self.transaction_pages.len() {
            if let Some(page_ref) = self.transaction_pages.last() {
                return page_ref;
            }
        }
        self.transaction_pages.first().unwrap()
    }

    /// Get the current number of pages
    pub fn transaction_pages_len(&self) -> usize {
        self.transaction_pages.len()
    }

    //Adds a new BTreeMap object to transaction_pages
    pub fn add_transaction_pages(&mut self) {
        self.transaction_pages.push(BTreeMap::new());
    }

    pub fn spent_transactions(&self) -> &BTreeMap<OutPoint, Asset> {
        &self.spent_transactions
    }

    pub fn into_transactions(self) -> BTreeMap<OutPoint, Asset> {
        self.transactions
    }

    pub fn into_paged_transactions(self) -> Vec<BTreeMap<OutPoint, Asset>> {
        self.transaction_pages
    }

    pub fn remove_spent_transactions(&mut self) -> BTreeMap<OutPoint, Asset> {
        std::mem::take(&mut self.spent_transactions)
    }

    pub fn store_tx(&mut self, out_p: OutPoint, amount: Asset) {
        let asset_to_save = amount.clone().with_fixed_hash(&out_p);

        if self.transaction_pages.is_empty()
            || self.transaction_pages.last_mut().unwrap().keys().len() == ENTRIES_PER_PAGE
        {
            self.add_transaction_pages();
        }

        if let Some(old_amount) = self
            .transactions
            .insert(out_p.clone(), asset_to_save.clone())
        {
            if old_amount != amount {
                panic!("Try to insert existing transaction with different amount");
            }
        } else {
            //Adds the entry to transaction pages
            if let Some(page) = self.transaction_pages.last_mut() {
                //Adds the address to the transaction page
                page.insert(out_p, asset_to_save.clone());
            }
            self.running_total.update_add(&asset_to_save);
        }
    }

    pub fn spend_tx(&mut self, out_p: &OutPoint) {
        if let Some((out_p_v, amount)) = self.transactions.remove_entry(out_p) {
            for i in 0..self.transaction_pages.len() {
                if let Some(page) = self.transaction_pages.get_mut(i) {
                    page.remove_entry(out_p);
                    if page.is_empty() && i != 0 {
                        self.transaction_pages.remove(i);
                    }
                }
            }

            self.running_total.update_sub(&amount);
            if self.spent_transactions.insert(out_p_v, amount).is_some() {
                panic!("Try to spend already spent transaction {:?}", out_p);
            }
        }
    }
}
