use naom::primitives::asset::{Asset, TokenAmount};
use naom::primitives::transaction::OutPoint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::AddAssign;

/// `AssetValue` struct used to represent the `FundStore`'s running total
/// Currently, the running total for `Token` and `Receipt` assets are represented.
#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetValues {
    pub tokens: TokenAmount,
    pub receipts: u64,
}

impl AddAssign for AssetValues {
    fn add_assign(&mut self, rhs: Self) {
        *self = Self {
            tokens: self.tokens + rhs.tokens,
            receipts: self.receipts + rhs.receipts,
        };
    }
}

impl AssetValues {
    pub fn new(tokens: TokenAmount, receipts: u64) -> Self {
        Self { tokens, receipts }
    }

    pub fn token_u64(tokens: u64) -> Self {
        AssetValues::new(TokenAmount(tokens), 0)
    }

    pub fn receipt(receipts: u64) -> Self {
        AssetValues::new(TokenAmount(0), receipts)
    }

    pub fn is_empty(&self) -> bool {
        self == &AssetValues::default()
    }

    pub fn has_enough(&self, asset_required: &Asset) -> bool {
        match asset_required {
            Asset::Token(tokens) => self.tokens >= *tokens,
            Asset::Receipt(receipts) => self.receipts >= *receipts,
            _ => false,
        }
    }

    pub fn update_add(&mut self, rhs: &Asset) {
        match rhs {
            Asset::Token(tokens) => self.tokens += *tokens,
            Asset::Receipt(receipts) => self.receipts += *receipts,
            _ => {}
        }
    }

    pub fn update_sub(&mut self, rhs: &Asset) {
        match rhs {
            Asset::Token(tokens) => self.tokens -= *tokens,
            Asset::Receipt(receipts) => self.receipts -= *receipts,
            _ => {}
        }
    }
}

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

    pub fn running_total(&self) -> AssetValues {
        self.running_total
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
        if let Some(old_amount) = self.transactions.insert(out_p, amount.clone()) {
            if old_amount != amount {
                panic!("Try to insert existing transaction with different amount");
            }
        } else {
            self.running_total.update_add(&amount);
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
