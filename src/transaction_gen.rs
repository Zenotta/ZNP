use crate::configurations::WalletTxSpec;
use crate::utils::{create_valid_transaction_with_ins_outs, make_wallet_tx_info};
use bincode::{deserialize, serialize};
use naom::crypto::sign_ed25519::{PublicKey, SecretKey};
use naom::primitives::asset::TokenAmount;
use naom::primitives::transaction::{OutPoint, Transaction};
use naom::utils::transaction_utils::{
    construct_address, construct_address_for, get_tx_out_with_out_point,
};
use std::collections::{BTreeMap, BTreeSet};

/// Key material to generate transactions
#[derive(Clone, Debug)]
pub struct TransactionsKeys {
    pub pk: PublicKey,
    pub sk: SecretKey,
    pub address: String,
    pub version: Option<u64>,
}

/// Maintain a list of valid transactions to submit
#[derive(Clone, Debug)]
pub struct TransactionGen {
    addr_to_keys: BTreeMap<String, TransactionsKeys>,
    up_to_date_with_snapshot: bool,
    pending: BTreeMap<String, Transaction>,
    ready: BTreeMap<String, Vec<(OutPoint, TokenAmount)>>,
    from_to_address: Vec<(String, String)>,
}

impl TransactionGen {
    /// New generator with seed infos
    pub fn new(tx_specs: Vec<WalletTxSpec>) -> Self {
        let infos: Vec<_> = tx_specs
            .iter()
            .map(make_wallet_tx_info)
            .map(|(out_p, pk, sk, amount, v)| {
                ((out_p, amount), (pk, sk, construct_address_for(&pk, v), v))
            })
            .collect();

        let mut addr_to_keys = BTreeMap::new();
        let mut ready: BTreeMap<_, Vec<_>> = Default::default();
        let mut old_address = BTreeSet::new();
        let mut new_address = BTreeSet::new();
        for (tx_out, (pk, sk, address, version)) in infos {
            if version.is_some() {
                let (pk, sk, address, version) = (pk, sk.clone(), construct_address(&pk), None);
                new_address.insert(address.clone());

                ready.entry(address.clone()).or_default();
                addr_to_keys.insert(
                    address.clone(),
                    TransactionsKeys {
                        pk,
                        sk,
                        address,
                        version,
                    },
                );
            }

            if version.is_some() {
                old_address.insert(address.clone());
            } else {
                new_address.insert(address.clone());
            }

            ready.entry(address.clone()).or_default().push(tx_out);
            addr_to_keys.insert(
                address.clone(),
                TransactionsKeys {
                    pk,
                    sk,
                    address,
                    version,
                },
            );
        }

        let mut from_to_address = Vec::new();
        let to_addr = new_address.iter().cycle().skip(1).cloned();
        from_to_address.extend(new_address.clone().into_iter().zip(to_addr.clone()));
        from_to_address.extend(old_address.into_iter().zip(to_addr.clone()));

        Self {
            addr_to_keys,
            up_to_date_with_snapshot: false,
            pending: Default::default(),
            ready,
            from_to_address,
        }
    }

    pub fn pending_txs(&self) -> &BTreeMap<String, Transaction> {
        &self.pending
    }

    pub fn is_up_to_date_with_snapshot(&self) -> bool {
        self.up_to_date_with_snapshot
    }

    pub fn snapshot_state(&mut self) -> Vec<u8> {
        self.up_to_date_with_snapshot = true;
        serialize(&(&self.pending, &self.ready)).unwrap()
    }

    pub fn apply_snapshot_state(&mut self, snapshot: &[u8]) {
        let (pending, ready) = deserialize(snapshot).unwrap();
        self.pending = pending;
        self.ready = ready;
        self.up_to_date_with_snapshot = true;
    }

    /// Commit transaction that are ready to be spent
    pub fn commit_transactions(&mut self, hashes: &[String]) {
        let txs: Vec<_> = hashes
            .iter()
            .filter_map(|c| self.pending.remove_entry(c))
            .collect();

        for (addr, read_txs) in &mut self.ready {
            read_txs.extend(
                get_tx_out_with_out_point(txs.iter().map(|(o, t)| (o, t)))
                    .filter(|(_, tx_out)| Some(addr) == tx_out.script_public_key.as_ref())
                    .map(|(out_p, tx_out)| (out_p, tx_out.value.token_amount())),
            );
        }
    }

    /// Make all transaction going from one address to the next
    pub fn make_all_transactions(
        &mut self,
        chunk_size: Option<usize>,
        total_tx: usize,
    ) -> Vec<(String, Transaction)> {
        let mut all_txs = Vec::new();

        for (from, to) in self.from_to_address.clone() {
            let input_len = if all_txs.len() >= total_tx {
                break;
            } else {
                chunk_size.unwrap_or(total_tx - all_txs.len())
            };

            while let Some(tx) = self.make_transaction(&from, &to, input_len) {
                all_txs.push(tx);
                if all_txs.len() >= total_tx {
                    break;
                }
            }
        }
        all_txs
    }

    /// Make a single transaction
    pub fn make_transaction(
        &mut self,
        from: &str,
        to: &str,
        input_len: usize,
    ) -> Option<(String, Transaction)> {
        if let Some(inputs) = self.ready.get_mut(from) {
            let input_len = std::cmp::min(inputs.len(), input_len);
            let inputs: Vec<_> = if input_len == 0 {
                return None;
            } else {
                inputs.drain(..input_len).collect()
            };

            let ouputs = inputs.iter().map(|(_, amount)| amount.0).sum();
            let tx_ins: Vec<(i32, &str)> = inputs
                .iter()
                .map(|(out_p, _)| (out_p.n, out_p.t_hash.as_str()))
                .collect();
            let receiver_addr_hexs: Vec<_> = (0..ouputs).map(|_| to).collect();

            let keys = self.addr_to_keys.get(from).unwrap();
            let (hash, tx) = create_valid_transaction_with_ins_outs(
                &tx_ins,
                &receiver_addr_hexs,
                &keys.pk,
                &keys.sk,
                TokenAmount(1),
                keys.version,
            );
            self.pending.insert(hash.clone(), tx.clone());

            Some((hash, tx))
        } else {
            None
        }
    }
}
