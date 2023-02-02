use crate::interfaces::{AddressesWithOutPoints, OutPointData, UtxoSet};
use crate::utils::{get_pk_with_out_point_cloned, get_pk_with_out_point_from_utxo_set_cloned};
use naom::primitives::asset::AssetValues;
use naom::primitives::transaction::{OutPoint, Transaction};
use naom::utils::transaction_utils::get_tx_out_with_out_point_cloned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Deref;

#[derive(Default, Debug, Clone, Serialize)]
pub struct TrackedUtxoBalance {
    total: AssetValues,
    address_list: AddressesWithOutPoints,
}

impl TrackedUtxoBalance {
    pub fn get_asset_values(&self) -> &AssetValues {
        &self.total
    }
}
/// Invariant: `pk_cache` contains exactly all relevant mapping for `base`
#[derive(Default, Clone, Debug)]
pub struct TrackedUtxoSet {
    /// The `UtxoSet`
    base: UtxoSet,
    /// Cache mapping of Some `script_public_key` to `OutPoints` present in `base`.
    pk_cache: HashMap<String, Vec<OutPoint>>,
}

impl TrackedUtxoSet {
    /// Create a new TrackedUtxoSet from `UtxoSet` base
    pub fn new(base: UtxoSet) -> Self {
        let pk_cache = create_pk_cache_from_base(&base);
        TrackedUtxoSet { base, pk_cache }
    }

    // Take ownership of self; return base `UtxoSet`
    pub fn into_utxoset(self) -> UtxoSet {
        self.base
    }

    /// Get all `OutPoints` for a `script_public_key`
    pub fn get_pk_cache_vec(&self, key: &str) -> Option<&Vec<OutPoint>> {
        self.pk_cache.get(key)
    }

    /// Add base 'UtxoSet' and pk_cache entry concurrently
    pub fn extend_tracked_utxo_set(&mut self, block_tx: &BTreeMap<String, Transaction>) {
        self.base
            .extend(get_tx_out_with_out_point_cloned(block_tx.iter()));
        extend_pk_cache_vec(
            &mut self.pk_cache,
            get_pk_with_out_point_cloned(block_tx.iter()),
        );
    }

    /// Remove base 'UtxoSet' and pk_cache entry concurrently
    pub fn remove_tracked_utxo_entry<'a>(&mut self, key: &'a OutPoint) -> Option<&'a OutPoint> {
        self.base.remove(key)?.script_public_key.and_then(|spk| {
            let pk_cache_entry = self.pk_cache.get_mut(&spk)?;
            pk_cache_entry.retain(|op| op != key);
            if pk_cache_entry.is_empty() {
                self.pk_cache.remove(&spk);
            }
            Some(key)
        })
    }

    /// Calculates the balance of `OutPoint`s based on provided addresses
    pub fn get_balance_for_addresses(&self, addresses: &[String]) -> TrackedUtxoBalance {
        let mut address_list = AddressesWithOutPoints::new();
        let mut total = AssetValues::default();
        let mut known_op: BTreeSet<OutPoint> = Default::default();

        for address in addresses {
            if let Some(ops) = self.get_pk_cache_vec(address) {
                for op in ops {
                    // Ignore `OutPoint` values already present
                    if known_op.get(op).is_some() {
                        continue;
                    }
                    known_op.insert(op.clone());
                    let t_out = self.base.get(op).unwrap();
                    let asset = t_out.value.clone().with_fixed_hash(op);
                    address_list
                        .entry(address.clone())
                        .or_insert_with(Vec::new)
                        .push(OutPointData::new(op.clone(), asset.clone()));
                    total.update_add(&asset);
                }
            }
        }

        TrackedUtxoBalance {
            total,
            address_list,
        }
    }

    /// Get all `script_public_key` values from the current UTXO set
    pub fn get_all_addresses(&self) -> Vec<String> {
        self.base
            .iter()
            .filter_map(|(_, tx_out)| tx_out.script_public_key.clone())
            .collect::<Vec<String>>()
    }
}

/// Create `pk_cache` entries from base `UtxoSet`
pub fn create_pk_cache_from_base(base: &UtxoSet) -> HashMap<String, Vec<OutPoint>> {
    let mut pk_cache: HashMap<String, Vec<OutPoint>> = HashMap::new();
    extend_pk_cache_vec(
        &mut pk_cache,
        get_pk_with_out_point_from_utxo_set_cloned(base.iter()),
    );
    pk_cache
}

/// Extend `pk_cache` entries
pub fn extend_pk_cache_vec<'a>(
    pk_cache: &mut HashMap<String, Vec<OutPoint>>,
    spk: impl Iterator<Item = (String, OutPoint)> + 'a,
) {
    spk.for_each(|(spk, op)| pk_cache.entry(spk).or_default().push(op));
}

impl Deref for TrackedUtxoSet {
    type Target = UtxoSet;

    fn deref(&self) -> &UtxoSet {
        &self.base
    }
}

impl Serialize for TrackedUtxoSet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.base.serialize(s)
    }
}

impl<'a> Deserialize<'a> for TrackedUtxoSet {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let base: UtxoSet = Deserialize::deserialize(deserializer)?;
        let pk_cache: HashMap<String, Vec<OutPoint>> = create_pk_cache_from_base(&base);
        Ok(TrackedUtxoSet { base, pk_cache })
    }
}
