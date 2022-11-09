use crate::active_raft::ActiveRaft;
use crate::raft::RaftData;
use bincode::{deserialize, serialize};
use naom::crypto::sha3_256;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use tracing::{debug, warn};

/// Key serialized into RaftData and process by Raft.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RaftContextKey {
    pub proposer_id: u64,
    pub proposer_run: u64,
    pub proposal_id: u64,
}

#[derive(Clone, Default)]
pub struct RaftInFlightProposals {
    /// Proposed items in flight.
    proposed_in_flight: BTreeMap<RaftContextKey, (RaftData, RaftData)>,
    /// Proposal block num associated with key
    proposed_keys_b_num: BTreeMap<RaftContextKey, u64>,
    /// The last id of a proposed item.
    proposed_last_id: u64,
    /// The current proposing key run.
    proposed_key_run: Option<u64>,
    /// Proposal data hash, to ignore if re-propose, with b_num to remove them at.
    already_proposed_hashes: BTreeMap<Vec<u8>, (RaftContextKey, u64)>,
    /// Minimum block number to accept for deduplicated entries
    min_b_num: u64,
}

impl RaftInFlightProposals {
    /// Set the key run for all proposals (load from db before first proposal).
    pub fn set_key_run(&mut self, key_run: u64) {
        self.proposed_key_run = Some(key_run);
    }

    /// Checks a commit of the RaftData for validity
    /// Return commited proposal
    ///
    /// ### Arguments
    ///
    /// * `raft_data` - Data for the commit
    /// * `raft_ctx`  - Context for the commit
    pub async fn received_commit_proposal<'a, Item: Deserialize<'a> + std::fmt::Debug>(
        &mut self,
        raft_data: &'a [u8],
        raft_ctx: &'a [u8],
    ) -> Option<(RaftContextKey, Item, bool)> {
        match (
            deserialize::<Item>(raft_data),
            deserialize::<RaftContextKey>(raft_ctx),
        ) {
            (Ok(item), Ok(key)) => {
                let removed = self.proposed_in_flight.remove(&key).is_some();
                self.proposed_keys_b_num.remove(&key);
                Some((key, item, removed))
            }
            (Err(error), Ok(key)) => {
                warn!("RaftItem-deserialize key {:?} -> error: {:?}", key, error);
                None
            }
            (_, Err(error)) => {
                warn!("RaftContextKey-deserialize error {:?}", error);
                None
            }
        }
    }

    /// Propose an item to raft if use_raft, or commit it otherwise.
    ///
    /// ### Arguments
    ///
    ///  * `raft_active` - The raft instance to propose to.
    ///  * `item`        - The item to be proposed to a raft.
    ///  * `dedup_b_num` - The block number to use for de-deduplication.
    pub async fn propose_item<Item: Serialize + Debug>(
        &mut self,
        raft_active: &mut ActiveRaft,
        item: &Item,
        dedup_b_num: Option<u64>,
    ) -> Option<RaftContextKey> {
        let data = serialize(item).unwrap();
        let dedup_info = check_deduplication(
            &self.already_proposed_hashes,
            self.min_b_num,
            &data,
            dedup_b_num,
        )?;

        let key = {
            self.proposed_last_id += 1;
            RaftContextKey {
                proposer_id: raft_active.peer_id(),
                proposer_run: self.proposed_key_run.unwrap(),
                proposal_id: self.proposed_last_id,
            }
        };
        let context = serialize(&key).unwrap();

        debug!("propose_item: {:?} -> {:?}", key, item);

        self.proposed_in_flight
            .insert(key, (data.clone(), context.clone()));
        if let Some((item_hash, b_num)) = dedup_info {
            self.already_proposed_hashes.insert(item_hash, (key, b_num));
            self.proposed_keys_b_num.insert(key, b_num);
        }

        raft_active.propose_data(data, context).await;
        Some(key)
    }

    /// Remove all items with provided keys
    pub fn remove_all_keys(&mut self, keys: &BTreeSet<RaftContextKey>) {
        for key in keys.iter() {
            self.proposed_in_flight.remove(key);
            self.proposed_keys_b_num.remove(key);
            self.already_proposed_hashes.retain(|_, (k, _)| *k != *key);
        }
    }

    /// Re-Propose an item in flight to raft.
    ///
    /// ### Arguments
    ///
    ///  * `raft_active` - The raft instance to propose to.
    ///  * `key`         - The item key to be proposed to a raft.
    pub async fn re_propose_item(&mut self, raft_active: &mut ActiveRaft, key: RaftContextKey) {
        if let Some((data, context)) = self.proposed_in_flight.get(&key) {
            raft_active
                .propose_data(data.clone(), context.clone())
                .await;
        }
    }

    /// Re-Propose all items in flight to raft.
    ///
    /// ### Arguments
    ///
    ///  * `raft_active` - The raft instance to propose to.
    pub async fn re_propose_all_items(&mut self, raft_active: &mut ActiveRaft) {
        debug!(
            "Re-propose all non committed items: {}",
            self.proposed_in_flight.len()
        );
        for (data, context) in self.proposed_in_flight.values() {
            raft_active
                .propose_data(data.clone(), context.clone())
                .await;
        }
    }

    /// Re-propose uncommited items relevant for current block.
    ///
    /// ### Arguments
    ///
    ///  * `raft_active`       - The raft instance to propose to.
    ///  * `current_block_num` - The block number to re-propose for.
    pub async fn re_propose_uncommitted_current_b_num(
        &mut self,
        raft_active: &mut ActiveRaft,
        current_block_num: u64,
    ) {
        for (key, block_num) in self.proposed_keys_b_num.clone() {
            if block_num == current_block_num {
                self.re_propose_item(raft_active, key).await;
            }
        }
    }

    /// Set new min_b_num for de-duplicate.
    /// Clear no lonber relevant entries.
    ///
    /// ### Arguments
    ///
    ///  * `min_b_num` - The minimum block number to accept.
    pub fn ignore_dedeup_b_num_less_than(&mut self, min_b_num: u64) {
        self.min_b_num = min_b_num;

        self.already_proposed_hashes = {
            std::mem::take(&mut self.already_proposed_hashes)
                .into_iter()
                .filter(|(_, (_, b_num))| min_b_num > *b_num)
                .collect()
        };
        self.proposed_keys_b_num = {
            std::mem::take(&mut self.proposed_keys_b_num)
                .into_iter()
                .filter(|(_, b_num)| min_b_num > *b_num)
                .collect()
        };
    }
}

/// Check if serialized item_data was already proposed
///
/// ### Arguments
///
///  * `already_proposed_hashes` - The already proposed hashes.
///  * `min_b_num`               - The minimum block number to accept.
///  * `item_data`               - The item to be proposed to a raft.
///  * `dedup_b_num`             - The block number to use for de-deduplication.
fn check_deduplication(
    already_proposed_hashes: &BTreeMap<Vec<u8>, (RaftContextKey, u64)>,
    min_b_num: u64,
    item_data: &[u8],
    dedup_b_num: Option<u64>,
) -> Option<Option<(Vec<u8>, u64)>> {
    if let Some(b_num) = dedup_b_num {
        if min_b_num > b_num {
            debug!("check_deduplication min({}) > b_num({})", min_b_num, b_num);
            return None;
        }

        let data_hash = sha3_256::digest(item_data).to_vec();
        if let Some((key, num)) = already_proposed_hashes.get(&data_hash) {
            debug!("check_deduplication found: key({:?}), b_num({})", key, num);
            None
        } else {
            Some(Some((data_hash, b_num)))
        }
    } else {
        Some(None)
    }
}
