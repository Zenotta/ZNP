use crate::configurations::NodeSpec;
use crate::interfaces::{BlockchainItem, BlockchainItemMeta};
use crate::storage::{indexed_block_hash_key, indexed_tx_hash_key};
use std::fmt;
use std::net::SocketAddr;
use std::ops::Range;
use std::time::Duration;
use tokio::time::{self, Instant};
use tracing::{debug, error};

pub type FetchedBlockChain = (u64, Vec<BlockchainItem>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchStatus {
    Contiguous(u64),
    NotContiguous(u64),
}

#[derive(Debug, Clone)]
enum FetchReceiveState {
    NoWait,
    WaitBlock { b_num: u64 },
    WaitTxs { b_num: u64, txs: Range<u32> },
    DoneBlock { b_num: u64 },
}

impl Default for FetchReceiveState {
    fn default() -> Self {
        Self::NoWait
    }
}

impl FetchReceiveState {
    fn get_key(&self) -> Option<String> {
        match self {
            Self::WaitBlock { b_num } => Some(indexed_block_hash_key(*b_num)),
            Self::WaitTxs { b_num, txs } if !txs.is_empty() => {
                Some(indexed_tx_hash_key(*b_num, txs.start))
            }
            Self::NoWait | Self::DoneBlock { .. } | Self::WaitTxs { .. } => None,
        }
    }
}

#[derive(Debug)]
struct FetchReceive {
    target_b_num: u64,
    state: FetchReceiveState,
    timeout_at: (Instant, bool),
    blockchain_items: Vec<BlockchainItem>,
}

impl FetchReceive {
    /// Start up fetching blocks
    pub fn new_block_fetch(start_b_num: u64, target_b_num: u64) -> Self {
        let b_num = start_b_num;
        Self {
            target_b_num,
            state: FetchReceiveState::WaitBlock { b_num },
            timeout_at: (Instant::now(), false),
            blockchain_items: Default::default(),
        }
    }

    /// Increase target
    pub fn increase_running_target(&mut self, b_num: u64) {
        self.target_b_num = std::cmp::max(self.target_b_num, b_num);
    }

    pub fn target(&self) -> u64 {
        self.target_b_num
    }

    /// Process received item
    pub fn receive_blockchain_items(&mut self, item: BlockchainItem) -> Option<FetchedBlockChain> {
        use BlockchainItemMeta as M;
        use FetchReceiveState as S;

        let new_state = match (item.item_meta, self.state.clone()) {
            (M::Block { block_num, tx_len }, S::WaitBlock { b_num }) if block_num == b_num => {
                let txs = 0..tx_len;
                if txs.is_empty() {
                    Some(S::DoneBlock { b_num })
                } else {
                    Some(S::WaitTxs { b_num, txs })
                }
            }
            (M::Tx { block_num, tx_num }, S::WaitTxs { b_num, txs })
                if block_num == b_num && tx_num == txs.start =>
            {
                if 1 < txs.len() {
                    let txs = txs.start + 1..txs.end;
                    Some(S::WaitTxs { b_num, txs })
                } else {
                    Some(S::DoneBlock { b_num })
                }
            }
            (meta, state) => {
                error!("Unexpected block type: ({:?}, {:?})", meta, state);
                None
            }
        };

        if let Some(new_state) = new_state {
            self.blockchain_items.push(item);
            self.state = new_state;
        }

        if let S::DoneBlock { b_num } = self.state {
            self.state = if b_num < self.target_b_num {
                let b_num = b_num + 1;
                S::WaitBlock { b_num }
            } else {
                S::NoWait
            };

            Some((b_num, std::mem::take(&mut self.blockchain_items)))
        } else {
            None
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state, FetchReceiveState::NoWait)
    }
}

pub struct StorageFetch {
    /// Duration of timeout before retry
    timeout_duration: Duration,
    /// Storage nodes to fetch from
    storage_nodes: Vec<SocketAddr>,
    /// The index of the peer in `storage_nodes` to fetch from.
    fetch_peer_idx: usize,
    /// Last block we have full history
    last_contiguous_block_num: Option<u64>,
    /// Target and receive state for catch up
    to_receive: Option<FetchReceive>,
}

impl StorageFetch {
    /// Initialize with database info
    pub fn new(addr: SocketAddr, storage_nodes: &[NodeSpec], timeout_duration: Duration) -> Self {
        let storage_nodes = storage_nodes.iter().map(|s| s.address);
        let storage_nodes = storage_nodes.filter(|a| a != &addr).collect();
        Self {
            timeout_duration,
            storage_nodes,
            fetch_peer_idx: 0,
            last_contiguous_block_num: None,
            to_receive: None,
        }
    }

    /// Set intial info loaded from db
    pub fn set_initial_last_contiguous_block_key(
        &mut self,
        last_contiguous_block_num: Option<u64>,
    ) {
        debug!(
            "set_initial_last_contiguous_block_key = {:?}",
            last_contiguous_block_num
        );
        self.last_contiguous_block_num = last_contiguous_block_num;
    }

    /// Increase target if running
    pub fn increase_running_target(&mut self, block_num: u64) {
        if let Some(to_receive) = &mut self.to_receive {
            to_receive.increase_running_target(block_num);
        }
    }

    /// Trigger fetching if missing block detected
    pub fn fetch_missing_blockchain_items(&mut self, block_num: u64) -> bool {
        if let Some(to_receive) = &mut self.to_receive {
            to_receive.increase_running_target(block_num);
            return false;
        }

        if Some(block_num) <= self.last_contiguous_block_num {
            // Up to date
            return false;
        }

        // Start fetch
        self.to_receive = {
            let next = self
                .last_contiguous_block_num
                .map(|v| v + 1)
                .unwrap_or_default();
            Some(FetchReceive::new_block_fetch(next, block_num))
        };
        true
    }

    /// Provvide the key to fetch
    pub async fn timeout_fetch_blockchain_item(&self) -> Option<()> {
        if let Some(to_receive) = &self.to_receive {
            time::sleep_until(to_receive.timeout_at.0).await;
            Some(())
        } else {
            None
        }
    }

    /// Update next timeout: return true if was retrying already
    pub fn set_retry_timeout(&mut self) -> bool {
        if let Some(to_receive) = &mut self.to_receive {
            let was_retry = to_receive.timeout_at.1;
            to_receive.timeout_at = (Instant::now() + self.timeout_duration, true);
            was_retry
        } else {
            false
        }
    }

    /// Update next timeout
    pub fn set_first_timeout(&mut self) {
        if let Some(to_receive) = &mut self.to_receive {
            to_receive.timeout_at = (Instant::now(), false);
        }
    }

    /// Get the peer to fetch items from and key
    pub fn get_fetch_peer_and_key(&self) -> Option<(SocketAddr, String)> {
        let key = self.to_receive.as_ref().and_then(|r| r.state.get_key());
        let peer = self.storage_nodes.get(self.fetch_peer_idx).copied();
        peer.zip(key)
    }

    /// Select the next peer to fetch from
    pub fn change_to_next_fetch_peer(&mut self) {
        let next = self.fetch_peer_idx + 1;
        self.fetch_peer_idx = if next < self.storage_nodes.len() {
            next
        } else {
            0
        };
    }

    /// Process received item
    pub fn receive_blockchain_items(
        &mut self,
        _key: String,
        item: BlockchainItem,
    ) -> Option<FetchedBlockChain> {
        if !self.is_complete() && item.is_empty() {
            // item not found
            self.change_to_next_fetch_peer();
            return None;
        }

        if let Some(to_receive) = &mut self.to_receive {
            let block = to_receive.receive_blockchain_items(item);
            if to_receive.is_complete() {
                self.to_receive = None;
            }

            block
        } else {
            None
        }
    }

    /// Check if fetch process is complete
    pub fn is_complete(&self) -> bool {
        self.to_receive.is_none()
    }

    /// Get next contiguous tracking
    pub fn check_contiguous_block_num(&self, block_num: u64) -> FetchStatus {
        let next_contiguous = self.last_contiguous_block_num.map(|v| v + 1);
        if block_num == next_contiguous.unwrap_or_default() {
            FetchStatus::Contiguous(block_num)
        } else {
            FetchStatus::NotContiguous(block_num)
        }
    }

    /// Update contiguous tracking
    pub fn update_contiguous_block_num(&mut self, status: FetchStatus) {
        if let FetchStatus::Contiguous(block_num) = status {
            self.last_contiguous_block_num = Some(block_num);
        }
    }
}

impl fmt::Debug for StorageFetch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StorageFetch({:?}, {:?})",
            self.last_contiguous_block_num,
            self.to_receive.as_ref().map(|v| v.target())
        )
    }
}
