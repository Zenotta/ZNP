#![allow(unused)]
use naom::constants::MAX_BLOCK_SIZE;
use naom::primitives::asset::Asset;
use naom::primitives::block::Block;
use naom::primitives::block::BlockHeader;
use naom::primitives::transaction::{Transaction, TxIn, TxOut};
use sha3::Digest;

use bincode::{deserialize, serialize};
use bytes::Bytes;
use naom::crypto::sign_ed25519::PublicKey;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::convert::TryInto;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// The hash information of the current block to mine
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct HashBlock {
    pub prev_hash: String,
    pub merkle_hash: String,
    pub nonce: Vec<u8>,
    pub b_num: u64,
}

impl HashBlock {
    /// Creates a new HashBlock to send for mining
    ///
    /// ### Arguments
    ///
    /// * `prev_hash`   - The previous hash of the block
    /// * `merkle_hash` - The merkle root hash of the transactions in this block
    /// * `b_num`       - The block number
    pub fn new_for_mining(prev_hash: String, merkle_hash: String, b_num: u64) -> HashBlock {
        HashBlock {
            prev_hash,
            merkle_hash,
            b_num,
            nonce: Vec::new(),
        }
    }

    /// Checks whether a HashBlock's nonce has been set
    pub fn has_nonce(&self) -> bool {
        self.nonce.is_empty()
    }
}
