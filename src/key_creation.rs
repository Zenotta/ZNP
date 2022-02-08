#![allow(non_snake_case, unused)]

use hex::encode;
use naom::crypto::sha3_256;
use naom::crypto::sign_ed25519 as sign;
use naom::crypto::sign_ed25519::{PublicKey, SecretKey};
use rug::integer::Order;
use rug::ops::Pow;
use rug::Integer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::iter::FromIterator;

/// Number of participants in a partition
const PARTICIPANTS: usize = 2;

/// A data structure for peer info
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInfo {
    u_i: u32,
    M_iI: Vec<u8>,
    ek_i: Vec<u8>,
    T_i: Vec<u8>,
    t_iL: Vec<u8>,
    pub k_j: Vec<u8>,
}

/// The data structure for partitioned key agreement
#[derive(Debug, Clone)]
pub struct KeyAgreement {
    g: u64,
    id: String,
    u_i: u32,
    x_i: u32,
    k_i: Vec<u8>,
    pub k_j: Vec<u8>,
    pub y_i: Vec<u8>,
    M_iI: Vec<u8>,
    M_iIU: Vec<u8>,
    M_iII: Vec<u8>,
    M_iIIsigma: Vec<u8>,
    sigma_iI: Vec<u8>,
    t_iL: Vec<u8>,
    t_iR: Vec<u8>,
    T_i: Vec<u8>,
    sid_i: Vec<u8>,
    ek_i: Vec<u8>,
    sigma_iII: Vec<u8>,
    s_key: SecretKey,
    pub p_key: PublicKey,
    pub left_y_i: Vec<u8>,
    pub right_y_i: Vec<u8>,
    broadcast_1: Vec<u8>,
    pub shared_key: Option<String>,
    pub pid_table: BTreeMap<String, PeerInfo>,
}

impl KeyAgreement {
    /// Generates a new KeyAgreement instance
    ///
    /// ### Arguments
    ///
    /// * `g` - Generator value
    pub fn new(id: String, g: u64, x_i: u32, u_i: u32) -> KeyAgreement {
        let (pk, sk) = sign::gen_keypair();

        KeyAgreement {
            g,
            id,
            x_i,
            u_i,
            s_key: sk,
            p_key: pk,
            k_i: Vec::new(),
            k_j: Vec::new(),
            y_i: Vec::new(),
            T_i: Vec::new(),
            shared_key: None,
            M_iI: Vec::new(),
            t_iL: Vec::new(),
            t_iR: Vec::new(),
            ek_i: Vec::new(),
            M_iIU: Vec::new(),
            M_iII: Vec::new(),
            sid_i: Vec::new(),
            left_y_i: Vec::new(),
            right_y_i: Vec::new(),
            sigma_iI: Vec::new(),
            sigma_iII: Vec::new(),
            M_iIIsigma: Vec::new(),
            broadcast_1: Vec::new(),
            pid_table: BTreeMap::new(),
        }
    }

    /// Retrieves and bundles peer info for peer
    pub fn get_peer_info(&self) -> PeerInfo {
        PeerInfo {
            u_i: self.u_i,
            M_iI: self.M_iI.clone(),
            ek_i: self.ek_i.clone(),
            T_i: self.T_i.clone(),
            t_iL: self.t_iL.clone(),
            k_j: self.k_j.clone(),
        }
    }

    /// Convenience method to run the first key agreement round of computation
    ///
    /// ### Arguments
    ///
    /// * `address` - payment address value as Vec<u8>
    /// * `unicorn ` - Unicorn value as Vec<u8>
    /// * `nonce` - block sequence number value as Vec<u8>
    pub fn first_round(
        &mut self,
        address: &mut Vec<u8>,
        unicorn: &mut Vec<u8>,
        nonce: &mut Vec<u8>,
    ) {
        self.compute_k_i(address, unicorn, nonce);
        self.compute_y_i();
        self.compute_hashes();
    }

    /// Convenience method to run the second key agreement round of computation
    ///
    /// ### Arguments
    ///
    /// * `peer_value_left` - Vec<u8> value held by peer to the left
    /// * `peer_value_right` - Vec<u8> value held by peer to the right
    pub fn second_round(&mut self, peer_value_left: Vec<u8>, peer_value_right: Vec<u8>) {
        self.compute_t_values(peer_value_left, peer_value_right);
        self.build_concatenation();
        self.compute_ek_i();
        self.compute_M_iII();
        self.compute_sigma_iII();
        self.compute_M_iIIsigma();
    }

    /// Convenience method to run the third key agreement round of computation
    pub fn third_round(&mut self) {
        self.compute_k_j();
    }

    /// Creates the K_i for the key creation protocol
    ///
    /// ### Arguments
    ///
    /// * `address` - Payment address
    /// * `unicorn` - Unicorn value
    /// * `nonce`   - Nonce value  
    fn compute_k_i(&mut self, address: &mut Vec<u8>, unicorn: &mut Vec<u8>, nonce: &mut Vec<u8>) {
        address.append(unicorn);
        address.append(nonce);

        self.k_i = address.to_vec();
    }

    /// Computes Y_i for the key creation protocol
    fn compute_y_i(&mut self) {
        self.y_i = self.g.pow(self.x_i).to_be_bytes().to_vec();
    }

    /// Computes M_iI, M_iIU, sigma_iI as the required hash values
    fn compute_hashes(&mut self) {
        let mut mi_handler = sha3_256::digest(&self.k_i).to_vec();

        // Set M_i^I = H(k_i) || y_i
        mi_handler.append(&mut self.y_i.clone());
        self.M_iI = mi_handler.clone();

        // Set M_i^U = M_i^I || U_i
        mi_handler.append(&mut self.u_i.to_be_bytes().to_vec());
        self.M_iIU = mi_handler;

        // Set sigma_i^I to the signed M_i^U
        self.sigma_iI = sign::sign_append(&self.M_iIU, &self.s_key);

        // Set broadcast_1 = M_i^I || sigma_i^I
        let mut M_iI_clone = self.M_iI.clone();
        M_iI_clone.append(&mut self.sigma_iI.clone());
        self.broadcast_1 = M_iI_clone;
    }

    /// Compute t_i^L = H(y_{i-1}^x_i) and t_i^R = H(y_{i+1}^x_i)
    ///
    /// ### Arguments
    ///
    /// * `peer_value_left`     - Y_i value from the peer to the "left"
    /// * `peer_value_right`    - Y_i value from the peer to the "right"
    fn compute_t_values(&mut self, peer_value_left: Vec<u8>, peer_value_right: Vec<u8>) {
        // LEFT SIDE
        let hexed_peer_left = encode(peer_value_left);
        let big_peer_left = Integer::from_str_radix(&hexed_peer_left, 16).unwrap();
        let val_l = big_peer_left.pow(self.x_i);

        // Complicated sorcery to get a big int into a byte form
        let l_as_digits = val_l.to_digits::<u8>(Order::MsfBe);

        self.t_iL = sha3_256::digest(&l_as_digits).to_vec();

        // RIGHT SIDE
        let hexed_peer_right = encode(peer_value_right);
        let big_peer_right = Integer::from_str_radix(&hexed_peer_right, 16).unwrap();
        let val_r = big_peer_right.pow(self.x_i);
        let r_as_digits = val_r.to_digits::<u8>(Order::MsfBe);

        self.t_iR = sha3_256::digest(&r_as_digits).to_vec();

        // Compute Ti
        self.T_i = self
            .t_iL
            .iter()
            .zip(self.t_iR.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    }

    /// Receives all necessary peer information for validation and key compute
    ///
    /// ### Arguments
    ///
    /// * `id`          - ID for the peer
    /// * `peer_info`   - Peer info to add
    pub fn receive_peer_info(&mut self, id: String, peer_info: PeerInfo) {
        self.pid_table.insert(id, peer_info);
    }

    /// Receives a PID U_I from a peer, along with the peer's ID
    ///
    /// ### Arguments
    ///
    /// * `id`      - ID for the peer
    /// * `U_I`    - Peer's Mi_I value
    pub fn receive_U_I(&mut self, id: String, U_I: u32) {
        let mut peer_info = self.pid_table.get(&id).unwrap().clone();
        peer_info.u_i = U_I;

        self.pid_table.insert(id, peer_info);
    }

    /// Receives a PID Mi_I from a peer, along with the peer's ID
    ///
    /// ### Arguments
    ///
    /// * `id`      - ID for the peer
    /// * `Mi_I`    - Peer's Mi_I value
    pub fn receive_miI(&mut self, id: String, M_iI: Vec<u8>) {
        let mut peer_info = self.pid_table.get(&id).unwrap().clone();
        peer_info.M_iI = M_iI;

        self.pid_table.insert(id, peer_info);
    }

    /// Receives a y_i from a peer, either from the "left" or "right" of the partition list
    ///
    /// ### Arguments
    ///
    /// * `id`  - ID for the peer
    /// * `y_i` - Peer's y_i value
    pub fn receive_y_i(&mut self, id: String, y_i: Vec<u8>) {
        // TODO: Figure out if it's left or right, and then save there
    }

    /// Receives a PID k_j from a peer, along with the peer's ID
    ///
    /// ### Arguments
    ///
    /// * `id`      - ID for the peer
    /// * `k_j`    - Peer's k_j value
    pub fn receive_k_j(&mut self, id: String, k_j: Vec<u8>) {
        let mut peer_info = self.pid_table.get(&id).unwrap().clone();
        peer_info.k_j = k_j;

        self.pid_table.insert(id, peer_info);
    }

    /// Receives a PID ek_i from a peer, along with the peer's ID
    ///
    /// ### Arguments
    ///
    /// * `id`      - ID for the peer
    /// * `ek_i`    - Peer's ek_i value
    pub fn receive_ek_i(&mut self, id: String, ek_i: Vec<u8>) {
        let mut peer_info = self.pid_table.get(&id).unwrap().clone();
        peer_info.ek_i = ek_i;

        self.pid_table.insert(id, peer_info);
    }

    /// Builds the concatenation for key agreement
    pub fn build_concatenation(&mut self) {
        let mut concatenation = Vec::new();

        // First sort the table
        let mut sorted_pid_table = Vec::from_iter(self.pid_table.clone());
        sorted_pid_table.sort_by(|(a, _), (b, _)| b.cmp(a));

        // Throw u_i into the concatenation
        for pid in sorted_pid_table.clone() {
            let u_i = pid.1.clone().u_i;
            concatenation.append(&mut u_i.to_be_bytes().to_vec());
        }

        // Then throw in Mi_i
        for pid in sorted_pid_table.clone() {
            let mut M_iI = pid.1.clone().M_iI;
            concatenation.append(&mut M_iI);
        }

        self.sid_i = sha3_256::digest(&concatenation).to_vec();
    }

    /// Computes k_j
    pub fn compute_k_j(&mut self) {
        // First add own PID info
        let own_peer_info = self.get_peer_info();
        self.pid_table.insert(self.id.clone(), own_peer_info);

        // Then sort the table
        let mut sorted_pid_table = Vec::from_iter(self.pid_table.clone());
        sorted_pid_table.sort_by(|(a, _), (b, _)| b.cmp(a));

        // Reconstruct PID table without self
        let index_of_self = sorted_pid_table
            .iter()
            .position(|x| x.0 == self.id)
            .unwrap();
        let mut backend = sorted_pid_table.split_off(index_of_self + 1);
        backend.append(&mut sorted_pid_table);
        let _removal_of_self = backend.pop();

        // Actually compute k_j finally
        self.k_j = self.ek_i.clone();

        // xor T_{i+1}..
        for pid in backend {
            self.k_j = self
                .k_j
                .iter()
                .zip(pid.1.T_i.iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();
        }

        // xor t_iL
        self.k_j = self
            .k_j
            .iter()
            .zip(self.t_iL.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        if self.k_j != self.k_i {
            panic!("Kj and Ki value for self not equal. Key agreement failed");
        }
    }

    /// Computes the key, assuming that all validation checks and computations have been performed
    pub fn compute_key(&mut self) {
        // First add own Kj to PID table
        self.receive_k_j(self.id.clone(), self.k_j.clone());

        // Sort the table
        let mut sorted_pid_table = Vec::from_iter(self.pid_table.clone());
        sorted_pid_table.sort_by(|(a, _), (b, _)| b.cmp(a));

        let mut key = Vec::new();

        // First PID concat
        for pid in sorted_pid_table.clone() {
            key.append(&mut pid.0.as_bytes().to_vec());
        }

        // Then Kj concat
        for pid in sorted_pid_table.clone() {
            key.append(&mut pid.1.k_j.clone());
        }

        self.shared_key = Some(encode(sha3_256::digest(&key)));
    }

    /// Compute ek_i
    fn compute_ek_i(&mut self) {
        self.ek_i = self
            .k_i
            .iter()
            .zip(self.t_iR.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
    }

    /// Compute M_iII as ek_i || T_i || sid_i
    fn compute_M_iII(&mut self) {
        self.M_iII.append(&mut self.ek_i.clone());
        self.M_iII.append(&mut self.T_i.clone());
        self.M_iII.append(&mut self.sid_i.clone());
    }

    /// Computes sigma_iII
    fn compute_sigma_iII(&mut self) {
        let hashed_M_iII = sha3_256::digest(&self.M_iII).to_vec();
        self.sigma_iII = sign::sign_append(&hashed_M_iII, &self.s_key);
    }

    /// Computes M_iIIsigma as M_iII || sigma_iII
    fn compute_M_iIIsigma(&mut self) {
        self.M_iIIsigma.append(&mut self.M_iII.clone());
        self.M_iIIsigma.append(&mut self.sigma_iII.clone());
    }

    /// Verifies a received value from a peer
    ///
    /// ### Arguments
    ///
    /// * `signed_data` - Signed data to verify
    /// * `pub_key`     - Public key for verification
    fn verify_data(&self, signed_data: Vec<u8>, pub_key: &PublicKey) -> bool {
        sign::verify_append(&signed_data, pub_key)
    }
}
