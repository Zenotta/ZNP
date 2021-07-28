//! Implementation of a UNiCORN process, as per Lenstra and Wesolowski's "Random Zoo"
//! paper (https://eprint.iacr.org/2015/366.pdf). The eval-verify processes use modular
//! square root (sloth) with swapped neighbours, but this particular implementation may
//! need to be optimised in future given certain seed or modulus sizes.
//!
//! The goal of a UNiCORN is to provide an uncontestable randomly generated number. The source
//! of the uncontestability is the seed, which is meant to be generated from multiple, random
//! oracle sources (eg. tweets). In the sloth implementation the seed is then run through a
//! function which is slow to compute but quick to verify (VDF, or Verifiable Delay Function)
//! and produces a witness value (for trapdoor verification) and the hash of the witness `g`.
//!
//! Although sloths have the extra ability to be slowed by a specific time length (through setting
//! the iterations, or `l`), any function that has slow evaluation and quick verification will
//! suffice for UNiCORN needs.
//!
//! Given the seed and witness values, anybody is able to verify the authenticity of the number
//! generated.

use crate::constants::MR_PRIME_ITERS;
use bincode::serialize;
use rug::integer::IsPrime;
use rug::Integer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use tracing::error;

/// Serialisation function for big ints
pub fn serialize_big_int<S>(x: &Integer, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&x.to_string_radix(16))
}

/// Deserialisation function for big ints
pub fn deserialize_big_int<'de, D>(d: D) -> Result<Integer, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(d)?;
    Ok(Integer::from_str_radix(&buf, 16).unwrap())
}

/// Constructs the seed for a new, ZNP-specific Unicorn
///
/// ### Arguments
///
/// * `tx_inputs` - Input transactions
/// * `participant_list` - List of miners participating in block round
/// * `last_winning_hashes` - The hashes of the winning PoWs from 2 blocks ago
pub fn construct_seed(
    tx_inputs: &[String],
    participant_list: &Vec<SocketAddr>,
    last_winning_hashes: &BTreeSet<String>,
) -> Integer {
    // Transaction inputs (sOot)
    let soot = hex::encode(Sha3_256::digest(&serialize(tx_inputs).unwrap()));
    // Miner participation applications (sOma)
    let soma = hex::encode(Sha3_256::digest(&serialize(participant_list).unwrap()));
    // Winning PoWs from 2 blocks ago
    let soms = hex::encode(Sha3_256::digest(&serialize(last_winning_hashes).unwrap()));

    let final_seed = hex::encode(Sha3_256::digest(
        &serialize(&vec![soot, soma, soms]).unwrap(),
    ));

    Integer::from_str_radix(&final_seed, 16).unwrap()
}

/// UNiCORN-relevant info for use on a RAFT
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct UnicornInfo {
    pub unicorn: Unicorn,
    pub g_value: String,
    #[serde(
        deserialize_with = "deserialize_big_int",
        serialize_with = "serialize_big_int"
    )]
    pub witness: Integer,
}

/// UNiCORN struct, with the following fields:
///
/// - modulus (`p`)
/// - iterations (`l`)
/// - seed (`s`)
/// - witness (`w`)
/// - security_level (`k`)
#[derive(Default, Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Unicorn {
    pub iterations: u64,
    pub security_level: u32,
    #[serde(
        deserialize_with = "deserialize_big_int",
        serialize_with = "serialize_big_int"
    )]
    pub seed: Integer,
    #[serde(
        deserialize_with = "deserialize_big_int",
        serialize_with = "serialize_big_int"
    )]
    pub modulus: Integer,
    #[serde(
        deserialize_with = "deserialize_big_int",
        serialize_with = "serialize_big_int"
    )]
    pub witness: Integer,
}

impl Unicorn {
    /// Sets the seed for the UNiCORN. Returns the commitment value `c`, as per
    /// Lenstra and Wesolowski recommendations
    ///
    /// ### Arguments
    ///
    /// * `seed`    - Seed to set
    pub fn set_seed(&mut self, seed: Integer) -> String {
        let u = hex::encode(Sha3_256::digest(&serialize(&seed.to_u64()).unwrap()));
        let c = hex::encode(Sha3_256::digest(u.as_bytes()));

        self.seed = seed;

        c
    }

    /// Evaluation of the Sloth VDF given internal params and a seed value,
    /// producing an uncontestable random number. Returns the raw witness value and hash `g`
    ///
    /// Mentioned in Section 3.3 of Lenstra et al's "Random Zoo", the modulus must be congruent
    /// to 3 % 4, so we can use this requirement to implement a slow modular square root through the
    /// exponent of `w`, the iterated value which will eventually become the witness.
    ///
    /// The general process as per Lenstra et al:
    /// - Let w0 be such that ̂w0 = seed (note that 0 ≤ w < 2^2k ≤ p).
    /// - For i = 1,2,...,l in succession let wi ← τ(wi−1).
    /// - Let g ← hash(wl) and w ← wl.
    /// - Return g and w as the output and quit.
    pub fn eval(&mut self) -> Option<(Integer, String)> {
        if !self.is_valid_modulus() {
            error!("Modulus for UNiCORN eval invalid");
            return None;
        }

        let mut w = self.seed.clone().div_rem_floor(self.modulus.clone()).1;

        // The slow modular square root
        let exponent = (self.modulus.clone() + 1) / 4;

        for _ in 0..self.iterations {
            self.xor_for_overflow(&mut w);

            w.pow_mod_mut(&exponent, &self.modulus).unwrap();
        }

        self.witness = w.clone();
        let g = hex::encode(Sha3_256::digest(&serialize(&w.to_u64()).unwrap()));

        Some((w, g))
    }

    /// Verifies a particular unicorn given a witness value. This is the "trapdoor"
    /// function for public use. This process is quick in comparison to `eval`, as the
    /// process is a simple power raise with a modulo
    ///
    /// The general process as per Lenstra et al:
    /// - Replace w by (τ^−1)^l (w).
    /// - If w != int(u) then return “false” and quit.
    /// - Return “true” and quit.
    ///
    /// ### Arguments
    ///
    /// * `seed`    - Seed to verify
    /// * `witness` - Witness value for trapdoor verification
    pub fn verify(&mut self, seed: Integer, witness: Integer) -> bool {
        let square: Integer = 2u64.into();
        let mut w = witness;

        for _ in 0..self.iterations {
            // Fast squaring modulo
            w.pow_mod_mut(&square, &self.modulus).unwrap();

            let inv_w = -w;
            w = inv_w.div_rem_floor(self.modulus.clone()).1;
            self.xor_for_overflow(&mut w);
        }

        w == seed.div_rem_floor(self.modulus.clone()).1
    }

    /// Gets the calculated UNiCORN value, with an optional modulus division
    ///
    /// ### Arguments
    ///
    /// * `modulus` - Modulus to divide the UNiCORN by. Optional
    pub fn get_unicorn(&self, modulus: Option<Integer>) -> Integer {
        match modulus {
            Some(p) => self.witness.clone().div_rem_floor(p).1,
            None => self.witness.clone(),
        }
    }

    /// Predicate for a valid modulus `p`
    ///
    /// As per Lenstra et al, requirements are as follows:
    /// - `p` must be large and prime
    /// - `p >= 2^2k` where `k` is a chosen security level
    fn is_valid_modulus(&self) -> bool {
        self.modulus >= 2u64.pow(2 * self.security_level)
            && !matches!(self.modulus.is_probably_prime(MR_PRIME_ITERS), IsPrime::No)
    }

    /// Performs a XOR of the input `x` as a basic secure permutation
    /// against modulus overflow
    ///
    /// ### Arguments
    ///
    /// * `w` - Input to XOR
    fn xor_for_overflow(&mut self, w: &mut Integer) {
        *w ^= 1;

        while *w >= self.modulus || *w == 0 {
            *w ^= 1;
        }
    }
}

/*---- TESTS ----*/

#[cfg(test)]
mod unicorn_tests {
    use super::*;
    const TEST_HASH: &str = "1eeb30c7163271850b6d018e8282093ac6755a771da6267edf6c9b4fce9242ba";
    const WITNESS: &str = "3519722601447054908751517254890810869415446534615259770378249754169022895693105944708707316137352415946228979178396400856098248558222287197711860247275230167";

    fn create_unicorn() -> Unicorn {
        let modulus_str: &str = "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151";
        let modulus = Integer::from_str_radix(modulus_str, 10).unwrap();

        Unicorn {
            modulus,
            iterations: 1_000,
            security_level: 1,
            seed: Integer::from_str_radix(TEST_HASH, 16).unwrap(),
            ..Default::default()
        }
    }

    #[test]
    /// Checks that a valid unicorn can be constructed from a seed hash
    fn should_generate_valid_unicorn() {
        let mut uni = create_unicorn();
        let (w, g) = uni.eval().unwrap();

        assert_eq!(w, Integer::from_str_radix(WITNESS, 10).unwrap());
        assert_eq!(
            g,
            "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0"
        );
        assert!(uni.verify(
            Integer::from_str_radix(TEST_HASH, 16).unwrap(),
            Integer::from_str_radix(WITNESS, 10).unwrap()
        ));
        assert_eq!(uni.get_unicorn(Some(Integer::from(20))), Integer::from(7));
    }

    #[test]
    /// Checks that an invalid unicorn is failed
    fn should_fail_invalid_unicorn() {
        let mut uni = create_unicorn();
        let _ = uni.eval();

        assert!(!uni.verify(
            Integer::from_str_radix(TEST_HASH, 16).unwrap(),
            Integer::from(8)
        ));
    }

    #[test]
    /// Checks that an invalid modulus is returned None
    fn should_fail_invalid_modulus() {
        let mut uni = create_unicorn();
        uni.modulus = Integer::from(2);

        assert_eq!(uni.eval(), None);
    }
}
