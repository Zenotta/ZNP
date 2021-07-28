use crate::constants::{
    MAX_MINERS_PER_ROUND, MINER_PARTICIPATION_UN, UNICORN_ITER, UNICORN_MOD, UNICORN_SECURITY,
    WINNING_MINER_UN,
};
use crate::interfaces::WinningPoWInfo;
use crate::unicorn::{construct_seed, Unicorn, UnicornInfo};
use keccak_prime::fortuna::Fortuna;
use rug::Integer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::fmt;
use std::net::SocketAddr;

/// Mining participant-related info
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParticipantInfo {
    list: Vec<SocketAddr>,
    window_closed: bool,
    list_max: usize,
}

/// Rolling info particular to a specific mining pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningPipelineInfo {
    participants: ParticipantInfo,
    mining_window_closed: bool,
    seed_txs: Vec<String>,
    last_winning_hashes: BTreeSet<String>,
    miner_list: Vec<SocketAddr>,
    all_winning_pow: Vec<(SocketAddr, WinningPoWInfo)>,
    unicorn_info: UnicornInfo,
    winning_pow: Option<(SocketAddr, WinningPoWInfo)>,
}

/// Result wrapper for compute errors
pub type Result<T> = std::result::Result<T, PipelineError>;

#[derive(Debug, Clone)]
pub enum PipelineError {
    ParticipantsFull,
    NotParticipant,
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParticipantsFull => write!(f, "Mining participation is full"),
            Self::NotParticipant => write!(f, "Miner is not eligible participant"),
        }
    }
}

impl Default for MiningPipelineInfo {
    fn default() -> Self {
        Self {
            participants: ParticipantInfo {
                list_max: MAX_MINERS_PER_ROUND as usize,
                ..Default::default()
            },
            mining_window_closed: false,
            seed_txs: Default::default(),
            last_winning_hashes: Default::default(),
            miner_list: Default::default(),
            all_winning_pow: Default::default(),
            unicorn_info: Default::default(),
            winning_pow: Default::default(),
        }
    }
}

impl MiningPipelineInfo {
    /// Retrieves the current unicorn for this pipeline
    pub fn get_unicorn(&self) -> &Unicorn {
        &self.unicorn_info.unicorn
    }

    /// Retrieves the unicorn's seed value
    pub fn get_unicorn_seed(&self) -> Integer {
        self.unicorn_info.unicorn.seed.clone()
    }

    /// Retrieves the unicorn's witness value
    pub fn get_unicorn_witness(&self) -> Integer {
        self.unicorn_info.witness.clone()
    }

    /// Retrieves the miners participating in the current round
    pub fn get_participants(&self) -> &Vec<SocketAddr> {
        &self.participants.list
    }

    /// Retrieves the current length of the participant list
    pub fn participant_len(&self) -> usize {
        self.participants.list.len()
    }

    /// Add a new participant to the eligible list, if possible
    pub fn add_to_participants(&mut self, participant: SocketAddr) -> Result<()> {
        if self.participants.list.len() < self.participants.list_max {
            self.participants.list.push(participant);
            return Ok(());
        }

        Err(PipelineError::ParticipantsFull)
    }

    /// Add winning PoW to the running list
    pub fn add_to_winning_pow(&mut self, winning_pow: (SocketAddr, WinningPoWInfo)) -> Result<()> {
        if self.participants.list.contains(&winning_pow.0) {
            self.all_winning_pow.push(winning_pow);
            return Ok(());
        }

        Err(PipelineError::NotParticipant)
    }

    /// Sets the new unicorn value based on the latest info
    pub fn construct_unicorn(&mut self, tx_inputs: &[String]) {
        let seed = construct_seed(
            tx_inputs,
            &self.participants.list,
            &self.last_winning_hashes,
        );

        let mut unicorn = Unicorn {
            seed,
            modulus: Integer::from_str_radix(UNICORN_MOD, 10).unwrap(),
            iterations: UNICORN_ITER,
            security_level: UNICORN_SECURITY,
            ..Default::default()
        };

        let (w, g): (Integer, String) = match unicorn.eval() {
            Some((w, g)) => (w, g),
            None => panic!("UNiCORN construction failed"),
        };

        self.unicorn_info = UnicornInfo {
            unicorn,
            witness: w,
            g_value: g,
        }
    }

    /// Select miners to mine current block
    pub fn select_participating_miners(&mut self) {
        if self.participants.list.len() <= MAX_MINERS_PER_ROUND as usize {
            self.miner_list = self.participants.list.clone();
        } else {
            for _ in 0..MAX_MINERS_PER_ROUND {
                let prn = self.get_unicorn_prn(MINER_PARTICIPATION_UN);
                let selection = prn as usize % self.participants.list.len();

                self.miner_list.push(self.participants.list[selection]);
            }
        }
    }

    /// Selects a winning miner from the list via UNiCORN
    pub fn select_winning_miner(&mut self) -> Option<(SocketAddr, WinningPoWInfo)> {
        if self.winning_pow.is_some() {
            return self.winning_pow.clone();
        }

        match self.all_winning_pow.len() {
            0 => return None,
            1 => {
                self.winning_pow = Some(self.all_winning_pow[0].clone());
            }
            _ => {
                let prn = self.get_unicorn_prn(WINNING_MINER_UN);
                let selection = prn as usize % self.all_winning_pow.len();
                self.winning_pow = Some(self.all_winning_pow[selection].clone());
            }
        }

        self.winning_pow.clone()
    }

    /// Gets a UNiCORN-generated pseudo random number
    ///
    /// ### Arguments
    ///
    /// * `usage_number` - Usage number for the CSPRNG
    pub fn get_unicorn_prn(&self, usage_number: u128) -> u8 {
        let prn_seed: [u8; 32] = self.unicorn_info.g_value.as_bytes()[..32]
            .try_into()
            .expect("Incorrect UNiCORN g value length");

        let mut csprng = Fortuna::new(&prn_seed, usage_number).unwrap();

        // TODO: Make this encapsulate full range of values, not just u8
        let val = csprng.get_bytes(1).unwrap();

        val[0]
    }
}
