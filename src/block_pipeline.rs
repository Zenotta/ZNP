use crate::constants::{
    MAX_MINERS_PER_ROUND, MINER_PARTICIPATION_UN, UNICORN_ITER, UNICORN_MOD, UNICORN_SECURITY,
    WINNING_MINER_UN,
};
use crate::interfaces::WinningPoWInfo;
use crate::unicorn::{construct_seed, Unicorn, UnicornInfo};
use keccak_prime::fortuna::Fortuna;
use naom::utils::transaction_utils::construct_tx_hash;
use rug::Integer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::fmt;
use std::net::SocketAddr;
use tracing::log::{debug, warn};

/// Rolling info particular to a specific mining pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningPipelineInfo {
    participants: Vec<SocketAddr>,
    last_winning_hashes: BTreeSet<String>,
    all_winning_pow: Vec<(SocketAddr, WinningPoWInfo)>,
    unicorn_info: UnicornInfo,
    winning_pow: Option<(SocketAddr, WinningPoWInfo)>,
}

/// Result wrapper for block pipeline error
pub type Result<T> = std::result::Result<T, PipelineError>;

#[derive(Debug, Clone)]
pub enum PipelineError {
    ParticipantsFull,
    NotParticipant,
    NoWinningPoWFound,
    NoMiningParticipants,
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParticipantsFull => write!(f, "Mining participation is full"),
            Self::NotParticipant => write!(f, "Miner is not eligible for participation"),
            Self::NoWinningPoWFound => write!(f, "No winning PoW found"),
            Self::NoMiningParticipants => write!(f, "No mining participants found"),
        }
    }
}

impl Default for MiningPipelineInfo {
    fn default() -> Self {
        Self {
            participants: Default::default(),
            last_winning_hashes: Default::default(),
            all_winning_pow: Default::default(),
            unicorn_info: Default::default(),
            winning_pow: Default::default(),
        }
    }
}

impl MiningPipelineInfo {
    pub fn reset(&mut self) {
        let last_all_winning_pow = self.all_winning_pow.clone();
        //Reset block pipeline
        *self = Self::default();
        //Set last winning hashes for UNiCORN construction
        self.last_winning_hashes = last_all_winning_pow
            .into_iter()
            .map(|(_, pow)| construct_tx_hash(&pow.coinbase))
            .collect();
    }

    /// Retrieves the current UNiCORN for this pipeline
    pub fn get_unicorn(&self) -> &Unicorn {
        &self.unicorn_info.unicorn
    }

    /// Retrieves the UNiCORN's seed value
    pub fn get_unicorn_seed(&self) -> Integer {
        self.unicorn_info.unicorn.seed.clone()
    }

    /// Retrieves the UNiCORN's witness value
    pub fn get_unicorn_witness(&self) -> Integer {
        self.unicorn_info.witness.clone()
    }

    /// Retrieves the miners participating in the current round
    pub fn get_mining_participants(&self) -> &Vec<SocketAddr> {
        &self.participants
    }

    /// Retrieves the winning miner for the current mining round
    pub fn get_winning_miner(&self) -> Option<(SocketAddr, WinningPoWInfo)> {
        self.winning_pow.clone()
    }

    /// Retrieves the current length of the participant list
    pub fn participant_len(&self) -> usize {
        self.participants.len()
    }

    /// Add a new participant to the eligible list, if possible
    pub fn add_to_participants(&mut self, participant: SocketAddr) -> Result<()> {
        if self.participants.len() < MAX_MINERS_PER_ROUND as usize {
            if !self.participants.contains(&participant) {
                self.participants.push(participant);
                warn!("Adding miner participant: {:?}", participant);
            }
            return Ok(());
        }
        Err(PipelineError::ParticipantsFull)
    }

    /// Add winning PoW to the running list
    pub fn add_to_winning_pow(&mut self, winning_pow: (SocketAddr, WinningPoWInfo)) -> Result<()> {
        if self.participants.contains(&winning_pow.0) {
            warn!("Adding PoW entry from miner: {:?}", winning_pow.0);
            self.all_winning_pow.push(winning_pow);
            return Ok(());
        }
        Err(PipelineError::NotParticipant)
    }

    /// Select miners to mine current block
    pub fn select_participating_miners(&mut self) -> Result<()> {
        let participants_len = self.participants.len();
        if participants_len >= MAX_MINERS_PER_ROUND as usize {
            self.participants = Default::default();
            for _ in 0..MAX_MINERS_PER_ROUND {
                let prn = self.get_unicorn_prn(MINER_PARTICIPATION_UN);
                let selection = prn as usize % participants_len;
                self.participants.push(self.participants[selection]);
            }
        }

        if !self.participants.is_empty() {
            warn!("Participating Miners: {:?}", self.participants);
            return Ok(());
        }

        Err(PipelineError::NoMiningParticipants)
    }

    /// Selects a winning miner from the list via UNiCORN
    pub fn select_winning_miner(&mut self) -> Result<()> {
        self.winning_pow = match self.all_winning_pow.len() {
            0 => None,
            1 => Some(self.all_winning_pow[0].clone()),
            _ => {
                let prn = self.get_unicorn_prn(WINNING_MINER_UN);
                let selection = prn as usize % self.all_winning_pow.len();
                Some(self.all_winning_pow[selection].clone())
            }
        };

        if self.winning_pow.is_some() {
            warn!("Winning PoW Entry: {:?}", self.winning_pow);
            return Ok(());
        }

        Err(PipelineError::NoWinningPoWFound)
    }

    /// Sets the new UNiCORN value based on the latest info
    pub fn construct_unicorn(&mut self, tx_inputs: &[String]) {
        warn!(
            "Constructing UNiCORN value using {:?}, {:?}, {:?}",
            tx_inputs, self.participants, self.last_winning_hashes
        );

        let seed = construct_seed(tx_inputs, &self.participants, &self.last_winning_hashes);

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

    /// Gets a UNiCORN-generated pseudo random number
    ///
    /// ### Arguments
    ///
    /// * `usage_number` - Usage number for the CSPRNG
    pub fn get_unicorn_prn(&self, usage_number: u128) -> u8 {
        debug!("Using UNiCORN value: {:?}", self.unicorn_info);
        let prn_seed: [u8; 32] = self.unicorn_info.g_value.as_bytes()[..32]
            .try_into()
            .expect("Incorrect UNiCORN g value length");

        let mut csprng = Fortuna::new(&prn_seed, usage_number).unwrap();

        // TODO: Make this encapsulate full range of values, not just u8
        let val = csprng.get_bytes(1).unwrap();

        val[0]
    }
}
