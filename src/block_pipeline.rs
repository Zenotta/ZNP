use crate::constants::{MINER_PARTICIPATION_UN, WINNING_MINER_UN};
use crate::interfaces::WinningPoWInfo;
use crate::unicorn::{construct_seed, construct_unicorn, UnicornFixedParam, UnicornInfo};
use keccak_prime::fortuna::Fortuna;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::fmt;
use std::net::SocketAddr;
use tracing::log::{debug, info};

/// Different states of the mining pipeline
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MiningPipelineStatus {
    Halted,
    ParticipantIntake,
    WinningPoWIntake,
}

impl Default for MiningPipelineStatus {
    fn default() -> Self {
        MiningPipelineStatus::Halted
    }
}

/// Change in phase.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MiningPipelinePhaseChange {
    StartPhasePowIntake,
    StartPhaseHalted,
}

/// Different types of items that can be proposed to the block pipeline
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MiningPipelineItem {
    MiningParticipant(SocketAddr),
    CompleteParticipant,
    WinningPoW(SocketAddr, WinningPoWInfo),
    CompleteMining,
}

/// Participants collection (unsorted: given order, and lookup collection)
#[derive(Default, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Participants {
    unsorted: Vec<SocketAddr>,
    lookup: BTreeSet<SocketAddr>,
}

impl fmt::Debug for Participants {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.unsorted.fmt(f)
    }
}

impl Participants {
    pub fn len(&self) -> usize {
        self.unsorted.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &'_ SocketAddr> + '_ {
        self.unsorted.iter()
    }

    pub fn contains(&self, k: &SocketAddr) -> bool {
        self.lookup.contains(k)
    }

    pub fn push(&mut self, k: SocketAddr) -> bool {
        if self.lookup.insert(k) {
            self.unsorted.push(k);
            true
        } else {
            false
        }
    }
}

/// Extra info needed to process pipeline event
#[derive(Default, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PipelineEventInfo {
    pub proposer_id: u64,
    pub sufficient_majority: usize,
    pub partition_full_size: usize,
}

/// Rolling info particular to a specific mining pipeline
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MiningPipelineInfo {
    participants: BTreeMap<u64, Participants>,
    empty_participants: Participants,
    last_winning_hashes: BTreeSet<String>,
    all_winning_pow: Vec<(SocketAddr, WinningPoWInfo)>,
    unicorn_info: UnicornInfo,
    winning_pow: Option<(SocketAddr, WinningPoWInfo)>,
    mining_pipeline_status: MiningPipelineStatus,
    current_phase_timeout_peer_ids: BTreeSet<u64>,
}

impl MiningPipelineInfo {
    /// Start participants intake phase
    pub fn start_participant_intake(
        &mut self,
        tx_inputs: &[String],
        fixed_params: &UnicornFixedParam,
    ) {
        //  Construct with  previous participants and winnning hashes
        self.construct_unicorn(tx_inputs, fixed_params);

        //Only keep relevant info for this phase
        *self = Self {
            unicorn_info: std::mem::take(&mut self.unicorn_info),
            mining_pipeline_status: MiningPipelineStatus::ParticipantIntake,
            ..Default::default()
        };
        debug!("MINING PIPELINE STATUS: {:?}", self.mining_pipeline_status);
    }

    /// Handle a mining pipeline item
    /// # Arguments
    /// * `pipeline_item` - The mining pipeline item (either a mining participant or PoW entry)
    /// * `extra`         - Extra info needed to process the item
    ///
    /// # Note
    /// Participant and PoW entries will only be added to the current `block_pipeline`
    /// if the mining pipeline state allows it.
    pub async fn handle_mining_pipeline_item(
        &mut self,
        pipeline_item: MiningPipelineItem,
        extra: PipelineEventInfo,
    ) -> Option<MiningPipelinePhaseChange> {
        use MiningPipelineItem::*;
        use MiningPipelineStatus::*;

        let pipeline_status = self.get_mining_pipeline_status().clone();
        match (pipeline_item, &pipeline_status) {
            (MiningParticipant(addr), ParticipantIntake) => {
                self.add_to_participants(extra.proposer_id, addr);
            }
            (CompleteParticipant, ParticipantIntake) => {
                self.append_current_phase_timeout(extra.proposer_id);
            }
            (WinningPoW(addr, info), WinningPoWIntake) => {
                self.add_to_winning_pow(extra.proposer_id, (addr, info));
            }
            (CompleteMining, WinningPoWIntake) => {
                self.append_current_phase_timeout(extra.proposer_id);
            }
            (item, status) => {
                debug!(
                    "Failed to add entry {:?} with pipeline status: {:?}",
                    item, status
                );
            }
        }

        match &pipeline_status {
            Halted => (),
            ParticipantIntake => {
                if self.has_ready_select_participating_miners(extra.sufficient_majority) {
                    self.start_participants_pow_intake(extra.partition_full_size);
                    return Some(MiningPipelinePhaseChange::StartPhasePowIntake);
                }
            }
            WinningPoWIntake => {
                if self.has_ready_select_winning_miner(extra.sufficient_majority) {
                    self.start_winning_pow_halted();
                    return Some(MiningPipelinePhaseChange::StartPhaseHalted);
                }
            }
        }

        None
    }

    /// New mining event to propose
    pub fn mining_event_at_timeout(&mut self) -> Option<MiningPipelineItem> {
        use MiningPipelineStatus::*;
        match self.get_mining_pipeline_status() {
            ParticipantIntake => Some(MiningPipelineItem::CompleteParticipant),
            WinningPoWIntake => Some(MiningPipelineItem::CompleteMining),
            Halted => None,
        }
    }

    /// Process all the mining phase in a single step
    pub fn test_skip_mining(&mut self, winning_pow: (SocketAddr, WinningPoWInfo)) {
        info!("test_skip_mining PoW entry: {:?}", winning_pow);
        self.start_participants_pow_intake(usize::MAX);
        self.all_winning_pow.push(winning_pow);
        self.start_winning_pow_halted();
    }

    /// Retrieves the current UNICORN for this pipeline
    pub fn get_unicorn(&self) -> &UnicornInfo {
        &self.unicorn_info
    }

    /// Retrieves the miners participating in the current round
    pub fn get_mining_participants(&self, proposer_id: u64) -> &Participants {
        self.participants
            .get(&proposer_id)
            .unwrap_or(&self.empty_participants)
    }

    /// Retrieves the winning miner for the current mining round
    pub fn get_winning_miner(&self) -> &Option<(SocketAddr, WinningPoWInfo)> {
        &self.winning_pow
    }

    /// Get the mining pipeline status
    pub fn get_mining_pipeline_status(&self) -> &MiningPipelineStatus {
        &self.mining_pipeline_status
    }

    /// Add a new participant to the eligible list, if possible
    pub fn add_to_participants(&mut self, proposer_id: u64, participant: SocketAddr) {
        let participants = self.participants.entry(proposer_id).or_default();
        if participants.push(participant) {
            debug!(
                "Adding miner participant: {}-{:?}",
                proposer_id, participant
            );
        }
    }

    /// Add winning PoW to the running list
    pub fn add_to_winning_pow(
        &mut self,
        proposer_id: u64,
        winning_pow: (SocketAddr, WinningPoWInfo),
    ) {
        let participants = self.get_mining_participants(proposer_id);
        if !participants.contains(&winning_pow.0) {
            debug!(
                "Ignore PoW entry from miner (Non participant): {}-{:?}",
                proposer_id, winning_pow.0
            );
            return;
        }

        debug!(
            "Adding PoW entry from miner: {}-{:?}",
            proposer_id, winning_pow.0
        );
        self.all_winning_pow.push(winning_pow);
    }

    /// Selects a winning miner from the list via UNICORN
    pub fn has_ready_select_participating_miners(&mut self, sufficient_majority: usize) -> bool {
        self.current_phase_timeout_peer_ids.len() >= sufficient_majority
            && self.participants.len() >= sufficient_majority
    }

    /// Select miners to mine current block and move to Pow intake
    pub fn start_participants_pow_intake(&mut self, partition_full_size: usize) {
        let mut participants = std::mem::take(&mut self.participants);
        let _timeouts = std::mem::take(&mut self.current_phase_timeout_peer_ids);

        for ps in participants.values_mut() {
            if ps.unsorted.len() <= partition_full_size {
                continue;
            }
            for i in 0..partition_full_size {
                self.swap_first_with_unicorn_item(MINER_PARTICIPATION_UN, &mut ps.unsorted[i..]);
            }
            ps.unsorted.truncate(partition_full_size);
            ps.lookup = ps.unsorted.iter().copied().collect();
        }

        self.participants = participants;
        self.mining_pipeline_status = MiningPipelineStatus::WinningPoWIntake;
        debug!("MINING PIPELINE STATUS: {:?}", self.mining_pipeline_status);
        debug!("Participating Miners: {:?}", self.participants);
    }

    /// Selects a winning miner from the list via UNICORN
    pub fn has_ready_select_winning_miner(&mut self, sufficient_majority: usize) -> bool {
        if self.current_phase_timeout_peer_ids.len() < sufficient_majority {
            return false;
        }

        !self.all_winning_pow.is_empty()
    }

    /// Selects a winning miner from the list via UNICORN and move to halted state
    pub fn start_winning_pow_halted(&mut self) {
        let all_winning_pow = std::mem::take(&mut self.all_winning_pow);
        let _timeouts = std::mem::take(&mut self.current_phase_timeout_peer_ids);

        self.winning_pow = self
            .get_unicorn_item(WINNING_MINER_UN, &all_winning_pow)
            .cloned();
        self.last_winning_hashes = all_winning_pow
            .into_iter()
            .map(|(_, pow)| pow.mining_tx.0)
            .collect();
        self.mining_pipeline_status = MiningPipelineStatus::Halted;

        debug!("MINING PIPELINE STATUS: {:?}", self.mining_pipeline_status);
        info!("Winning PoW Entry: {:?}", self.winning_pow);
    }

    ///Inserts a prosper_id into the current_block_complete_timeout_peer_ids.
    /// proposer_id is take from key
    ///
    /// ### Arguments
    ///
    /// * `proposer_id` - The proposer_id to be appended.
    pub fn append_current_phase_timeout(&mut self, proposer_id: u64) {
        self.current_phase_timeout_peer_ids.insert(proposer_id);
    }

    /// Sets the new UNICORN value based on the latest info
    pub fn construct_unicorn(&mut self, tx_inputs: &[String], fixed_params: &UnicornFixedParam) {
        debug!(
            "Constructing UNICORN value using {:?}, {:?}, {:?}",
            tx_inputs, self.participants, self.last_winning_hashes
        );

        let all_participants = self.participants.values().map(|p| &p.unsorted);
        let all_participants: Vec<_> = all_participants.flatten().copied().collect();
        let seed = construct_seed(tx_inputs, &all_participants, &self.last_winning_hashes);
        self.unicorn_info = construct_unicorn(seed, fixed_params);
    }

    /// Gets a UNICORN-generated pseudo random number
    ///
    /// ### Arguments
    ///
    /// * `usage_number` - Usage number for the CSPRNG
    pub fn get_unicorn_prn(&self, usage_number: u128) -> u64 {
        debug!("Using UNICORN value: {:?}", self.unicorn_info);
        let prn_seed: [u8; 32] = self.unicorn_info.g_value.as_bytes()[..32]
            .try_into()
            .unwrap();

        let mut csprng = Fortuna::new(&prn_seed, usage_number).unwrap();

        let val = csprng.get_bytes(8).unwrap();
        u64::from_be_bytes(val[0..8].try_into().unwrap())
    }

    /// Gets a UNICORN-generated pseudo random number
    ///
    /// ### Arguments
    ///
    /// * `usage_number` - Usage number for the CSPRNG
    pub fn get_unicorn_item<'a, T>(&self, usage_number: u128, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }

        let prn = self.get_unicorn_prn(usage_number);
        let selection = prn as usize % items.len();
        Some(&items[selection])
    }

    /// Swap item at index with item at index + UNICORN-generated pseudo random number
    ///
    /// ### Arguments
    ///
    /// * `usage_number` - Usage number for the CSPRNG
    pub fn swap_first_with_unicorn_item<T>(&self, usage_number: u128, items: &mut [T]) {
        if items.len() < 2 {
            return;
        }

        let prn = self.get_unicorn_prn(usage_number);
        let selection = 1 + prn as usize % (items.len() - 1);
        items.swap(0, selection);
    }
}
