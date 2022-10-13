use crate::db_utils::{
    SimpleDb, SimpleDbError, SimpleDbWriteBatch, SimpleDbWriteBatchDone, DB_COL_DEFAULT,
};
use bincode::{deserialize, serialize, Error as BincodeError};
use protobuf::Message;
use raft::prelude::*;
use raft::storage::MemStorage;
use raft::{Result as RaftResult, StorageError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info};

pub const HARDSTATE_KEY: &str = "HardStateKey";
pub const SNAPSHOT_DATA_KEY: &str = "SnaphotDataKey";
pub const SNAPSHOT_META_KEY: &str = "SnaphotMetaKey";
pub const ENTRY_KEY: &str = "EntryKey";
pub const LAST_ENTRY_KEY: &str = "LastEntryKey";

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapMetadata {
    pub index: u64,
    pub term: u64,
}

#[derive(Default, Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommittedIndex {
    pub index: u64,
    pub term: u64,
}

pub struct RaftStore {
    /// In memory storage used during normal operation
    in_memory: MemStorage,
    /// Persistent storage used when restarting
    presistent: SimpleDb,
    /// First valid entry index in persistent storage
    persistent_first_entry: u64,
    /// Proposed context and log index
    proposed_context: HashMap<Vec<u8>, u64>,
}

impl RaftStore {
    // Create a persistent Storage for raft
    pub fn new(presistent: SimpleDb) -> Self {
        Self {
            in_memory: MemStorage::new(),
            presistent,
            persistent_first_entry: 0,
            proposed_context: Default::default(),
        }
    }

    /// Consume store and return peristent storage
    pub fn take_persistent(&mut self) -> SimpleDb {
        self.presistent.take()
    }

    /// Consume store and return peristent storage
    pub fn backup_persistent(&self) -> Result<(), SimpleDbError> {
        self.presistent.file_backup()
    }

    /// Saves the current HardState.
    pub fn set_hardstate(&mut self, hs: HardState) -> RaftResult<()> {
        let bytes = hs.write_to_bytes()?;

        self.in_memory.wl().set_hardstate(hs);
        set_persistent_hardstate(&mut self.presistent, &bytes)?;

        Ok(())
    }

    /// Overwrites the contents of this Storage object with those of the given snapshot.
    pub fn apply_snapshot(&mut self, snapshot: Snapshot) -> RaftResult<()> {
        self.in_memory.wl().apply_snapshot(snapshot.clone())?;
        let index = snapshot.get_metadata().get_index();

        let mut batch = self.presistent.batch_writer();
        set_persistent_snapshot(&mut batch, &snapshot)?;
        set_last_persistent_entry(&mut batch, index)?;
        discard_persistent_entries_before_snapshot(
            &mut batch,
            &mut self.persistent_first_entry,
            index,
        );
        let batch = batch.done();
        batch_write(&mut self.presistent, batch)?;
        Ok(())
    }

    /// Create and store snapshot
    pub fn create_snapshot(
        &mut self,
        idx: u64,
        cs: Option<ConfState>,
        pending_membership_change: Option<ConfChange>,
        data: Vec<u8>,
    ) -> RaftResult<()> {
        let mut wl = self.in_memory.wl();
        let snapshot = wl.create_snapshot(idx, cs, pending_membership_change, data)?;

        let mut batch = self.presistent.batch_writer();
        set_persistent_snapshot(&mut batch, snapshot)?;
        discard_persistent_entries_before_snapshot(
            &mut batch,
            &mut self.persistent_first_entry,
            idx,
        );
        let batch = batch.done();
        batch_write(&mut self.presistent, batch)?;
        Ok(())
    }

    /// Discards all log entries prior to compact_index.
    /// Only apply to in memory storage: persistent storage always match the last snapshot
    pub fn compact(&mut self, compact_index: u64) -> RaftResult<()> {
        self.in_memory.wl().compact(compact_index)?;
        self.proposed_context
            .retain(|_, ctx_idx| *ctx_idx >= compact_index);
        Ok(())
    }

    /// Append the new entries to storage.
    pub fn append(&mut self, ents: &[Entry]) -> RaftResult<()> {
        self.in_memory.wl().append(ents)?;

        let persistent_first_entry = self.persistent_first_entry;
        let entries_to_write = ents
            .iter()
            .map(|e| (e, e.get_index()))
            .filter(|(_, i)| *i >= persistent_first_entry);

        let mut first = true;
        let mut batch = self.presistent.batch_writer();
        for (ent, index) in entries_to_write {
            if first {
                first = false;
                self.proposed_context.retain(|_, ctx_idx| *ctx_idx < index);
            }
            self.proposed_context
                .insert(ent.get_context().to_owned(), index);
            set_persistent_entry(&mut batch, index, ent)?;
            set_last_persistent_entry(&mut batch, index)?;
        }
        let batch = batch.done();
        batch_write(&mut self.presistent, batch)?;

        Ok(())
    }

    /// Load in_memory from persistent DB if data is available.
    /// Otherwise only use configuration.
    pub fn load_in_memory_or_default(mut self, init_cs: ConfState) -> RaftResult<Self> {
        let in_memory = &self.in_memory;
        let presistent = &self.presistent;
        in_memory.wl().set_conf_state(init_cs.clone(), None);

        if let Some(snapshot) = get_persistent_snapshot(presistent, init_cs)? {
            let snap_index = snapshot.get_metadata().get_index();
            info!("load snapshot idx={}", snap_index);

            in_memory.wl().apply_snapshot(snapshot)?;
            self.persistent_first_entry = snap_index;
        }

        if let Some(last_index) = get_last_persistent_entry(presistent)? {
            info!("load entries last entry={}", last_index);
            // If no snapshot, entry 0 does not existd.
            // If snapshot, skip snapshot entry as already applied.
            let end_index = last_index + 1;
            let start_index = std::cmp::min(self.persistent_first_entry + 1, end_index);

            let mut entries = Vec::new();
            let mut missing_entries = false;
            for index in start_index..end_index {
                let entry = match get_persistent_entry(presistent, index)? {
                    Some(e) => e,
                    None => {
                        error!(
                            "Entry unabailable {} in [{}..{}]",
                            index, start_index, end_index
                        );
                        missing_entries = true;
                        continue;
                    }
                };
                entries.push(entry);
            }
            if missing_entries {
                return Err(StorageError::Unavailable.into());
            }
            in_memory.wl().append(&entries)?;
        }

        if let Some(hs) = get_persistent_hardstate(presistent)? {
            info!("load hard_state commit={}", hs.get_commit());
            in_memory.wl().set_hardstate(hs);
        } else {
            // Snapshot only, every thing else discarded on upgrade.
            let mut hs = HardState::default();
            hs.set_commit(self.persistent_first_entry);
            in_memory.wl().set_hardstate(hs);
        }

        Ok(self)
    }

    pub fn is_context_in_log(&self, context: &[u8]) -> bool {
        self.proposed_context.contains_key(context)
    }
}

impl Storage for RaftStore {
    /// Implements the Storage trait.
    fn initial_state(&self) -> RaftResult<RaftState> {
        self.in_memory.initial_state()
    }

    /// Implements the Storage trait.
    fn entries(&self, low: u64, high: u64, max_size: u64) -> RaftResult<Vec<Entry>> {
        self.in_memory.entries(low, high, max_size)
    }

    /// Implements the Storage trait.
    fn term(&self, idx: u64) -> RaftResult<u64> {
        self.in_memory.term(idx)
    }

    /// Implements the Storage trait.
    fn first_index(&self) -> RaftResult<u64> {
        self.in_memory.first_index()
    }

    /// Implements the Storage trait.
    fn last_index(&self) -> RaftResult<u64> {
        self.in_memory.last_index()
    }

    /// Implements the Storage trait.
    fn snapshot(&self) -> RaftResult<Snapshot> {
        self.in_memory.snapshot()
    }
}

/// Create a generic StorageError from SimpleDbError
fn from_db_err(err: SimpleDbError) -> StorageError {
    StorageError::Other(Box::new(err))
}

/// Create a generic StorageError from BincodeError
fn from_ser_err(err: BincodeError) -> StorageError {
    StorageError::Other(err)
}

/// Format entry key for db
fn format_entry_key(index: u64) -> String {
    format!("{}_{}", ENTRY_KEY, index)
}

fn batch_write(presistent: &mut SimpleDb, batch: SimpleDbWriteBatchDone) -> RaftResult<()> {
    presistent.write(batch).map_err(from_db_err)?;
    Ok(())
}

fn get_persistent_entry(presistent: &SimpleDb, index: u64) -> RaftResult<Option<Entry>> {
    let key = format_entry_key(index);
    if let Some(bytes) = presistent
        .get_cf(DB_COL_DEFAULT, &key)
        .map_err(from_db_err)?
    {
        Ok(Some(protobuf::parse_from_bytes::<Entry>(&bytes)?))
    } else {
        Ok(None)
    }
}

fn set_persistent_entry(
    presistent: &mut SimpleDbWriteBatch,
    index: u64,
    ent: &Entry,
) -> RaftResult<()> {
    let key = format_entry_key(index);
    let bytes = ent.write_to_bytes()?;
    presistent.put_cf(DB_COL_DEFAULT, &key, &bytes);
    Ok(())
}

fn discard_persistent_entries_before_snapshot(
    presistent: &mut SimpleDbWriteBatch,
    first_entry: &mut u64,
    snap_index: u64,
) {
    let old = std::mem::replace(first_entry, snap_index);

    for index in old..snap_index {
        discard_persistent_entry(presistent, index);
    }
}

fn discard_persistent_entry(presistent: &mut SimpleDbWriteBatch, index: u64) {
    let key = format_entry_key(index);
    presistent.delete_cf(DB_COL_DEFAULT, &key);
}

fn get_last_persistent_entry(presistent: &SimpleDb) -> RaftResult<Option<u64>> {
    if let Some(bytes) = presistent
        .get_cf(DB_COL_DEFAULT, LAST_ENTRY_KEY)
        .map_err(from_db_err)?
    {
        Ok(Some(deserialize::<u64>(&bytes).map_err(from_ser_err)?))
    } else {
        Ok(None)
    }
}

fn set_last_persistent_entry(presistent: &mut SimpleDbWriteBatch, index: u64) -> RaftResult<()> {
    let bytes = serialize(&index).map_err(from_ser_err)?;
    presistent.put_cf(DB_COL_DEFAULT, LAST_ENTRY_KEY, &bytes);
    Ok(())
}

fn get_persistent_snapshot(
    presistent: &SimpleDb,
    init_cs: ConfState,
) -> RaftResult<Option<Snapshot>> {
    let data = presistent
        .get_cf(DB_COL_DEFAULT, SNAPSHOT_DATA_KEY)
        .map_err(from_db_err)?;
    let meta = presistent
        .get_cf(DB_COL_DEFAULT, SNAPSHOT_META_KEY)
        .map_err(from_db_err)?;

    if let (Some(data), Some(meta)) = (data, meta) {
        let meta = {
            let metadata: SnapMetadata = deserialize(&meta).map_err(from_ser_err)?;
            let mut meta = SnapshotMetadata::new();
            meta.set_conf_state(init_cs);
            meta.index = metadata.index;
            meta.term = metadata.term;
            meta
        };

        let mut snapshot = Snapshot::new();
        snapshot.set_data(data);
        snapshot.set_metadata(meta);
        Ok(Some(snapshot))
    } else {
        Ok(None)
    }
}

fn set_persistent_snapshot(
    presistent: &mut SimpleDbWriteBatch,
    snapshot: &Snapshot,
) -> RaftResult<()> {
    let data = snapshot.get_data();
    let meta = snapshot.get_metadata();
    let meta = serialize(&SnapMetadata {
        index: meta.index,
        term: meta.term,
    })
    .map_err(from_ser_err)?;
    presistent.put_cf(DB_COL_DEFAULT, SNAPSHOT_DATA_KEY, data);
    presistent.put_cf(DB_COL_DEFAULT, SNAPSHOT_META_KEY, meta);
    Ok(())
}

fn get_persistent_hardstate(presistent: &SimpleDb) -> RaftResult<Option<HardState>> {
    if let Some(bytes) = presistent
        .get_cf(DB_COL_DEFAULT, HARDSTATE_KEY)
        .map_err(from_db_err)?
    {
        Ok(Some(protobuf::parse_from_bytes::<HardState>(&bytes)?))
    } else {
        Ok(None)
    }
}

fn set_persistent_hardstate(presistent: &mut SimpleDb, bytes: &[u8]) -> RaftResult<()> {
    presistent
        .put_cf(DB_COL_DEFAULT, HARDSTATE_KEY, bytes)
        .map_err(from_db_err)?;
    Ok(())
}

pub fn get_presistent_committed(presistent: &SimpleDb) -> RaftResult<Option<CommittedIndex>> {
    if let Some(v) = get_persistent_hardstate(presistent)? {
        return Ok(Some(CommittedIndex {
            index: v.commit,
            term: v.term,
        }));
    }

    if let Some(v) = presistent
        .get_cf(DB_COL_DEFAULT, SNAPSHOT_META_KEY)
        .map_err(from_db_err)?
    {
        let metadata: SnapMetadata = deserialize(&v).map_err(from_ser_err)?;
        return Ok(Some(CommittedIndex {
            index: metadata.index,
            term: metadata.term,
        }));
    }

    Ok(None)
}
