use crate::configurations::DbMode;
use crate::constants::{
    DB_PATH_LIVE, DB_PATH_TEST, DB_VERSION_KEY, NETWORK_VERSION_SERIALIZED, OLD_BACKUP_COUNT,
};
use rocksdb::backup::{BackupEngine, BackupEngineOptions};
use rocksdb::{DBCompressionType, IteratorMode, Options, WriteBatch, DB};
pub use rocksdb::{Error as DBError, DEFAULT_COLUMN_FAMILY_NAME as DB_COL_DEFAULT};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::{error::Error, fmt};
use tracing::{debug, warn};

pub type DbIteratorItem = (Vec<u8>, Vec<u8>);
pub type InMemoryWriteBatch = Vec<(usize, Vec<u8>, Option<Vec<u8>>)>;
pub type InMemoryColumns = BTreeMap<String, usize>;
pub type InMemoryDb = Vec<BTreeMap<Vec<u8>, Vec<u8>>>;

/// Result wrapper for SimpleDb errors
pub type Result<T> = std::result::Result<T, SimpleDbError>;

/// Description for a database
#[derive(Debug, Clone, Copy)]
pub struct SimpleDbSpec {
    pub db_path: &'static str,
    pub suffix: &'static str,
    pub columns: &'static [&'static str],
}

#[derive(Debug)]
pub struct SimpleDbError(String);

impl Error for SimpleDbError {
    fn description(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SimpleDbError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<DBError> for SimpleDbError {
    fn from(other: DBError) -> Self {
        Self(other.into_string())
    }
}

impl SimpleDbError {
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Database that can store in memory or using rocksDB.
pub enum SimpleDb {
    File {
        options: Options,
        path: String,
        columns: BTreeSet<String>,
        db: DB,
    },
    InMemory {
        columns: InMemoryColumns,
        key_values: InMemoryDb,
    },
}

impl fmt::Debug for SimpleDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { .. } => write!(f, "SimpleDb::File"),
            Self::InMemory { .. } => write!(f, "SimpleDb::InMemory"),
        }
    }
}

impl Drop for SimpleDb {
    fn drop(&mut self) {
        match self {
            Self::File { options, path, .. } => {
                if let Err(e) = DB::destroy(options, path.clone()) {
                    // Note: This seem to always happen.
                    warn!("Db(path) Failed to destroy: {:?}", e);
                }
            }
            Self::InMemory { .. } => (),
        }
    }
}

impl SimpleDb {
    /// Create rocksDB
    pub fn new_file(path: String, columns: &[&str]) -> Result<Self> {
        debug!("Open/Create Db at {}", path);
        let columns = [DB_COL_DEFAULT].iter().chain(columns.iter());
        let mut options = get_db_options();

        if let Ok(old_columns) = DB::list_cf(&options, &path) {
            let c_old = old_columns.iter().map(|k| k.as_str());
            let c_new = columns.copied();

            check_old_includes_new(c_old, c_new)?;
            let db = DB::open_cf(&options, path.clone(), &old_columns)?;
            Ok(Self::File {
                columns: old_columns.into_iter().collect(),
                options,
                path,
                db,
            })
        } else {
            // Allow create empty db with required column families.
            // Do not create column families on existing db but error.
            debug!("Create Db at {}", path);
            options.create_if_missing(true);
            options.create_missing_column_families(true);

            let db = DB::open_cf(&options, path.clone(), columns.clone())?;
            with_initial_data(Self::File {
                columns: columns.map(|k| k.to_string()).collect(),
                options,
                path,
                db,
            })
        }
    }

    /// Create in memory db
    pub fn new_in_memory(columns: &[&str], old_db: Option<Self>) -> Result<Self> {
        let key_values = vec![Default::default(); columns.len() + 1];
        let columns = [DB_COL_DEFAULT].iter().chain(columns.iter());

        if let Some(old_db) = old_db {
            let c_old = if let SimpleDb::InMemory { columns, .. } = &old_db {
                columns.keys().map(|k| k.as_str())
            } else {
                panic!("Try to open an in memory db from a File db");
            };
            let c_new = columns.copied();

            check_old_includes_new(c_old, c_new)?;
            Ok(old_db)
        } else {
            let columns = columns
                .enumerate()
                .map(|(idx, v)| (v.to_string(), idx))
                .collect();
            with_initial_data(Self::InMemory {
                key_values,
                columns,
            })
        }
    }

    /// Take the current db and replace with default
    pub fn take(&mut self) -> Self {
        std::mem::replace(
            self,
            Self::InMemory {
                key_values: Default::default(),
                columns: Default::default(),
            },
        )
    }

    /// Return only in memory db
    pub fn in_memory(self) -> Option<Self> {
        if let Self::InMemory { .. } = &self {
            Some(self)
        } else {
            // Drop/close file db
            None
        }
    }

    /// Return only in memory db cloned
    pub fn cloned_in_memory(&self) -> Option<Self> {
        if let Self::InMemory {
            columns,
            key_values,
        } = &self
        {
            Some(Self::InMemory {
                columns: columns.clone(),
                key_values: key_values.clone(),
            })
        } else {
            // Drop/close file db
            None
        }
    }

    /// Backup path for file db
    pub fn file_backup_path(&self) -> Option<String> {
        if let Self::File { path, .. } = &self {
            Some(path.clone() + "_backup")
        } else {
            None
        }
    }

    /// Backup for file db
    pub fn file_backup(&self) -> Result<()> {
        if let Self::File { path, db, .. } = &self {
            let backup_path = path.clone() + "_backup";
            let backup_opts = BackupEngineOptions::default();
            let mut backup_engine = BackupEngine::open(&backup_opts, &backup_path).unwrap();
            let flush_before_backup = true;

            warn!("Backup db {} to {}", path, backup_path);
            backup_engine.create_new_backup_flush(db, flush_before_backup)?;

            warn!("Purging old backups at {backup_path:?} leaving {OLD_BACKUP_COUNT:?} latest backups intact");
            backup_engine.purge_old_backups(OLD_BACKUP_COUNT)?;
        }

        Ok(())
    }

    /// Create a column as part of an upgrade if not already open
    pub fn upgrade_create_missing_cf(&mut self, name: &'static str) -> Result<()> {
        match self {
            Self::File {
                db,
                options,
                columns,
                ..
            } => {
                if db.cf_handle(name).is_none() {
                    db.create_cf(name, options)?;
                    columns.insert(name.to_owned());
                }
            }
            Self::InMemory {
                columns,
                key_values,
            } => {
                if !columns.contains_key(name) {
                    columns.insert(name.to_owned(), key_values.len());
                    key_values.push(Default::default());
                }
            }
        };
        Ok(())
    }

    /// Writter to accumulate batch edits
    pub fn batch_writer(&self) -> SimpleDbWriteBatch {
        match self {
            Self::File { db, .. } => SimpleDbWriteBatch::File {
                write: Default::default(),
                db,
            },
            Self::InMemory { columns, .. } => SimpleDbWriteBatch::InMemory {
                write: Default::default(),
                columns,
            },
        }
    }

    /// Write batch to database
    ///
    /// ### Arguments
    ///
    /// * `batch` - batch of put/delete to process
    pub fn write(&mut self, batch: SimpleDbWriteBatchDone) -> Result<()> {
        use SimpleDbWriteBatchDone as Batch;
        match (self, batch) {
            (Self::File { db, .. }, Batch::File { write }) => {
                db.write(write)?;
            }
            (Self::InMemory { key_values, .. }, Batch::InMemory { write }) => {
                for (cf, key, action) in write {
                    if let Some(value) = action {
                        key_values[cf].insert(key, value);
                    } else {
                        key_values[cf].remove(&key);
                    }
                }
            }
            (Self::File { .. }, Batch::InMemory { .. })
            | (Self::InMemory { .. }, Batch::File { .. }) => panic!("Incompatible db and batch"),
        }
        Ok(())
    }

    /// Write batch imported items to database, if error nothing added.
    ///
    /// ### Arguments
    ///
    /// * `items` - items to add
    pub fn import_items<'a>(
        &mut self,
        items: impl Iterator<Item = (&'a str, &'a [u8], &'a [u8])>,
    ) -> Result<()> {
        let mut writter = self.batch_writer();
        for (cf, key, value) in items {
            writter.put_cf_checked(cf, key, value)?;
        }
        let writter = writter.done();
        self.write(writter)
    }

    /// Add entry to database
    ///
    /// ### Arguments
    ///
    /// * `cf`  - The column family to use
    /// * `key` - reference to the value in database to when the entry is added
    /// * `value` - value to be added to the db
    pub fn put_cf<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        cf: &'static str,
        key: K,
        value: V,
    ) -> Result<()> {
        match self {
            Self::File { db, .. } => {
                let cf = db.cf_handle(cf).unwrap();
                db.put_cf(cf, key, value)?;
            }
            Self::InMemory {
                key_values,
                columns,
            } => {
                let cf = columns.get(cf).unwrap();
                key_values[*cf].insert(key.as_ref().to_vec(), value.as_ref().to_vec());
            }
        }
        Ok(())
    }

    /// Remove entry from database
    ///
    /// ### Arguments
    ///
    /// * `cf`  - The column family to use
    /// * `key` - position in database to be deleted
    pub fn delete_cf<K: AsRef<[u8]>>(&mut self, cf: &'static str, key: K) -> Result<()> {
        match self {
            Self::File { db, .. } => {
                let cf = db.cf_handle(cf).unwrap();
                db.delete_cf(cf, key)?;
            }
            Self::InMemory {
                key_values,
                columns,
            } => {
                let cf = columns.get(cf).unwrap();
                key_values[*cf].remove(key.as_ref());
            }
        }
        Ok(())
    }

    /// Get entry from database
    ///
    /// ### Arguments
    ///
    /// * `cf`  - The column family to use
    /// * `key` - used to find position in database
    pub fn get_cf<K: AsRef<[u8]>>(&self, cf: &'static str, key: K) -> Result<Option<Vec<u8>>> {
        match self {
            Self::File { db, .. } => {
                let cf = db.cf_handle(cf).unwrap();
                Ok(db.get_cf(cf, key)?)
            }
            Self::InMemory {
                key_values,
                columns,
            } => {
                let cf = columns.get(cf).unwrap();
                Ok(key_values[*cf].get(key.as_ref()).cloned())
            }
        }
    }

    /// Count entries from database
    pub fn count_cf(&self, cf: &'static str) -> usize {
        match self {
            Self::File { db, .. } => {
                let cf = db.cf_handle(cf).unwrap();
                db.iterator_cf(cf, IteratorMode::Start).count()
            }
            Self::InMemory {
                key_values,
                columns,
            } => {
                let cf = columns.get(cf).unwrap();
                key_values[*cf].len()
            }
        }
    }

    /// Get entries from database as iterable db items
    pub fn iter_cf_clone(&self, cf: &'static str) -> Box<dyn Iterator<Item = DbIteratorItem> + '_> {
        self.iter_cf_clone_pvt(cf)
    }

    /// Get entries from database as iterable db items for all opened columns
    pub fn iter_all_cf_clone(
        &self,
    ) -> Vec<(String, Box<dyn Iterator<Item = DbIteratorItem> + '_>)> {
        self.open_columns()
            .iter()
            .map(|cf| (cf.clone(), self.iter_cf_clone_pvt(cf)))
            .collect()
    }

    /// Get entries from database as iterable db items
    fn iter_cf_clone_pvt(&self, cf: &str) -> Box<dyn Iterator<Item = DbIteratorItem> + '_> {
        match self {
            Self::File { db, .. } => {
                let cf = db.cf_handle(cf).unwrap();
                let iter = db
                    .iterator_cf(cf, IteratorMode::Start)
                    .map(|(k, v)| (k.to_vec(), v.to_vec()));
                Box::new(iter)
            }
            Self::InMemory {
                key_values,
                columns,
            } => {
                let cf = columns.get(cf).unwrap();
                let iter = key_values[*cf].iter().map(|(k, v)| (k.clone(), v.clone()));
                Box::new(iter)
            }
        }
    }

    /// Return all open columns
    fn open_columns(&self) -> Vec<String> {
        match self {
            Self::InMemory { columns, .. } => columns.keys().cloned().collect(),
            Self::File { columns, .. } => columns.iter().cloned().collect(),
        }
    }
}

/// Database Atomic update accross column with performance benefit.
pub enum SimpleDbWriteBatchDone {
    File { write: WriteBatch },
    InMemory { write: InMemoryWriteBatch },
}

/// Database Atomic update accross column with performance benefit.
pub enum SimpleDbWriteBatch<'a> {
    File {
        write: WriteBatch,
        db: &'a DB,
    },
    InMemory {
        write: InMemoryWriteBatch,
        columns: &'a InMemoryColumns,
    },
}

impl SimpleDbWriteBatch<'_> {
    /// Complete write releasing non mutable reference to db
    pub fn done(self) -> SimpleDbWriteBatchDone {
        match self {
            Self::File { write, .. } => SimpleDbWriteBatchDone::File { write },
            Self::InMemory { write, .. } => SimpleDbWriteBatchDone::InMemory { write },
        }
    }

    /// Add entry to database on write
    ///
    /// ### Arguments
    ///
    /// * `cf`  - The column family to use
    /// * `key` - reference to the value in database to when the entry is added
    /// * `value` - value to be added to the db
    pub fn put_cf<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, cf: &'static str, key: K, value: V) {
        self.put_cf_checked(cf, key, value).unwrap();
    }

    /// Add entry to database on write
    ///
    /// ### Arguments
    ///
    /// * `cf`  - The column family to use: may not be found not inserting the value
    /// * `key` - reference to the value in database to when the entry is added
    /// * `value` - value to be added to the db
    fn put_cf_checked<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        cf: &str,
        key: K,
        value: V,
    ) -> Result<()> {
        match self {
            Self::File { write, db } => {
                let cf = db
                    .cf_handle(cf)
                    .ok_or_else(|| SimpleDbError(format!("Missing column {}", cf)))?;
                write.put_cf(cf, key, value);
            }
            Self::InMemory { write, columns } => {
                let cf = columns
                    .get(cf)
                    .ok_or_else(|| SimpleDbError(format!("Missing column {}", cf)))?;
                write.push((*cf, key.as_ref().to_vec(), Some(value.as_ref().to_vec())));
            }
        }
        Ok(())
    }

    /// Remove entry from database on write
    ///
    /// ### Arguments
    ///
    /// * `cf`  - The column family to use
    /// * `key` - position in database to be deleted
    pub fn delete_cf<K: AsRef<[u8]>>(&mut self, cf: &'static str, key: K) {
        match self {
            Self::File { write, db } => {
                let cf = db.cf_handle(cf).unwrap();
                write.delete_cf(cf, key);
            }
            Self::InMemory { write, columns } => {
                let cf = columns.get(cf).unwrap();
                write.push((*cf, key.as_ref().to_vec(), None));
            }
        }
    }
}

/// Add initial state to freshly created DB: Version.
fn with_initial_data(mut db: SimpleDb) -> Result<SimpleDb> {
    if let Some(version) = db.get_cf(DB_COL_DEFAULT, DB_VERSION_KEY)? {
        panic!("with_initial_data: version exists {:?}", version);
    }
    db.put_cf(DB_COL_DEFAULT, DB_VERSION_KEY, NETWORK_VERSION_SERIALIZED)?;
    Ok(db)
}

/// Check Version in database is as expected.
fn check_version(db: &SimpleDb, expected: Option<&[u8]>) -> Result<()> {
    let version = db.get_cf(DB_COL_DEFAULT, DB_VERSION_KEY)?;
    if version.as_deref() == expected {
        Ok(())
    } else {
        warn!("DB Version mismatch {:?} != {:?}", version, expected);
        Err(SimpleDbError("DB Version mismatch".to_owned()))
    }
}

/// Creates a set of DB opening options for rocksDB instances
fn get_db_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(DBCompressionType::Snappy);

    opts
}

/// Check iterators are equals when sorted
fn check_old_includes_new<'a>(
    old: impl Iterator<Item = &'a str>,
    new: impl Iterator<Item = &'a str>,
) -> Result<()> {
    let old: HashSet<_> = old.collect();
    let new: HashSet<_> = new.collect();
    if new.is_subset(&old) {
        Ok(())
    } else {
        Err(SimpleDbError("Column mismatch while opening".to_owned()))
    }
}

/// Creates a new database(db) object in selected mode
///
/// ### Arguments
///
/// * `db_moode` - Mode for the database.
/// * `db_spec`  - Database specification.
/// * `old_db`   - Old in memory Database to try to open.
pub fn new_db(db_mode: DbMode, db_spec: &SimpleDbSpec, old_db: Option<SimpleDb>) -> SimpleDb {
    new_db_with_version(db_mode, db_spec, Some(NETWORK_VERSION_SERIALIZED), old_db).unwrap()
}

/// Creates a new database(db) object in selected mode
///
/// ### Arguments
///
/// * `db_moode` - Mode for the database.
/// * `db_spec`  - Database specification.
/// * `version`  - Database exact version to use (if none check key absent).
/// * `old_db`   - Old in memory Database to try to open.
pub fn new_db_with_version(
    db_mode: DbMode,
    db_spec: &SimpleDbSpec,
    version: Option<&[u8]>,
    old_db: Option<SimpleDb>,
) -> Result<SimpleDb> {
    let db = new_db_no_check_version(db_mode, db_spec, old_db)?;
    check_version(&db, version)?;
    Ok(db)
}

/// Creates a new database(db) object in selected mode
///
/// ### Arguments
///
/// * `db_moode` - Mode for the database.
/// * `db_spec`  - Database specification.
/// * `old_db`   - Old in memory Database to try to open.
pub fn new_db_no_check_version(
    db_mode: DbMode,
    db_spec: &SimpleDbSpec,
    old_db: Option<SimpleDb>,
) -> Result<SimpleDb> {
    if let Some(save_path) = new_db_save_path(db_mode, db_spec) {
        if old_db.is_some() {
            panic!("new_db: Do not provide database, read it from disk");
        }
        SimpleDb::new_file(save_path, db_spec.columns)
    } else {
        SimpleDb::new_in_memory(db_spec.columns, old_db)
    }
}

/// Path for the database is selected mode
///
/// ### Arguments
///
/// * `db_moode` - Mode for the database.
/// * `db_spec`  - Database specification.
pub fn new_db_save_path(db_mode: DbMode, db_spec: &SimpleDbSpec) -> Option<String> {
    let db_path = db_spec.db_path;
    let suffix = db_spec.suffix;
    match db_mode {
        DbMode::Live => Some(format!("{}/{}{}", db_path, DB_PATH_LIVE, suffix)),
        DbMode::Test(idx) => Some(format!("{}/{}{}.{}", db_path, DB_PATH_TEST, suffix, idx)),
        DbMode::InMemory => None,
    }
}

/// Restore backup for file db
pub fn restore_file_backup(db_mode: DbMode, db_spec: &SimpleDbSpec) -> Result<()> {
    if let Some(path) = new_db_save_path(db_mode, db_spec) {
        let backup_path = path.clone() + "_backup";
        let backup_opts = BackupEngineOptions::default();
        let mut backup_engine = BackupEngine::open(&backup_opts, &backup_path).unwrap();

        let mut restore_option = rocksdb::backup::RestoreOptions::default();
        restore_option.set_keep_log_files(true);

        warn!("Restore db {} from {}", path, backup_path);
        backup_engine.restore_from_latest_backup(path, "", &restore_option)?;
    }

    Ok(())
}
