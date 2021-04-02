use crate::configurations::DbMode;
use crate::constants::{DB_PATH_LIVE, DB_PATH_TEST};
use rocksdb::{DBCompressionType, IteratorMode, Options, WriteBatch, DB};
pub use rocksdb::{Error as DBError, DEFAULT_COLUMN_FAMILY_NAME as DB_COL_DEFAULT};
use std::collections::HashMap;
use std::fmt;
use tracing::{debug, warn};

pub type DbIteratorItem = (Vec<u8>, Vec<u8>);
pub type InMemoryWriteBatch = Vec<(usize, Vec<u8>, Option<Vec<u8>>)>;
pub type InMemoryColumns = HashMap<String, usize>;
pub type InMemoryDb = Vec<HashMap<Vec<u8>, Vec<u8>>>;

/// Description for a database
pub struct SimpleDbSpec {
    pub db_path: &'static str,
    pub suffix: &'static str,
    pub columns: &'static [&'static str],
}

/// Database that can store in memory or using rocksDB.
pub enum SimpleDb {
    File {
        options: Options,
        path: String,
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
        self.destroy();
    }
}

impl SimpleDb {
    /// Create rocksDB
    pub fn new_file(path: String, columns: &[&str]) -> Result<Self, DBError> {
        debug!("Open/Create Db at {}", path);
        let options = get_db_options();
        let columns = [DB_COL_DEFAULT].iter().chain(columns.iter());
        let db = DB::open_cf(&options, path.clone(), columns)?;
        Ok(Self::File { options, path, db })
    }

    /// Create in memory db
    pub fn new_in_memory(columns: &[&str]) -> Self {
        let key_values = vec![Default::default(); columns.len() + 1];
        let columns = [DB_COL_DEFAULT].iter().chain(columns.iter());
        let columns = columns
            .enumerate()
            .map(|(idx, v)| (v.to_string(), idx))
            .collect();
        Self::InMemory {
            key_values,
            columns,
        }
    }

    /// Destroys the database in memory
    fn destroy(&mut self) {
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
    pub fn write(&mut self, batch: SimpleDbWriteBatchDone) -> Result<(), DBError> {
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
    ) -> Result<(), DBError> {
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
    pub fn delete_cf<K: AsRef<[u8]>>(&mut self, cf: &'static str, key: K) -> Result<(), DBError> {
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
    pub fn get_cf<K: AsRef<[u8]>>(
        &self,
        cf: &'static str,
        key: K,
    ) -> Result<Option<Vec<u8>>, DBError> {
        match self {
            Self::File { db, .. } => {
                let cf = db.cf_handle(cf).unwrap();
                db.get_cf(cf, key)
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
        match self {
            Self::File { write, db } => {
                let cf = db.cf_handle(cf).unwrap();
                write.put_cf(cf, key, value);
            }
            Self::InMemory { write, columns } => {
                let cf = columns.get(cf).unwrap();
                write.push((*cf, key.as_ref().to_vec(), Some(value.as_ref().to_vec())));
            }
        }
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

/// Creates a set of DB opening options for rocksDB instances
fn get_db_options() -> Options {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.set_compression_type(DBCompressionType::Snappy);

    opts
}

///Creates a new database(db) object in selected mode
///
/// ### Arguments
///
/// * `db_moode` - Mode for the database.
/// * `db_spec`  - Database specification.
pub fn new_db(db_mode: DbMode, db_spec: &SimpleDbSpec) -> SimpleDb {
    let save_path = match db_mode {
        DbMode::Live => format!("{}/{}{}", db_spec.db_path, DB_PATH_LIVE, db_spec.suffix),
        DbMode::Test(idx) => format!(
            "{}/{}{}.{}",
            db_spec.db_path, DB_PATH_TEST, db_spec.suffix, idx
        ),
        DbMode::InMemory => {
            return SimpleDb::new_in_memory(db_spec.columns);
        }
    };

    SimpleDb::new_file(save_path, db_spec.columns).unwrap()
}
