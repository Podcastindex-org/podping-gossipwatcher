use rusqlite::{params, Connection};
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Archive {
    conn: Connection,
}

impl Archive {
    // Open (or create) the SQLite archive at the given path.
    pub fn open(path: &str) -> Result<Self, Box<dyn Error>> {
        let conn = Connection::open(path)?;

        // WAL lets the sync handler read while notifications are still being
        // written; the default rollback journal makes readers and the writer
        // block each other. The mode is persisted in the database header, the
        // other two pragmas are per-connection and must be set on every open.
        let journal_mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            eprintln!(
                "\x1b[35m[WARN] Archive journal_mode is \"{}\", not WAL\x1b[0m",
                journal_mode
            );
        }
        // NORMAL is the matching durability level for WAL: commits don't fsync,
        // checkpoints do. A crash can lose the last commits but not corrupt.
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Without a busy timeout a concurrent writer (second instance, backup
        // tool) makes an insert fail outright instead of waiting.
        conn.busy_timeout(Duration::from_secs(5))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                 hash       TEXT PRIMARY KEY,
                 payload    BLOB,
                 created_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS manifest (
                 hour_key   TEXT,
                 hash       TEXT,
                 sender     TEXT,
                 medium     TEXT,
                 reason     TEXT,
                 timestamp  INTEGER,
                 iri_count  INTEGER,
                 UNIQUE(hour_key, hash)
             );
             CREATE INDEX IF NOT EXISTS idx_messages_created_at
                 ON messages(created_at);",
        )?;

        Ok(Archive { conn })
    }

    // Store a notification payload, deduplicating by its blake3 content hash.
    // Returns `true` if the row was newly inserted, `false` if it already existed.
    pub fn store(
        &self,
        payload: &[u8],
        sender: &str,
        medium: &str,
        reason: &str,
        timestamp: u64,
        iri_count: usize,
    ) -> Result<bool, Box<dyn Error>> {
        let hash = blake3::hash(payload);
        let hash_hex = hash.to_hex().to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();

        // Both inserts in one transaction: a crash between them would otherwise
        // leave a message with no manifest row, and it halves the commit count.
        let tx = self.conn.unchecked_transaction()?;

        // INSERT OR IGNORE deduplicates by content hash
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO messages (hash, payload, created_at) VALUES (?1, ?2, ?3)",
            params![hash_hex, payload, now as i64],
        )?;

        // hour_key for manifest partitioning: "YYYY-MM-DD-HH"
        let hour_key = {
            // Simple hour key from unix timestamp
            let hours_since_epoch = timestamp / 3600;
            let day = hours_since_epoch / 24;
            let hour = hours_since_epoch % 24;
            let days_since_epoch = day;
            // Approximate date from days since epoch
            format!("{}-{:02}", days_since_epoch, hour)
        };

        tx.execute(
            "INSERT OR IGNORE INTO manifest (hour_key, hash, sender, medium, reason, timestamp, iri_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                hour_key,
                hash_hex,
                sender,
                medium,
                reason,
                timestamp as i64,
                iri_count as i64,
            ],
        )?;

        tx.commit()?;

        Ok(inserted > 0)
    }

    /// Return up to `limit` message payloads whose `created_at >= since`
    /// (unix seconds), ordered by created_at ASC. The limit is applied in SQL:
    /// the caller is a remote peer that picks `since`, so an unbounded query
    /// would let it pull the whole archive into memory.
    pub fn messages_since(&self, since: u64, limit: usize) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT payload FROM messages
             WHERE created_at >= ?1
             ORDER BY created_at ASC
             LIMIT ?2",
        )?;

        let rows = stmt
            .query_map(params![since as i64, limit as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    /// Return the latest `created_at` timestamp in the archive, or `None` if empty.
    pub fn latest_timestamp(&self) -> Result<Option<u64>, Box<dyn Error>> {
        let result: Option<i64> = self
            .conn
            .query_row("SELECT MAX(created_at) FROM messages", [], |row| row.get(0))?;

        Ok(result.map(|ts| ts as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Archive::open needs a real file: WAL is not available for :memory:.
    struct TempDb(PathBuf);

    impl TempDb {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            let mut path = std::env::temp_dir();
            path.push(format!("gossipwatcher-{}-{}-{}.db", tag, std::process::id(), nanos));
            TempDb(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{}", self.0.display(), suffix));
            }
        }
    }

    fn store_at(db: &Archive, payload: &[u8], created_at: u64) -> bool {
        let inserted = db.store(payload, "sender", "podcast", "update", created_at, 1).unwrap();
        // store() stamps created_at with the wall clock, so rewrite it to make
        // ordering and range queries testable.
        db.conn
            .execute(
                "UPDATE messages SET created_at = ?1 WHERE hash = ?2",
                params![created_at as i64, blake3::hash(payload).to_hex().to_string()],
            )
            .unwrap();
        inserted
    }

    #[test]
    fn open_enables_wal_and_indexes_created_at() {
        let tmp = TempDb::new("wal");
        let db = Archive::open(tmp.path()).unwrap();

        let mode: String = db
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");

        let index: Option<String> = db
            .conn
            .query_row(
                "SELECT name FROM sqlite_master
                 WHERE type = 'index' AND name = 'idx_messages_created_at'",
                [],
                |row| row.get(0),
            )
            .ok();
        assert_eq!(index.as_deref(), Some("idx_messages_created_at"));
    }

    #[test]
    fn store_deduplicates_by_content_hash() {
        let tmp = TempDb::new("dedupe");
        let db = Archive::open(tmp.path()).unwrap();

        assert!(store_at(&db, b"payload-a", 100));
        assert!(!store_at(&db, b"payload-a", 100));
        assert!(store_at(&db, b"payload-b", 100));

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn messages_since_honors_range_limit_and_order() {
        let tmp = TempDb::new("since");
        let db = Archive::open(tmp.path()).unwrap();

        for i in 0..5u64 {
            store_at(&db, format!("payload-{i}").as_bytes(), 100 + i);
        }

        let all = db.messages_since(0, 100).unwrap();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0], b"payload-0");
        assert_eq!(all[4], b"payload-4");

        let from_middle = db.messages_since(103, 100).unwrap();
        assert_eq!(from_middle.len(), 2);
        assert_eq!(from_middle[0], b"payload-3");

        // The limit is what keeps a remote `since` from pulling the whole archive.
        let capped = db.messages_since(0, 2).unwrap();
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[0], b"payload-0");
        assert_eq!(capped[1], b"payload-1");

        assert_eq!(db.latest_timestamp().unwrap(), Some(104));
    }
}
