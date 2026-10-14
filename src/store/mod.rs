// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! Storage drivers for [`RecordStore`] and [`LeaseStore`].
//!
//! Every driver passes the `wacore-recordstore` conformance suite. Values
//! arrive already sealed; drivers store opaque bytes and enforce two rules in
//! the database itself: a write batch applies only while its fence is the
//! scope's current lease generation, and an exclusive insert fails the whole
//! batch if its key exists.

mod postgres;
mod sqlite;

pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;

use async_trait::async_trait;
use std::sync::Arc;
use wacore::store::error::{Result, StoreError};
use wacore_recordstore::{Fence, Lease, LeaseStore, MemoryRecordStore, Namespace, RecordStore, WriteOp};

use crate::config::{Resolved, StorageDriver};

/// The configured driver.
#[derive(Clone)]
pub enum Backend {
    Memory(Arc<MemoryRecordStore>),
    Postgres(PostgresStore),
    Sqlite(SqliteStore),
}

impl Backend {
    /// Connect and run migrations.
    pub async fn connect(config: &Resolved) -> anyhow::Result<Self> {
        Ok(match config.storage_driver {
            StorageDriver::Memory => Backend::Memory(Arc::new(MemoryRecordStore::new())),
            StorageDriver::Postgres => Backend::Postgres(
                PostgresStore::connect(config.storage_url.expose(), config.max_connections)
                    .await?,
            ),
            StorageDriver::Sqlite => Backend::Sqlite(
                SqliteStore::connect(config.storage_url.expose(), config.max_connections).await?,
            ),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Backend::Memory(_) => "memory",
            Backend::Postgres(_) => "postgres",
            Backend::Sqlite(_) => "sqlite",
        }
    }
}

#[async_trait]
impl RecordStore for Backend {
    async fn get(&self, scope: &str, ns: Namespace, key: &str) -> Result<Option<Vec<u8>>> {
        match self {
            Backend::Memory(s) => s.get(scope, ns, key).await,
            Backend::Postgres(s) => s.get(scope, ns, key).await,
            Backend::Sqlite(s) => s.get(scope, ns, key).await,
        }
    }

    async fn get_many(
        &self,
        scope: &str,
        ns: Namespace,
        keys: &[&str],
    ) -> Result<Vec<(String, Vec<u8>)>> {
        match self {
            Backend::Memory(s) => s.get_many(scope, ns, keys).await,
            Backend::Postgres(s) => s.get_many(scope, ns, keys).await,
            Backend::Sqlite(s) => s.get_many(scope, ns, keys).await,
        }
    }

    async fn scan_keys(
        &self,
        scope: &str,
        ns: Namespace,
        prefix: &str,
        limit: Option<usize>,
    ) -> Result<Vec<String>> {
        match self {
            Backend::Memory(s) => s.scan_keys(scope, ns, prefix, limit).await,
            Backend::Postgres(s) => s.scan_keys(scope, ns, prefix, limit).await,
            Backend::Sqlite(s) => s.scan_keys(scope, ns, prefix, limit).await,
        }
    }

    async fn write(&self, fence: &Fence, ops: &[WriteOp]) -> Result<()> {
        match self {
            Backend::Memory(s) => s.write(fence, ops).await,
            Backend::Postgres(s) => s.write(fence, ops).await,
            Backend::Sqlite(s) => s.write(fence, ops).await,
        }
    }
}

#[async_trait]
impl LeaseStore for Backend {
    async fn acquire(
        &self,
        scope: &str,
        holder: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<Option<Lease>> {
        match self {
            Backend::Memory(s) => s.acquire(scope, holder, now_ms, ttl_ms).await,
            Backend::Postgres(s) => s.acquire(scope, holder, now_ms, ttl_ms).await,
            Backend::Sqlite(s) => s.acquire(scope, holder, now_ms, ttl_ms).await,
        }
    }

    async fn renew(&self, lease: &Lease, now_ms: u64, ttl_ms: u64) -> Result<Option<Lease>> {
        match self {
            Backend::Memory(s) => s.renew(lease, now_ms, ttl_ms).await,
            Backend::Postgres(s) => s.renew(lease, now_ms, ttl_ms).await,
            Backend::Sqlite(s) => s.renew(lease, now_ms, ttl_ms).await,
        }
    }

    async fn release(&self, lease: &Lease) -> Result<()> {
        match self {
            Backend::Memory(s) => s.release(lease).await,
            Backend::Postgres(s) => s.release(lease).await,
            Backend::Sqlite(s) => s.release(lease).await,
        }
    }
}

/// Wrap a driver error. The message names the operation only; it never
/// carries values.
pub(crate) fn db_error(op: &'static str, error: sqlx::Error) -> StoreError {
    StoreError::Database(Box::new(DbError { op, source: error }))
}

#[derive(Debug, thiserror::Error)]
#[error("database {op} failed")]
pub(crate) struct DbError {
    op: &'static str,
    #[source]
    source: sqlx::Error,
}

/// Exclusive upper bound of the keys starting with `prefix`, in byte order.
/// `None` means unbounded (empty prefix, or a prefix of only 0xFF bytes).
pub(crate) fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xFF {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// Lease decision shared by the SQL drivers, given the current row.
pub(crate) enum LeaseDecision {
    Refuse,
    Take { generation: u64 },
}

pub(crate) fn decide(
    row: Option<(&str, u64, u64)>,
    holder: &str,
    now_ms: u64,
) -> LeaseDecision {
    match row {
        None => LeaseDecision::Take { generation: 1 },
        Some((current, generation, _)) if current == holder => LeaseDecision::Take { generation },
        Some((_, _, expires_at_ms)) if expires_at_ms > now_ms => LeaseDecision::Refuse,
        Some((_, generation, _)) => LeaseDecision::Take {
            generation: generation + 1,
        },
    }
}

pub(crate) fn empty_holder() -> StoreError {
    StoreError::Validation("lease holder must not be empty".into())
}

/// SQL integers are signed; lease times and generations stay below 2^63.
pub(crate) fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub(crate) fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_end_is_the_next_byte_string() {
        assert_eq!(prefix_end(b""), None);
        assert_eq!(prefix_end(b"ab").as_deref(), Some(&b"ac"[..]));
        assert_eq!(prefix_end(b"a\xff").as_deref(), Some(&b"b"[..]));
        assert_eq!(prefix_end(b"\xff\xff"), None);
    }

    #[test]
    fn the_memory_driver_passes_conformance() {
        let store = Backend::Memory(Arc::new(MemoryRecordStore::new()));
        futures_executor_block_on(wacore_recordstore::conformance::run_all(&store));
    }

    fn futures_executor_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }
}
