// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! SQLite driver, for a single host. Every write and lease change runs in a
//! `BEGIN IMMEDIATE` transaction, which takes SQLite's write lock up front,
//! so the fence check and the batch it guards cannot interleave with a lease
//! takeover. Several processes on one host may share the file; nodes on
//! different hosts need PostgreSQL.

use super::postgres::key_string;
use super::{LeaseDecision, db_error, decide, empty_holder, prefix_end, to_i64, to_u64};
use async_trait::async_trait;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use sqlx::{Row, Sqlite};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use wacore::store::error::Result;
use wacore_recordstore::{
    Fence, FenceLost, Lease, LeaseStore, Namespace, RecordExists, RecordStore, WriteOp,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

type Conn = PoolConnection<Sqlite>;

impl SqliteStore {
    /// `url` is `sqlite://path/to/file.db` (created if missing) or
    /// `sqlite::memory:` for a throwaway database.
    pub async fn connect(url: &str, max_connections: u32) -> anyhow::Result<Self> {
        let in_memory = url.contains(":memory:");
        let mut options = SqliteConnectOptions::from_str(url)
            .map_err(|e| anyhow::anyhow!("invalid SQLite URL: {e}"))?
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(10))
            .foreign_keys(true);
        if !in_memory {
            options = options.journal_mode(SqliteJournalMode::Wal);
        }
        // Each in-memory connection would be a separate database.
        let max = if in_memory { 1 } else { max_connections };
        let pool = SqlitePoolOptions::new()
            .max_connections(max)
            .connect_with(options)
            .await
            .map_err(|e| anyhow::anyhow!("opening SQLite: {e}"))?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|e| anyhow::anyhow!("running SQLite migrations: {e}"))?;
        Ok(Self { pool })
    }

    async fn begin_immediate(&self, op: &'static str) -> Result<Conn> {
        let mut conn = self.pool.acquire().await.map_err(|e| db_error(op, e))?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .map_err(|e| db_error(op, e))?;
        Ok(conn)
    }

    /// Commit on success, roll back on any error, so a connection never goes
    /// back to the pool inside a transaction.
    async fn finish<T>(mut conn: Conn, result: Result<T>) -> Result<T> {
        match result {
            Ok(value) => {
                if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(db_error("commit", e));
                }
                Ok(value)
            }
            Err(error) => {
                if sqlx::query("ROLLBACK").execute(&mut *conn).await.is_err() {
                    // Do not reuse a connection in an unknown state.
                    conn.detach();
                }
                Err(error)
            }
        }
    }

    async fn write_in(conn: &mut Conn, fence: &Fence, ops: &[WriteOp]) -> Result<()> {
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM signal_leases WHERE scope = ? AND holder <> ''",
        )
        .bind(&*fence.scope)
        .fetch_optional(&mut **conn)
        .await
        .map_err(|e| db_error("write fence check", e))?;
        if current.map(to_u64) != Some(fence.generation) {
            return Err(FenceLost {
                scope: fence.scope.clone(),
                generation: fence.generation,
            }
            .into_store_error());
        }
        for op in ops {
            let applied = match op {
                WriteOp::Put { ns, key, value } => sqlx::query(
                    "INSERT INTO signal_records (scope, ns, key, value) VALUES (?, ?, ?, ?) \
                     ON CONFLICT (scope, ns, key) DO UPDATE SET value = excluded.value",
                )
                .bind(&*fence.scope)
                .bind(ns.tag())
                .bind(key.as_bytes())
                .bind(value.as_slice())
                .execute(&mut **conn)
                .await
                .map(|_| true),
                WriteOp::Insert { ns, key, value } => sqlx::query(
                    "INSERT INTO signal_records (scope, ns, key, value) VALUES (?, ?, ?, ?) \
                     ON CONFLICT (scope, ns, key) DO NOTHING",
                )
                .bind(&*fence.scope)
                .bind(ns.tag())
                .bind(key.as_bytes())
                .bind(value.as_slice())
                .execute(&mut **conn)
                .await
                .map(|done| done.rows_affected() == 1),
                WriteOp::Update { ns, key, value } => sqlx::query(
                    "UPDATE signal_records SET value = ? WHERE scope = ? AND ns = ? AND key = ?",
                )
                .bind(value.as_slice())
                .bind(&*fence.scope)
                .bind(ns.tag())
                .bind(key.as_bytes())
                .execute(&mut **conn)
                .await
                .map(|_| true),
                WriteOp::Delete { ns, key } => {
                    sqlx::query("DELETE FROM signal_records WHERE scope = ? AND ns = ? AND key = ?")
                        .bind(&*fence.scope)
                        .bind(ns.tag())
                        .bind(key.as_bytes())
                        .execute(&mut **conn)
                        .await
                        .map(|_| true)
                }
            }
            .map_err(|e| db_error("write", e))?;
            if !applied && let WriteOp::Insert { ns, key, .. } = op {
                return Err(RecordExists {
                    ns: *ns,
                    key: key.clone(),
                }
                .into_store_error());
            }
        }
        Ok(())
    }

    async fn acquire_in(
        conn: &mut Conn,
        scope: &str,
        holder: &str,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Option<u64>> {
        let row = sqlx::query(
            "SELECT holder, generation, expires_at_ms FROM signal_leases WHERE scope = ?",
        )
        .bind(scope)
        .fetch_optional(&mut **conn)
        .await
        .map_err(|e| db_error("acquire select", e))?;
        let current = row.map(|r| {
            (
                r.get::<String, _>(0),
                to_u64(r.get::<i64, _>(1)),
                to_u64(r.get::<i64, _>(2)),
            )
        });
        let decision = decide(
            current.as_ref().map(|(h, g, e)| (h.as_str(), *g, *e)),
            holder,
            now_ms,
        );
        let LeaseDecision::Take { generation } = decision else {
            return Ok(None);
        };
        sqlx::query(
            "INSERT INTO signal_leases (scope, holder, generation, expires_at_ms) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (scope) DO UPDATE SET holder = excluded.holder, \
             generation = excluded.generation, expires_at_ms = excluded.expires_at_ms",
        )
        .bind(scope)
        .bind(holder)
        .bind(to_i64(generation))
        .bind(to_i64(expires_at_ms))
        .execute(&mut **conn)
        .await
        .map_err(|e| db_error("acquire upsert", e))?;
        Ok(Some(generation))
    }
}

#[async_trait]
impl RecordStore for SqliteStore {
    async fn get(&self, scope: &str, ns: Namespace, key: &str) -> Result<Option<Vec<u8>>> {
        let row =
            sqlx::query("SELECT value FROM signal_records WHERE scope = ? AND ns = ? AND key = ?")
                .bind(scope)
                .bind(ns.tag())
                .bind(key.as_bytes())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| db_error("get", e))?;
        Ok(row.map(|r| r.get::<Vec<u8>, _>(0)))
    }

    async fn scan_keys(
        &self,
        scope: &str,
        ns: Namespace,
        prefix: &str,
        limit: Option<usize>,
    ) -> Result<Vec<String>> {
        let end = prefix_end(prefix.as_bytes());
        // SQLite treats a negative LIMIT as no limit.
        let limit = limit.map_or(-1, |l| i64::try_from(l).unwrap_or(i64::MAX));
        let rows = sqlx::query(
            "SELECT key FROM signal_records \
             WHERE scope = ? AND ns = ? AND key >= ? AND (? IS NULL OR key < ?) \
             ORDER BY key LIMIT ?",
        )
        .bind(scope)
        .bind(ns.tag())
        .bind(prefix.as_bytes())
        .bind(end.as_deref())
        .bind(end.as_deref())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| db_error("scan_keys", e))?;
        rows.into_iter().map(|r| key_string(r.get(0))).collect()
    }

    async fn write(&self, fence: &Fence, ops: &[WriteOp]) -> Result<()> {
        let mut conn = self.begin_immediate("write").await?;
        let result = Self::write_in(&mut conn, fence, ops).await;
        Self::finish(conn, result).await
    }
}

#[async_trait]
impl LeaseStore for SqliteStore {
    async fn acquire(
        &self,
        scope: &str,
        holder: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<Option<Lease>> {
        if holder.is_empty() {
            return Err(empty_holder());
        }
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        let mut conn = self.begin_immediate("acquire").await?;
        let result = Self::acquire_in(&mut conn, scope, holder, now_ms, expires_at_ms).await;
        let generation = Self::finish(conn, result).await?;
        Ok(generation.map(|generation| Lease {
            fence: Fence {
                scope: Arc::from(scope),
                generation,
            },
            holder: Arc::from(holder),
            expires_at_ms,
        }))
    }

    async fn renew(&self, lease: &Lease, now_ms: u64, ttl_ms: u64) -> Result<Option<Lease>> {
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        let done = sqlx::query(
            "UPDATE signal_leases SET expires_at_ms = ? \
             WHERE scope = ? AND generation = ? AND holder = ?",
        )
        .bind(to_i64(expires_at_ms))
        .bind(&*lease.fence.scope)
        .bind(to_i64(lease.fence.generation))
        .bind(&*lease.holder)
        .execute(&self.pool)
        .await
        .map_err(|e| db_error("renew", e))?;
        Ok((done.rows_affected() == 1).then(|| Lease {
            expires_at_ms,
            ..lease.clone()
        }))
    }

    async fn release(&self, lease: &Lease) -> Result<()> {
        sqlx::query(
            "UPDATE signal_leases SET holder = '', expires_at_ms = 0 \
             WHERE scope = ? AND generation = ? AND holder = ?",
        )
        .bind(&*lease.fence.scope)
        .bind(to_i64(lease.fence.generation))
        .bind(&*lease.holder)
        .execute(&self.pool)
        .await
        .map_err(|e| db_error("release", e))?;
        Ok(())
    }
}
