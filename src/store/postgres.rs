// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! PostgreSQL driver.
//!
//! A write batch runs in one transaction that first locks the scope's lease
//! row with `FOR SHARE`. Taking over a lease updates that row, which needs a
//! conflicting lock, so a takeover and a write from the old holder are
//! serialised: the write either commits before the generation moves or sees
//! the new generation and applies nothing.

use super::{LeaseDecision, db_error, decide, empty_holder, prefix_end, to_i64, to_u64};
use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};
use std::sync::Arc;
use wacore::store::error::{Result, StoreError};
use wacore_recordstore::{
    Fence, FenceLost, Lease, LeaseStore, Namespace, RecordExists, RecordStore, WriteOp,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(url: &str, max_connections: u32) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await
            .map_err(|e| anyhow::anyhow!("connecting to PostgreSQL: {e}"))?;
        Self::from_pool(pool).await
    }

    /// Use an existing pool; runs migrations.
    pub async fn from_pool(pool: PgPool) -> anyhow::Result<Self> {
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|e| anyhow::anyhow!("running PostgreSQL migrations: {e}"))?;
        Ok(Self { pool })
    }

    async fn begin(&self, op: &'static str) -> Result<Transaction<'_, Postgres>> {
        self.pool.begin().await.map_err(|e| db_error(op, e))
    }
}

fn fence_lost(fence: &Fence) -> StoreError {
    FenceLost {
        scope: fence.scope.clone(),
        generation: fence.generation,
    }
    .into_store_error()
}

#[async_trait]
impl RecordStore for PostgresStore {
    async fn get(&self, scope: &str, ns: Namespace, key: &str) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query(
            "SELECT value FROM signal_records WHERE scope = $1 AND ns = $2 AND key = $3",
        )
        .bind(scope)
        .bind(ns.tag())
        .bind(key.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| db_error("get", e))?;
        Ok(row.map(|r| r.get::<Vec<u8>, _>(0)))
    }

    async fn get_many(
        &self,
        scope: &str,
        ns: Namespace,
        keys: &[&str],
    ) -> Result<Vec<(String, Vec<u8>)>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<Vec<u8>> = keys.iter().map(|k| k.as_bytes().to_vec()).collect();
        let rows = sqlx::query(
            "SELECT key, value FROM signal_records \
             WHERE scope = $1 AND ns = $2 AND key = ANY($3)",
        )
        .bind(scope)
        .bind(ns.tag())
        .bind(&keys)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| db_error("get_many", e))?;
        rows.into_iter()
            .map(|r| Ok((key_string(r.get(0))?, r.get(1))))
            .collect()
    }

    async fn scan_keys(
        &self,
        scope: &str,
        ns: Namespace,
        prefix: &str,
        limit: Option<usize>,
    ) -> Result<Vec<String>> {
        let start = prefix.as_bytes().to_vec();
        let end = prefix_end(prefix.as_bytes());
        let limit = limit.map(|l| i64::try_from(l).unwrap_or(i64::MAX));
        let rows = sqlx::query(
            "SELECT key FROM signal_records \
             WHERE scope = $1 AND ns = $2 AND key >= $3 AND ($4::bytea IS NULL OR key < $4) \
             ORDER BY key LIMIT $5",
        )
        .bind(scope)
        .bind(ns.tag())
        .bind(start)
        .bind(end)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| db_error("scan_keys", e))?;
        rows.into_iter().map(|r| key_string(r.get(0))).collect()
    }

    async fn write(&self, fence: &Fence, ops: &[WriteOp]) -> Result<()> {
        let mut tx = self.begin("write").await?;
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT generation FROM signal_leases WHERE scope = $1 AND holder <> '' FOR SHARE",
        )
        .bind(&*fence.scope)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| db_error("write fence check", e))?;
        if current.map(to_u64) != Some(fence.generation) {
            return Err(fence_lost(fence));
        }
        for op in ops {
            let applied = match op {
                WriteOp::Put { ns, key, value } => sqlx::query(
                    "INSERT INTO signal_records (scope, ns, key, value) VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (scope, ns, key) DO UPDATE SET value = EXCLUDED.value",
                )
                .bind(&*fence.scope)
                .bind(ns.tag())
                .bind(key.as_bytes())
                .bind(value.as_slice())
                .execute(&mut *tx)
                .await
                .map(|_| true),
                WriteOp::Insert { ns, key, value } => sqlx::query(
                    "INSERT INTO signal_records (scope, ns, key, value) VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (scope, ns, key) DO NOTHING",
                )
                .bind(&*fence.scope)
                .bind(ns.tag())
                .bind(key.as_bytes())
                .bind(value.as_slice())
                .execute(&mut *tx)
                .await
                .map(|done| done.rows_affected() == 1),
                WriteOp::Update { ns, key, value } => sqlx::query(
                    "UPDATE signal_records SET value = $4 \
                     WHERE scope = $1 AND ns = $2 AND key = $3",
                )
                .bind(&*fence.scope)
                .bind(ns.tag())
                .bind(key.as_bytes())
                .bind(value.as_slice())
                .execute(&mut *tx)
                .await
                .map(|_| true),
                WriteOp::Delete { ns, key } => sqlx::query(
                    "DELETE FROM signal_records WHERE scope = $1 AND ns = $2 AND key = $3",
                )
                .bind(&*fence.scope)
                .bind(ns.tag())
                .bind(key.as_bytes())
                .execute(&mut *tx)
                .await
                .map(|_| true),
            }
            .map_err(|e| db_error("write", e))?;
            if !applied && let WriteOp::Insert { ns, key, .. } = op {
                // Dropping the transaction rolls back the earlier ops.
                return Err(RecordExists {
                    ns: *ns,
                    key: key.clone(),
                }
                .into_store_error());
            }
        }
        tx.commit().await.map_err(|e| db_error("write commit", e))
    }
}

#[async_trait]
impl LeaseStore for PostgresStore {
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
        let mut tx = self.begin("acquire").await?;
        // Make sure a row exists so it can be locked; a fresh row starts at
        // generation 1 for this holder.
        let inserted = sqlx::query(
            "INSERT INTO signal_leases (scope, holder, generation, expires_at_ms) \
             VALUES ($1, $2, 1, $3) ON CONFLICT (scope) DO NOTHING",
        )
        .bind(scope)
        .bind(holder)
        .bind(to_i64(expires_at_ms))
        .execute(&mut *tx)
        .await
        .map_err(|e| db_error("acquire insert", e))?
        .rows_affected()
            == 1;
        let generation = if inserted {
            1
        } else {
            let row = sqlx::query(
                "SELECT holder, generation, expires_at_ms FROM signal_leases \
                 WHERE scope = $1 FOR UPDATE",
            )
            .bind(scope)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| db_error("acquire select", e))?;
            let current: String = row.get(0);
            let decision = decide(
                Some((&current, to_u64(row.get(1)), to_u64(row.get(2)))),
                holder,
                now_ms,
            );
            let LeaseDecision::Take { generation } = decision else {
                return Ok(None);
            };
            sqlx::query(
                "UPDATE signal_leases SET holder = $2, generation = $3, expires_at_ms = $4 \
                 WHERE scope = $1",
            )
            .bind(scope)
            .bind(holder)
            .bind(to_i64(generation))
            .bind(to_i64(expires_at_ms))
            .execute(&mut *tx)
            .await
            .map_err(|e| db_error("acquire update", e))?;
            generation
        };
        tx.commit()
            .await
            .map_err(|e| db_error("acquire commit", e))?;
        Ok(Some(Lease {
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
            "UPDATE signal_leases SET expires_at_ms = $4 \
             WHERE scope = $1 AND generation = $2 AND holder = $3",
        )
        .bind(&*lease.fence.scope)
        .bind(to_i64(lease.fence.generation))
        .bind(&*lease.holder)
        .bind(to_i64(expires_at_ms))
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
             WHERE scope = $1 AND generation = $2 AND holder = $3",
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

/// Keys are written from `&str`, so they are always UTF-8.
pub(crate) fn key_string(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes)
        .map_err(|_| StoreError::Validation("stored record key is not UTF-8".into()))
}
