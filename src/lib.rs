// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa (Softium LLC)
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

//! signal-node: the self-hosted Signal service for Polymorfa
//! zero-knowledge sessions.

pub mod config;
pub mod delivery;
pub mod http;
pub mod keys;
pub mod link;
pub mod message;
pub mod node;
pub mod proto;
pub mod ratelimit;
pub mod resolver;
pub mod send;
pub mod serve;
pub mod store;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;

/// Build identifier sent in `Hello.service_version`.
pub const SERVICE_VERSION: &str = concat!("signal-node/", env!("CARGO_PKG_VERSION"));

/// A running node.
pub struct Running {
    pub node: Arc<node::Node>,
    pub http_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    /// Release every session, then stop.
    pub async fn shutdown(mut self) {
        // Open SSE streams or a stalled peer cannot hold shutdown forever.
        // Aborting after this deadline leaves any unreleased lease to expire.
        let cleanup = async {
            self.node.shutdown().await;
            for task in &mut self.tasks {
                let _ = task.await;
            }
        };
        if tokio::time::timeout(std::time::Duration::from_secs(10), cleanup)
            .await
            .is_err()
        {
            for task in &self.tasks {
                task.abort();
            }
            tracing::warn!("shutdown deadline reached; remaining leases will expire");
        }
    }

    /// Stop every task at once without releasing leases, as a crash would.
    /// For tests.
    pub fn abort(&self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Start a node: bind the application API, then run the link, lease and
/// pruning loops.
pub async fn start(cfg: config::Resolved, backend: store::Backend) -> anyhow::Result<Running> {
    let listener = tokio::net::TcpListener::bind(cfg.http_listen).await?;
    let http_addr = listener.local_addr()?;
    let node = node::Node::new(cfg, backend);
    let mut tasks = node.spawn_loops(SERVICE_VERSION);
    let app = http::router(node.clone());
    let mut stop = node.shutdown_signal();
    tasks.push(tokio::spawn(async move {
        let served = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = stop.changed().await;
        });
        if let Err(e) = served.await {
            tracing::error!(error = %e, "application API stopped");
        }
    }));
    tracing::info!(node = %node.cfg.node_id, %http_addr, "signal-node started");
    Ok(Running {
        node,
        http_addr,
        tasks,
    })
}
