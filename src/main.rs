// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

use base64::Engine as _;
use rand::RngCore;
use signal_node::config::Config;
use std::path::PathBuf;

const USAGE: &str = "usage: signal-node [--config <file>] | signal-node generate-key";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("generate-key") {
        // For the operator to store as storage.master_key; printed once.
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        println!("{}", base64::engine::general_purpose::STANDARD.encode(key));
        return Ok(());
    }
    let path = match args.as_slice() {
        [] => std::env::var("SIGNAL_NODE_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("signal-node.toml")),
        [flag, path] if flag == "--config" => PathBuf::from(path),
        _ => anyhow::bail!(USAGE),
    };

    let json = std::env::var("SIGNAL_NODE_LOG_FORMAT").as_deref() == Ok("json");
    let filter = tracing_subscriber::EnvFilter::try_from_env("SIGNAL_NODE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if json {
        tracing_subscriber::fmt().json().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let mut config = Config::load(&path)?;
    config.apply_env(|name| std::env::var(name).ok())?;
    let resolved = config.resolve()?;
    let backend = signal_node::store::Backend::connect(&resolved).await?;
    tracing::info!(driver = backend.name(), "storage ready");
    let running = signal_node::start(resolved, backend).await?;

    wait_for_stop().await;
    tracing::info!("stopping: releasing sessions");
    running.shutdown().await;
    Ok(())
}

async fn wait_for_stop() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
