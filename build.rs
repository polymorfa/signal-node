// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa (Softium LLC)

//! Compiles the runner contract with a pure-Rust protobuf compiler, so
//! building needs no `protoc` on the host.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/polymorfa/signal/v1/signal_service.proto";
    println!("cargo:rerun-if-changed={proto}");
    let descriptors = protox::compile([proto], ["proto"])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
