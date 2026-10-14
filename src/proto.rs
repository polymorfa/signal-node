// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! Generated types for `polymorfa.signal.v1` plus small constructors.

#![allow(clippy::all, missing_docs)]

include!(concat!(env!("OUT_DIR"), "/polymorfa.signal.v1.rs"));

/// The contract version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// WebSocket subprotocol name.
pub const SUBPROTOCOL: &str = "polymorfa.signal.v1";

pub use error::Code;

impl Error {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code: code as i32,
            message: message.into(),
            decrypt_failure: DecryptFailure::Unspecified as i32,
        }
    }

    pub fn decrypt_failed(failure: DecryptFailure, message: impl Into<String>) -> Self {
        Self {
            code: Code::DecryptFailed as i32,
            message: message.into(),
            decrypt_failure: failure as i32,
        }
    }

    pub fn code_enum(&self) -> Code {
        Code::try_from(self.code).unwrap_or(Code::Unspecified)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code_enum().as_str_name(), self.message)
    }
}

impl std::error::Error for Error {}

impl Frame {
    pub fn with(id: u64, body: frame::Body) -> Self {
        Self {
            id,
            body: Some(body),
        }
    }
}
