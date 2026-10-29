// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa (Softium LLC)

//! Key custody for server mode.
//!
//! The operator supplies one 256-bit master key. Each session has its own
//! random 256-bit data key, stored in the session's records wrapped
//! (AES-256-GCM) by the master key. A node unwraps the data key once, when it
//! takes the session's lease, and seals every record with it from then on.
//! The master key never touches the database, and the data key is never
//! stored unwrapped.
//!
//! The wrapped data key lives in the session's `device` namespace under
//! [`DATA_KEY_RECORD`]. It is written with an exclusive, fenced insert, so
//! two nodes that race to initialise a session cannot both pick a key.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use wacore_recordstore::{Fence, Namespace, RecordStore, WriteOp, is_record_exists};

/// Record key of the wrapped data key, in [`Namespace::Device`]. The Signal
/// store uses only the key `local` in that namespace.
pub const DATA_KEY_RECORD: &str = "signal-node.data-key";

const WRAP_FORMAT_V1: u8 = 1;
const WRAP_DOMAIN: &[u8] = b"signal-node/data-key/v1";
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("the session's data key does not open with this master key")]
    WrongMasterKey,
    #[error("the session's wrapped data key is malformed")]
    Malformed,
    #[error("storage: {0}")]
    Store(#[from] wacore::store::error::StoreError),
}

/// The operator's master key. Holds the key only in memory.
pub struct MasterKey {
    cipher: Aes256Gcm,
}

impl MasterKey {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    fn aad(scope: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(WRAP_DOMAIN.len() + scope.len() + 8);
        for part in [WRAP_DOMAIN, scope.as_bytes()] {
            aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
            aad.extend_from_slice(part);
        }
        aad
    }

    /// `[format][nonce][ciphertext||tag]`, bound to `scope`.
    pub fn wrap(&self, scope: &str, data_key: &[u8; 32]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = Self::aad(scope);
        let sealed = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: data_key,
                    aad: &aad,
                },
            )
            .expect("AES-GCM encryption of 32 bytes cannot fail");
        let mut out = Vec::with_capacity(1 + NONCE_LEN + sealed.len());
        out.push(WRAP_FORMAT_V1);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        out
    }

    pub fn unwrap(&self, scope: &str, wrapped: &[u8]) -> Result<[u8; 32], KeyError> {
        let (&format, rest) = wrapped.split_first().ok_or(KeyError::Malformed)?;
        if format != WRAP_FORMAT_V1 || rest.len() < NONCE_LEN + 16 {
            return Err(KeyError::Malformed);
        }
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let aad = Self::aad(scope);
        let opened = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyError::WrongMasterKey)?;
        opened.try_into().map_err(|_| KeyError::Malformed)
    }

    /// The scope's data key, creating it on first use. Call once per lease.
    pub async fn data_key_for<R: RecordStore>(
        &self,
        records: &R,
        fence: &Fence,
    ) -> Result<[u8; 32], KeyError> {
        let scope = &*fence.scope;
        if let Some(wrapped) = records
            .get(scope, Namespace::Device, DATA_KEY_RECORD)
            .await?
        {
            return self.unwrap(scope, &wrapped);
        }
        let mut data_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data_key);
        let insert = WriteOp::Insert {
            ns: Namespace::Device,
            key: DATA_KEY_RECORD.to_owned(),
            value: self.wrap(scope, &data_key),
        };
        match records.write(fence, &[insert]).await {
            Ok(()) => Ok(data_key),
            // Another holder initialised it between our read and write.
            Err(e) if is_record_exists(&e) => {
                let wrapped = records
                    .get(scope, Namespace::Device, DATA_KEY_RECORD)
                    .await?
                    .ok_or(KeyError::Malformed)?;
                self.unwrap(scope, &wrapped)
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_recordstore::{LeaseStore, MemoryRecordStore};

    #[test]
    fn a_wrapped_key_opens_only_for_its_scope_and_master_key() {
        let master = MasterKey::new(&[1; 32]);
        let wrapped = master.wrap("sess-a", &[7; 32]);
        assert_eq!(master.unwrap("sess-a", &wrapped).unwrap(), [7; 32]);
        assert!(matches!(
            master.unwrap("sess-b", &wrapped),
            Err(KeyError::WrongMasterKey)
        ));
        assert!(matches!(
            MasterKey::new(&[2; 32]).unwrap("sess-a", &wrapped),
            Err(KeyError::WrongMasterKey)
        ));
        assert!(matches!(
            master.unwrap("sess-a", &[1, 2, 3]),
            Err(KeyError::Malformed)
        ));
    }

    #[tokio::test]
    async fn the_data_key_is_created_once_and_stays_the_same() {
        let records = MemoryRecordStore::new();
        let master = MasterKey::new(&[1; 32]);
        let lease = records.acquire("s", "a", 0, 10_000).await.unwrap().unwrap();
        let first = master.data_key_for(&records, &lease.fence).await.unwrap();
        let again = master.data_key_for(&records, &lease.fence).await.unwrap();
        assert_eq!(first, again);
        let raw = records
            .get("s", Namespace::Device, DATA_KEY_RECORD)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !raw.windows(32).any(|w| w == first),
            "the data key was stored unwrapped"
        );
        // A later holder of the scope opens the same key.
        let next = records
            .acquire("s", "b", 20_000, 10_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            master.data_key_for(&records, &next.fence).await.unwrap(),
            first
        );
    }
}
