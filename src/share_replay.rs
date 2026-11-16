// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa (Softium LLC)

//! Sealed own-device key shares that survive a lost runner receive response.
//! No application plaintext is retained here. Entries share the decrypt
//! buffer's retention window, but do not depend on its private record format.

use std::sync::Arc;
use wacore::store::error::{Result, StoreError};
use wacore_recordstore::{Fence, Namespace, RecordStore, Sealer, WriteOp, is_record_exists};

const PREFIX: &str = "signal-node.app-state-share/";
const FORMAT: u8 = 1;

pub(crate) struct ShareReplay<R, S> {
    records: Arc<R>,
    sealer: Arc<S>,
    fence: Fence,
}

impl<R: RecordStore, S: Sealer> ShareReplay<R, S> {
    pub(crate) fn new(records: Arc<R>, sealer: Arc<S>, fence: Fence) -> Self {
        Self {
            records,
            sealer,
            fence,
        }
    }

    fn aad(&self, key: &str) -> Vec<u8> {
        let mut aad = b"signal-node/app-state-share/v1\0".to_vec();
        for part in [self.fence.scope.as_bytes(), key.as_bytes()] {
            aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
            aad.extend_from_slice(part);
        }
        aad
    }

    async fn open(&self, key: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        self.sealer
            .open(&self.aad(key), bytes)
            .await
            .map_err(|e| StoreError::Serialization(Box::new(e)))
    }

    fn inserted_ms(bytes: &[u8]) -> Result<u64> {
        if bytes.len() < 9 || bytes[0] != FORMAT {
            return Err(StoreError::Validation(
                "invalid app-state share replay record".into(),
            ));
        }
        Ok(u64::from_be_bytes(
            bytes[1..9].try_into().expect("checked length"),
        ))
    }

    pub(crate) async fn save(&self, receipt: &str, share: &[u8], now: u64) -> Result<()> {
        let key = format!("{PREFIX}{receipt}");
        let mut plain = Vec::with_capacity(9 + share.len());
        plain.push(FORMAT);
        plain.extend_from_slice(&now.to_be_bytes());
        plain.extend_from_slice(share);
        let sealed = self
            .sealer
            .seal(&self.aad(&key), &plain)
            .await
            .map_err(|e| StoreError::Serialization(Box::new(e)))?;
        match self
            .records
            .write(
                &self.fence,
                &[WriteOp::Insert {
                    ns: Namespace::Device,
                    key,
                    value: sealed,
                }],
            )
            .await
        {
            // Repeating receive must not extend the original retention window.
            Err(e) if is_record_exists(&e) => Ok(()),
            result => result,
        }
    }

    pub(crate) async fn load(&self, receipt: &str, cutoff: u64) -> Result<Vec<u8>> {
        let key = format!("{PREFIX}{receipt}");
        let Some(sealed) = self
            .records
            .get(&self.fence.scope, Namespace::Device, &key)
            .await?
        else {
            return Ok(Vec::new());
        };
        let plain = self.open(&key, &sealed).await?;
        if Self::inserted_ms(&plain)? < cutoff {
            return Ok(Vec::new());
        }
        Ok(plain[9..].to_vec())
    }

    pub(crate) async fn prune(&self, cutoff: u64) -> Result<usize> {
        let mut expired = Vec::new();
        for key in self
            .records
            .scan_keys(&self.fence.scope, Namespace::Device, PREFIX, None)
            .await?
        {
            let Some(sealed) = self
                .records
                .get(&self.fence.scope, Namespace::Device, &key)
                .await?
            else {
                continue;
            };
            let inserted = self
                .open(&key, &sealed)
                .await
                .and_then(|b| Self::inserted_ms(&b));
            // A corrupt entry cannot answer a retry; do not let it prevent
            // pruning later entries or retain unusable key material forever.
            if inserted.map_or(true, |time| time < cutoff) {
                expired.push(WriteOp::Delete {
                    ns: Namespace::Device,
                    key,
                });
            }
        }
        if !expired.is_empty() {
            self.records.write(&self.fence, &expired).await?;
        }
        Ok(expired.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_recordstore::{AesGcmSealer, LeaseStore, MemoryRecordStore};

    #[tokio::test]
    async fn replay_is_sealed_fenced_and_retains_the_original_expiry() {
        let records = Arc::new(MemoryRecordStore::new());
        let lease = records
            .acquire("scope", "first", 0, 100)
            .await
            .unwrap()
            .unwrap();
        let sealer = Arc::new(AesGcmSealer::new(&[7; 32]));
        let replay = ShareReplay::new(records.clone(), sealer.clone(), lease.fence.clone());
        let share = [9; 32];
        replay.save("receipt", &share, 10).await.unwrap();
        replay.save("receipt", &[8; 32], 20).await.unwrap();
        assert_eq!(replay.load("receipt", 10).await.unwrap(), share);
        assert!(replay.load("receipt", 11).await.unwrap().is_empty());
        let key = format!("{PREFIX}receipt");
        let sealed = records
            .get("scope", Namespace::Device, &key)
            .await
            .unwrap()
            .unwrap();
        assert!(!sealed.windows(share.len()).any(|b| b == share));
        records
            .write(
                &lease.fence,
                &[WriteOp::Put {
                    ns: Namespace::Device,
                    key: format!("{PREFIX}other"),
                    value: sealed,
                }],
            )
            .await
            .unwrap();
        assert!(
            replay.load("other", 0).await.is_err(),
            "moving a sealed share to another receipt must fail"
        );
        let next = records
            .acquire("scope", "second", 101, 100)
            .await
            .unwrap()
            .unwrap();
        assert!(replay.save("late", &share, 101).await.is_err());
        assert!(
            replay.prune(11).await.is_err(),
            "the old fence cannot delete shares"
        );
        let replacement = ShareReplay::new(records, sealer, next.fence);
        assert_eq!(replacement.load("receipt", 10).await.unwrap(), share);
        assert_eq!(replacement.prune(11).await.unwrap(), 2);
        assert!(replacement.load("receipt", 0).await.unwrap().is_empty());
    }
}
