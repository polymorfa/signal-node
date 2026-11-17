// SPDX-License-Identifier: MIT

use wacore::libsignal::protocol::SignalProtocolError;
use wacore::store::error::StoreError;

#[derive(Debug, thiserror::Error)]
#[error("a Signal operation was interrupted; acquire a new fenced instance")]
struct InterruptedOperation;

pub(crate) fn interrupted_operation() -> OpsError {
    StoreError::Database(Box::new(InterruptedOperation)).into()
}

fn state_is_refused(error: &StoreError) -> bool {
    wacore_recordstore::is_fence_lost(error)
        || matches!(error, StoreError::Database(source) if source.is::<InterruptedOperation>())
}

#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    #[error("signal protocol error")]
    Signal(#[from] SignalProtocolError),
    #[error("store error")]
    Store(#[from] StoreError),
    /// The caller sent something this operation cannot accept.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Pairing was refused. `code` and `text` are the values WhatsApp Web
    /// answers the server with for the same failure.
    #[error("pairing refused: {code} {text}")]
    Pairing { code: u16, text: &'static str },
    /// Building an outbound stanza failed, including resolver (device list,
    /// prekey fetch) failures reported by the WhatsApp client.
    #[error("send failed: {0}")]
    Send(String),
    /// A peer's prekey bundle did not verify against its pinned account
    /// identity; see [`crate::BundleRejection`].
    #[error("prekey bundle refused: {0}")]
    BundleRefused(crate::trust::BundleRejection),
    /// The scope has no device keys yet; call `SignalOps::create`.
    #[error("device keys are not initialised for this scope")]
    NotInitialised,
}

impl OpsError {
    /// The state must no longer be served: its lease moved, or cancellation
    /// left a write with uncertain completion. Release the lease and open a
    /// new instance at a higher fence before resuming operations.
    pub fn is_fence_lost(&self) -> bool {
        match self {
            OpsError::Store(e) => state_is_refused(e),
            OpsError::Signal(error) => signal_state_is_refused(error),
            _ => false,
        }
    }
}

fn signal_state_is_refused(error: &SignalProtocolError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if current
            .downcast_ref::<StoreError>()
            .is_some_and(state_is_refused)
        {
            return true;
        }
        source = current.source();
    }
    false
}
