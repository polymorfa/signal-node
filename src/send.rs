// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! Sending a message the application handed to the node.
//!
//! The node builds the encrypted stanza itself (device lists, prekeys and
//! group routing come from Polymorfa through [`RemoteResolver`]), then asks
//! Polymorfa to transmit it with `SendStanza`. Every `SendStanza`, including
//! a resend, first waits for the per-session ceiling.
//!
//! When the server reports a participant-hash mismatch, the device list
//! changed while the message was in flight. WhatsApp Web then refreshes the
//! device list or group and resends the same message ID
//! (`WAWebSendUserMsgJob.js:53-79`, `WAWebSendGroupSkmsgJob.js:194-213`,
//! Cellar bundle `whatsapp-1049950004`). The node rebuilds once with fresh
//! lookups and the same ID. WA Web excludes previously addressed devices;
//! this implementation re-encrypts for every current device. Provider
//! acceptance of that broader resend remains an integration gate.

use crate::link::LinkError;
use crate::message::{self, BuildError, SendRequest};
use crate::node::{ActiveSession, Node};
use crate::proto::{self, Code, SendStanza, runner_response, service_request};
use crate::resolver::{RemoteResolver, TokioRuntime};
use serde::Serialize;
use std::sync::Arc;
use wacore_binary::{Jid, JidExt as _};
use wacore_signal_ops::OpsError;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SendOutcome {
    pub message_id: String,
    pub server_timestamp: i64,
    /// The stanza was sent a second time after a device-list change.
    pub resent: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("{0}")]
    Invalid(String),
    #[error("this node does not hold the session")]
    NotLeaseHolder,
    #[error("the session is not paired yet")]
    NotPaired,
    #[error("not connected to Polymorfa")]
    Disconnected,
    #[error("send outcome is unconfirmed; do not automatically resend")]
    Unconfirmed { message_id: String },
    #[error("Polymorfa refused the send: {0}")]
    Refused(proto::Error),
    #[error("send ceiling reached")]
    RateLimited,
    #[error("session storage is unavailable")]
    StorageUnavailable,
    #[error("building the stanza failed")]
    Build,
}

impl From<BuildError> for SendError {
    fn from(e: BuildError) -> Self {
        SendError::Invalid(e.to_string())
    }
}

enum Built {
    Direct {
        stanza: Vec<u8>,
        phash: Option<String>,
    },
    Group {
        stanza: Vec<u8>,
        phash: Option<String>,
        targets: Vec<Jid>,
    },
}

fn ops_failure(node: &Node, session: &ActiveSession, error: &OpsError) -> SendError {
    if error.is_fence_lost() {
        node.ops_error(session, error);
        return SendError::NotLeaseHolder;
    }
    match error {
        OpsError::InvalidInput(m) if m.contains("not paired") || m.contains("own JID") => {
            SendError::NotPaired
        }
        OpsError::InvalidInput(m) => SendError::Invalid(m.clone()),
        // A storage outage is retryable; it is not a stanza construction failure.
        OpsError::Store(_) => SendError::StorageUnavailable,
        _ => SendError::Build,
    }
}

pub async fn send(
    node: &Node,
    session: &Arc<ActiveSession>,
    request: SendRequest,
) -> Result<SendOutcome, SendError> {
    let to: Jid = request
        .to
        .parse()
        .map_err(|_| SendError::Invalid("to is not a valid JID".into()))?;
    let now = crate::delivery::now_secs();
    let message = message::build_message(&request, now)?;
    let ops = session.ops().ok_or(SendError::NotPaired)?;
    let own = session.view().pn.and_then(|pn| pn.parse::<Jid>().ok());
    let message_id =
        wacore::request::RequestUtils::message_id_at(own.as_ref(), u64::try_from(now).unwrap_or(0));

    let mut resent = false;
    let outcome = async {
        loop {
            let link = node.link().ok_or(SendError::Disconnected)?;
            if !session.can_serve().await || !session.is_claimed() {
                return Err(SendError::NotLeaseHolder);
            }
            let resolver = RemoteResolver {
                link: link.clone(),
                session_id: session.id.clone(),
                generation: session.generation,
            };
            let built = if to.is_group() {
                let prepared = ops
                    .send_group(&TokioRuntime, &resolver, &to, &message, &message_id)
                    .await
                    .map_err(|e| ops_failure(node, session, &e))?;
                Built::Group {
                    stanza: prepared.stanza,
                    phash: prepared.phash,
                    targets: prepared.distribution_targets,
                }
            } else {
                let prepared = ops
                    .send_direct(&TokioRuntime, &resolver, &to, &message, &message_id)
                    .await
                    .map_err(|e| ops_failure(node, session, &e))?;
                Built::Direct {
                    stanza: prepared.stanza,
                    phash: prepared.phash,
                }
            };
            let (stanza, phash) = match &built {
                Built::Direct { stanza, phash } | Built::Group { stanza, phash, .. } => {
                    (stanza.clone(), phash.clone().unwrap_or_default())
                }
            };

            session.limiter.acquire(link.max_sends_per_second()).await;
            if !session.can_serve().await || !session.is_claimed() {
                return Err(SendError::NotLeaseHolder);
            }
            let op = service_request::Op::SendStanza(SendStanza {
                node: stanza,
                phash,
            });
            let result = match link.request(&session.id, session.generation, op).await {
                Ok(runner_response::Result::Send(result)) => result,
                Ok(_) => {
                    return Err(SendError::Unconfirmed {
                        message_id: message_id.clone(),
                    });
                }
                Err(LinkError::Remote(error)) => {
                    return Err(match error.code_enum() {
                        Code::RateLimited => SendError::RateLimited,
                        Code::NotLeaseHolder => {
                            node.refused_generation(
                                session,
                                "Polymorfa refused a send at this generation",
                            )
                            .await;
                            SendError::NotLeaseHolder
                        }
                        _ => SendError::Refused(error),
                    });
                }
                Err(LinkError::Disconnected) => return Err(SendError::Disconnected),
                Err(LinkError::Timeout | LinkError::ResponseLost | LinkError::UnexpectedResponse) => {
                    return Err(SendError::Unconfirmed {
                        message_id: message_id.clone(),
                    });
                }
            };

            // WA Web marks the sender key as held once the server acks, before
            // it looks at the participant hash (WAWebSendGroupSkmsgJob.js:188-205,
            // Cellar bundle whatsapp-1051710191).
            if let Built::Group { targets, .. } = &built
                && !targets.is_empty()
                && let Err(e) = ops.mark_sender_key_distributed(&to, targets).await
            {
                // The runner has already confirmed the send. A failed local
                // distribution mark must not invite a new message ID. Only fence
                // loss stops the same-ID mismatch resend and retires this session.
                node.ops_error(session, &e);
                tracing::warn!(session = %session.id, message_id = %message_id, "send accepted; sender-key distribution was not recorded");
                if e.is_fence_lost() {
                    return Ok(SendOutcome {
                        message_id: message_id.clone(),
                        server_timestamp: result.server_timestamp,
                        resent,
                    });
                }
            }
            tracing::info!(session = %session.id, message_id = %message_id, resent, "sent");
            if result.participant_hash_mismatch && !resent {
                tracing::info!(session = %session.id, message_id = %message_id, "device list changed; resending once");
                resent = true;
                continue;
            }
            return Ok(SendOutcome {
                message_id: message_id.clone(),
                server_timestamp: result.server_timestamp,
                resent,
            });
        }
    }
    .await;
    // A mismatch ACK may already represent delivery to some participants.
    // Any later failure belongs to this message, even if the resend was never
    // built or queued. Ordinary retryable errors would invite a fresh ID.
    outcome.map_err(|error| {
        if resent {
            SendError::Unconfirmed { message_id }
        } else {
            error
        }
    })
}
