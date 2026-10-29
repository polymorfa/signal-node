// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa (Softium LLC)

//! Serving `RunnerRequest` operations with `wacore-signal-ops`.
//!
//! Nothing returned here carries plaintext, with the contract's one
//! exception: an explicitly enabled app-state key share from an own device.
//! Error messages name the failure, never content or key material.

use crate::message::{self, Event};
use crate::node::{ActiveSession, Node};
use crate::proto::{
    self, Code, DecryptFailure, Identity, MigrateResult, PreKey, PreKeyCount, PreKeyUploadBatch,
    PreKeys, ReceiveResult, ServiceResponse, SignedPairing, Stanza, runner_request::Op,
    service_response::Result as Out,
};
use crate::resolver::{RemoteResolver, remote_bundle};
use std::sync::Arc;
use wacore::libsignal::protocol::SignalProtocolError;
use wacore::types::jid::JidExt as _;
use wacore::types::message::AddressingMode;
use wacore_binary::Jid;
use wacore_signal_ops::{
    OpsError, ReceiveKind, ReceiveRequest, Received, RetryRequest, RetryRoute,
};
use waproto::whatsapp as wa;

fn respond(result: Out) -> Result<ServiceResponse, proto::Error> {
    Ok(ServiceResponse {
        result: Some(result),
    })
}

fn invalid(message: impl Into<String>) -> proto::Error {
    proto::Error::new(Code::InvalidArgument, message)
}

fn jid(value: &str, field: &str) -> Result<Jid, proto::Error> {
    value
        .parse()
        .map_err(|_| invalid(format!("{field} is not a valid JID")))
}

pub async fn handle(
    node: &Node,
    session: &Arc<ActiveSession>,
    op: Op,
) -> Result<ServiceResponse, proto::Error> {
    if let Op::GetIdentity(_) = op {
        let ops = session
            .ops_or_create()
            .await
            .map_err(|e| node.ops_error(session, &e))?;
        let identity = ops.public_identity().await;
        return respond(Out::Identity(Identity {
            registration_id: identity.registration_id,
            identity_key: identity.identity_key.to_vec(),
            signed_pre_key_id: identity.signed_prekey.id,
            signed_pre_key: identity.signed_prekey.public_key.to_vec(),
            signed_pre_key_signature: identity.signed_prekey.signature.to_vec(),
            adv_secret: identity.adv_secret.to_vec(),
        }));
    }
    let Some(ops) = session.ops() else {
        return Err(proto::Error::new(
            Code::SessionUnavailable,
            "device keys do not exist yet; GetIdentity creates them",
        ));
    };
    let fail = |e: OpsError| node.ops_error(session, &e);
    match op {
        Op::GetIdentity(_) => unreachable!("handled above"),
        Op::Receive(receive) => self::receive(node, session, &ops, receive).await,
        Op::GeneratePreKeys(request) => {
            let keys = ops.generate_prekeys(request.count).await.map_err(fail)?;
            respond(Out::PreKeys(PreKeys {
                pre_keys: keys
                    .into_iter()
                    .map(|k| PreKey {
                        id: k.id,
                        public_key: k.public_key.to_vec(),
                    })
                    .collect(),
            }))
        }
        Op::MarkPreKeysUploaded(request) => {
            ops.mark_prekeys_uploaded(&request.ids)
                .await
                .map_err(fail)?;
            respond(Out::Ok(proto::Ok {}))
        }
        Op::PreparePreKeyUpload(request) => {
            let batch = ops
                .prepare_prekey_upload(request.count)
                .await
                .map_err(fail)?;
            respond(Out::PreKeyUploadBatch(PreKeyUploadBatch {
                batch_id: batch.batch_id,
                pre_keys: batch
                    .pre_keys
                    .into_iter()
                    .map(|key| PreKey {
                        id: key.id,
                        public_key: key.public_key.to_vec(),
                    })
                    .collect(),
            }))
        }
        Op::AcknowledgePreKeyUpload(request) => {
            ops.acknowledge_prekey_upload(&request.batch_id, &request.ids)
                .await
                .map_err(fail)?;
            respond(Out::Ok(proto::Ok {}))
        }
        Op::UploadedPreKeyCount(_) => {
            let count = uploaded_prekey_count(node, session).await?;
            respond(Out::PreKeyCount(PreKeyCount { count }))
        }
        Op::SignPairing(request) => {
            let signed = ops
                .sign_pairing(&request.device_identity_container)
                .await
                .map_err(fail)?;
            respond(Out::SignedPairing(SignedPairing {
                signed_device_identity: signed.signed_identity,
            }))
        }
        Op::SetOwnJids(request) => {
            jid(&request.pn, "pn")?;
            let lid = Some(request.lid.as_str()).filter(|l| !l.is_empty());
            ops.set_own_jids(&request.pn, lid).await.map_err(fail)?;
            respond(Out::Ok(proto::Ok {}))
        }
        Op::Resend(request) => {
            let Some(link) = node.link() else {
                return Err(proto::Error::new(Code::Unavailable, "not connected"));
            };
            let chat = jid(&request.chat, "chat")?;
            let requester = jid(&request.requester, "requester")?;
            let encryption_jid = if request.encryption_jid.is_empty() {
                requester.clone()
            } else {
                jid(&request.encryption_jid, "encryption_jid")?
            };
            let route = if request.is_group {
                RetryRoute::Group {
                    addressing_mode: match request.addressing_mode.as_str() {
                        "lid" => AddressingMode::Lid,
                        "pn" => AddressingMode::Pn,
                        _ => return Err(invalid("group addressing_mode must be pn or lid")),
                    },
                }
            } else if request.is_broadcast {
                RetryRoute::BroadcastList
            } else {
                RetryRoute::Direct {
                    recipient: if request.recipient.is_empty() {
                        None
                    } else {
                        Some(jid(&request.recipient, "recipient")?)
                    },
                }
            };
            let bundle = match &request.bundle {
                Some(b) => Some(remote_bundle(b).map_err(|e| invalid(e.to_string()))?),
                None => None,
            };
            let resolver = RemoteResolver {
                link,
                session_id: session.id.clone(),
                generation: session.generation,
            };
            let node_bytes = ops
                .resend(
                    &resolver,
                    RetryRequest {
                        chat: &chat,
                        message_id: &request.message_id,
                        requester: &requester,
                        encryption_jid: &encryption_jid,
                        route,
                        retry_count: u8::try_from(request.retry_count).unwrap_or(u8::MAX),
                        bundle: bundle.as_ref(),
                    },
                )
                .await
                .map_err(fail)?;
            respond(Out::Stanza(Stanza { node: node_bytes }))
        }
        Op::ForgetIdentity(request) => {
            let user = jid(&request.user, "user")?;
            ops.forget_user(&user).await.map_err(fail)?;
            respond(Out::Ok(proto::Ok {}))
        }
        Op::MigratePnToLid(request) => {
            let pn = jid(&request.pn, "pn")?;
            let lid = jid(&request.lid, "lid")?;
            let moved = ops.migrate_pn_to_lid(&pn, &lid).await.map_err(fail)?;
            respond(Out::Migrate(MigrateResult {
                moved: u32::try_from(moved).unwrap_or(u32::MAX),
            }))
        }
    }
}

/// Map a receive failure to the contract's decrypt failures.
pub fn receive_error(node: &Node, session: &ActiveSession, error: &OpsError) -> proto::Error {
    if error.is_fence_lost() {
        return node.ops_error(session, error);
    }
    match error {
        OpsError::Store(_) | OpsError::Signal(SignalProtocolError::BackendError(..)) => {
            proto::Error::new(Code::Unavailable, "storage is unavailable")
        }
        OpsError::Signal(SignalProtocolError::DuplicatedMessage(..)) => {
            proto::Error::decrypt_failed(DecryptFailure::OldCounter, "message counter already used")
        }
        OpsError::Signal(
            SignalProtocolError::NoSenderKeyState(_) | SignalProtocolError::InvalidSenderKeySession,
        ) => proto::Error::decrypt_failed(
            DecryptFailure::NoSenderKey,
            "no sender key for this sender",
        ),
        OpsError::InvalidInput(message) if message.starts_with("plaintext did not decode") => {
            proto::Error::decrypt_failed(
                DecryptFailure::Undecodable,
                "decrypted payload is not a message",
            )
        }
        OpsError::NotInitialised => node.ops_error(session, error),
        _ => proto::Error::decrypt_failed(DecryptFailure::Unspecified, "decryption failed"),
    }
}

async fn receive(
    node: &Node,
    session: &Arc<ActiveSession>,
    ops: &crate::node::Ops,
    receive: proto::Receive,
) -> Result<ServiceResponse, proto::Error> {
    let sender = jid(&receive.sender, "sender")?;
    let address = sender.to_protocol_address();
    let kind = match receive.kind.as_str() {
        "pkmsg" => ReceiveKind::PreKey,
        "msg" => ReceiveKind::Message,
        "skmsg" => ReceiveKind::SenderKey,
        _ => return Err(invalid("kind must be pkmsg, msg or skmsg")),
    };
    let padding_version = u8::try_from(receive.padding_version)
        .map_err(|_| invalid("padding_version out of range"))?;
    let received = ops
        .receive(ReceiveRequest {
            chat: &receive.chat,
            sender: &address,
            kind,
            ciphertext: &receive.ciphertext,
            padding_version,
            is_from_me: receive.is_from_me,
        })
        .await
        .map_err(|e| {
            let error = receive_error(node, session, &e);
            tracing::info!(
                session = %session.id,
                message_id = %receive.message_id,
                kind = %receive.kind,
                code = error.code_enum().as_str_name(),
                "receive failed"
            );
            error
        })?;
    let message = match received {
        Received::AlreadyDelivered { .. } => {
            return respond(Out::Receive(ReceiveResult {
                already_delivered: true,
                ..Default::default()
            }));
        }
        Received::Message(message) => message,
    };

    // Explicit operator consent in addition to the pinned core own-device gate.
    let app_state_key_share = if node.cfg.share_app_state_keys && receive.is_from_me {
        message
            .app_state_key_share
            .as_ref()
            .map(message::encode)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    if let Some(event) = event_for(node, session, &receive, &message) {
        let kind = event.kind;
        if let Err(e) = node.delivery.deliver(event).await {
            tracing::info!(
                session = %session.id,
                message_id = %receive.message_id,
                error = %e,
                "delivery not acknowledged; the message stays sealed in the buffer for redelivery"
            );
            return Err(proto::Error::new(Code::Unavailable, e.to_string()));
        }
        tracing::debug!(session = %session.id, message_id = %receive.message_id, kind, "delivered");
    }
    if !session.can_serve().await {
        return Err(proto::Error::new(
            Code::NotLeaseHolder,
            "the lease expired before delivery was recorded",
        ));
    }
    ops.mark_delivered(&message.receipt_key)
        .await
        .map_err(|e| node.ops_error(session, &e))?;
    respond(Out::Receive(ReceiveResult {
        already_delivered: false,
        redelivered: message.redelivered,
        sender_key_rejected: message.sender_key_rejected,
        app_state_key_share,
    }))
}

/// The application event for a received message, or `None` when the
/// message is protocol-only (sender keys, app-state keys, peer data
/// operations) or is history and history delivery is off.
fn event_for(
    node: &Node,
    session: &ActiveSession,
    receive: &proto::Receive,
    received: &wacore_signal_ops::ReceivedMessage,
) -> Option<Event> {
    let content = &received.content;
    if content.is_skdm_only {
        return None;
    }
    let base = |kind: &'static str| Event {
        id: received.receipt_key.clone(),
        kind,
        session_id: session.id.clone(),
        chat: receive.chat.clone(),
        sender: receive.sender.clone(),
        sender_alt: Some(receive.sender_alt.clone()).filter(|s| !s.is_empty()),
        message_id: receive.message_id.clone(),
        timestamp: receive.timestamp,
        is_from_me: receive.is_from_me,
        redelivered: received.redelivered,
        identity_changed: received.identity_changed,
        text: None,
        media: None,
        history: None,
        message_proto: String::new(),
    };
    // Protocol fields are independent of ordinary fields in waE2E.Message.
    // Preserve mixed-message content while removing protocol keys/descriptors
    // from its application protobuf (including history when consent is off).
    let mut app_message = content.message.clone();
    app_message.protocol_message = Default::default();
    app_message.sender_key_distribution_message = Default::default();
    // Context accompanies content; by itself it is not an application event.
    // Clear only the probe so mixed-message output retains its context.
    let mut content_probe = app_message.clone();
    content_probe.message_context_info = Default::default();
    let has_app_content = !message::encode(&content_probe).is_empty();
    let has_protocol_request =
        content
            .message
            .protocol_message
            .as_option()
            .is_some_and(|protocol| {
                protocol.app_state_sync_key_request.is_set()
                    || protocol.peer_data_operation_request_message.is_set()
                    || matches!(protocol.r#type, Some(wa::message::protocol_message::Type::AppStateSyncKeyShare | wa::message::protocol_message::Type::AppStateSyncKeyRequest | wa::message::protocol_message::Type::PeerDataOperationRequestMessage | wa::message::protocol_message::Type::PeerDataOperationRequestResponseMessage))
            });
    if has_protocol_request && !has_app_content {
        return None;
    }
    if let Some(protocol) = &content.protocol_message {
        if let Some(history) = &protocol.history_sync_notification
            && !has_app_content
        {
            // History comes only from this account's own devices.
            if !node.cfg.deliver_history || !receive.is_from_me {
                tracing::debug!(session = %session.id, "history notification not delivered (history delivery is off)");
                return None;
            }
            return Some(Event {
                history: Some(message::history_descriptor(history)),
                ..base("history.sync")
            });
        }
        if !has_app_content
            && (protocol.app_state_sync_key_share.is_some()
                || protocol.peer_data_operation_request_response.is_some())
        {
            return None;
        }
    }
    let wa_message = if has_app_content {
        &app_message
    } else {
        &content.message
    };
    Some(Event {
        text: message::text_of(wa_message),
        media: message::media_of(wa_message),
        message_proto: base64_of(&message::encode(wa_message)),
        history: content
            .protocol_message
            .as_ref()
            .and_then(|p| p.history_sync_notification.as_ref())
            .filter(|_| node.cfg.deliver_history && receive.is_from_me)
            .map(message::history_descriptor),
        ..base("message")
    })
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Surviving uploaded keys in customer-local state, not a provider pool count.
pub async fn uploaded_prekey_count(
    node: &Node,
    session: &ActiveSession,
) -> Result<u32, proto::Error> {
    session
        .uploaded_prekey_count()
        .await
        .map_err(|error| node.ops_error(session, &error))
}
