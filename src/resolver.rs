// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! The [`SendContextResolver`] the stanza builder uses, answered by Polymorfa
//! over the link: device lists (`ResolveDevices`), prekey bundles
//! (`FetchPreKeys`) and group routing (`ResolveGroup`). Polymorfa keeps the
//! WhatsApp connection, so these lookups are the only way the node learns
//! who to encrypt for. Nothing here is cached; each send asks again.

use crate::link::{Link, LinkError};
use crate::proto::{self, runner_response, service_request};
use async_trait::async_trait;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use wacore::client::context::{GroupRoutingInfo, SendContextResolver};
use wacore::libsignal::protocol::PreKeyBundle;
use wacore::prekeys::PreKeyFetchOutcome;
use wacore::runtime::{AbortHandle, Runtime};
use wacore::types::message::AddressingMode;
use wacore_binary::Jid;
use wacore_signal_ops::RemoteBundle;

/// Tokio-backed [`Runtime`] for the stanza builder.
pub struct TokioRuntime;

type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

impl Runtime for TokioRuntime {
    fn spawn(&self, future: BoxFuture) -> AbortHandle {
        let task = tokio::spawn(future);
        AbortHandle::new(move || task.abort())
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn spawn_blocking(&self, f: Box<dyn FnOnce() + Send + 'static>) -> BoxFuture {
        Box::pin(async move {
            let _ = tokio::task::spawn_blocking(f).await;
        })
    }

    fn yield_now(&self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        Some(Box::pin(tokio::task::yield_now()))
    }
}

pub struct RemoteResolver {
    pub link: Arc<Link>,
    pub session_id: String,
    pub generation: u64,
}

fn parse_jids(jids: &[String]) -> anyhow::Result<Vec<Jid>> {
    jids.iter()
        .map(|j| {
            j.parse::<Jid>()
                .map_err(|_| anyhow::anyhow!("Polymorfa returned an invalid JID"))
        })
        .collect()
}

fn array<const N: usize>(bytes: &[u8], what: &str) -> anyhow::Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be {N} bytes"))
}

/// Contract bundle to the form `wacore-signal-ops` validates.
pub fn remote_bundle(bundle: &proto::Bundle) -> anyhow::Result<RemoteBundle> {
    Ok(RemoteBundle {
        registration_id: bundle.registration_id,
        device_id: bundle.device_id,
        identity_key: array(&bundle.identity_key, "identity_key")?,
        signed_prekey_id: bundle.signed_pre_key_id,
        signed_prekey: array(&bundle.signed_pre_key, "signed_pre_key")?,
        signed_prekey_signature: array(
            &bundle.signed_pre_key_signature,
            "signed_pre_key_signature",
        )?,
        prekey: match &bundle.pre_key {
            Some(pk) => Some((pk.id, array(&pk.public_key, "pre_key.public_key")?)),
            None => None,
        },
    })
}

impl RemoteResolver {
    async fn ask(&self, op: service_request::Op) -> anyhow::Result<runner_response::Result> {
        self.link
            .request(&self.session_id, self.generation, op)
            .await
            .map_err(|e: LinkError| anyhow::Error::new(e))
    }
}

#[async_trait]
impl SendContextResolver for RemoteResolver {
    async fn resolve_devices(&self, jids: &[Jid]) -> anyhow::Result<Vec<Jid>> {
        let op = service_request::Op::ResolveDevices(proto::ResolveDevices {
            jids: jids.iter().map(ToString::to_string).collect(),
        });
        match self.ask(op).await? {
            runner_response::Result::Devices(devices) => parse_jids(&devices.jids),
            _ => Err(LinkError::UnexpectedResponse.into()),
        }
    }

    async fn fetch_prekeys(&self, jids: &[Jid]) -> anyhow::Result<HashMap<Jid, PreKeyBundle>> {
        let op = service_request::Op::FetchPreKeys(proto::FetchPreKeys {
            jids: jids.iter().map(ToString::to_string).collect(),
        });
        let runner_response::Result::Bundles(bundles) = self.ask(op).await? else {
            return Err(LinkError::UnexpectedResponse.into());
        };
        let mut out = HashMap::with_capacity(bundles.bundles.len());
        for (jid, bundle) in &bundles.bundles {
            let jid: Jid = jid
                .parse()
                .map_err(|_| anyhow::anyhow!("Polymorfa returned an invalid JID"))?;
            let bundle = remote_bundle(bundle)?
                .to_prekey_bundle()
                .map_err(|_| anyhow::anyhow!("Polymorfa returned an invalid prekey bundle"))?;
            out.insert(jid, bundle);
        }
        Ok(out)
    }

    async fn fetch_prekeys_for_identity_check(
        &self,
        jids: &[Jid],
    ) -> anyhow::Result<PreKeyFetchOutcome> {
        Ok(PreKeyFetchOutcome {
            bundles: self.fetch_prekeys(jids).await?,
            rejected: Vec::new(),
        })
    }

    async fn resolve_group_routing_info(&self, jid: &Jid) -> anyhow::Result<Arc<GroupRoutingInfo>> {
        let op = service_request::Op::ResolveGroup(proto::ResolveGroup {
            jid: jid.to_string(),
        });
        let runner_response::Result::GroupRouting(routing) = self.ask(op).await? else {
            return Err(LinkError::UnexpectedResponse.into());
        };
        let mode = match routing.addressing_mode.as_str() {
            "lid" => AddressingMode::Lid,
            "pn" => AddressingMode::Pn,
            // The contract allows only pn or lid; never guess the address family.
            _ => anyhow::bail!("Polymorfa returned an unknown addressing mode"),
        };
        let participants = parse_jids(&routing.participants)?;
        let mut lid_to_pn = HashMap::with_capacity(routing.lid_to_pn.len());
        for (lid_user, pn) in &routing.lid_to_pn {
            let pn: Jid = pn
                .parse()
                .map_err(|_| anyhow::anyhow!("Polymorfa returned an invalid JID"))?;
            lid_to_pn.insert(lid_user.as_str().into(), pn);
        }
        Ok(Arc::new(GroupRoutingInfo::with_lid_to_pn_map(
            participants,
            mode,
            lid_to_pn,
        )))
    }
}
