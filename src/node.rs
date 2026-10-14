// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! The node: which sessions it holds, its link to Polymorfa, and the loops
//! that keep both current.
//!
//! Every configured session is tried on each lease tick. A node serves a
//! session only while it holds the session's lease in the shared store.
//! Holding the lease, it claims the session from Polymorfa at that lease's
//! generation; Polymorfa routes to the highest generation it accepted. If
//! the node stops renewing (crash, partition), the lease expires and another
//! node takes it at a higher generation. Any write the old node still
//! attempts carries the old generation and the store refuses it.

use crate::config::Resolved;
use crate::delivery::{Delivery, Webhook};
use crate::keys::MasterKey;
use crate::link::{self, Handler, Link, LinkError, LinkSettings};
use crate::proto::{
    self, ClaimSession, Code, ReleaseSession, RunnerRequest, ServiceResponse, SessionEvent,
    runner_response, service_request, session_event::State,
};
use crate::ratelimit::SendLimiter;
use crate::store::Backend;
use async_trait::async_trait;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::{Mutex, OnceCell, watch};
use tokio::task::JoinHandle;
use wacore_recordstore::{AesGcmSealer, Lease, LeaseStore, RecordSignalStore};
use wacore_signal_ops::{OpsError, SignalOps};

pub type Store = RecordSignalStore<Backend, AesGcmSealer>;
pub type Ops = SignalOps<Store>;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// What the application sees about a session on this node.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SessionView {
    pub state: String,
    pub pn: Option<String>,
    pub lid: Option<String>,
}

fn state_name(state: i32) -> String {
    State::try_from(state)
        .unwrap_or(State::Unspecified)
        .as_str_name()
        .trim_start_matches("STATE_")
        .to_ascii_lowercase()
}

/// A session this node holds the lease for.
pub struct ActiveSession {
    pub id: String,
    pub generation: u64,
    lease: Mutex<Lease>,
    store: Arc<Store>,
    pub(crate) sealer: Arc<AesGcmSealer>,
    ops: OnceCell<Arc<Ops>>,
    claimed: AtomicBool,
    claiming: AtomicBool,
    lost: AtomicBool,
    pub limiter: SendLimiter,
    view: RwLock<SessionView>,
}

impl ActiveSession {
    /// The Signal operations, if the device keys exist.
    pub fn ops(&self) -> Option<Arc<Ops>> {
        self.ops.get().cloned()
    }

    /// The Signal operations, creating the device keys on first use.
    pub async fn ops_or_create(&self) -> Result<Arc<Ops>, OpsError> {
        self.ops
            .get_or_try_init(|| async {
                match SignalOps::create(self.store.clone()).await {
                    Ok(ops) => Ok(Arc::new(ops)),
                    // Created by an earlier holder after this lease opened.
                    Err(OpsError::InvalidInput(_)) => {
                        Ok(Arc::new(SignalOps::open(self.store.clone()).await?))
                    }
                    Err(e) => Err(e),
                }
            })
            .await
            .cloned()
    }

    pub fn is_claimed(&self) -> bool {
        self.claimed.load(Ordering::SeqCst)
    }

    pub fn is_lost(&self) -> bool {
        self.lost.load(Ordering::SeqCst)
    }

    /// Fail closed when a paused process resumes beyond its lease deadline.
    pub async fn can_serve(&self) -> bool {
        !self.is_lost() && now_ms() < self.lease.lock().await.expires_at_ms
    }

    pub fn view(&self) -> SessionView {
        self.view.read().expect("view lock").clone()
    }

    fn set_view(&self, state: i32, pn: &str, lid: &str) {
        let mut view = self.view.write().expect("view lock");
        view.state = state_name(state);
        if !pn.is_empty() {
            view.pn = Some(pn.to_owned());
        }
        if !lid.is_empty() {
            view.lid = Some(lid.to_owned());
        }
    }

    pub async fn lease(&self) -> Lease {
        self.lease.lock().await.clone()
    }
}

pub struct Node {
    me: std::sync::Weak<Node>,
    pub cfg: Arc<Resolved>,
    backend: Arc<Backend>,
    master: MasterKey,
    /// Unique process incarnation; stable diagnostic node IDs cannot share a fence.
    lease_holder: String,
    sessions: RwLock<HashMap<String, Arc<ActiveSession>>>,
    /// Sessions Polymorfa reported logged out; not taken again until restart.
    retired: RwLock<HashSet<String>>,
    link: RwLock<Option<Arc<Link>>>,
    pub delivery: Delivery,
    shutdown: watch::Sender<bool>,
}

impl Node {
    pub fn new(cfg: Resolved, backend: Backend) -> Arc<Self> {
        let webhook = cfg.webhook_url.clone().map(|url| Webhook {
            url,
            secret: cfg.webhook_secret.clone(),
        });
        let delivery = Delivery::new(webhook, cfg.sse, cfg.ack_timeout);
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            master: MasterKey::new(&cfg.master_key),
            lease_holder: format!(
                "{}:{}",
                cfg.node_id,
                hex::encode(rand::random::<[u8; 16]>())
            ),
            cfg: Arc::new(cfg),
            backend: Arc::new(backend),
            sessions: RwLock::new(HashMap::new()),
            retired: RwLock::new(HashSet::new()),
            link: RwLock::new(None),
            delivery,
            shutdown: watch::channel(false).0,
        })
    }

    pub fn backend(&self) -> &Arc<Backend> {
        &self.backend
    }

    pub fn session(&self, id: &str) -> Option<Arc<ActiveSession>> {
        self.sessions
            .read()
            .expect("sessions lock")
            .get(id)
            .cloned()
    }

    pub fn sessions(&self) -> Vec<Arc<ActiveSession>> {
        let mut all: Vec<_> = self
            .sessions
            .read()
            .expect("sessions lock")
            .values()
            .cloned()
            .collect();
        all.sort_by(|a, b| a.id.cmp(&b.id));
        all
    }

    pub fn is_configured(&self, id: &str) -> bool {
        self.cfg.sessions.iter().any(|s| s == id)
    }

    pub fn link(&self) -> Option<Arc<Link>> {
        self.link
            .read()
            .expect("link lock")
            .clone()
            .filter(|l| !l.is_closed())
    }

    pub fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    /// Stop serving `id` because another node owns it now. The lease is not
    /// released: it is no longer ours.
    pub fn lose(&self, id: &str, generation: u64, why: &str) {
        let removed = {
            let mut sessions = self.sessions.write().expect("sessions lock");
            if sessions.get(id).is_none_or(|s| s.generation != generation) {
                return;
            }
            sessions.remove(id)
        };
        if let Some(session) = removed {
            session.lost.store(true, Ordering::SeqCst);
            tracing::warn!(
                session = id,
                generation = session.generation,
                reason = why,
                "stopped serving session"
            );
        }
    }

    /// Give a session up voluntarily: tell Polymorfa, then release the lease
    /// so another node can take it at once.
    pub async fn release(&self, id: &str) {
        let removed = self.sessions.write().expect("sessions lock").remove(id);
        let Some(session) = removed else { return };
        session.lost.store(true, Ordering::SeqCst);
        if let Some(link) = self.link()
            && session.is_claimed()
        {
            let op = service_request::Op::ReleaseSession(ReleaseSession {});
            if let Err(e) = link.request(id, session.generation, op).await {
                tracing::debug!(session = id, error = %e, "ReleaseSession was not acknowledged");
            }
        }
        let lease = session.lease().await;
        if let Err(e) = self.backend.release(&lease).await {
            tracing::warn!(session = id, error = %e, "could not release the lease; it will expire");
        }
        tracing::info!(
            session = id,
            generation = session.generation,
            "released session"
        );
    }

    /// Map an operation error to a contract error, dropping the session if
    /// the store says another node took it.
    pub fn ops_error(&self, session: &ActiveSession, error: &OpsError) -> proto::Error {
        if error.is_fence_lost() {
            self.lose(
                &session.id,
                session.generation,
                "store refused a write: lease moved to another node",
            );
            return proto::Error::new(
                Code::NotLeaseHolder,
                "this node no longer holds the session",
            );
        }
        match error {
            OpsError::Store(_) => proto::Error::new(Code::Unavailable, "storage is unavailable"),
            OpsError::InvalidInput(message) => {
                proto::Error::new(Code::InvalidArgument, message.clone())
            }
            OpsError::NotInitialised => proto::Error::new(
                Code::SessionUnavailable,
                "device keys do not exist yet; GetIdentity creates them",
            ),
            OpsError::Pairing { code, text } => proto::Error::new(
                Code::InvalidArgument,
                format!("pairing refused: {code} {text}"),
            ),
            OpsError::Send(_) => proto::Error::new(Code::Unavailable, "building the stanza failed"),
            OpsError::Signal(_) => proto::Error::new(Code::Internal, "signal protocol error"),
        }
    }

    async fn activate(&self, lease: Lease) -> anyhow::Result<Arc<ActiveSession>> {
        let data_key = self
            .master
            .data_key_for(self.backend.as_ref(), &lease.fence)
            .await?;
        let sealer = Arc::new(AesGcmSealer::new(&data_key));
        let store = Arc::new(RecordSignalStore::new(
            self.backend.clone(),
            sealer.clone(),
            lease.fence.clone(),
        ));
        let ops = OnceCell::new();
        match SignalOps::open(store.clone()).await {
            Ok(opened) => {
                let _ = ops.set(Arc::new(opened));
            }
            Err(OpsError::NotInitialised) => {}
            Err(e) => return Err(anyhow::anyhow!("opening the session's Signal state: {e}")),
        }
        Ok(Arc::new(ActiveSession {
            id: lease.fence.scope.to_string(),
            generation: lease.fence.generation,
            lease: Mutex::new(lease),
            store,
            sealer,
            ops,
            claimed: AtomicBool::new(false),
            claiming: AtomicBool::new(false),
            lost: AtomicBool::new(false),
            limiter: SendLimiter::new(),
            view: RwLock::new(SessionView {
                state: "unclaimed".into(),
                ..Default::default()
            }),
        }))
    }

    /// One pass over every configured session: renew what we hold, try to
    /// take what is free, and claim anything Polymorfa has not accepted yet.
    pub async fn tick_leases(self: &Arc<Self>) {
        let ttl = self.cfg.lease_ttl_ms;
        for id in &self.cfg.sessions {
            if *self.shutdown.borrow() {
                return;
            }
            if self.retired.read().expect("retired lock").contains(id) {
                continue;
            }
            match self.session(id) {
                Some(session) => {
                    let lease = session.lease().await;
                    let now = now_ms();
                    if now >= lease.expires_at_ms {
                        self.lose(id, session.generation, "lease expired before renewal");
                        // Releasing our still-current expired lease ensures a subsequent
                        // reacquisition increments the generation, even with this holder ID.
                        let _ = self.backend.release(&lease).await;
                        continue;
                    }
                    match self.backend.renew(&lease, now, ttl).await {
                        Ok(Some(renewed)) => *session.lease.lock().await = renewed,
                        Ok(None) => {
                            self.lose(id, session.generation, "lease taken over");
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(session = %id, error = %e, "lease renewal failed");
                            // Stop before another node can take it.
                            let margin = self.cfg.lease_renew.as_millis() as u64;
                            if now.saturating_add(margin) >= lease.expires_at_ms {
                                self.lose(
                                    id,
                                    session.generation,
                                    "lease could not be renewed before it expired",
                                );
                                continue;
                            }
                        }
                    }
                    if !session.is_claimed() {
                        self.spawn_claim(session);
                    }
                }
                None => {
                    let acquired = self
                        .backend
                        .acquire(id, &self.lease_holder, now_ms(), ttl)
                        .await;
                    match acquired {
                        Ok(Some(lease)) => {
                            let generation = lease.fence.generation;
                            match self.activate(lease.clone()).await {
                                Ok(session) => {
                                    if *self.shutdown.borrow() {
                                        let _ = self.backend.release(&lease).await;
                                        continue;
                                    }
                                    tracing::info!(session = %id, generation, "took session lease");
                                    self.sessions
                                        .write()
                                        .expect("sessions lock")
                                        .insert(id.clone(), session.clone());
                                    self.spawn_claim(session);
                                }
                                Err(e) => {
                                    tracing::error!(session = %id, error = %e, "cannot serve session; releasing its lease");
                                    let _ = self.backend.release(&lease).await;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(e) => tracing::warn!(session = %id, error = %e, "lease acquire failed"),
                    }
                }
            }
        }
    }

    fn spawn_claim(&self, session: Arc<ActiveSession>) {
        let Some(link) = self.link() else { return };
        let Some(node) = self.me.upgrade() else {
            return;
        };
        if session.claiming.swap(true, Ordering::SeqCst) {
            return;
        }
        tokio::spawn(async move {
            node.claim(&session, &link).await;
            session.claiming.store(false, Ordering::SeqCst);
        });
    }

    async fn claim(&self, session: &Arc<ActiveSession>, link: &Arc<Link>) {
        if !session.can_serve().await {
            return;
        }
        let op = service_request::Op::ClaimSession(ClaimSession {
            generation: session.generation,
        });
        match link.request(&session.id, 0, op).await {
            Ok(runner_response::Result::SessionClaimed(claimed)) => {
                if !session.can_serve().await {
                    return;
                }
                session.claimed.store(true, Ordering::SeqCst);
                session.set_view(claimed.state, &claimed.pn, &claimed.lid);
                tracing::info!(
                    session = %session.id,
                    generation = session.generation,
                    state = %state_name(claimed.state),
                    "Polymorfa accepted the claim"
                );
                if claimed.state == State::LoggedOut as i32 {
                    self.retire(&session.id).await;
                    return;
                }
                if !claimed.pn.is_empty()
                    && let Some(ops) = session.ops()
                {
                    let lid = Some(claimed.lid.as_str()).filter(|l| !l.is_empty());
                    if let Err(e) = ops.set_own_jids(&claimed.pn, lid).await {
                        let error = self.ops_error(session, &e);
                        tracing::warn!(session = %session.id, error = %error, "could not record own JIDs");
                    }
                }
            }
            Ok(_) => tracing::warn!(session = %session.id, "unexpected answer to ClaimSession"),
            Err(LinkError::Remote(error)) => match error.code_enum() {
                Code::NotLeaseHolder => {
                    self.lose(
                        &session.id,
                        session.generation,
                        "Polymorfa accepted a newer claim",
                    );
                }
                Code::SessionUnavailable => tracing::warn!(
                    session = %session.id,
                    "Polymorfa refused the claim: the session is not in this project or is logged out"
                ),
                _ => tracing::warn!(session = %session.id, error = %error, "claim refused"),
            },
            Err(e) => tracing::warn!(session = %session.id, error = %e, "claim failed"),
        }
    }

    async fn retire(&self, id: &str) {
        self.retired
            .write()
            .expect("retired lock")
            .insert(id.to_owned());
        tracing::warn!(
            session = id,
            "session is logged out; stopped serving it. Its sealed state is kept; remove it from the configuration and delete its records when no longer needed"
        );
        self.release(id).await;
    }

    async fn prune(self: &Arc<Self>) {
        let now = now_ms();
        let buffer_cutoff =
            now.saturating_sub(self.cfg.decrypt_buffer_retention.as_millis() as u64);
        let sent_cutoff = now.saturating_sub(self.cfg.sent_message_retention.as_millis() as u64);
        for session in self.sessions() {
            if !session.can_serve().await {
                continue;
            }
            let Some(ops) = session.ops() else { continue };
            let result = async {
                let buffered = ops.prune_decrypt_buffer(buffer_cutoff).await?;
                let sent = ops.prune_sent_messages(sent_cutoff).await?;
                Ok::<_, OpsError>((buffered, sent))
            }
            .await;
            match result {
                Ok((buffered, sent)) if buffered + sent > 0 => {
                    tracing::info!(session = %session.id, buffered, sent, "pruned expired records")
                }
                Ok(_) => {}
                Err(e) => {
                    let error = self.ops_error(&session, &e);
                    tracing::warn!(session = %session.id, error = %error, "pruning failed");
                }
            }
        }
    }

    /// Start the link, lease and pruning loops.
    pub fn spawn_loops(self: &Arc<Self>, service_version: &str) -> Vec<JoinHandle<()>> {
        let settings = LinkSettings {
            url: self.cfg.polymorfa_url.clone(),
            credential: self.cfg.credential.clone(),
            node_id: self.cfg.node_id.clone(),
            service_version: service_version.to_owned(),
            request_timeout: self.cfg.request_timeout,
            reconnect_min: self.cfg.reconnect_min,
            reconnect_max: self.cfg.reconnect_max,
        };
        let link_task = tokio::spawn(link::run(
            settings,
            self.clone() as Arc<dyn Handler>,
            self.shutdown_signal(),
        ));
        let leases = {
            let node = self.clone();
            let mut stop = self.shutdown_signal();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(node.cfg.lease_renew);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => node.tick_leases().await,
                        _ = stop.changed() => break,
                    }
                }
            })
        };
        let pruner = {
            let node = self.clone();
            let mut stop = self.shutdown_signal();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(node.cfg.prune_interval);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => node.prune().await,
                        _ = stop.changed() => break,
                    }
                }
            })
        };
        vec![link_task, leases, pruner]
    }

    /// Release every session, then stop the loops.
    pub async fn shutdown(&self) {
        // Prevent renewal/reacquisition while releasing sessions. Socket closure
        // removes routing claims even if ReleaseSession races the stop signal.
        let _ = self.shutdown.send(true);
        let ids: Vec<String> = self.sessions().iter().map(|s| s.id.clone()).collect();
        for id in ids {
            self.release(&id).await;
        }
    }
}

#[async_trait]
impl Handler for Node {
    async fn runner_request(
        &self,
        request: RunnerRequest,
    ) -> Result<ServiceResponse, proto::Error> {
        let Some(session) = self.session(&request.session_id) else {
            return Err(proto::Error::new(
                Code::NotLeaseHolder,
                "this node does not hold the session",
            ));
        };
        if request.lease_generation != session.generation || !session.can_serve().await {
            return Err(proto::Error::new(
                Code::NotLeaseHolder,
                format!(
                    "request generation {} is not this node's generation {}",
                    request.lease_generation, session.generation
                ),
            ));
        }
        let Some(op) = request.op else {
            return Err(proto::Error::new(Code::Unsupported, "unknown operation"));
        };
        crate::serve::handle(self, &session, op).await
    }

    async fn session_event(&self, event: SessionEvent) {
        let Some(session) = self.session(&event.session_id) else {
            return;
        };
        session.set_view(event.state, &event.pn, &event.lid);
        tracing::info!(session = %session.id, state = %state_name(event.state), "session state changed");
        match State::try_from(event.state).unwrap_or(State::Unspecified) {
            State::LoggedOut => self.retire(&session.id).await,
            // Polymorfa no longer routes to us; claim again.
            State::Paused => {
                session.claimed.store(false, Ordering::SeqCst);
                self.spawn_claim(session);
            }
            _ => {}
        }
    }

    async fn connected(&self, link: Arc<Link>) {
        *self.link.write().expect("link lock") = Some(link);
        for session in self.sessions() {
            self.spawn_claim(session);
        }
    }

    async fn disconnected(&self) {
        *self.link.write().expect("link lock") = None;
        // A new socket must claim a strictly higher generation. Relinquish
        // these fences before reconnect so the durable store increments them.
        let ids: Vec<_> = self.sessions().iter().map(|s| s.id.clone()).collect();
        for id in ids {
            self.release(&id).await;
        }
    }
}
