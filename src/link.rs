// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! The WebSocket link to Polymorfa.
//!
//! The node dials out, sends `Hello`, waits for `Welcome`, then multiplexes
//! requests in both directions over binary frames. A Ping goes out every
//! `Welcome.heartbeat_interval_ms`; a missing answer closes the link. On any
//! failure the link reconnects with jittered exponential backoff.

use crate::proto::{
    self, Code, Frame, Hello, RunnerRequest, ServiceRequest, ServiceResponse, SessionEvent,
    Welcome, frame::Body, runner_response, service_request,
};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest, http::HeaderValue};

/// Defaults when Welcome leaves a value at zero.
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(10);
pub const DEFAULT_MAX_SENDS_PER_SECOND: u32 = 5;
const WELCOME_TIMEOUT: Duration = Duration::from_secs(10);
/// A link that stayed up this long resets the reconnect backoff.
const STABLE_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct LinkSettings {
    pub url: String,
    pub credential: crate::config::Secret,
    pub node_id: String,
    pub service_version: String,
    pub request_timeout: Duration,
    pub reconnect_min: Duration,
    pub reconnect_max: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("not connected to Polymorfa")]
    Disconnected,
    #[error("Polymorfa did not answer in time")]
    Timeout,
    #[error("Polymorfa refused the request: {0}")]
    Remote(proto::Error),
    #[error("Polymorfa sent an unexpected response")]
    UnexpectedResponse,
}

impl LinkError {
    pub fn remote_code(&self) -> Option<Code> {
        match self {
            LinkError::Remote(e) => Some(e.code_enum()),
            _ => None,
        }
    }
}

type Pending = oneshot::Sender<Result<runner_response::Result, proto::Error>>;

/// One live connection. Cloned handles stay valid until it closes; requests
/// on a closed link fail with [`LinkError::Disconnected`].
pub struct Link {
    out: mpsc::UnboundedSender<Frame>,
    pending: Mutex<HashMap<u64, Pending>>,
    next_id: AtomicU64,
    welcome: Welcome,
    timeout: Duration,
    closed: watch::Sender<bool>,
}

impl Link {
    pub fn welcome(&self) -> &Welcome {
        &self.welcome
    }

    /// The send ceiling Polymorfa announced.
    pub fn max_sends_per_second(&self) -> u32 {
        match self.welcome.max_sends_per_second {
            0 => DEFAULT_MAX_SENDS_PER_SECOND,
            n => n,
        }
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    fn close(&self) {
        let _ = self.closed.send(true);
    }

    /// Send a request and wait for its response.
    pub async fn request(
        &self,
        session_id: &str,
        lease_generation: u64,
        op: service_request::Op,
    ) -> Result<runner_response::Result, LinkError> {
        if self.is_closed() {
            return Err(LinkError::Disconnected);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        let frame = Frame::with(
            id,
            Body::ServiceRequest(ServiceRequest {
                session_id: session_id.to_owned(),
                lease_generation,
                op: Some(op),
            }),
        );
        if self.out.send(frame).is_err() {
            self.pending.lock().await.remove(&id);
            return Err(LinkError::Disconnected);
        }
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(Ok(result))) => Ok(result),
            Ok(Ok(Err(error))) => Err(LinkError::Remote(error)),
            Ok(Err(_)) => Err(LinkError::Disconnected),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(LinkError::Timeout)
            }
        }
    }

    async fn complete(&self, id: u64, result: Result<runner_response::Result, proto::Error>) {
        if let Some(waiter) = self.pending.lock().await.remove(&id) {
            let _ = waiter.send(result);
        }
    }

    fn reply(&self, frame: Frame) {
        let _ = self.out.send(frame);
    }

    async fn fail_all(&self) {
        // Dropping the senders wakes every waiter with Disconnected.
        self.pending.lock().await.clear();
    }
}

/// What the node does with traffic from Polymorfa.
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn runner_request(&self, request: RunnerRequest) -> Result<ServiceResponse, proto::Error>;
    async fn session_event(&self, event: SessionEvent);
    /// A link finished its handshake. Claims go out from here.
    async fn connected(&self, link: Arc<Link>);
    async fn disconnected(&self);
}

#[derive(Debug, thiserror::Error)]
enum ConnectError {
    #[error("WebSocket: {0}")]
    WebSocket(#[from] tungstenite::Error),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("Polymorfa refused the connection: {0}")]
    Refused(proto::Error),
}

/// Keep a link to Polymorfa until `shutdown` turns true.
pub async fn run(
    settings: LinkSettings,
    handler: Arc<dyn Handler>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut attempt: u32 = 0;
    while !*shutdown.borrow() {
        let started = tokio::time::Instant::now();
        let result = tokio::select! {
            r = connect_and_serve(&settings, handler.clone(), shutdown.clone()) => r,
            _ = shutdown.changed() => break,
        };
        match &result {
            Ok(()) => tracing::info!("link to Polymorfa closed"),
            Err(e) => tracing::warn!(error = %e, "link to Polymorfa failed"),
        }
        if *shutdown.borrow() {
            break;
        }
        if started.elapsed() >= STABLE_AFTER {
            attempt = 0;
        }
        let delay = backoff(settings.reconnect_min, settings.reconnect_max, attempt);
        attempt = attempt.saturating_add(1);
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => break,
        }
    }
}

/// Full-jitter exponential backoff.
pub fn backoff(min: Duration, max: Duration, attempt: u32) -> Duration {
    let ceiling = min
        .saturating_mul(1u32 << attempt.min(16))
        .min(max)
        .max(min);
    let millis = ceiling.as_millis().max(1) as u64;
    Duration::from_millis(rand::thread_rng().gen_range(min.as_millis() as u64..=millis))
}

async fn connect_and_serve(
    settings: &LinkSettings,
    handler: Arc<dyn Handler>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ConnectError> {
    let mut request = settings.url.as_str().into_client_request()?;
    let headers = request.headers_mut();
    headers.insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(proto::SUBPROTOCOL),
    );
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", settings.credential.expose()))
        .map_err(|_| ConnectError::Handshake("credential is not a valid header value".into()))?;
    auth.set_sensitive(true);
    headers.insert("Authorization", auth);

    let (socket, response) = tokio_tungstenite::connect_async(request).await?;
    let agreed = response
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok());
    if agreed != Some(proto::SUBPROTOCOL) {
        return Err(ConnectError::Handshake(
            "Polymorfa did not accept subprotocol polymorfa.signal.v1".into(),
        ));
    }
    let (mut sink, mut stream) = socket.split();

    let hello = Frame::with(
        0,
        Body::Hello(Hello {
            protocol_version: proto::PROTOCOL_VERSION,
            service_version: settings.service_version.clone(),
            node_id: settings.node_id.clone(),
        }),
    );
    sink.send(tungstenite::Message::Binary(hello.encode_to_vec().into()))
        .await?;

    let welcome = tokio::time::timeout(WELCOME_TIMEOUT, async {
        while let Some(message) = stream.next().await {
            let tungstenite::Message::Binary(bytes) = message? else {
                continue;
            };
            let frame = Frame::decode(bytes.as_ref())
                .map_err(|_| ConnectError::Handshake("undecodable frame".into()))?;
            match frame.body {
                Some(Body::Welcome(welcome)) => return Ok(welcome),
                Some(Body::Error(error)) => return Err(ConnectError::Refused(error)),
                _ => {
                    return Err(ConnectError::Handshake(
                        "expected Welcome as the first frame".into(),
                    ));
                }
            }
        }
        Err(ConnectError::Handshake("closed before Welcome".into()))
    })
    .await
    .map_err(|_| ConnectError::Handshake("no Welcome in time".into()))??;
    if welcome.protocol_version != proto::PROTOCOL_VERSION {
        return Err(ConnectError::Handshake(format!(
            "Polymorfa speaks protocol {}, this build speaks {}",
            welcome.protocol_version,
            proto::PROTOCOL_VERSION
        )));
    }
    tracing::info!(
        project = %welcome.project_id,
        heartbeat_ms = welcome.heartbeat_interval_ms,
        max_sends_per_second = welcome.max_sends_per_second,
        "connected to Polymorfa"
    );

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Frame>();
    let (closed_tx, mut closed_rx) = watch::channel(false);
    let heartbeat = match welcome.heartbeat_interval_ms {
        0 => DEFAULT_HEARTBEAT,
        ms => Duration::from_millis(u64::from(ms)),
    };
    let link = Arc::new(Link {
        out: out_tx,
        pending: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        welcome,
        timeout: settings.request_timeout,
        closed: closed_tx,
    });

    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let bytes = frame.encode_to_vec();
            if sink
                .send(tungstenite::Message::Binary(bytes.into()))
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let pinger = {
        let link = link.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(heartbeat);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if link.is_closed() {
                    break;
                }
                let ping = service_request::Op::Ping(proto::Ping {});
                if let Err(e) = link.request("", 0, ping).await {
                    tracing::warn!(error = %e, "heartbeat failed; closing the link");
                    link.close();
                    break;
                }
            }
        })
    };

    handler.connected(link.clone()).await;

    let result = loop {
        tokio::select! {
            message = stream.next() => {
                let message = match message {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => break Err(ConnectError::WebSocket(e)),
                    None => break Ok(()),
                };
                match message {
                    tungstenite::Message::Binary(bytes) => match Frame::decode(bytes.as_ref()) {
                        Ok(frame) => dispatch(&link, &handler, frame).await,
                        Err(_) => tracing::warn!("dropped an undecodable frame"),
                    },
                    tungstenite::Message::Close(_) => break Ok(()),
                    _ => {}
                }
            }
            _ = closed_rx.changed() => break Ok(()),
            _ = shutdown.changed() => break Ok(()),
        }
    };

    link.close();
    link.fail_all().await;
    pinger.abort();
    writer.abort();
    handler.disconnected().await;
    result
}

async fn dispatch(link: &Arc<Link>, handler: &Arc<dyn Handler>, frame: Frame) {
    let id = frame.id;
    match frame.body {
        Some(Body::RunnerRequest(request)) => {
            let link = link.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let body = match handler.runner_request(request).await {
                    Ok(response) => Body::ServiceResponse(response),
                    Err(error) => Body::Error(error),
                };
                link.reply(Frame::with(id, body));
            });
        }
        Some(Body::RunnerResponse(response)) => match response.result {
            Some(result) => link.complete(id, Ok(result)).await,
            None => {
                link.complete(
                    id,
                    Err(proto::Error::new(
                        Code::Unsupported,
                        "response with an unknown result",
                    )),
                )
                .await
            }
        },
        Some(Body::Error(error)) => {
            if id == 0 {
                tracing::warn!(code = error.code_enum().as_str_name(), "Polymorfa reported an error");
            } else {
                link.complete(id, Err(error)).await;
            }
        }
        Some(Body::SessionEvent(event)) => {
            let handler = handler.clone();
            tokio::spawn(async move { handler.session_event(event).await });
        }
        Some(Body::Welcome(_)) => {}
        Some(Body::Hello(_) | Body::ServiceRequest(_) | Body::ServiceResponse(_)) => {
            if id != 0 {
                link.reply(Frame::with(
                    id,
                    Body::Error(proto::Error::new(
                        Code::InvalidArgument,
                        "frame type is not sent by Polymorfa",
                    )),
                ));
            }
        }
        None => {
            if id != 0 {
                link.reply(Frame::with(
                    id,
                    Body::Error(proto::Error::new(
                        Code::Unsupported,
                        "unknown frame type",
                    )),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_stays_within_bounds_and_grows() {
        let min = Duration::from_millis(100);
        let max = Duration::from_secs(5);
        for attempt in 0..40 {
            let d = backoff(min, max, attempt);
            assert!(d >= min && d <= max, "{d:?} at attempt {attempt}");
        }
        assert!(backoff(min, max, 0) <= Duration::from_millis(100));
    }
}
