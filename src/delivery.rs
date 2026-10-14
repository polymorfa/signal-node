// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! Delivery of decrypted messages to the customer's application.
//!
//! An event counts as delivered when the application acknowledges it: a 2xx
//! answer to the signed webhook, or `POST /v1/events/{id}/ack` after reading
//! it from the event stream. With both configured, the first
//! acknowledgement wins. The receive that produced the event waits for that
//! acknowledgement; if none arrives within the timeout the receive fails,
//! Polymorfa does not send the delivery receipt, and the same ciphertext
//! comes back later and is served again from the sealed decrypt buffer.

use crate::message::Event;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, broadcast, oneshot};

/// Webhook headers.
pub const SIGNATURE_HEADER: &str = "Signal-Node-Signature";
pub const TIMESTAMP_HEADER: &str = "Signal-Node-Timestamp";
pub const EVENT_ID_HEADER: &str = "Signal-Node-Event-Id";

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_BUFFER: usize = 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeliveryError {
    #[error("no application is listening: no webhook configured and no event-stream client")]
    NoListener,
    #[error("the application did not acknowledge the event in time")]
    NotAcknowledged,
    #[error("the webhook answered with status {0}")]
    WebhookRejected(u16),
    #[error("the webhook could not be reached")]
    WebhookUnreachable,
}

/// `v1=<hex HMAC-SHA256(secret, "{timestamp}.{body}")>`.
pub fn sign(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("v1={}", hex::encode(mac.finalize().into_bytes()))
}

/// Check a signature in constant time. Applications can copy this logic.
pub fn verify(secret: &[u8], timestamp: i64, body: &[u8], signature: &str) -> bool {
    let Some(hex_mac) = signature.strip_prefix("v1=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_mac) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Verify both the MAC and the timestamp window before processing an event.
/// This does not replace durable deduplication by the event ID.
pub fn verify_recent(
    secret: &[u8],
    timestamp: i64,
    body: &[u8],
    signature: &str,
    now: i64,
    max_age: Duration,
) -> bool {
    timestamp.abs_diff(now) <= max_age.as_secs() && verify(secret, timestamp, body, signature)
}

pub struct Webhook {
    pub url: String,
    pub secret: crate::config::Secret,
}

pub struct Delivery {
    webhook: Option<Webhook>,
    http: reqwest::Client,
    stream: Option<broadcast::Sender<Arc<Event>>>,
    waiting: Mutex<HashMap<String, HashMap<u64, oneshot::Sender<()>>>>,
    next_waiter: AtomicU64,
    ack_timeout: Duration,
}

impl Delivery {
    pub fn new(webhook: Option<Webhook>, sse: bool, ack_timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(WEBHOOK_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("the HTTP client builds with static settings");
        Self {
            webhook,
            http,
            stream: sse.then(|| broadcast::channel(STREAM_BUFFER).0),
            waiting: Mutex::new(HashMap::new()),
            next_waiter: AtomicU64::new(1),
            ack_timeout,
        }
    }

    /// A new event-stream subscriber, if the stream is enabled.
    pub fn subscribe(&self) -> Option<broadcast::Receiver<Arc<Event>>> {
        self.stream.as_ref().map(broadcast::Sender::subscribe)
    }

    /// Record an acknowledgement from the event stream. Returns whether an
    /// event with that id was waiting.
    pub async fn acknowledge(&self, event_id: &str) -> bool {
        match self.waiting.lock().await.remove(event_id) {
            Some(waiters) => {
                for (_, waiter) in waiters {
                    let _ = waiter.send(());
                }
                true
            }
            None => false,
        }
    }

    /// Hand `event` to the application and wait for its acknowledgement.
    pub async fn deliver(&self, event: Event) -> Result<(), DeliveryError> {
        let event = Arc::new(event);
        let listeners = self
            .stream
            .as_ref()
            .map_or(0, broadcast::Sender::receiver_count);
        if self.webhook.is_none() && listeners == 0 {
            return Err(DeliveryError::NoListener);
        }

        let waiter_id = self.next_waiter.fetch_add(1, Ordering::Relaxed);
        let acked = if listeners > 0 {
            let (tx, rx) = oneshot::channel();
            self.waiting
                .lock()
                .await
                .entry(event.id.clone())
                .or_default()
                .insert(waiter_id, tx);
            if let Some(stream) = &self.stream {
                let _ = stream.send(event.clone());
            }
            Some(rx)
        } else {
            None
        };

        let result = tokio::time::timeout(self.ack_timeout, async {
            match (&self.webhook, acked) {
                (Some(webhook), None) => self.post(webhook, &event).await,
                (None, Some(rx)) => rx.await.map_err(|_| DeliveryError::NotAcknowledged),
                (Some(webhook), Some(rx)) => {
                    // Either acknowledgement completes delivery. A webhook
                    // failure leaves the stream acknowledgement to decide.
                    let posted = self.post(webhook, &event);
                    tokio::pin!(posted, rx);
                    tokio::select! {
                        r = &mut posted => match r {
                            Ok(()) => Ok(()),
                            Err(_) => rx.await.map_err(|_| DeliveryError::NotAcknowledged),
                        },
                        r = &mut rx => r.map_err(|_| DeliveryError::NotAcknowledged),
                    }
                }
                (None, None) => Err(DeliveryError::NoListener),
            }
        })
        .await
        .unwrap_or(Err(DeliveryError::NotAcknowledged));

        let mut waiting = self.waiting.lock().await;
        if let Some(waiters) = waiting.get_mut(&event.id) {
            waiters.remove(&waiter_id);
            if waiters.is_empty() {
                waiting.remove(&event.id);
            }
        }
        result
    }

    async fn post(&self, webhook: &Webhook, event: &Event) -> Result<(), DeliveryError> {
        let body = serde_json::to_vec(event).expect("events always serialize");
        let timestamp = now_secs();
        let signature = sign(webhook.secret.expose().as_bytes(), timestamp, &body);
        let response = self
            .http
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header(TIMESTAMP_HEADER, timestamp.to_string())
            .header(SIGNATURE_HEADER, signature)
            .header(EVENT_ID_HEADER, &event.id)
            .body(body)
            .send()
            .await
            .map_err(|_| DeliveryError::WebhookUnreachable)?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(DeliveryError::WebhookRejected(status.as_u16()))
        }
    }
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str) -> Event {
        Event {
            id: id.into(),
            kind: "message",
            session_id: "s".into(),
            chat: "c".into(),
            sender: "x".into(),
            sender_alt: None,
            message_id: "m".into(),
            timestamp: 0,
            is_from_me: false,
            redelivered: false,
            identity_changed: false,
            text: Some("t".into()),
            media: None,
            history: None,
            message_proto: String::new(),
        }
    }

    #[test]
    fn signatures_verify_and_reject_changes() {
        let sig = sign(b"secret", 100, b"{}");
        assert!(verify(b"secret", 100, b"{}", &sig));
        assert!(!verify(b"secret", 101, b"{}", &sig));
        assert!(!verify(b"other", 100, b"{}", &sig));
        assert!(!verify(b"secret", 100, b"{ }", &sig));
        assert!(!verify(b"secret", 100, b"{}", "garbage"));
        assert!(verify_recent(
            b"secret",
            100,
            b"{}",
            &sig,
            105,
            Duration::from_secs(5)
        ));
        assert!(!verify_recent(
            b"secret",
            100,
            b"{}",
            &sig,
            106,
            Duration::from_secs(5)
        ));
        assert!(!verify_recent(
            b"secret",
            100,
            b"{}",
            &sig,
            94,
            Duration::from_secs(5)
        ));
    }

    #[tokio::test]
    async fn without_a_listener_delivery_fails_fast() {
        let delivery = Delivery::new(None, true, Duration::from_secs(5));
        assert_eq!(
            delivery.deliver(event("a")).await,
            Err(DeliveryError::NoListener)
        );
    }

    #[tokio::test]
    async fn a_stream_acknowledgement_completes_delivery() {
        let delivery = Arc::new(Delivery::new(None, true, Duration::from_secs(5)));
        let mut rx = delivery.subscribe().unwrap();
        let acker = {
            let delivery = delivery.clone();
            tokio::spawn(async move {
                let got = rx.recv().await.unwrap();
                assert!(delivery.acknowledge(&got.id).await);
            })
        };
        delivery.deliver(event("b")).await.unwrap();
        acker.await.unwrap();
        assert!(!delivery.acknowledge("b").await, "the waiter must be gone");
    }

    #[tokio::test]
    async fn an_unacknowledged_event_times_out() {
        let delivery = Delivery::new(None, true, Duration::from_millis(50));
        let _rx = delivery.subscribe().unwrap();
        assert_eq!(
            delivery.deliver(event("c")).await,
            Err(DeliveryError::NotAcknowledged)
        );
    }
    #[tokio::test(start_paused = true)]
    async fn one_duplicate_timeout_does_not_remove_another_waiter() {
        let delivery = Arc::new(Delivery::new(None, true, Duration::from_millis(250)));
        let mut rx = delivery.subscribe().unwrap();
        let first = {
            let d = delivery.clone();
            tokio::spawn(async move { d.deliver(event("same")).await })
        };
        rx.recv().await.unwrap();
        tokio::time::advance(Duration::from_millis(100)).await;
        let second = {
            let d = delivery.clone();
            tokio::spawn(async move { d.deliver(event("same")).await })
        };
        rx.recv().await.unwrap();
        tokio::time::advance(Duration::from_millis(151)).await;
        assert_eq!(first.await.unwrap(), Err(DeliveryError::NotAcknowledged));
        assert!(delivery.acknowledge("same").await);
        assert_eq!(second.await.unwrap(), Ok(()));
    }
}
