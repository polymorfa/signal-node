// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Polymorfa

//! Configuration: a TOML file, then `SIGNAL_NODE_*` environment variables on
//! top. Every secret can also be read from a file (`*_file` keys), so it
//! never has to appear in the config file or the process environment.

use base64::Engine as _;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing the config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("{0}")]
    Invalid(String),
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

/// A value that must not be printed. `Debug` shows only whether it is set.
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() {
            "<unset>"
        } else {
            "<redacted>"
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Stable identifier of this node; the lease holder name. Defaults to the
    /// host name.
    #[serde(default)]
    pub node_id: String,
    pub polymorfa: PolymorfaConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub leases: LeaseConfig,
    pub http: HttpConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default)]
    pub history: HistoryConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolymorfaConfig {
    /// WebSocket URL of Polymorfa's Signal service endpoint.
    pub url: String,
    /// Project credential, sent as `Authorization: Bearer <credential>`.
    #[serde(default)]
    pub credential: Secret,
    #[serde(default)]
    pub credential_file: Option<PathBuf>,
    /// Zero-knowledge session IDs this deployment serves. Every node of a
    /// deployment lists the same sessions; leases decide which node serves
    /// each one.
    #[serde(default)]
    pub sessions: Vec<String>,
    /// Longest wait for a response to a request this node sends.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Reconnect backoff bounds.
    #[serde(default = "default_backoff_min_ms")]
    pub reconnect_min_ms: u64,
    #[serde(default = "default_backoff_max_ms")]
    pub reconnect_max_ms: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageDriver {
    Postgres,
    Sqlite,
    /// In-process only. State is lost on restart; for tests and trials.
    Memory,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub driver: StorageDriver,
    /// `postgres://...` or `sqlite://path?mode=rwc`. Unused for `memory`.
    #[serde(default)]
    pub url: Secret,
    #[serde(default)]
    pub url_file: Option<PathBuf>,
    /// Base64 of 32 random bytes. Wraps each session's data key.
    #[serde(default)]
    pub master_key: Secret,
    #[serde(default)]
    pub master_key_file: Option<PathBuf>,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseConfig {
    /// How long a lease lives without renewal. Failover takes at most this
    /// long after a node stops.
    #[serde(default = "default_lease_ttl_ms")]
    pub ttl_ms: u64,
    /// How often leases are renewed and free sessions are tried.
    #[serde(default = "default_lease_renew_ms")]
    pub renew_interval_ms: u64,
}

impl Default for LeaseConfig {
    fn default() -> Self {
        Self {
            ttl_ms: default_lease_ttl_ms(),
            renew_interval_ms: default_lease_renew_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    /// Address of the application API. Keep it on a private network.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Bearer secret every application request must present.
    #[serde(default)]
    pub secret: Secret,
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryConfig {
    /// Signed webhook target. Optional when the application reads the event
    /// stream instead.
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_secret: Secret,
    #[serde(default)]
    pub webhook_secret_file: Option<PathBuf>,
    /// Serve `GET /v1/events` as a server-sent-events stream.
    #[serde(default = "default_true")]
    pub sse: bool,
    /// How long a received message waits for the application to acknowledge
    /// it before the receive fails and WhatsApp redelivers it later.
    #[serde(default = "default_ack_timeout_ms")]
    pub ack_timeout_ms: u64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            webhook_secret: Secret::default(),
            webhook_secret_file: None,
            sse: true,
            ack_timeout_ms: default_ack_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryConfig {
    /// Deliver history-sync descriptors to the application. Off by default:
    /// history notifications are decrypted and dropped. Turning this on is
    /// the operator's decision and responsibility.
    #[serde(default)]
    pub deliver: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// Decrypt-buffer entries (sealed) older than this are deleted.
    #[serde(default = "default_buffer_hours")]
    pub decrypt_buffer_hours: u64,
    /// Sent-message records, kept to answer retry receipts.
    #[serde(default = "default_sent_hours")]
    pub sent_message_hours: u64,
    #[serde(default = "default_prune_minutes")]
    pub prune_interval_minutes: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            decrypt_buffer_hours: default_buffer_hours(),
            sent_message_hours: default_sent_hours(),
            prune_interval_minutes: default_prune_minutes(),
        }
    }
}

fn default_request_timeout_ms() -> u64 {
    15_000
}
fn default_backoff_min_ms() -> u64 {
    500
}
fn default_backoff_max_ms() -> u64 {
    30_000
}
fn default_max_connections() -> u32 {
    10
}
fn default_lease_ttl_ms() -> u64 {
    30_000
}
fn default_lease_renew_ms() -> u64 {
    10_000
}
fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8787))
}
fn default_true() -> bool {
    true
}
fn default_ack_timeout_ms() -> u64 {
    10_000
}
fn default_buffer_hours() -> u64 {
    14 * 24
}
fn default_sent_hours() -> u64 {
    7 * 24
}
fn default_prune_minutes() -> u64 {
    60
}

/// Settings resolved from the file, environment and secret files.
#[derive(Clone)]
pub struct Resolved {
    pub node_id: String,
    pub polymorfa_url: String,
    pub credential: Secret,
    pub sessions: Vec<String>,
    pub request_timeout: Duration,
    pub reconnect_min: Duration,
    pub reconnect_max: Duration,
    pub storage_driver: StorageDriver,
    pub storage_url: Secret,
    pub max_connections: u32,
    pub master_key: [u8; 32],
    pub lease_ttl_ms: u64,
    pub lease_renew: Duration,
    pub http_listen: SocketAddr,
    pub http_secret: Secret,
    pub webhook_url: Option<String>,
    pub webhook_secret: Secret,
    pub sse: bool,
    pub ack_timeout: Duration,
    pub deliver_history: bool,
    pub decrypt_buffer_retention: Duration,
    pub sent_message_retention: Duration,
    pub prune_interval: Duration,
}

impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("node_id", &self.node_id)
            .field("sessions", &self.sessions)
            .field("storage_driver", &self.storage_driver)
            .field("master_key", &"<redacted>")
            .field("credential", &self.credential)
            .field("http_secret", &self.http_secret)
            .field("webhook_secret", &self.webhook_secret)
            .finish_non_exhaustive()
    }
}

/// The environment variables read on top of the file.
pub const ENV_VARS: &[&str] = &[
    "SIGNAL_NODE_ID",
    "SIGNAL_NODE_POLYMORFA_URL",
    "SIGNAL_NODE_POLYMORFA_CREDENTIAL",
    "SIGNAL_NODE_SESSIONS",
    "SIGNAL_NODE_STORAGE_DRIVER",
    "SIGNAL_NODE_STORAGE_URL",
    "SIGNAL_NODE_MASTER_KEY",
    "SIGNAL_NODE_HTTP_LISTEN",
    "SIGNAL_NODE_HTTP_SECRET",
    "SIGNAL_NODE_WEBHOOK_URL",
    "SIGNAL_NODE_WEBHOOK_SECRET",
    "SIGNAL_NODE_HISTORY_DELIVER",
];

impl Config {
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(text)?)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Apply `SIGNAL_NODE_*` overrides read through `env`.
    pub fn apply_env(&mut self, env: impl Fn(&str) -> Option<String>) -> Result<(), ConfigError> {
        if let Some(v) = env("SIGNAL_NODE_ID") {
            self.node_id = v;
        }
        if let Some(v) = env("SIGNAL_NODE_POLYMORFA_URL") {
            self.polymorfa.url = v;
        }
        if let Some(v) = env("SIGNAL_NODE_POLYMORFA_CREDENTIAL") {
            self.polymorfa.credential = Secret::new(v);
        }
        if let Some(v) = env("SIGNAL_NODE_SESSIONS") {
            self.polymorfa.sessions = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
        }
        if let Some(v) = env("SIGNAL_NODE_STORAGE_DRIVER") {
            self.storage.driver = match v.as_str() {
                "postgres" => StorageDriver::Postgres,
                "sqlite" => StorageDriver::Sqlite,
                "memory" => StorageDriver::Memory,
                other => return Err(invalid(format!("unknown storage driver {other}"))),
            };
        }
        if let Some(v) = env("SIGNAL_NODE_STORAGE_URL") {
            self.storage.url = Secret::new(v);
        }
        if let Some(v) = env("SIGNAL_NODE_MASTER_KEY") {
            self.storage.master_key = Secret::new(v);
        }
        if let Some(v) = env("SIGNAL_NODE_HTTP_LISTEN") {
            self.http.listen = v
                .parse()
                .map_err(|_| invalid("SIGNAL_NODE_HTTP_LISTEN is not host:port"))?;
        }
        if let Some(v) = env("SIGNAL_NODE_HTTP_SECRET") {
            self.http.secret = Secret::new(v);
        }
        if let Some(v) = env("SIGNAL_NODE_WEBHOOK_URL") {
            self.delivery.webhook_url = Some(v).filter(|u| !u.is_empty());
        }
        if let Some(v) = env("SIGNAL_NODE_WEBHOOK_SECRET") {
            self.delivery.webhook_secret = Secret::new(v);
        }
        if let Some(v) = env("SIGNAL_NODE_HISTORY_DELIVER") {
            self.history.deliver = matches!(v.as_str(), "1" | "true" | "yes");
        }
        Ok(())
    }

    /// Read secret files and check every setting.
    pub fn resolve(self) -> Result<Resolved, ConfigError> {
        let credential = secret_or_file(
            self.polymorfa.credential,
            self.polymorfa.credential_file.as_deref(),
            "polymorfa.credential",
        )?;
        if credential.is_empty() {
            return Err(invalid("polymorfa.credential is required"));
        }
        let relay = reqwest::Url::parse(&self.polymorfa.url)
            .map_err(|_| invalid("polymorfa.url is invalid"))?;
        let local = matches!(relay.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(relay.scheme() == "wss" || relay.scheme() == "ws" && local)
            || !relay.username().is_empty()
            || relay.password().is_some()
            || relay.query().is_some()
            || relay.fragment().is_some()
        {
            return Err(invalid(
                "polymorfa.url requires wss (ws only on loopback) without credentials, query or fragment",
            ));
        }
        if let Some(target) = &self.delivery.webhook_url {
            let url = reqwest::Url::parse(target)
                .map_err(|_| invalid("delivery.webhook_url is invalid"))?;
            let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if !(url.scheme() == "https" || url.scheme() == "http" && local)
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid(
                    "delivery.webhook_url requires HTTPS (HTTP only on loopback) without URL credentials or fragment",
                ));
            }
        }
        if self.polymorfa.request_timeout_ms == 0
            || self.polymorfa.reconnect_min_ms == 0
            || self.polymorfa.reconnect_max_ms < self.polymorfa.reconnect_min_ms
            || self.leases.ttl_ms == 0
            || self.leases.renew_interval_ms == 0
            || self.delivery.ack_timeout_ms == 0
        {
            return Err(invalid(
                "timeouts and lease intervals must be positive and reconnect bounds ordered",
            ));
        }
        let storage_url = secret_or_file(
            self.storage.url,
            self.storage.url_file.as_deref(),
            "storage.url",
        )?;
        if self.storage.driver != StorageDriver::Memory && storage_url.is_empty() {
            return Err(invalid("storage.url is required for this driver"));
        }
        let master_key = secret_or_file(
            self.storage.master_key,
            self.storage.master_key_file.as_deref(),
            "storage.master_key",
        )?;
        let master_key = decode_master_key(master_key.expose())?;
        let http_secret = secret_or_file(
            self.http.secret,
            self.http.secret_file.as_deref(),
            "http.secret",
        )?;
        if http_secret.expose().len() < 16 {
            return Err(invalid("http.secret must be at least 16 characters"));
        }
        let webhook_secret = secret_or_file(
            self.delivery.webhook_secret,
            self.delivery.webhook_secret_file.as_deref(),
            "delivery.webhook_secret",
        )?;
        if self.delivery.webhook_url.is_some() && webhook_secret.expose().len() < 16 {
            return Err(invalid(
                "delivery.webhook_secret (16 characters or more) is required with a webhook_url",
            ));
        }
        if self.delivery.webhook_url.is_none() && !self.delivery.sse {
            return Err(invalid(
                "set delivery.webhook_url or enable delivery.sse; messages need somewhere to go",
            ));
        }
        if self.leases.renew_interval_ms * 2 > self.leases.ttl_ms {
            return Err(invalid(
                "leases.renew_interval_ms must be at most half of leases.ttl_ms",
            ));
        }
        for id in &self.polymorfa.sessions {
            if id.is_empty() || id.len() > 200 {
                return Err(invalid("session IDs must be 1 to 200 characters"));
            }
        }
        let node_id = if self.node_id.is_empty() {
            default_node_id()
        } else {
            self.node_id
        };
        Ok(Resolved {
            node_id,
            polymorfa_url: self.polymorfa.url,
            credential,
            sessions: self.polymorfa.sessions,
            request_timeout: Duration::from_millis(self.polymorfa.request_timeout_ms),
            reconnect_min: Duration::from_millis(self.polymorfa.reconnect_min_ms),
            reconnect_max: Duration::from_millis(self.polymorfa.reconnect_max_ms),
            storage_driver: self.storage.driver,
            storage_url,
            max_connections: self.storage.max_connections.max(1),
            master_key,
            lease_ttl_ms: self.leases.ttl_ms,
            lease_renew: Duration::from_millis(self.leases.renew_interval_ms),
            http_listen: self.http.listen,
            http_secret,
            webhook_url: self.delivery.webhook_url,
            webhook_secret,
            sse: self.delivery.sse,
            ack_timeout: Duration::from_millis(self.delivery.ack_timeout_ms),
            deliver_history: self.history.deliver,
            decrypt_buffer_retention: Duration::from_secs(
                self.retention.decrypt_buffer_hours * 3600,
            ),
            sent_message_retention: Duration::from_secs(self.retention.sent_message_hours * 3600),
            prune_interval: Duration::from_secs(self.retention.prune_interval_minutes.max(1) * 60),
        })
    }
}

fn secret_or_file(inline: Secret, file: Option<&Path>, name: &str) -> Result<Secret, ConfigError> {
    match (inline.is_empty(), file) {
        (false, Some(_)) => Err(invalid(format!("set {name} or {name}_file, not both"))),
        (true, Some(path)) => {
            let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
                path: path.to_owned(),
                source,
            })?;
            Ok(Secret::new(text.trim()))
        }
        (_, None) => Ok(inline),
    }
}

fn decode_master_key(text: &str) -> Result<[u8; 32], ConfigError> {
    if text.is_empty() {
        return Err(invalid(
            "storage.master_key is required (base64 of 32 random bytes)",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| invalid("storage.master_key is not valid base64"))?;
    bytes
        .try_into()
        .map_err(|_| invalid("storage.master_key must decode to exactly 32 bytes"))
}

fn default_node_id() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| format!("node-{:08x}", rand::random::<u32>()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [polymorfa]
        url = "wss://example.invalid/signal"
        credential = "pk_test_credential"
        sessions = ["sess_a", "sess_b"]

        [storage]
        driver = "memory"
        master_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

        [http]
        secret = "local-secret-0123456789"
    "#;

    #[test]
    fn a_minimal_file_resolves_with_defaults() {
        let resolved = Config::from_toml(MINIMAL).unwrap().resolve().unwrap();
        assert_eq!(resolved.sessions, ["sess_a", "sess_b"]);
        assert_eq!(resolved.lease_ttl_ms, 30_000);
        assert!(!resolved.deliver_history, "history must be off by default");
        assert!(resolved.sse);
        assert_eq!(resolved.master_key, [0; 32]);
    }

    #[test]
    fn environment_overrides_the_file() {
        let mut config = Config::from_toml(MINIMAL).unwrap();
        config
            .apply_env(|name| match name {
                "SIGNAL_NODE_SESSIONS" => Some("one, two".into()),
                "SIGNAL_NODE_HISTORY_DELIVER" => Some("true".into()),
                "SIGNAL_NODE_ID" => Some("node-9".into()),
                _ => None,
            })
            .unwrap();
        let resolved = config.resolve().unwrap();
        assert_eq!(resolved.sessions, ["one", "two"]);
        assert!(resolved.deliver_history);
        assert_eq!(resolved.node_id, "node-9");
    }

    #[test]
    fn secrets_never_print() {
        let resolved = Config::from_toml(MINIMAL).unwrap().resolve().unwrap();
        let printed = format!("{resolved:?}");
        assert!(!printed.contains("pk_test_credential"));
        assert!(!printed.contains("local-secret"));
    }

    #[test]
    fn bad_values_are_refused() {
        let short_key = MINIMAL.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAA");
        assert!(Config::from_toml(&short_key).unwrap().resolve().is_err());
        let http_url = MINIMAL.replace("wss://", "https://");
        assert!(Config::from_toml(&http_url).unwrap().resolve().is_err());
        let weak = MINIMAL.replace("local-secret-0123456789", "short");
        assert!(Config::from_toml(&weak).unwrap().resolve().is_err());
        let mut no_sink = Config::from_toml(MINIMAL).unwrap();
        no_sink.delivery.sse = false;
        assert!(no_sink.resolve().is_err());
    }
}
