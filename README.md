# signal-node

`signal-node` is the customer-operated Signal service for Polymorfa zero-knowledge sessions. It owns the linked device's keys, decrypts incoming messages in the customer's process, and delivers them directly to the customer's server application. Its outbound WebSocket carries encrypted stanzas and protocol operations to Polymorfa. The application sends messages through this service's local API.

This repository is private. The implementation is under review and has not been published or accepted against a real WhatsApp account. Deployment also requires the corresponding Polymorfa runner/API support and session eligibility. Starting this binary does not enable zero-knowledge sessions or grant permissions.

## Contracts and dependency status

- Runner protocol: [`proto/polymorfa/signal/v1/signal_service.proto`](proto/polymorfa/signal/v1/signal_service.proto), version `1`, subprotocol `polymorfa.signal.v1`, originating at `b6d5f5f`.
- Application API: [`docs/app-api.openapi.json`](docs/app-api.openapi.json). JSON field names use snake_case. Event and message timestamps use Unix seconds; lease expiry uses Unix milliseconds internally.
- Signal libraries: exact `polymorfa/whatsapp-rust` revision `4b3b13cacd40a27573d0246386db553ef887539b`, the unmerged [recordstore/Signal operations producer PR](https://github.com/polymorfa/whatsapp-rust/pull/5). All five normal/dev crate families use this same source. A successful local build does not make that producer a released dependency.
- Rust MSRV: `1.94`. The checked-in toolchain selects `1.94.0`.

The server connection uses a project credential in `Authorization`, never in a URL or browser. The local API uses a separate application bearer secret. It rejects every authenticated request with an `Origin` header, including `Origin: null`, and supplies no CORS permission. Browser/WASM remote transport is unavailable until Polymorfa provides a distinct, short-lived client grant backed by live authorization. Never put the project credential or application secret in a browser.

## Durable public prekey uploads

The additive runner operations `PreparePreKeyUpload` and `AcknowledgePreKeyUpload` retain protocol version `1`. Prepare accepts 1..812 and returns the entire surviving pending batch under one opaque token, including after a process or database reopen. A later request for 50 can return the outstanding 812 keys; it never truncates or tops up that batch. Only public keys, IDs and the token cross the runner protocol. Counter, private keys and pending metadata commit atomically in the customer store. Keep one `SignalOps` instance per held session scope, as the service does.

The runner acknowledges only after its upload succeeds, using that token and unique original IDs covering every surviving key. Consumed originals may remain in an in-flight ACK; they stay deleted. Flags, the exact replay receipt and pending retirement commit together. The most recent exact ACK can be repeated after a lost response or restart without changing a newer pending batch. A timeout does not establish whether WhatsApp accepted an upload. Fresh retry-receipt keys still use `GeneratePreKeys` and `MarkPreKeysUploaded`; the legacy mark rejects the entire request if it includes an original pending-batch member, including a consumed member. Uploaded counts describe surviving local flags, not WhatsApp's remaining pool.

Upgrade the supporting service before a runner requires these operations. An older service rejects an unknown operation with `CODE_UNSUPPORTED`; the runner must fail without falling back to fresh generation. The matching HyperMeow/backend consumers remain separate unmerged dependencies. This library/service checkpoint does not establish live-provider retry acceptance or change application HTTP routes, consent, custody, eligibility or deployment availability. Rollback must retain the sealed device, private-key and batch records; do not run an older writer over active pending batches without verifying compatible batch-aware behavior.

## Run

Build the binary with Rust 1.94 or newer:

```sh
cargo build --release --locked
./target/release/signal-node --version
./target/release/signal-node --config /etc/signal-node/signal-node.toml
```

Copy [`signal-node.example.toml`](signal-node.example.toml) to a private configuration directory. Set the actual runner URL and eligible session IDs. Give every node a unique `node_id`. Place the project credential, application secret, master key and optional webhook secret in separately mounted secret files. Secret file paths resolve against the process working directory; use absolute paths in deployments. Keep the master key and its recovery copy outside the database.

The operator can generate a random master key with `signal-node generate-key`, redirecting its output directly to a private secret file. The value is base64 of 32 random bytes. Do not print it in logs, paste it into a support ticket, or commit it. Application secrets require at least 16 visible ASCII characters without spaces; webhook secrets require at least 16 characters; provision independent random secrets.

Environment variables override inline file settings. An inline override and a configured `*_file` for the same secret are rejected, so remove the file setting before switching sources. Supported overrides are `SIGNAL_NODE_ID`, `SIGNAL_NODE_POLYMORFA_URL`, `SIGNAL_NODE_POLYMORFA_CREDENTIAL`, `SIGNAL_NODE_SESSIONS` (comma-separated), `SIGNAL_NODE_STORAGE_DRIVER`, `SIGNAL_NODE_STORAGE_URL`, `SIGNAL_NODE_MASTER_KEY`, `SIGNAL_NODE_HTTP_LISTEN`, `SIGNAL_NODE_HTTP_SECRET`, `SIGNAL_NODE_WEBHOOK_URL`, `SIGNAL_NODE_WEBHOOK_SECRET` and `SIGNAL_NODE_HISTORY_DELIVER`. `SIGNAL_NODE_CONFIG` selects the file when `--config` is absent. `SIGNAL_NODE_LOG_FORMAT=json` selects structured logs; `SIGNAL_NODE_LOG` sets the log filter. Avoid verbose dependency logging in production.

The runner URL requires `wss`; loopback `ws` is available for local testing. It cannot contain URL credentials, a query or a fragment. Webhooks require HTTPS, with loopback HTTP allowed for tests. The service does not follow webhook redirects or forward either bearer credential to the webhook.

### Container

```sh
docker build -t signal-node:local .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount type=bind,src="$PWD/deployment-config",dst=/etc/signal-node,readonly \
  --mount type=bind,src="$PWD/deployment-secrets",dst=/run/secrets,readonly \
  --mount type=bind,src="$PWD/deployment-state",dst=/var/lib/signal-node \
  -p 127.0.0.1:8787:8787 \
  signal-node:local --config /etc/signal-node/signal-node.toml
```

The image runs as UID/GID `10001`. Grant that identity read access to secret/config files and write access to the state directory. Use `http.listen = "0.0.0.0:8787"` inside the container, while binding the host port to loopback or a private network. The HTTP API carries plaintext and descriptors with media keys; use authenticated TLS termination if it crosses a host boundary. The default binary listener is `127.0.0.1:8787`. `/healthz` is public and returns only `{"status":"ok"}`. It reports process liveness, not upstream connectivity or session readiness. Authenticated `/v1/sessions` supplies local ownership and claim state.

SIGINT/SIGTERM stop renewal and release held leases. HTTP shutdown waits for open requests and SSE streams, then aborts remaining tasks after a ten-second deadline. Unreleased leases expire after a forced stop; configure the supervisor to allow at least that shutdown period.

## Application API

All `/v1/*` requests require `Authorization: Bearer <application secret>`. The secret authorizes every configured local session; deploy separate services/secrets for applications that must not share that authority. Do not pass a Polymorfa project credential to these endpoints.

| Method | Path | Result |
| --- | --- | --- |
| GET | `/v1/sessions` | Node ID and locally held sessions, each with `id`, `lease_generation`, `claimed`, `has_device_keys`, `state`, nullable `pn` and `lid` |
| POST | `/v1/sessions/{id}/messages` | Send text or one encrypted-media descriptor; returns `message_id`, `server_timestamp`, `resent` |
| GET | `/v1/events?session_id={id}` | SSE stream of decrypted `message` events and explicitly enabled `history.sync` descriptors |
| POST | `/v1/events/{id}/ack` | `204` for a pending event; `404` when no delivery awaits that ID |

A text send has this body:

```json
{"to":"15551234567@s.whatsapp.net","text":"Hello"}
```

Supply exactly one of `text` or `media`. A media send provides an already encrypted/uploaded descriptor; the service does not upload plaintext or fetch media. The OpenAPI schema defines image, video, audio and document descriptors, required hashes/key/path/size fields, and optional metadata. An unknown configured session returns `404`; an unowned or unpaired session returns `409`; disconnected/storage-unavailable operations return `503`; runner rate refusal returns `429`. Local pacing queues sends rather than rejecting them solely because the five-per-second window is full. Invalid input returns `400`. Error envelopes use `{"error":{"code":"...","message":"..."}}`.

If a queued send loses its reply through timeout or connection loss, the service returns `504 send_unconfirmed` with `error.message_id`. This also applies when a participant-hash mismatch acknowledgment requires a resend and that resend fails, even before the second stanza is queued. The first stanza may already have reached some participants. The ordinary `503` response applies only before a send acknowledgment. Retain the ID and reconcile the outcome before sending again. Do not automatically retry: a new POST generates another message ID and can duplicate delivery. The returned ID is neither an idempotency key nor an application-API status lookup.

A sender-key distribution write failure preserves the acknowledgment and permits the one same-ID mismatch resend. Without a mismatch, the confirmed send returns `200`. Fence loss retires the old session and returns the confirmed result without a resend.

Events contain a stable `id`, `type`, `session_id`, routing metadata, `message_id`, `timestamp`, `is_from_me`, `redelivered`, `identity_changed` and `message_proto`. Optional fields include `sender_alt`, `text`, `media` and `history`. `message_proto` is a base64 WhatsApp message protobuf for ordinary messages. History events use an empty `message_proto` and expose only the history notification descriptor (including any inline payload already contained in that notification). Descriptor keys are sensitive application data.

### Acknowledgment and replay

A receive that produces an application event succeeds only after one application acknowledgment. With both channels enabled, the first successful webhook or SSE acknowledgment wins.

- Webhook: any `2xx` response acknowledges the event. Persist/deduplicate the event before responding. Non-`2xx`, redirects, timeouts and connection failures do not acknowledge it.
- SSE: persist/deduplicate the event, then POST its `id` to the ACK route. Multiple subscribers receive the same event; one acknowledgment completes all pending receives for that ID. Keep authorization headers on the stream and ACK request.

The webhook signs the exact request body bytes. Headers are `Signal-Node-Timestamp` (Unix seconds), `Signal-Node-Event-Id`, and `Signal-Node-Signature: v1=<hex HMAC-SHA256>`. The signed bytes are `timestamp + "." + rawBody`. Verify the MAC in constant time and reject timestamps outside a bounded window, such as five minutes, before parsing or processing. The Rust helpers `delivery::verify` and `delivery::verify_recent` implement the MAC and timestamp checks. Deduplicate by event ID in durable application storage; a valid signature alone does not prevent replay.

Only then does the service call `mark_delivered` on its sealed decrypt-buffer record. The runner receives success after that write succeeds. If application acknowledgment or the final write fails, the same ciphertext can replay from the buffer with `redelivered = true`. Application processing and this write cannot form one distributed transaction, so delivery is at least once. Provider redelivery behavior still requires real-account acceptance.

Protocol-only messages such as sender-key distributions and app-state shares do not produce application events; the Signal core processes them locally and marks them consumed without an application ACK. Disabled or foreign-device history notifications also produce no application event. The service never sends decrypted message content in the runner receive response. The service returns app-state key shares to the runner only after explicit operator opt-in and only from the account's own devices. Mixed protocol/text or media messages preserve ordinary application content; their application protobuf omits protocol fields, and history metadata is included only with consent.

SSE buffers at most 1,024 events per connection. A lagging subscriber can miss an event, but it cannot acknowledge an event it never processes. There is no SSE cursor replay or `Last-Event-ID` recovery. Reconnect the stream and rely on runner ciphertext retry plus the sealed buffer for unacknowledged messages. With no webhook and no stream subscriber, receive fails immediately instead of silently dropping an application message. The default acknowledgment timeout is ten seconds.

## App-state key sharing consent

`app_state.share_keys` defaults to `false`. Set it to `true`, or set
`SIGNAL_NODE_APP_STATE_SHARE_KEYS=true`, only after accepting the metadata disclosure.
The environment override accepts `1`, `true`, `yes`, `0`, `false`, or `no`;
other values refuse startup. Keep the setting consistent across deployment replicas.
This consent is independent of `history.deliver`: neither setting enables the other.

When enabled, the service forwards app-state keys received from the account's own
devices to the runner. Foreign-device shares remain excluded. These keys allow the
runner to decrypt synchronized metadata, including contact names, labels and
mute/archive/pin state. Message-plaintext custody does not imply metadata opacity;
Polymorfa can also see operational metadata such as blocklists. Disabling the
setting stops future key forwarding; it cannot recall keys or metadata already
shared. This operator setting grants no session eligibility or hosted-history access.

Shipped-client evidence is Cellar bundle `whatsapp-1049950004`,
`WAWebSyncdDecryptMutations.js:24-35` (key-based mutation decryption) and
`WAWebProtobufSyncAction.pb.js:459-508,1268-1304` (contact, label and chat-state
fields). This evidence does not establish live-provider acceptance or prove that
blocklists use those app-state keys.

## History consent and content limits

`history.deliver` defaults to `false`. Enabling it is an explicit deployment-level consent decision by the customer operator; it does not grant Polymorfa session eligibility, hosted-history storage, or a backend entitlement. Even with consent, only notifications marked `is_from_me` are delivered. The service forwards descriptors and optional inline notification payloads. It never downloads, inflates, stores or MMS-deletes history chunks. The application SDK owns those actions and its own retention decision.

Zero-knowledge sessions do not use hosted message history or content-dependent Campaigns. Polymorfa still sees routing and operational metadata required for transport. The customer service and application see plaintext. A compromised customer host or application bearer can expose it. This service does not remove the need to protect the customer runtime, backups and application database.

## Storage and key custody

Use SQLite for a deployment on one host, or PostgreSQL for multiple hosts. SQLite uses WAL and `BEGIN IMMEDIATE` for atomic fence checks and write batches. Multiple processes can share one local file; do not place that file on a network filesystem for multi-host failover. PostgreSQL locks the lease row and commits each fence check with its write batch. Startup runs the checked-in driver migrations; the database identity needs schema/migration permissions. Use a dedicated customer-owned database and network/TLS policy. The `memory` driver loses state on restart and is for tests only.

Each session gets a random 256-bit data key. An exclusive, fenced insert stores it wrapped with AES-256-GCM under the operator's master key. The wrap authenticates the session scope. Every Signal record then uses the session key and authenticates a length-prefixed domain, scope, namespace and record key. Copying ciphertext to another slot fails authentication. Record keys, namespace tags, session scopes and lease metadata remain readable. Sealing does not detect a rollback to an older valid value in the same slot.

All nodes sharing a deployment need the same master key and database. A wrong key fails session activation without resetting state. Back up the database and master key separately, retain a protected recovery copy, and test restoration in an isolated deployment that cannot compete with production claims. Losing the master key loses access to the sealed device state. Online master/data-key rotation and a sealed cross-mode handoff are not implemented; never overwrite an existing key to simulate rotation. Set an operational rotation plan before approaching AES-GCM's per-key nonce limits.

The sealed decrypt buffer defaults to 14 days; sealed sent-message retry records default to seven days. The pruner runs hourly for locally held sessions. Expired records in inactive/logged-out scopes persist until an owning node prunes them or the operator removes that scope. A retention window bounds replay/retry support, not delivery latency. Retention applies to customer-owned sealed protocol state and is distinct from optional hosted history.

## Scale and failover

Give each replica a unique stable node ID, the same session list, the same master key, and access to the same PostgreSQL store. Each process uses a fresh random incarnation token for its database lease holder, so even a replacement with the same configured node ID cannot share the old fence. Every replica attempts free sessions. The first successful lease holder claims that session over its outbound connection. Polymorfa routes to its highest accepted generation. A closed transport releases its fences, and a new socket claims only after acquiring higher durable generations. A crash leaves the lease to expire; another node then takes a higher generation. The old generation cannot commit record writes after takeover.

Defaults are a 30-second lease TTL and renewal every ten seconds. Keep renewal at most half the TTL. A node stops serving on loss, expiry, or a renewal failure close to expiry. A resumed process checks its deadline before requests and again after send pacing or application ACK. Generation-specific callbacks cannot evict a newer local holder. Keep host clocks synchronized; lease timestamps come from the service clock, so this implementation does not solve arbitrary clock skew. Store loss fails closed; it does not create a new in-memory key store.

The service clamps the upstream send limit to at most five `SendStanza` operations per second per session, including its own participant-hash resend. The runner independently enforces its transport admission limit. Lookups/prekey operations do not consume the service's SendStanza pacing window. The ceiling is not a throughput guarantee or a WhatsApp safety approval.

After a participant-hash mismatch, the service refreshes routing and rebuilds once with the same message ID. WhatsApp Web excludes previously addressed devices; this implementation re-encrypts for all current devices. Real-provider acceptance of that broader resend is unresolved. Source evidence is Cellar bundle `whatsapp-1049950004`, `WAWebSendUserMsgJob.js:53-79` and `WAWebSendGroupSkmsgJob.js:194-213`. Protocol-message dispatch evidence is `WAWebHandleMsgProcess.js:201-228`. Those shipped-client observations do not prove current server behavior.

## Verification and release gates

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
# Use a dedicated fixture database; do not point tests at production.
SIGNAL_NODE_TEST_POSTGRES_URL=postgres://fixture@127.0.0.1/signal_node_tests \
  cargo test --all-targets --locked
cargo test --doc --locked
cargo build --release --locked
```

Without the PostgreSQL variable, local tests explicitly report that PG conformance was not exercised. CI requires it. Tests exercise real SQLite and PostgreSQL store conformance; per-slot authentication; a fake Polymorfa WebSocket with Hello/Welcome/claims; actual two-device Signal encryption/decryption; signed webhook failure/ACK and SSE delivery; encrypted SendStanza; consent-off history; expiry, stale writes and crash replay; and the five-per-second ceiling. The transport peer is a fixture, not a real runner or WhatsApp account.

Release still requires the pinned library producer to merge, backend/SDK/CLI/docs consumers to integrate on explicit revisions, real-account pairing/send/receive/media/history/group/retry acceptance, and the private AGPL/legal review plus owner publication approval. Repository visibility, package/image publication and production rollout controls remain unchanged by this implementation. The service adds no staff control authority; backend-owned eligibility and counts-only diagnostics stay in the Polymorfa control plane.
