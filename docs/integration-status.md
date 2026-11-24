# Signal service integration status

The service is private and unmerged. Local verification does not establish live
WhatsApp, hosted transport, deployment or package availability. This Connection
candidate preserves rename source `61209057729b002a2122b898d744a8813a702fc7` and
implementation PR [#1](https://github.com/polymorfa/signal-node/pull/1) target
`4d9694eaf97deca34c78990d1293b2b533e19d17`. Its existing PR
[#3](https://github.com/polymorfa/signal-node/pull/3) targets
`feat/signal-service-completion-20261014`, not `main`. Attribution PR #2 is separate.

## Producer and client ABI

| Boundary | Current source and contract |
| --- | --- |
| Signal core | `wacore`, `wacore-binary` and `waproto` use oxidezap/whatsapp-rust `2671430db6161c01c507587d0e3c90dcf153aa85`. |
| Record store and Signal operations | Workspace crates under `crates/recordstore` and `crates/signal-ops`, preserved from target4d9694e. Their cryptographic sessions, trust/cancellation/prekey behavior and storage domains are not account-resource aliases. |
| Toolchain and native checks | Rust1.95.0; accepted workspace/lock, CI matrix and Docker inputs remain. |
| Runner protocol | `proto/polymorfa/signal/v1/signal_service.proto`, protocol1 and subprotocol `polymorfa.signal.v1`. Account symbols change; numeric tags, types, enum values and oneof positions remain. |
| Companion identity | Accepted target adds `Receive.device_identity` tag10 and `Bundle.device_identity` tag8. Bytes are forwarded to existing verification; they are not synthesized or substituted from the service's own identity. |
| Application API | `docs/app-api.openapi.json`; `/v1/connections`, `connection_id` events/filter and canonical account errors. Actual phone and per-peer Signal session fields retain their meanings. |
| Configuration | `polymorfa.connections`, `SIGNAL_NODE_CONNECTIONS`; stable configured selector values and local lease generations retain their values. |

Account messages are `ClaimConnection`, `ReleaseConnection`, `ConnectionClaimed`
and `ConnectionEvent`. The complete descriptor matches target4d9694e after only
the exact account-name mapping, including the accepted companion additions.
Two native wire regressions pin lease/event tags and companion byte fields.
The unavailable-account enum remains numeric8. No account compatibility alias,
retired HTTP route or permissive old event-filter reader is added.

Signal ratchets, `Namespace::Session`, upstream Signal errors,
`peer_data_request_session_id`, stored record keys, sealing domains, IDs and
fences retain their meanings and bytes. Retry-receipt bundles establish a fresh
Signal session, not a fresh account Connection. Application event IDs retain the
accepted target's domain and length-prefixed account selector, so an ACK cannot
complete another Connection's event.

## Companion producer dependencies

The pinned backend HyperMeow `c858e73f841a` does not carry these identity bytes
through `RemoteReceive`, and its existing `prekey.Bundle` conversion does not
supply the companion identity. Regeneration alone cannot populate them.

Existing counterpart [HyperMeow #69](https://github.com/polymorfa/hypermeow/pull/69),
head `4792d8dfc24c793711dd563079bba8fae787ec98`, adds
`RemoteReceive.DeviceIdentity` for prekey messages and
`FetchPreKeysWithIdentityNoError` / `FetchedPreKey.DeviceIdentity`. Existing bundle
APIs stay unchanged; its shadow relay still has no identity bytes. This source
has a separate human-maintainer and native/provider acceptance boundary.

The existing backend counterpart is [Polymorfa #1037](https://github.com/polymorfa/polymorfa/pull/1037),
source `e8ab3e02b00f76b63c6918232e3ca7c6ddd8d6c0`, supplied by the family owner.
It carries the narrow HyperMeow companion producer, receive/bundle projections,
WebSocket regression and generated bindings. Root owns preserved integration into
[Backend #1022](https://github.com/polymorfa/polymorfa/pull/1022) and regeneration
against this exact final Signal proto. No monorepo/library pin, binding or runtime
producer was edited in this service lane. Consumer composition remains pending;
this document does not claim that the published backend already carries it.

Cellar shipped-client evidence is bundle `whatsapp-1054794655`, indexed2026-11-16,
with zero chunk/codegen failures and5719 unresolved dependencies.
`WAWebMsgProcessingDecryptApi.js:24-39` passes received device identity into
companion verification before decryption. `WAWebAdvSignatureApi.js:42-59,80-91`
checks account/device signatures and selects the prekey verification path.
These are shipped-client observations, not current server or live-provider
acceptance. The service retains the target's verification and refusal gates;
missing data does not justify bypassing them.

## Verification and availability

The preserved candidate passes178 workspace/all-target native tests with zero
failed or ignored cases, including two new binary contract regressions. Tests
use a dedicated real PostgreSQL16.14 instance, real SQLite, sealed state and
actual synthetic-device Signal crypto with a framed fixture peer. Authentication,
Origin rejection, canonical routes, rejected old filters, claim/generation fences,
trust/cancellation, consent, prekey batch recovery and ACK isolation remain tested.
Strict workspace/all-target Clippy, formatting and Buf lint/build pass.

The actual debug binary reports `signal-node/0.1.0`. Release compilation is not
attempted at the observed1.6GiB free disk. Docker runtime is unavailable locally;
container/TLS/native provider acceptance remains hosted. Official MBX Cargo is
used without manual cache, target, profile, cap or authentication changes.
Automatic MBX collection is host-managed and remains in the command receipts.

The customer API, six SDKs, CLI, integrations, Inspector, Console, Connect,
Admin, docs and Help Center remain in the same coordinated family. This producer
adds no eligibility, enrollment, feature flag, metering/financial authority,
QuickLink/browser tunnel grant, staff authority or hosted history access. Existing
app-state/history opt-ins and customer custody boundaries remain. Source API date
and public-spec availability are owned by the family release record.

Real pairing, send/receive/media/history/group/retry and retained/signed-state
acceptance remain separate gates. Private AGPL/legal review, human notice/approval,
exact merged source cohorts and owner publication authority remain. No merge,
deployment, publication, provider configuration or main-only cutover occurs here.
Rollback must preserve sealed/device/prekey state, event identity and fences;
never reset keys or weaken verification to fit an older consumer.
