# Producer integration status

This service implements the accepted server-mode contract. It does not establish deployed zero-knowledge availability or browser remote transport support. Source revisions remain explicit: runner protocol originates at signal-node `b6d5f5f` and adds durable public upload requests 20/21 and response 18 without changing protocol version 1; all Signal library families are pinned to `4b3b13cacd40a27573d0246386db553ef887539b` in unmerged whatsapp-rust PR #5. The unchanged service OpenAPI artifact is the application/native-client contract.

## Mandatory six-part assessment

| Part | Status | Evidence / remaining owner |
| --- | --- | --- |
| API | Updated locally; upstream integration blocked | Additive protobuf upload prepare/ACK and full-batch response; local HTTP/OpenAPI, Origin rejection and SSE/ACK contract unchanged by this checkpoint. Backend PR #593 and HyperMeow own exact wire consumption, live authorization and real runner acceptance. |
| SDKs | Application HTTP unaffected by this wire addition; program integration remains coordinated | Native application clients do not implement private runner prekey operations or import the AGPL core. Parent coordinates TypeScript and five handwritten native consumers against exact application pins. The separate WASM producer shares the guarded core API; no private service proto belongs in MIT SDKs. |
| CLI | Updated service CLI; Polymorfa CLI blocked | `--config`, `--help`, `--version`, private operator key generation and SIGINT/SIGTERM shutdown. Customer CLI must consume accepted SDK/backend revisions; this producer does not edit that repository. |
| Docs | Updated operator/API docs; public release docs blocked | README, example configuration, OpenAPI and this integration record. Parent owns Mintlify guides, language pages, Help Center and release-appropriate changelog. No local draft date is presented as a shipped release. |
| Feature releases | Blocked for release | Backend owns beta eligibility/flag/enrollment/entitlement enforcement. Service does not grant access or change rollout controls. No publication, visibility, tags or production flag edits. Unmerged library producer, real-provider acceptance and legal review remain gates. |
| Admin controls | Unaffected within service authority; backend integration blocked | No customer/control-plane state or staff action is added here. Keys/plaintext remain customer-side. Backend PR #593 owns counts-only transport diagnostics and existing eligibility/disable controls; no new admin credential or direct database authority. |

## All fourteen program layers

| Layer | Service slice status / dependency |
| --- | --- |
| 1. Libraries | All normal/dev families repinned to exact `4b3b13c`; PR #5 unmerged. Durable atomic upload batches, exact replay ACK and fresh-only legacy marks consumed without a private-format parser. No library rewrite or publication here. |
| 1b. Signal service | Additive durable upload dispatch and core-backed local uploaded count; real framed SQLite/PostgreSQL recovery and rollback tests. HTTP routes, consent, key custody and runtime policy unchanged. |
| 2. Runners / Bartender | HyperMeow explicit batch interface and backend PR #593 wire/vendor integration remain pending. Unknown operations fail Unsupported without fresh-generation fallback. Fake WS is not a live runner; Bartender unchanged. |
| 3. Temporal | Parent/backend owner assesses workflows and transport recovery; this process creates no Temporal workflow or control-plane command. |
| 4. Customer API | Backend PR #593 owns mode, consent, refusal and project authority. Local API cannot bypass them. |
| 5. Admin API | Backend owns bounded diagnostics/capabilities. Service does not expose customer keys to staff. |
| 6. Inspector | Parent owns real-account acceptance scenarios; local two-device fixture is not Inspector acceptance. |
| 7. Console UI | Parent owns customer mode/consent/trade-off flow and backend integration. |
| 8. Admin UI | Parent/backend owner integrates diagnostics through API-owned authority. No service management UI added. |
| 9. SDKs | Parent coordinates TS + Go/Python/PHP/Rust/C# media/history/storage and sidecar clients against exact producer pins. |
| 10. CLI | Service CLI updated. Polymorfa CLI integration remains with its owner. |
| 11. Docs | Operator/API documentation updated here. Public Mintlify guides/references/language pages remain coordinated by parent. |
| 12. Help Center | Parent owns consent and operational trade-off article; no shipped availability claim in this producer. |
| 13. Marketing | Parent owns release-aligned copy; no announcement or availability claim authorized here. |

## Verification limits

Native checks use Rust 1.94 and a dedicated real PostgreSQL fixture plus SQLite. The integration transport is a fake Polymorfa peer; actual Signal encryption/decryption runs on both devices. Tests cover application ACK before durable delivery, HMAC over exact bytes, webhook rejection/redirect, SSE duplicate waiters, sealed replay after crash, old-generation writes, expiry/reacquisition, slot authentication, history consent and send pacing.

Durable-upload tests additionally prepare 812, reopen the service/store and request 50 while retaining the full original batch. Real SQL failures at pending publication and ACK receipt insertion roll back counter/private-key or uploaded-flag changes. An actual encrypted receive consumes a pending key, the app fsyncs its receipt before ACK, and the subsequent batch ACK cannot resurrect that key. Discarding a serialized ACK response, reopening and repeating the exact ACK leaves a newer pending batch unchanged. Partial, duplicate, foreign, malformed and stale acknowledgments fail; legacy marks refuse mixed/consumed pending members. Wire-tag fixtures preserve additive version-1 decoding. Malformed frames allocate nothing; a frame above the existing 16 MiB transport ceiling reconnects with a higher fence and recovers the pending batch.

The existing `[app_state].share_keys` opt-in remains false by default and requires own-device evidence when enabled. That exception permits contact-name, label and mute/archive/pin metadata decryption; message plaintext custody does not promise metadata opacity. QuickLink admission, short-lived tunnel/grant authority, Temporal, standard-custody behavior, billing/metering, logging and hosted retention are unchanged. No public release record or feature-flag change is warranted for an unmerged private protocol producer; parent owns coordinated release documentation and availability gates.

Real WhatsApp pairing, media/history download, group resend, retry receipts and server redelivery have not been exercised. The participant-hash resend addresses every current device rather than WA Web's exclusion list; provider acceptance remains unresolved. Arbitrary clock skew, key rotation and same-slot rollback protection are not implemented. Browser remote relay is blocked pending distinct short-lived client grant authority. AGPL/legal review and owner approval are required before making this repository or artifacts public.
