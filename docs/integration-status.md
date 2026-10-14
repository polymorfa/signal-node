# Producer integration status

This service implements the accepted server-mode contract. It does not establish deployed zero-knowledge availability or browser remote transport support. Source revisions remain explicit: runner protocol originates at signal-node `b6d5f5f`; Signal libraries are pinned to `b69bc85b5242d48047b87c2189d30693c247b229` in unmerged whatsapp-rust PR #5. The service OpenAPI artifact is the native-client contract.

## Mandatory six-part assessment

| Part | Status | Evidence / remaining owner |
| --- | --- | --- |
| API | Updated locally; upstream integration blocked | Local HTTP OpenAPI, Origin rejection, authenticated SSE/ACK, send and error tests. Protobuf runner contract unchanged. Backend PR #593 owns project-principal live authorization and real runner acceptance. |
| SDKs | Blocked on coordinated consumers | TypeScript and five handwritten native SDK consumers must pin this local application contract. They call the service without taking custody of its master/session keys. Their media/history/storage work is separate from this producer. |
| CLI | Updated service CLI; Polymorfa CLI blocked | `--config`, `--help`, `--version`, private operator key generation and SIGINT/SIGTERM shutdown. Customer CLI must consume accepted SDK/backend revisions; this producer does not edit that repository. |
| Docs | Updated operator/API docs; public release docs blocked | README, example configuration, OpenAPI and this integration record. Parent owns Mintlify guides, language pages, Help Center and release-appropriate changelog. No local draft date is presented as a shipped release. |
| Feature releases | Blocked for release | Backend owns beta eligibility/flag/enrollment/entitlement enforcement. Service does not grant access or change rollout controls. No publication, visibility, tags or production flag edits. Unmerged library producer, real-provider acceptance and legal review remain gates. |
| Admin controls | Unaffected within service authority; backend integration blocked | No customer/control-plane state or staff action is added here. Keys/plaintext remain customer-side. Backend PR #593 owns counts-only transport diagnostics and existing eligibility/disable controls; no new admin credential or direct database authority. |

## All fourteen program layers

| Layer | Service slice status / dependency |
| --- | --- |
| 1. Libraries | Exact producer pin retained; PR #5 unmerged. No upstream library rewrite or publication. |
| 1b. Signal service | Local implementation updated: HTTP API, encrypted runner operations, sealed stores, ACK delivery, failover, operator/container/CI artifacts. |
| 2. Runners / Bartender | Backend PR #593 integration pending. Fake WS exercises Hello/Welcome/claims/SendStanza, not a live runner. Bartender unchanged by this service. |
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

Real WhatsApp pairing, media/history download, group resend, retry receipts and server redelivery have not been exercised. The participant-hash resend addresses every current device rather than WA Web's exclusion list; provider acceptance remains unresolved. Arbitrary clock skew, key rotation and same-slot rollback protection are not implemented. Browser remote relay is blocked pending distinct short-lived client grant authority. AGPL/legal review and owner approval are required before making this repository or artifacts public.
