# Review follow-up, 2026-10-27

This source batch follows `4312d82ae5811cd1b94861a530a7864a4596e576` in PR #1. It does not establish a deployed service or live WhatsApp session.

| Review remark | Change | Behavioral evidence |
| --- | --- | --- |
| Codex and CodeRabbit: SQLite cancellation leaves a transaction open | Own the pooled connection before `BEGIN IMMEDIATE`; detach and close it on cancellation or an unconfirmed commit/rollback | Cancellation regression first exposed an uncommitted row through the pool; it now rolls back and permits an independent writer. A deferred foreign-key commit failure also rolls back before reuse. |
| CodeRabbit: timeout is an unknown send outcome | Return `504 send_unconfirmed` and the original `error.message_id` after a queued send loses its answer | Actual HTTP/WebSocket tests cover timeout and disconnect after accepting one stanza, with the returned ID matching the stanza and no retry. |
| CodeRabbit: sender-key bookkeeping failure must not turn an accepted send into an error | Preserve the runner-confirmed result and log metadata only; fence loss still retires the old session | Actual group send with SQLite trigger failure and a durable generation change returns `200`, sends once and invalidates the superseded session. |
| CodeRabbit: message context is not application content | Remove context only from the content probe | Real encrypted protocol-only shares with context require no application ACK; mixed messages retain their text and context. |
| CodeRabbit: remove per-scope receipt directories | Close and remove the synthetic receipt after its durable write and ACK | SQLite framed upload/receive recovery test passes with cleanup. |
| CodeRabbit review-body suggestion: checkout credentials | Set `persist-credentials: false` on both checkout steps | Workflow diff; hosted workflow execution remains required. |
| CodeRabbit review-body suggestion: count matching SSE subscribers | Use channels for the exact session filter and all-session subscribers; prune channels without receivers | Library and actual HTTP/encrypted-receive tests refuse unwatched sessions immediately, while matching and unfiltered ACK paths pass. |

Native local checks use Rust 1.94.0 under the shared `run.py` resource lease. The all-target harness reports 50 passing cases; two PostgreSQL-gated cases return without running because the local fixture URL is unset, so 48 cases execute locally. Hosted CI supplies PostgreSQL and remains a separate gate. No resource bound, assertion or timeout was raised.

Shipped-client evidence was refreshed to Cellar bundle `whatsapp-1051710191`. `modules/WAWebSendGroupSkmsgJob.js:188-205` receives/parses the send ACK before recording sender-key distribution and handling participant-hash changes. `modules/WAWebDeviceSentMessageProtoUtils.js:14-29` treats message context as accompanying metadata when wrapping a device-sent message. These sources support the ordering and context distinction; they do not establish server acceptance or exactly-once delivery. The explicit unconfirmed HTTP result is this service's contract.

Owner decisions: address valid bot remarks and make staging available for the owner's team/project. Agent decisions: retain the existing PR, preserve the pinned Signal core, keep the original message identity on uncertainty, and apply the smallest fixes above. Open items: exact staging team/project, deployment source, API version selection, release/runtime policy and enrollment, service hosting and real-device acceptance. Production controls and package publication are outside the staging request.

The local application HTTP API, README and OpenAPI change together. No Signal wire field, core storage ABI, crypto algorithm, runner, Temporal, platform API, Admin API/MCP/UI, Console, Inspector, SDK/CLI source, billing meter, analytics event, retained content policy or production release control changes in this batch. The repository SDKs use the platform APIs and do not call this private sidecar endpoint. Integrators of the sidecar must handle the documented unconfirmed result without automatic resends.

Rollback before deployment can revert this source batch. After deployment, preserve sealed records, durable lease generations, pending prekey batches and application receipts. A rollback must not turn an unconfirmed send into a new message. Staging test access and customer release have separate receipts.

Session: T3 `319f8994-cdc7-4427-b681-cb437bbb9da2`, Codex `gpt-6.1-sol`, existing registration polymorfa/polymorfa#511. The [selected visible checkpoint](https://github.com/polymorfa/polymorfa/blob/3f52123a64715db4cd9486087d39e78fcd400bd0/internal/agent-sessions/sessions/purpshell-t3-codex/signal-review-staging-20261027/1df203a245094aa0c2c800cb4f4f653773d1559d27766f5ca8b3d1fa9dae2e32.md) is committed in the monorepo at `3f52123a64715db4cd9486087d39e78fcd400bd0`. It records nine selected entries, summarized tool evidence, checkpoint timestamps and manual capture gaps. It excludes authentication URLs/screens and hidden reasoning. No automated review was requested. Linear lookup remains inaccessible; the existing Notion feature records were read with their truncation limits.

## Mismatch resend follow-up

Two new findings on `f3d6a8c8fe4d6b76021fe08227e72d16dc566fb8` were valid.

| Review thread | Finding and repair | Behavioral evidence |
| --- | --- | --- |
| `PRRT_kwDOVETUrM6wf9zO` | Failure after the first mismatch ACK escaped as an ordinary error. Convert every failure in that resend attempt, including preparation and pre-queue failures, to `504 send_unconfirmed` with the original ID. Update README and OpenAPI. | HTTP/WebSocket regression first returned `502 send_failed` without the ID. It now returns the same ID for routing disconnect, runner refusal and a lost resend reply. One or two observed stanzas, as appropriate, all retain that ID; no third send occurs. |
| `PRRT_kwDOVETUrM6wf9zP` | A distribution bookkeeping error suppressed the mismatch resend. Continue after ordinary storage errors; only fence loss returns the confirmed result early and retires the session. | SQLite trigger and durable generation-change tests cover both errors with and without a mismatch. Ordinary storage failure plus mismatch first sent once instead of twice; it now resends once under the original ID. Fence loss sends once and invalidates the old holder. |

Rust 1.94.0 validation through `run.py` reports 51 passing all-target cases, including 17 actual HTTP/WebSocket cases. Two PostgreSQL-gated cases return without running because the local fixture URL is unset, so 49 cases execute locally. Strict all-target Clippy, formatting, zero doctests, diff checks, OpenAPI JSON and local references pass at the standard resource bounds. Hosted checks for the new head remain required.

Cellar bundle `whatsapp-1051710191`, `modules/WAWebSendGroupSkmsgJob.js:188-205`, confirms the ACK precedes sender-key bookkeeping and mismatch handling. Lines 209-224 catch a resend failure while preserving the original message record. This supports the ordering; the service's explicit `send_unconfirmed` response remains its own contract. Live server acceptance is unverified.

The existing owner decisions, impact assessment and rollback rules above still apply. No core repin or wire/storage change is included. Rust #5 remains blocked on four CodSpeed upload `401 Unauthorized` results and E2E workflow validation at its empty `BARTENDER_GHCR_TOKEN` password. The repository secret list is empty; organization-level secret availability was not independently inspected. Preserve the authorized order: green Rust #5, then service repin and green service #1. No registry publication or deployment occurred.

The [selected resend checkpoint](https://github.com/polymorfa/polymorfa/blob/b94794a9e9d0992ffcbc7c4b541ac8c89874f858/internal/agent-sessions/sessions/purpshell-t3-codex/signal-resend-followup-20261027/f85e98ab600c7c2d0e807e45d6b27d222603d15964b83dd9a09b3b3107daebf6.md), evidence commit `b94794a9e9d0992ffcbc7c4b541ac8c89874f858`, records nine selected entries with manual capture gaps and checkpoint timestamps. Registration and T3 thread are unchanged. No automated review was requested.
