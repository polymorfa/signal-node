//! Durable upload recovery through the actual serialized WebSocket boundary.
mod support;

use futures_util::StreamExt;
use prost::Message as _;
use signal_node::{
    proto::{self, frame::Body, runner_request::Op, service_response::Result as Out},
    store::{Backend, PostgresStore, SqliteStore},
};
use std::{path::PathBuf, time::Duration};
use support::{APP_SECRET, Hub, config, peer, wait};
use wacore::types::jid::JidExt as _;
use wacore_recordstore::{Namespace, RecordStore};
use waproto::whatsapp as wa;

enum Database {
    Sqlite {
        url: String,
        path: PathBuf,
        pool: sqlx::SqlitePool,
    },
    Postgres {
        pool: sqlx::PgPool,
    },
}
impl Database {
    async fn sqlite() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-state");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("upload-{}.sqlite", rand::random::<u64>()));
        let url = format!("sqlite://{}", path.display());
        let _ = SqliteStore::connect(&url, 2).await.unwrap();
        let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
        Self::Sqlite { url, path, pool }
    }
    async fn postgres() -> Option<Self> {
        let Ok(url) = std::env::var("SIGNAL_NODE_TEST_POSTGRES_URL") else {
            assert!(
                std::env::var("CI").is_err(),
                "CI requires PostgreSQL proofs"
            );
            eprintln!("PostgreSQL upload proof not run: fixture URL unset");
            return None;
        };
        Some(Self::Postgres {
            pool: sqlx::PgPool::connect(&url).await.unwrap(),
        })
    }
    async fn reopen(&self) -> Backend {
        match self {
            Self::Sqlite { url, .. } => {
                Backend::Sqlite(SqliteStore::connect(url, 4).await.unwrap())
            }
            Self::Postgres { pool } => {
                Backend::Postgres(PostgresStore::from_pool(pool.clone()).await.unwrap())
            }
        }
    }
    // Inject a real SQL error at pending publication or ACK receipt insertion.
    // Conditions isolate this trigger to the test's random session scope.
    async fn fail_on(&self, scope: &str, key: &str) {
        let token = scope.strip_prefix("upload_").unwrap();
        let key = hex::encode(key);
        match self {
            Self::Sqlite { pool, .. } => {
                let sql = format!(
                    "CREATE TRIGGER upload_failure BEFORE INSERT ON signal_records WHEN NEW.scope = '{scope}' AND NEW.ns = 'device' AND NEW.key = X'{key}' BEGIN SELECT RAISE(ABORT, 'synthetic atomic failure'); END"
                );
                sqlx::query(&sql).execute(pool).await.unwrap();
            }
            Self::Postgres { pool } => {
                let sql = format!(
                    "CREATE FUNCTION upload_failure_{token}() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN IF NEW.scope = '{scope}' AND NEW.ns = 'device' AND NEW.key = decode('{key}', 'hex') THEN RAISE EXCEPTION 'synthetic atomic failure'; END IF; RETURN NEW; END $$"
                );
                sqlx::query(&sql).execute(pool).await.unwrap();
                sqlx::query(&format!("CREATE TRIGGER upload_failure_{token} BEFORE INSERT ON signal_records FOR EACH ROW EXECUTE FUNCTION upload_failure_{token}()"))
                    .execute(pool).await.unwrap();
            }
        }
    }
    async fn clear_failure(&self, scope: &str) {
        let token = scope.strip_prefix("upload_").unwrap();
        match self {
            Self::Sqlite { pool, .. } => {
                sqlx::query("DROP TRIGGER upload_failure")
                    .execute(pool)
                    .await
                    .unwrap();
            }
            Self::Postgres { pool } => {
                sqlx::query(&format!(
                    "DROP TRIGGER upload_failure_{token} ON signal_records"
                ))
                .execute(pool)
                .await
                .unwrap();
                sqlx::query(&format!("DROP FUNCTION upload_failure_{token}()"))
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
    }
    async fn cleanup(self, scope: &str) {
        match self {
            Self::Sqlite { pool, path, .. } => {
                pool.close().await;
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
                let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
            }
            Self::Postgres { pool } => {
                sqlx::query("DELETE FROM signal_records WHERE scope = $1")
                    .bind(scope)
                    .execute(&pool)
                    .await
                    .unwrap();
                sqlx::query("DELETE FROM signal_leases WHERE scope = $1")
                    .bind(scope)
                    .execute(&pool)
                    .await
                    .unwrap();
                pool.close().await;
            }
        }
    }
}

fn request(scope: &str, generation: u64, op: Op) -> proto::RunnerRequest {
    proto::RunnerRequest {
        session_id: scope.into(),
        lease_generation: generation,
        op: Some(op),
    }
}
async fn start(
    hub: &Hub,
    name: &str,
    scope: &str,
    backend: Backend,
    ttl: u64,
) -> signal_node::Running {
    let mut cfg = config(name, &hub.url, false);
    cfg.sessions = vec![scope.into()];
    cfg.lease_ttl_ms = ttl;
    // Keep fixture reacquisition within Hub's five-second test deadline;
    // bulk SQL work still gets the configured, unchanged lease TTL.
    cfg.lease_renew = Duration::from_millis((ttl / 4).min(100));
    let running = signal_node::start(cfg, backend).await.unwrap();
    wait(|| running.node.session(scope).is_some_and(|s| s.is_claimed())).await;
    running
}
fn result(frame: proto::Frame) -> Out {
    let Some(Body::ServiceResponse(proto::ServiceResponse {
        result: Some(result),
    })) = frame.body
    else {
        panic!("expected service response");
    };
    result
}
fn error(frame: proto::Frame, expected: proto::Code) {
    let Some(Body::Error(error)) = frame.body else {
        panic!("expected safe contract error");
    };
    assert_eq!(error.code_enum(), expected);
    assert!(!error.message.contains("synthetic atomic failure"));
}
fn ok(frame: proto::Frame) {
    assert!(matches!(result(frame), Out::Ok(_)));
}
async fn prepare(
    hub: &Hub,
    name: &str,
    scope: &str,
    generation: u64,
    count: u32,
) -> proto::PreKeyUploadBatch {
    let Out::PreKeyUploadBatch(batch) = result(
        hub.request(
            name,
            request(
                scope,
                generation,
                Op::PreparePreKeyUpload(proto::PreparePreKeyUpload { count }),
            ),
        )
        .await,
    ) else {
        panic!("expected public batch");
    };
    assert_eq!(batch.batch_id.len(), 32);
    assert!(
        batch
            .batch_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert!((1..=812).contains(&batch.pre_keys.len()));
    let ids: std::collections::BTreeSet<_> = batch.pre_keys.iter().map(|key| key.id).collect();
    assert_eq!(ids.len(), batch.pre_keys.len());
    for key in &batch.pre_keys {
        assert!((1..=0x00ff_ffff).contains(&key.id));
        assert_eq!(key.public_key.len(), 32);
    }
    batch
}
async fn count(hub: &Hub, name: &str, scope: &str, generation: u64) -> u32 {
    let Out::PreKeyCount(count) = result(
        hub.request(
            name,
            request(
                scope,
                generation,
                Op::UploadedPreKeyCount(proto::UploadedPreKeyCount {}),
            ),
        )
        .await,
    ) else {
        panic!("expected local count");
    };
    count.count
}
fn ack(batch: &proto::PreKeyUploadBatch, ids: Vec<u32>) -> Op {
    Op::AcknowledgePreKeyUpload(proto::AcknowledgePreKeyUpload {
        batch_id: batch.batch_id.clone(),
        ids,
    })
}

// Models a future unrecognized operation; the service must refuse it rather
// than silently allocate fresh keys. The raw request traverses actual framing.
#[derive(prost::Message)]
struct FutureRequest {
    #[prost(string, tag = "1")]
    session_id: String,
    #[prost(uint64, tag = "2")]
    lease_generation: u64,
    #[prost(bytes = "vec", tag = "99")]
    future_operation: Vec<u8>,
}
// An old receiver knows only legacy fresh generation. Newly added request
// cases therefore decode to None under the existing additive protocol v1.
#[derive(prost::Message)]
struct OldRequest {
    #[prost(string, tag = "1")]
    session_id: String,
    #[prost(uint64, tag = "2")]
    lease_generation: u64,
    #[prost(message, optional, tag = "11")]
    generate: Option<proto::GeneratePreKeys>,
}

async fn consume_pending(
    hub: &Hub,
    name: &str,
    scope: &str,
    running: &signal_node::Running,
    batch: &proto::PreKeyUploadBatch,
    identity: proto::Identity,
) {
    let generation = running.node.session(scope).unwrap().generation;
    let (sender, _) = peer("upload-sender-fixture").await;
    let target: wacore_binary::Jid = "222:1@s.whatsapp.net".parse().unwrap();
    sender
        .establish_session(
            &target.to_protocol_address(),
            &signal_node::resolver::remote_bundle(&proto::Bundle {
                registration_id: identity.registration_id,
                device_id: 1,
                identity_key: identity.identity_key,
                signed_pre_key_id: identity.signed_pre_key_id,
                signed_pre_key: identity.signed_pre_key,
                signed_pre_key_signature: identity.signed_pre_key_signature,
                pre_key: Some(batch.pre_keys[0].clone()),
            })
            .unwrap(),
        )
        .await
        .unwrap();
    let body = wa::Message {
        conversation: Some("synthetic pending-prekey consumption".into()),
        ..Default::default()
    };
    let bytes = wacore::messages::MessageUtils::pad_message_v2(signal_node::message::encode(&body));
    let encrypted = sender
        .encrypt(&target.to_protocol_address(), &bytes)
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let base = format!("http://{}", running.http_addr);
    let mut events = client
        .get(format!("{base}/v1/events"))
        .bearer_auth(APP_SECRET)
        .send()
        .await
        .unwrap()
        .bytes_stream();
    let receive = proto::Receive {
        chat: "111@s.whatsapp.net".into(),
        sender: "111:1@s.whatsapp.net".into(),
        message_id: "upload-consumption".into(),
        kind: encrypted.kind.wire().into(),
        ciphertext: encrypted.ciphertext,
        padding_version: 2,
        is_from_me: false,
        timestamp: 1720000000,
        sender_alt: String::new(),
    };
    let delivery = hub.request(name, request(scope, generation, Op::Receive(receive)));
    let app = async {
        let event = tokio::time::timeout(Duration::from_secs(3), async {
            let mut bytes = Vec::new();
            loop {
                bytes.extend_from_slice(&events.next().await.unwrap().unwrap());
                if let Some(data) = String::from_utf8_lossy(&bytes)
                    .lines()
                    .find_map(|line| line.strip_prefix("data: "))
                {
                    break serde_json::from_str::<serde_json::Value>(data).unwrap();
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(event["text"], "synthetic pending-prekey consumption");
        // The app's fixture receipt is durable before its explicit HTTP ACK.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-state")
            .join(scope);
        std::fs::create_dir_all(&dir).unwrap();
        use std::io::Write as _;
        let mut file = std::fs::File::create(dir.join("event.json")).unwrap();
        file.write_all(&serde_json::to_vec(&event).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        std::fs::File::open(&dir).unwrap().sync_all().unwrap();
        drop(file);
        assert_eq!(
            client
                .post(format!(
                    "{base}/v1/events/{}/ack",
                    event["id"].as_str().unwrap()
                ))
                .bearer_auth(APP_SECRET)
                .send()
                .await
                .unwrap()
                .status(),
            204
        );
        std::fs::remove_dir_all(&dir).unwrap();
    };
    let (received, ()) = tokio::join!(delivery, app);
    assert!(matches!(
        result(received),
        Out::Receive(proto::ReceiveResult {
            already_delivered: false,
            ..
        })
    ));
}

async fn exercise_database(db: Database) {
    let scope = format!("upload_{:016x}", rand::random::<u64>());
    let hub = Hub::start().await;
    let backend = db.reopen().await;
    let first = start(&hub, "upload-first", &scope, backend.clone(), 30_000).await;
    let generation = first.node.session(&scope).unwrap().generation;
    let init = hub
        .request(
            "upload-first",
            request(&scope, generation, Op::GetIdentity(proto::GetIdentity {})),
        )
        .await;
    let Out::Identity(identity) = result(init) else {
        panic!("missing identity");
    };
    let before = backend
        .get(&scope, Namespace::Device, "local")
        .await
        .unwrap();
    for value in [0, 813, u32::MAX] {
        error(
            hub.request(
                "upload-first",
                request(
                    &scope,
                    generation,
                    Op::PreparePreKeyUpload(proto::PreparePreKeyUpload { count: value }),
                ),
            )
            .await,
            proto::Code::InvalidArgument,
        );
    }
    db.fail_on(&scope, "prekey-upload-v1").await;
    error(
        hub.request(
            "upload-first",
            request(
                &scope,
                generation,
                Op::PreparePreKeyUpload(proto::PreparePreKeyUpload { count: 812 }),
            ),
        )
        .await,
        proto::Code::Unavailable,
    );
    assert!(
        backend
            .scan_keys(&scope, Namespace::PreKey, "", None)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        backend
            .get(&scope, Namespace::Device, "local")
            .await
            .unwrap(),
        before
    );
    db.clear_failure(&scope).await;
    let batch = prepare(&hub, "upload-first", &scope, generation, 812).await;
    assert_eq!(batch.pre_keys.len(), 812);
    for _ in 0..3 {
        assert_eq!(
            prepare(&hub, "upload-first", &scope, generation, 1).await,
            batch
        );
    }
    assert_eq!(count(&hub, "upload-first", &scope, generation).await, 0);
    first.shutdown().await;
    drop(backend);

    let backend = db.reopen().await;
    let second = start(&hub, "upload-second", &scope, backend.clone(), 30_000).await;
    let generation2 = second.node.session(&scope).unwrap().generation;
    assert!(generation2 > generation);
    assert_eq!(
        prepare(&hub, "upload-second", &scope, generation2, 50).await,
        batch
    );
    error(
        hub.request(
            "upload-second",
            request(
                &scope,
                generation,
                Op::PreparePreKeyUpload(proto::PreparePreKeyUpload { count: 50 }),
            ),
        )
        .await,
        proto::Code::NotLeaseHolder,
    );
    error(
        hub.request(
            "upload-second",
            request(
                "other-session",
                generation2,
                Op::PreparePreKeyUpload(proto::PreparePreKeyUpload { count: 1 }),
            ),
        )
        .await,
        proto::Code::NotLeaseHolder,
    );
    let pending_before = backend
        .get(&scope, Namespace::Device, "prekey-upload-v1")
        .await
        .unwrap();
    let keys_before = backend
        .scan_keys(&scope, Namespace::PreKey, "", None)
        .await
        .unwrap();
    error(
        hub.raw_request(
            "upload-second",
            FutureRequest {
                session_id: scope.clone(),
                lease_generation: generation2,
                future_operation: vec![1],
            }
            .encode_to_vec(),
        )
        .await,
        proto::Code::Unsupported,
    );
    assert_eq!(
        backend
            .scan_keys(&scope, Namespace::PreKey, "", None)
            .await
            .unwrap(),
        keys_before
    );
    assert_eq!(
        backend
            .get(&scope, Namespace::Device, "prekey-upload-v1")
            .await
            .unwrap(),
        pending_before
    );
    let added = request(
        &scope,
        generation2,
        Op::PreparePreKeyUpload(proto::PreparePreKeyUpload { count: 50 }),
    );
    assert!(
        OldRequest::decode(added.encode_to_vec().as_slice())
            .unwrap()
            .generate
            .is_none()
    );
    let Out::PreKeys(fresh) = result(
        hub.request(
            "upload-second",
            request(
                &scope,
                generation2,
                Op::GeneratePreKeys(proto::GeneratePreKeys { count: 1 }),
            ),
        )
        .await,
    ) else {
        panic!("missing fresh retry keys");
    };
    let fresh = fresh.pre_keys[0].id;
    error(
        hub.request(
            "upload-second",
            request(
                &scope,
                generation2,
                Op::MarkPreKeysUploaded(proto::MarkPreKeysUploaded {
                    ids: vec![fresh, batch.pre_keys[0].id],
                }),
            ),
        )
        .await,
        proto::Code::InvalidArgument,
    );
    assert_eq!(count(&hub, "upload-second", &scope, generation2).await, 0);
    ok(hub
        .request(
            "upload-second",
            request(
                &scope,
                generation2,
                Op::MarkPreKeysUploaded(proto::MarkPreKeysUploaded { ids: vec![fresh] }),
            ),
        )
        .await);
    consume_pending(&hub, "upload-second", &scope, &second, &batch, identity).await;
    assert!(
        backend
            .get(
                &scope,
                Namespace::PreKey,
                &format!("{:010}", batch.pre_keys[0].id)
            )
            .await
            .unwrap()
            .is_none()
    );
    let filtered = prepare(&hub, "upload-second", &scope, generation2, 50).await;
    assert_eq!(filtered.batch_id, batch.batch_id);
    assert_eq!(filtered.pre_keys, batch.pre_keys[1..]);
    error(
        hub.request(
            "upload-second",
            request(
                &scope,
                generation2,
                Op::MarkPreKeysUploaded(proto::MarkPreKeysUploaded {
                    ids: vec![batch.pre_keys[0].id],
                }),
            ),
        )
        .await,
        proto::Code::InvalidArgument,
    );
    let ids: Vec<_> = batch.pre_keys.iter().map(|key| key.id).collect();
    for invalid in [
        ack(&batch, vec![]),
        ack(&batch, vec![0]),
        ack(&batch, vec![0x0100_0000]),
        ack(&batch, vec![ids[1]]),
        ack(&batch, vec![ids[1], ids[1]]),
        ack(&batch, vec![fresh]),
        ack(
            &proto::PreKeyUploadBatch {
                batch_id: "foreign".into(),
                pre_keys: vec![],
            },
            ids.clone(),
        ),
    ] {
        error(
            hub.request("upload-second", request(&scope, generation2, invalid))
                .await,
            proto::Code::InvalidArgument,
        );
        assert_eq!(count(&hub, "upload-second", &scope, generation2).await, 1);
    }
    db.fail_on(&scope, "prekey-upload-ack-v1").await;
    error(
        hub.request(
            "upload-second",
            request(&scope, generation2, ack(&batch, ids.clone())),
        )
        .await,
        proto::Code::Unavailable,
    );
    assert_eq!(count(&hub, "upload-second", &scope, generation2).await, 1);
    assert_eq!(
        prepare(&hub, "upload-second", &scope, generation2, 50).await,
        filtered
    );
    db.clear_failure(&scope).await;
    hub.request_losing_response(
        "upload-second",
        request(&scope, generation2, ack(&batch, ids.clone())),
    )
    .await;
    assert_eq!(count(&hub, "upload-second", &scope, generation2).await, 812);
    second.shutdown().await;
    drop(backend);

    let backend = db.reopen().await;
    let third = start(&hub, "upload-third", &scope, backend.clone(), 30_000).await;
    let generation3 = third.node.session(&scope).unwrap().generation;
    assert!(generation3 > generation2);
    let next = prepare(&hub, "upload-third", &scope, generation3, 2).await;
    assert_ne!(next.batch_id, batch.batch_id);
    ok(hub
        .request(
            "upload-third",
            request(&scope, generation3, ack(&batch, ids.clone())),
        )
        .await);
    assert_eq!(
        prepare(&hub, "upload-third", &scope, generation3, 50).await,
        next
    );
    assert_eq!(count(&hub, "upload-third", &scope, generation3).await, 812);
    error(
        hub.request(
            "upload-third",
            request(&scope, generation2, ack(&batch, ids)),
        )
        .await,
        proto::Code::NotLeaseHolder,
    );
    assert!(
        backend
            .get(
                &scope,
                Namespace::PreKey,
                &format!("{:010}", batch.pre_keys[0].id)
            )
            .await
            .unwrap()
            .is_none()
    );
    third.shutdown().await;
    drop(backend);
    db.cleanup(&scope).await;
}

#[tokio::test]
async fn sqlite_framed_uploads_recover_and_ack_atomically() {
    exercise_database(Database::sqlite().await).await;
}

#[tokio::test]
async fn postgres_framed_uploads_recover_and_ack_atomically() {
    if let Some(db) = Database::postgres().await {
        exercise_database(db).await;
    }
}

#[tokio::test]
async fn durable_batch_survives_process_crash_and_refuses_the_old_holder() {
    let db = Database::sqlite().await;
    let scope = format!("upload_{:016x}", rand::random::<u64>());
    let hub = Hub::start().await;
    let backend = db.reopen().await;
    let first = start(&hub, "upload-crash-first", &scope, backend.clone(), 500).await;
    let generation = first.node.session(&scope).unwrap().generation;
    result(
        hub.request(
            "upload-crash-first",
            request(&scope, generation, Op::GetIdentity(proto::GetIdentity {})),
        )
        .await,
    );
    let batch = prepare(&hub, "upload-crash-first", &scope, generation, 3).await;
    let stale_ops = first.node.session(&scope).unwrap().ops().unwrap();
    first.abort();
    tokio::time::sleep(Duration::from_millis(650)).await;
    let second = start(&hub, "upload-crash-second", &scope, db.reopen().await, 500).await;
    let generation2 = second.node.session(&scope).unwrap().generation;
    assert!(generation2 > generation);
    assert_eq!(
        prepare(&hub, "upload-crash-second", &scope, generation2, 1).await,
        batch
    );
    let ids: Vec<_> = batch.pre_keys.iter().map(|key| key.id).collect();
    assert!(
        stale_ops
            .acknowledge_prekey_upload(&batch.batch_id, &ids)
            .await
            .unwrap_err()
            .is_fence_lost()
    );
    ok(hub
        .request(
            "upload-crash-second",
            request(&scope, generation2, ack(&batch, ids)),
        )
        .await);
    assert_eq!(
        count(&hub, "upload-crash-second", &scope, generation2).await,
        3
    );
    second.shutdown().await;
    drop(stale_ops);
    drop(first);
    drop(backend);
    db.cleanup(&scope).await;
}

#[test]
fn added_wire_tags_preserve_legacy_decoding_without_a_fresh_fallback() {
    let prepare = request(
        "",
        0,
        Op::PreparePreKeyUpload(proto::PreparePreKeyUpload { count: 1 }),
    );
    assert_eq!(prepare.encode_to_vec(), [0xa2, 0x01, 2, 8, 1]);
    let acknowledge = request(
        "",
        0,
        Op::AcknowledgePreKeyUpload(proto::AcknowledgePreKeyUpload {
            batch_id: "b".into(),
            ids: vec![1, 2],
        }),
    );
    assert_eq!(
        acknowledge.encode_to_vec(),
        [0xaa, 0x01, 7, 10, 1, b'b', 18, 2, 1, 2]
    );
    for encoded in [prepare.encode_to_vec(), acknowledge.encode_to_vec()] {
        assert!(
            OldRequest::decode(encoded.as_slice())
                .unwrap()
                .generate
                .is_none()
        );
    }
    let response = proto::ServiceResponse {
        result: Some(Out::PreKeyUploadBatch(proto::PreKeyUploadBatch {
            batch_id: "b".into(),
            pre_keys: vec![],
        })),
    };
    assert_eq!(response.encode_to_vec(), [0x92, 0x01, 3, 10, 1, b'b']);
    assert_eq!(signal_node::proto::PROTOCOL_VERSION, 1);
}

#[tokio::test]
async fn malformed_and_oversized_frames_do_not_allocate_or_lose_the_pending_batch() {
    let db = Database::sqlite().await;
    let scope = format!("upload_{:016x}", rand::random::<u64>());
    let hub = Hub::start().await;
    let backend = db.reopen().await;
    let running = start(&hub, "upload-framing", &scope, backend.clone(), 30_000).await;
    let generation = running.node.session(&scope).unwrap().generation;
    result(
        hub.request(
            "upload-framing",
            request(&scope, generation, Op::GetIdentity(proto::GetIdentity {})),
        )
        .await,
    );
    let batch = prepare(&hub, "upload-framing", &scope, generation, 2).await;
    hub.send_unanswered_frame("upload-framing", vec![0x80])
        .await;
    assert_eq!(
        prepare(&hub, "upload-framing", &scope, generation, 50).await,
        batch
    );
    // Existing tungstenite 0.27 transport ceiling:16MiB per frame. The
    // oversized frame closes the link; reconnection takes a higher fence.
    hub.send_unanswered_frame("upload-framing", vec![0; 17 << 20])
        .await;
    wait(|| {
        running
            .node
            .session(&scope)
            .is_some_and(|s| s.generation > generation && s.is_claimed())
    })
    .await;
    let successor = running.node.session(&scope).unwrap().generation;
    assert_eq!(
        prepare(&hub, "upload-framing", &scope, successor, 50).await,
        batch
    );
    assert_eq!(
        backend
            .scan_keys(&scope, Namespace::PreKey, "", None)
            .await
            .unwrap()
            .len(),
        2
    );
    running.shutdown().await;
    drop(backend);
    db.cleanup(&scope).await;
}
