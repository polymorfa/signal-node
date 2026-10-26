mod support;
use futures_util::StreamExt;
use serde_json::Value;
use signal_node::{
    proto::{self, frame::Body, runner_request::Op, service_response::Result as Out},
    store::Backend,
};
use std::sync::Arc;
use support::*;
use wacore::types::jid::JidExt as _;
use wacore_recordstore::{MemoryRecordStore, Namespace, RecordStore};
use waproto::whatsapp as wa;

async fn identity(hub: &Hub, node: &str, generation: u64) -> proto::Identity {
    let response = hub
        .command(node, generation, Op::GetIdentity(proto::GetIdentity {}))
        .await;
    let Some(Body::ServiceResponse(proto::ServiceResponse {
        result: Some(Out::Identity(identity)),
    })) = response.body
    else {
        panic!("identity response missing")
    };
    identity
}
async fn encrypted(
    hub: &Hub,
    node: &str,
    running: &signal_node::Running,
    body: wa::Message,
    from_me: bool,
) -> proto::Receive {
    let session = running.node.session(SESSION).unwrap();
    let identity = identity(hub, node, session.generation).await;
    let response = hub
        .command(
            node,
            session.generation,
            Op::GeneratePreKeys(proto::GeneratePreKeys { count: 1 }),
        )
        .await;
    let Some(Body::ServiceResponse(proto::ServiceResponse {
        result: Some(Out::PreKeys(keys)),
    })) = response.body
    else {
        panic!("prekeys response missing")
    };
    let (peer, _) = peer("alice-fixture").await;
    let bundle = proto::Bundle {
        registration_id: identity.registration_id,
        device_id: 1,
        identity_key: identity.identity_key,
        signed_pre_key_id: identity.signed_pre_key_id,
        signed_pre_key: identity.signed_pre_key,
        signed_pre_key_signature: identity.signed_pre_key_signature,
        pre_key: Some(keys.pre_keys[0].clone()),
    };
    let bob: wacore_binary::Jid = "222:1@s.whatsapp.net".parse().unwrap();
    peer.establish_session(
        &bob.to_protocol_address(),
        &signal_node::resolver::remote_bundle(&bundle).unwrap(),
    )
    .await
    .unwrap();
    let bytes = wacore::messages::MessageUtils::pad_message_v2(signal_node::message::encode(&body));
    let cipher = peer
        .encrypt(&bob.to_protocol_address(), &bytes)
        .await
        .unwrap();
    proto::Receive {
        chat: "111@s.whatsapp.net".into(),
        sender: "111:1@s.whatsapp.net".into(),
        message_id: "message-fixture".into(),
        kind: match cipher.kind {
            wacore_signal_ops::EncKind::PreKey => "pkmsg",
            wacore_signal_ops::EncKind::Message => "msg",
        }
        .into(),
        ciphertext: cipher.ciphertext,
        padding_version: 2,
        is_from_me: from_me,
        timestamp: 1720000000,
        sender_alt: String::new(),
    }
}
async fn next_event<S>(stream: &mut S) -> Value
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Unpin,
{
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut data = Vec::new();
        loop {
            data.extend_from_slice(&stream.next().await.unwrap().unwrap());
            if let Some(line) = String::from_utf8_lossy(&data)
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
            {
                return serde_json::from_str(line).unwrap();
            }
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn app_auth_origin_and_public_liveness_keep_private_state_hidden() {
    let hub = Hub::start().await;
    let running = start(
        &hub,
        "node-auth",
        Backend::Memory(Arc::new(MemoryRecordStore::new())),
        false,
    )
    .await;
    let url = format!("http://{}", running.http_addr);
    let client = reqwest::Client::new();
    let health = client
        .get(format!("{url}/healthz"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(health, serde_json::json!({"status":"ok"}));
    assert_eq!(
        client
            .get(format!("{url}/v1/sessions"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{url}/v1/sessions"))
            .bearer_auth(APP_SECRET)
            .header("Origin", "null")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let sessions = client
        .get(format!("{url}/v1/sessions"))
        .bearer_auth(APP_SECRET)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(sessions["sessions"][0]["claimed"], true);
    assert!(!sessions.to_string().contains("master_key"));
    running.shutdown().await;
}

#[tokio::test]
async fn an_unrelated_sse_filter_does_not_make_a_session_wait_for_an_ack() {
    let hub = Hub::start().await;
    let running = start(
        &hub,
        "node-filter",
        Backend::Memory(Arc::new(MemoryRecordStore::new())),
        false,
    )
    .await;
    let generation = running.node.session(SESSION).unwrap().generation;
    let receive = encrypted(
        &hub,
        "node-filter",
        &running,
        wa::Message {
            conversation: Some("unwatched fixture".into()),
            ..Default::default()
        },
        false,
    )
    .await;
    let response = reqwest::Client::new()
        .get(format!(
            "http://{}/v1/events?session_id=other",
            running.http_addr
        ))
        .bearer_auth(APP_SECRET)
        .send()
        .await
        .unwrap();
    let result = hub
        .command("node-filter", generation, Op::Receive(receive))
        .await;
    let Some(Body::Error(error)) = result.body else {
        panic!("unwatched receive was acknowledged");
    };
    assert_eq!(error.code_enum(), proto::Code::Unavailable);
    assert!(error.message.starts_with("no application is listening"));
    drop(response);
    running.shutdown().await;
}
#[tokio::test]
async fn real_encrypted_receive_requires_app_ack_then_is_durable_and_sealed() {
    let hub = Hub::start().await;
    let records = Arc::new(MemoryRecordStore::new());
    let running = start(
        &hub,
        "node-receive",
        Backend::Memory(records.clone()),
        false,
    )
    .await;
    let generation = running.node.session(SESSION).unwrap().generation;
    let receive = encrypted(
        &hub,
        "node-receive",
        &running,
        wa::Message {
            conversation: Some("application-private-text".into()),
            ..Default::default()
        },
        false,
    )
    .await;
    let client = reqwest::Client::new();
    let url = format!("http://{}", running.http_addr);
    let mut stream = client
        .get(format!("{url}/v1/events"))
        .bearer_auth(APP_SECRET)
        .send()
        .await
        .unwrap()
        .bytes_stream();
    let command = hub.command("node-receive", generation, Op::Receive(receive.clone()));
    let app = async {
        let event = next_event(&mut stream).await;
        assert_eq!(event["text"], "application-private-text");
        assert_eq!(event["type"], "message");
        assert!(!event["redelivered"].as_bool().unwrap());
        assert_eq!(
            client
                .post(format!(
                    "{url}/v1/events/{}/ack",
                    event["id"].as_str().unwrap()
                ))
                .bearer_auth(APP_SECRET)
                .send()
                .await
                .unwrap()
                .status(),
            204
        );
        event
    };
    let (response, event) = tokio::join!(command, app);
    assert!(matches!(
        response.body,
        Some(Body::ServiceResponse(proto::ServiceResponse {
            result: Some(Out::Receive(proto::ReceiveResult {
                already_delivered: false,
                ..
            }))
        }))
    ));
    let again = hub
        .command("node-receive", generation, Op::Receive(receive))
        .await;
    assert!(matches!(
        again.body,
        Some(Body::ServiceResponse(proto::ServiceResponse {
            result: Some(Out::Receive(proto::ReceiveResult {
                already_delivered: true,
                ..
            }))
        }))
    ));
    for ns in Namespace::ALL {
        for key in records.scan_keys(SESSION, ns, "", None).await.unwrap() {
            let value = records.get(SESSION, ns, &key).await.unwrap().unwrap();
            assert!(
                !value
                    .windows(b"application-private-text".len())
                    .any(|part| part == b"application-private-text")
            );
        }
    }
    assert_eq!(
        client
            .post(format!(
                "{url}/v1/events/{}/ack",
                event["id"].as_str().unwrap()
            ))
            .bearer_auth(APP_SECRET)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    drop(stream);
    running.shutdown().await;
}
#[tokio::test]
async fn unacknowledged_receive_replays_across_crash_and_old_holder_is_fenced() {
    let hub = Hub::start().await;
    let records = Arc::new(MemoryRecordStore::new());
    let first = start(
        &hub,
        "node-crash-a",
        Backend::Memory(records.clone()),
        false,
    )
    .await;
    let old = first.node.session(SESSION).unwrap();
    let generation = old.generation;
    let receive = encrypted(
        &hub,
        "node-crash-a",
        &first,
        wa::Message {
            conversation: Some("application-private-text".into()),
            ..Default::default()
        },
        false,
    )
    .await;
    let outcome = hub
        .command("node-crash-a", generation, Op::Receive(receive.clone()))
        .await;
    assert!(
        matches!(outcome.body,Some(Body::Error(proto::Error{code,..})) if code==proto::Code::Unavailable as i32)
    );
    let stale = old.ops().unwrap();
    first.abort();
    tokio::time::sleep(std::time::Duration::from_millis(650)).await;
    let second = start(&hub, "node-crash-b", Backend::Memory(records), false).await;
    let generation2 = second.node.session(SESSION).unwrap().generation;
    assert!(generation2 > generation);
    let old_write = stale.generate_prekeys(1).await.unwrap_err();
    assert!(old_write.is_fence_lost());
    let client = reqwest::Client::new();
    let url = format!("http://{}", second.http_addr);
    let mut stream = client
        .get(format!("{url}/v1/events"))
        .bearer_auth(APP_SECRET)
        .send()
        .await
        .unwrap()
        .bytes_stream();
    let command = hub.command("node-crash-b", generation2, Op::Receive(receive));
    let app = async {
        let event = next_event(&mut stream).await;
        assert_eq!(event["redelivered"], true);
        assert_eq!(event["text"], "application-private-text");
        assert_eq!(
            client
                .post(format!(
                    "{url}/v1/events/{}/ack",
                    event["id"].as_str().unwrap()
                ))
                .bearer_auth(APP_SECRET)
                .send()
                .await
                .unwrap()
                .status(),
            204
        );
    };
    let (response, _) = tokio::join!(command, app);
    assert!(matches!(response.body, Some(Body::ServiceResponse(_))));
    drop(stream);
    second.shutdown().await;
}

fn app_state_share() -> wa::message::AppStateSyncKeyShare {
    wa::message::AppStateSyncKeyShare {
        keys: vec![wa::message::AppStateSyncKey {
            key_id: Some(wa::message::AppStateSyncKeyId {
                key_id: Some(vec![3; 32]),
            })
            .into(),
            key_data: Some(wa::message::AppStateSyncKeyData {
                key_data: Some(vec![4; 32]),
                ..Default::default()
            })
            .into(),
        }],
    }
}

#[tokio::test]
async fn app_state_keys_require_separate_consent_and_an_own_device() {
    for (consent, from_me, history) in [
        (false, true, false),
        (false, true, true),
        (true, true, false),
        (true, false, false),
    ] {
        let hub = Hub::start().await;
        let mut cfg = config("node-app-state", &hub.url, history);
        assert!(!cfg.share_app_state_keys);
        cfg.share_app_state_keys = consent;
        let running = signal_node::start(cfg, Backend::Memory(Arc::new(MemoryRecordStore::new())))
            .await
            .unwrap();
        wait(|| {
            running
                .node
                .session(SESSION)
                .is_some_and(|s| s.is_claimed())
        })
        .await;
        let generation = running.node.session(SESSION).unwrap().generation;
        let expected = app_state_share();
        let receive = encrypted(
            &hub,
            "node-app-state",
            &running,
            wa::Message {
                protocol_message: wa::message::ProtocolMessage {
                    r#type: Some(wa::message::protocol_message::Type::AppStateSyncKeyShare),
                    app_state_sync_key_share: Some(expected.clone()).into(),
                    ..Default::default()
                }
                .into(),
                message_context_info: Some(wa::MessageContextInfo {
                    message_secret: Some(vec![9; 32]),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
            from_me,
        )
        .await;
        let mut stream = reqwest::Client::new()
            .get(format!("http://{}/v1/events", running.http_addr))
            .bearer_auth(APP_SECRET)
            .send()
            .await
            .unwrap()
            .bytes_stream();
        let response = hub
            .command("node-app-state", generation, Op::Receive(receive.clone()))
            .await;
        let Some(Body::ServiceResponse(proto::ServiceResponse {
            result: Some(Out::Receive(result)),
        })) = response.body
        else {
            panic!("receive response missing");
        };
        let expected_bytes = if consent && from_me {
            signal_node::message::encode(&expected)
        } else {
            Vec::new()
        };
        assert_eq!(
            result.app_state_key_share, expected_bytes,
            "consent={consent}, own_device={from_me}, history={history}"
        );
        let replay = hub
            .command("node-app-state", generation, Op::Receive(receive))
            .await;
        assert!(
            matches!(replay.body, Some(Body::ServiceResponse(proto::ServiceResponse { result: Some(Out::Receive(proto::ReceiveResult { already_delivered: true, app_state_key_share, .. })) })) if app_state_key_share.is_empty())
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), stream.next())
                .await
                .is_err()
        );
        drop(stream);
        running.shutdown().await;
    }
}

#[tokio::test]
async fn history_stays_off_until_explicit_consent_and_delivers_only_the_notification() {
    for (consent, from_me) in [(false, true), (true, false), (true, true)] {
        let hub = Hub::start().await;
        let running = start(
            &hub,
            "node-history",
            Backend::Memory(Arc::new(MemoryRecordStore::new())),
            consent,
        )
        .await;
        let generation = running.node.session(SESSION).unwrap().generation;
        let message = wa::Message {
            protocol_message: wa::message::ProtocolMessage {
                r#type: Some(wa::message::protocol_message::Type::HistorySyncNotification),
                history_sync_notification: wa::message::HistorySyncNotification {
                    direct_path: Some("/fixture/history".into()),
                    media_key: Some(vec![1; 32]),
                    file_sha256: Some(vec![2; 32]),
                    file_enc_sha256: Some(vec![3; 32]),
                    file_length: Some(1234),
                    chunk_order: Some(1),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let receive = encrypted(&hub, "node-history", &running, message, from_me).await;
        let client = reqwest::Client::new();
        let url = format!("http://{}", running.http_addr);
        let mut stream = client
            .get(format!("{url}/v1/events"))
            .bearer_auth(APP_SECRET)
            .send()
            .await
            .unwrap()
            .bytes_stream();
        if consent && from_me {
            let command = hub.command("node-history", generation, Op::Receive(receive));
            let app = async {
                let event = next_event(&mut stream).await;
                assert_eq!(event["type"], "history.sync");
                assert_eq!(event["history"]["direct_path"], "/fixture/history");
                assert_eq!(event["message_proto"], "");
                assert!(event.get("text").is_none());
                assert!(event.get("media").is_none());
                assert_eq!(
                    client
                        .post(format!(
                            "{url}/v1/events/{}/ack",
                            event["id"].as_str().unwrap()
                        ))
                        .bearer_auth(APP_SECRET)
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    204
                );
            };
            let (result, _) = tokio::join!(command, app);
            assert!(matches!(result.body, Some(Body::ServiceResponse(_))));
        } else {
            let result = hub
                .command("node-history", generation, Op::Receive(receive))
                .await;
            assert!(matches!(result.body, Some(Body::ServiceResponse(_))));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), stream.next())
                    .await
                    .is_err()
            );
        }
        drop(stream);
        running.shutdown().await;
    }
}
#[tokio::test]
async fn http_send_stanza_round_trips_into_the_other_device_and_never_exceeds_five_per_second() {
    let hub = Hub::start().await;
    let running = start(
        &hub,
        "node-send",
        Backend::Memory(Arc::new(MemoryRecordStore::new())),
        false,
    )
    .await;
    let generation = running.node.session(SESSION).unwrap().generation;
    identity(&hub, "node-send", generation).await;
    let ops = running.node.session(SESSION).unwrap().ops().unwrap();
    pair(&*ops).await;
    ops.set_own_jids("222:1@s.whatsapp.net", None)
        .await
        .unwrap();
    let (peer, bundle) = peer("send-peer").await;
    hub.bundle("111:1@s.whatsapp.net", bundle).await;
    let client = reqwest::Client::new();
    let url = format!(
        "http://{}/v1/sessions/{SESSION}/messages",
        running.http_addr
    );
    for _ in 0..7 {
        let response = client
            .post(&url)
            .bearer_auth(APP_SECRET)
            .json(&serde_json::json!({"to":"111@s.whatsapp.net","text":"application-private-text"}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let value = response.json::<Value>().await.unwrap();
        assert!(
            status.is_success(),
            "send error code: {:?}",
            value["error"]["code"]
        );
        assert!(value["message_id"].is_string());
    }
    let sends = hub.sends().await;
    assert_eq!(sends.len(), 7);
    for (i, (when, _)) in sends.iter().enumerate() {
        assert!(
            sends[i..]
                .iter()
                .filter(|(time, _)| time.duration_since(*when) < std::time::Duration::from_secs(1))
                .count()
                <= 5
        );
    }
    fn enc(node: &wacore_binary::Node) -> Option<&wacore_binary::Node> {
        if node.tag == "enc" {
            return Some(node);
        }
        node.children()?.iter().find_map(enc)
    }
    let node = wacore_binary::marshal::unmarshal_packed_ref(&sends[0].1)
        .unwrap()
        .to_owned();
    assert_eq!(node.tag, "message");
    let payload = enc(&node).unwrap();
    let Some(wacore_binary::node::NodeContent::Bytes(ciphertext)) = &payload.content else {
        panic!("encrypted content missing")
    };
    let bob: wacore_binary::Jid = "222:1@s.whatsapp.net".parse().unwrap();
    let opened = peer
        .decrypt(
            &bob.to_protocol_address(),
            wacore_signal_ops::EncKind::PreKey,
            ciphertext,
        )
        .await
        .unwrap();
    let plaintext =
        wacore::messages::MessageUtils::unpad_message_ref(&opened.plaintext, 2).unwrap();
    let message = waproto::codec::message_decode(plaintext).unwrap();
    assert_eq!(
        message.conversation.as_deref(),
        Some("application-private-text")
    );
    running.shutdown().await;
}

#[tokio::test]
async fn a_lost_send_reply_reports_the_original_unconfirmed_message_without_retrying() {
    for disconnect in [false, true] {
        let hub = Hub::start().await;
        let running = start(
            &hub,
            "node-uncertain",
            Backend::Memory(Arc::new(MemoryRecordStore::new())),
            false,
        )
        .await;
        let generation = running.node.session(SESSION).unwrap().generation;
        identity(&hub, "node-uncertain", generation).await;
        let ops = running.node.session(SESSION).unwrap().ops().unwrap();
        pair(&*ops).await;
        ops.set_own_jids("222:1@s.whatsapp.net", Some("22201:1@lid"))
            .await
            .unwrap();
        let (_peer, bundle) = peer("uncertain-peer").await;
        hub.bundle("111:1@s.whatsapp.net", bundle).await;
        hub.lose_send_reply(disconnect);
        let response = reqwest::Client::new()
            .post(format!(
                "http://{}/v1/sessions/{SESSION}/messages",
                running.http_addr
            ))
            .bearer_auth(APP_SECRET)
            .json(&serde_json::json!({"to":"111@s.whatsapp.net","text":"application-private-text"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 504, "disconnect={disconnect}");
        let body = response.json::<Value>().await.unwrap();
        assert_eq!(body["error"]["code"], "send_unconfirmed");
        let sends = hub.sends().await;
        assert_eq!(sends.len(), 1, "an uncertain send must not be repeated");
        let stanza = wacore_binary::marshal::unmarshal_packed_ref(&sends[0].1)
            .unwrap()
            .to_owned();
        assert_eq!(
            body["error"]["message_id"].as_str().unwrap(),
            stanza.attrs.get("id").unwrap().as_str()
        );
        running.shutdown().await;
    }
}

#[tokio::test]
async fn an_accepted_group_send_survives_distribution_storage_failure_or_fence_loss() {
    use signal_node::store::SqliteStore;
    for fence_lost in [false, true] {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-state");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("send-{}.sqlite", rand::random::<u64>()));
        let url = format!("sqlite://{}", path.display());
        let backend = SqliteStore::connect(&url, 2).await.unwrap();
        let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
        let hub = Hub::start().await;
        let running = start(&hub, "node-mark-failure", Backend::Sqlite(backend), false).await;
        let session = running.node.session(SESSION).unwrap();
        identity(&hub, "node-mark-failure", session.generation).await;
        let ops = session.ops().unwrap();
        pair(&*ops).await;
        ops.set_own_jids("222:1@s.whatsapp.net", Some("22201:1@lid"))
            .await
            .unwrap();
        let (_peer, bundle) = peer("mark-failure-peer").await;
        hub.bundle("111:1@s.whatsapp.net", bundle).await;
        if !fence_lost {
            sqlx::query("CREATE TRIGGER fail_distribution BEFORE INSERT ON signal_records WHEN NEW.ns = 'sender_key_devices' BEGIN SELECT RAISE(ABORT, 'synthetic distribution write failure'); END")
                .execute(&pool).await.unwrap();
        }
        let (observed, release) = hub.gate_next_send().await;
        let send = reqwest::Client::new()
            .post(format!(
                "http://{}/v1/sessions/{SESSION}/messages",
                running.http_addr
            ))
            .bearer_auth(APP_SECRET)
            .json(&serde_json::json!({"to":"12345@g.us","text":"application-private-text"}))
            .send();
        let change = async {
            tokio::time::timeout(std::time::Duration::from_secs(3), observed.notified())
                .await
                .expect("send never reached the runner");
            if fence_lost {
                sqlx::query("UPDATE signal_leases SET generation = generation + 1 WHERE scope = ?")
                    .bind(SESSION)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            release.notify_one();
        };
        let (response, ()) = tokio::join!(send, change);
        let response = response.unwrap();
        let status = response.status();
        let body = response.json::<Value>().await.unwrap();
        assert_eq!(
            status, 200,
            "fence_lost={fence_lost}, error={:?}",
            body["error"]["code"]
        );
        assert!(body["message_id"].is_string());
        assert_eq!(body["server_timestamp"], 1720000000);
        assert_eq!(hub.sends().await.len(), 1);
        if fence_lost {
            assert!(
                !session.can_serve().await,
                "fence loss must still retire the old session"
            );
        }
        drop(ops);
        drop(session);
        running.shutdown().await;
        pool.close().await;
        std::fs::remove_file(&path).unwrap();
    }
}

#[tokio::test]
async fn webhook_signature_failure_and_ack_gate_durable_delivery() {
    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use hmac::Mac;
    use std::sync::atomic::{AtomicU16, Ordering};
    #[derive(Clone)]
    struct Sink {
        status: Arc<AtomicU16>,
        observed: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        events: Arc<tokio::sync::Mutex<Vec<Value>>>,
    }
    async fn receive(
        State(sink): State<Sink>,
        headers: HeaderMap,
        body: bytes::Bytes,
    ) -> StatusCode {
        let timestamp = headers[signal_node::delivery::TIMESTAMP_HEADER]
            .to_str()
            .unwrap();
        let mut mac =
            <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(b"webhook-fixture-secret").unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(&body);
        assert_eq!(
            headers[signal_node::delivery::SIGNATURE_HEADER]
                .to_str()
                .unwrap(),
            format!("v1={}", hex::encode(mac.finalize().into_bytes()))
        );
        assert!(
            headers.get("Authorization").is_none(),
            "no app or project bearer goes to webhook"
        );
        let event: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            headers[signal_node::delivery::EVENT_ID_HEADER]
                .to_str()
                .unwrap(),
            event["id"].as_str().unwrap()
        );
        sink.events.lock().await.push(event);
        let status = sink.status.load(Ordering::SeqCst);
        sink.observed.notify_one();
        if status == 204 {
            sink.release.notified().await;
        }
        StatusCode::from_u16(status).unwrap()
    }
    let sink = Sink {
        status: Arc::new(AtomicU16::new(500)),
        observed: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
        events: Arc::new(tokio::sync::Mutex::new(Vec::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/events", post(receive))
        .with_state(sink.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let hub = Hub::start().await;
    let mut cfg = config("node-webhook", &hub.url, false);
    cfg.sse = false;
    cfg.webhook_url = Some(format!("http://{addr}/events"));
    cfg.webhook_secret = signal_node::config::Secret::new("webhook-fixture-secret");
    let running = signal_node::start(cfg, Backend::Memory(Arc::new(MemoryRecordStore::new())))
        .await
        .unwrap();
    wait(|| {
        running
            .node
            .session(SESSION)
            .is_some_and(|s| s.is_claimed())
    })
    .await;
    let generation = running.node.session(SESSION).unwrap().generation;
    let ciphertext = encrypted(
        &hub,
        "node-webhook",
        &running,
        wa::Message {
            conversation: Some("webhook-secret-text".into()),
            ..Default::default()
        },
        false,
    )
    .await;
    let first = hub
        .command("node-webhook", generation, Op::Receive(ciphertext.clone()))
        .await;
    assert!(
        matches!(first.body, Some(Body::Error(proto::Error {code, ..})) if code == proto::Code::Unavailable as i32)
    );
    sink.observed.notified().await;
    // A redirect is also a rejection; the client must never follow it.
    sink.status.store(307, Ordering::SeqCst);
    let redirected = hub
        .command("node-webhook", generation, Op::Receive(ciphertext.clone()))
        .await;
    assert!(matches!(redirected.body, Some(Body::Error(_))));
    sink.observed.notified().await;
    sink.status.store(204, Ordering::SeqCst);
    let command = hub.command("node-webhook", generation, Op::Receive(ciphertext.clone()));
    tokio::pin!(command);
    tokio::select! {
        result = &mut command => panic!("delivery completed before webhook ACK: {result:?}"),
        _ = sink.observed.notified() => {}
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut command)
            .await
            .is_err()
    );
    sink.release.notify_one();
    assert!(matches!(command.await.body, Some(Body::ServiceResponse(_))));
    let again = hub
        .command("node-webhook", generation, Op::Receive(ciphertext))
        .await;
    assert!(matches!(
        again.body,
        Some(Body::ServiceResponse(proto::ServiceResponse {
            result: Some(Out::Receive(proto::ReceiveResult {
                already_delivered: true,
                ..
            }))
        }))
    ));
    let events = sink.events.lock().await;
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["redelivered"], false);
    assert_eq!(events[1]["redelivered"], true);
    assert_eq!(events[2]["redelivered"], true);
    assert_eq!(events[0]["id"], events[2]["id"]);
    drop(events);
    running.shutdown().await;
    server.abort();
}

#[tokio::test]
async fn expired_holder_refuses_requests_and_old_callbacks_preserve_new_generation() {
    use signal_node::link::Handler;
    let hub = Hub::start().await;
    let records = Arc::new(MemoryRecordStore::new());
    let old = start(
        &hub,
        "node-expired",
        Backend::Memory(records.clone()),
        false,
    )
    .await;
    let old_session = old.node.session(SESSION).unwrap();
    old.abort();
    tokio::time::sleep(std::time::Duration::from_millis(650)).await;
    assert!(!old_session.can_serve().await);
    let error = old
        .node
        .runner_request(proto::RunnerRequest {
            session_id: SESSION.into(),
            lease_generation: old_session.generation,
            op: Some(Op::GetIdentity(proto::GetIdentity {})),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code_enum(), proto::Code::NotLeaseHolder);
    old.node.tick_leases().await; // Releases the expired generation.
    old.node.tick_leases().await; // Same holder ID must take a new generation.
    let new_session = old.node.session(SESSION).unwrap();
    assert!(new_session.generation > old_session.generation);
    old.node
        .lose(SESSION, old_session.generation, "late old callback");
    assert_eq!(
        old.node.session(SESSION).unwrap().generation,
        new_session.generation
    );
    old.node.shutdown().await;
}

#[tokio::test]
async fn process_incarnations_with_the_same_node_id_cannot_share_a_fence() {
    // Both processes hold live links: a node without one takes no leases.
    let hub = Hub::start().await;
    let records = Arc::new(MemoryRecordStore::new());
    let first = start(
        &hub,
        "same-stable-node",
        Backend::Memory(records.clone()),
        false,
    )
    .await;
    let old = first.node.session(SESSION).unwrap();
    let ops = old.ops_or_create().await.unwrap();
    let replacement = signal_node::start(
        config("same-stable-node", &hub.url, false),
        Backend::Memory(records),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(
        replacement.node.session(SESSION).is_none(),
        "an active lease cannot be reacquired by another process with the same node ID"
    );
    first.abort();
    wait(|| {
        replacement
            .node
            .session(SESSION)
            .is_some_and(|s| s.generation > old.generation)
    })
    .await;
    assert!(ops.generate_prekeys(1).await.unwrap_err().is_fence_lost());
    first.node.shutdown().await;
    replacement.shutdown().await;
}

#[tokio::test]
async fn group_retry_rejects_unknown_or_missing_addressing_mode() {
    let hub = Hub::start().await;
    let running = start(
        &hub,
        "node-group-validation",
        Backend::Memory(Arc::new(MemoryRecordStore::new())),
        false,
    )
    .await;
    let generation = running.node.session(SESSION).unwrap().generation;
    identity(&hub, "node-group-validation", generation).await;
    for mode in ["", "unknown"] {
        let response = hub
            .command(
                "node-group-validation",
                generation,
                Op::Resend(proto::Resend {
                    chat: "123@g.us".into(),
                    requester: "111:1@s.whatsapp.net".into(),
                    is_group: true,
                    addressing_mode: mode.into(),
                    ..Default::default()
                }),
            )
            .await;
        assert!(
            matches!(response.body, Some(Body::Error(error)) if error.code_enum()==proto::Code::InvalidArgument)
        );
    }
    running.shutdown().await;
}

#[tokio::test]
async fn mixed_protocol_text_is_delivered_without_foreign_keys_or_unconsented_history() {
    for (protocol, from_me) in [
        (
            wa::message::ProtocolMessage {
                r#type: Some(wa::message::protocol_message::Type::AppStateSyncKeyShare),
                app_state_sync_key_share: Some(app_state_share()).into(),
                ..Default::default()
            },
            true,
        ),
        (
            wa::message::ProtocolMessage {
                r#type: Some(wa::message::protocol_message::Type::AppStateSyncKeyShare),
                app_state_sync_key_share: Some(wa::message::AppStateSyncKeyShare {
                    keys: vec![wa::message::AppStateSyncKey {
                        key_id: Some(wa::message::AppStateSyncKeyId {
                            key_id: Some(vec![3; 32]),
                        })
                        .into(),
                        key_data: Some(wa::message::AppStateSyncKeyData {
                            key_data: Some(vec![4; 32]),
                            ..Default::default()
                        })
                        .into(),
                    }],
                })
                .into(),
                ..Default::default()
            },
            false,
        ),
        (
            wa::message::ProtocolMessage {
                r#type: Some(wa::message::protocol_message::Type::HistorySyncNotification),
                history_sync_notification: Some(wa::message::HistorySyncNotification {
                    direct_path: Some("/never-release-without-consent".into()),
                    media_key: Some(vec![5; 32]),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
            true,
        ),
        (
            wa::message::ProtocolMessage {
                r#type: Some(
                    wa::message::protocol_message::Type::PeerDataOperationRequestResponseMessage,
                ),
                peer_data_operation_request_response_message: Some(
                    wa::message::PeerDataOperationRequestResponseMessage::default(),
                )
                .into(),
                ..Default::default()
            },
            false,
        ),
    ] {
        let hub = Hub::start().await;
        let running = start(
            &hub,
            "node-mixed",
            Backend::Memory(Arc::new(MemoryRecordStore::new())),
            false,
        )
        .await;
        let generation = running.node.session(SESSION).unwrap().generation;
        let ciphertext = encrypted(
            &hub,
            "node-mixed",
            &running,
            wa::Message {
                conversation: Some("mixed-user-content".into()),
                protocol_message: Some(protocol).into(),
                message_context_info: Some(wa::MessageContextInfo {
                    message_secret: Some(vec![9; 32]),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
            from_me,
        )
        .await;
        let client = reqwest::Client::new();
        let url = format!("http://{}", running.http_addr);
        let mut stream = client
            .get(format!("{url}/v1/events"))
            .bearer_auth(APP_SECRET)
            .send()
            .await
            .unwrap()
            .bytes_stream();
        let command = hub.command("node-mixed", generation, Op::Receive(ciphertext));
        let app = async {
            let event = next_event(&mut stream).await;
            assert_eq!(event["text"], "mixed-user-content");
            assert_eq!(event["type"], "message");
            assert!(event.get("history").is_none());
            use base64::Engine as _;
            let message = waproto::codec::message_decode(
                &base64::engine::general_purpose::STANDARD
                    .decode(event["message_proto"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert!(!message.protocol_message.is_set());
            assert_eq!(
                message
                    .message_context_info
                    .as_option()
                    .unwrap()
                    .message_secret,
                Some(vec![9; 32])
            );
            assert_eq!(
                client
                    .post(format!(
                        "{url}/v1/events/{}/ack",
                        event["id"].as_str().unwrap()
                    ))
                    .bearer_auth(APP_SECRET)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                204
            );
        };
        let (response, ()) = tokio::join!(command, app);
        assert!(
            matches!(response.body, Some(Body::ServiceResponse(proto::ServiceResponse {result: Some(Out::Receive(proto::ReceiveResult { app_state_key_share, .. }))})) if app_state_key_share.is_empty())
        );
        drop(stream);
        running.shutdown().await;
    }
}

#[tokio::test]
async fn reconnect_claims_a_strictly_higher_durable_generation() {
    let hub = Hub::start().await;
    let running = start(
        &hub,
        "node-reconnect",
        Backend::Memory(Arc::new(MemoryRecordStore::new())),
        false,
    )
    .await;
    let first = running.node.session(SESSION).unwrap().generation;
    hub.disconnect("node-reconnect").await;
    wait(|| {
        running
            .node
            .session(SESSION)
            .is_some_and(|s| s.generation > first && s.is_claimed())
    })
    .await;
    assert!(running.node.session(SESSION).unwrap().generation > first);
    running.shutdown().await;
}

#[tokio::test]
async fn a_node_without_a_live_link_takes_no_leases() {
    // A partitioned replica must leave free sessions to a connected one.
    let node = signal_node::node::Node::new(
        config("partitioned", "ws://127.0.0.1:1/signal", false),
        Backend::Memory(Arc::new(MemoryRecordStore::new())),
    );
    node.tick_leases().await;
    assert!(node.session(SESSION).is_none());
    node.shutdown().await;
}
