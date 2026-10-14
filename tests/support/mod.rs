#![allow(dead_code)]
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use signal_node::{
    config::Config,
    proto::{self, frame::Body, runner_response, service_request},
    store::Backend,
};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_tungstenite::tungstenite;

pub const APP_SECRET: &str = "fixture-application-secret";
pub const SESSION: &str = "session-fixture";
struct State {
    connections: Mutex<HashMap<String, mpsc::UnboundedSender<proto::Frame>>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<proto::Frame>>>,
    claims: Mutex<HashMap<String, (u64, String)>>,
    disconnects: Mutex<HashMap<String, oneshot::Sender<()>>>,
    next: AtomicU64,
    sends: Mutex<Vec<(tokio::time::Instant, Vec<u8>)>>,
    bundles: Mutex<HashMap<String, proto::Bundle>>,
}
struct ContractHandshake;
impl tungstenite::handshake::server::Callback for ContractHandshake {
    fn on_request(
        self,
        request: &tungstenite::handshake::server::Request,
        mut response: tungstenite::handshake::server::Response,
    ) -> Result<
        tungstenite::handshake::server::Response,
        tungstenite::handshake::server::ErrorResponse,
    > {
        assert_eq!(
            request.headers()["sec-websocket-protocol"],
            proto::SUBPROTOCOL
        );
        assert_eq!(
            request.headers()["authorization"],
            "Bearer fixture-project-principal"
        );
        assert!(!request.headers().contains_key("origin"));
        response.headers_mut().insert(
            "sec-websocket-protocol",
            proto::SUBPROTOCOL.parse().unwrap(),
        );
        Ok(response)
    }
}
pub struct Hub {
    pub url: String,
    state: Arc<State>,
    task: JoinHandle<()>,
}
impl Hub {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/signal", listener.local_addr().unwrap());
        let state = Arc::new(State {
            connections: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            claims: Mutex::new(HashMap::new()),
            disconnects: Mutex::new(HashMap::new()),
            next: AtomicU64::new(10000),
            sends: Mutex::new(vec![]),
            bundles: Mutex::new(HashMap::new()),
        });
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let state = shared.clone();
                tokio::spawn(async move {
                    let socket = tokio_tungstenite::accept_hdr_async(socket, ContractHandshake)
                        .await
                        .unwrap();
                    let (mut sink, mut stream) = socket.split();
                    let first = stream.next().await.unwrap().unwrap();
                    let first = proto::Frame::decode(first.into_data()).unwrap();
                    let Some(Body::Hello(hello)) = first.body else {
                        panic!("Expected Hello")
                    };
                    assert_eq!(hello.protocol_version, 1);
                    let node_id = hello.node_id;
                    let connection_id =
                        format!("{node_id}:{}", state.next.fetch_add(1, Ordering::SeqCst));
                    let (disconnect_tx, mut disconnect_rx) = oneshot::channel();
                    state
                        .disconnects
                        .lock()
                        .await
                        .insert(node_id.clone(), disconnect_tx);
                    sink.send(tungstenite::Message::Binary(
                        proto::Frame::with(
                            0,
                            Body::Welcome(proto::Welcome {
                                protocol_version: 1,
                                project_id: "project-fixture".into(),
                                heartbeat_interval_ms: 100,
                                max_sends_per_second: 5,
                            }),
                        )
                        .encode_to_vec()
                        .into(),
                    ))
                    .await
                    .unwrap();
                    let (tx, mut rx) = mpsc::unbounded_channel::<proto::Frame>();
                    state
                        .connections
                        .lock()
                        .await
                        .insert(node_id.clone(), tx.clone());
                    loop {
                        tokio::select! {
                            _ = &mut disconnect_rx => break,
                            out = rx.recv() => {
                                let Some(frame) = out else { break };
                                if sink.send(tungstenite::Message::Binary(frame.encode_to_vec().into())).await.is_err() { break; }
                            }
                            incoming = stream.next() => {
                                let Some(Ok(tungstenite::Message::Binary(bytes))) = incoming else { break };
                                let frame = proto::Frame::decode(bytes).unwrap();
                                match frame.body {
                                    Some(Body::ServiceRequest(request)) => {
                                        let op = request.op.unwrap();
                                        let mut failure = None;
                                        let result = match op {
                                            service_request::Op::ClaimSession(claim) => {
                                                let mut claims = state.claims.lock().await;
                                                if claims.get(&request.session_id).is_some_and(|(generation, owner)| *generation > claim.generation || *generation == claim.generation && *owner != connection_id) {
                                                    failure = Some(proto::Error::new(proto::Code::NotLeaseHolder, "stale claim"));
                                                } else {
                                                    claims.insert(request.session_id.clone(), (claim.generation, connection_id.clone()));
                                                }
                                                runner_response::Result::SessionClaimed(proto::SessionClaimed { state: proto::session_event::State::Connected as i32, pn: "222:1@s.whatsapp.net".into(), lid: String::new() })
                                            }
                                            service_request::Op::ResolveDevices(_) => runner_response::Result::Devices(proto::Devices { jids: state.bundles.lock().await.keys().cloned().collect() }),
                                            service_request::Op::FetchPreKeys(query) => runner_response::Result::Bundles(proto::Bundles { bundles: state.bundles.lock().await.iter().filter(|(jid, _)| query.jids.contains(jid)).map(|(jid, bundle)| (jid.clone(), bundle.clone())).collect() }),
                                            service_request::Op::SendStanza(stanza) => {
                                                assert!(!stanza.node.windows(b"application-private-text".len()).any(|b| b == b"application-private-text"));
                                                state.sends.lock().await.push((tokio::time::Instant::now(), stanza.node));
                                                runner_response::Result::Send(proto::SendResult { server_timestamp: 1720000000, participant_hash_mismatch: false })
                                            }
                                            service_request::Op::Ping(_) | service_request::Op::ReleaseSession(_) => runner_response::Result::Ok(proto::Ok {}),
                                            _ => panic!("Unexpected fixture lookup"),
                                        };
                                        let body = match failure { Some(error) => Body::Error(error), None => Body::RunnerResponse(proto::RunnerResponse { result: Some(result) }) };
                                        tx.send(proto::Frame::with(frame.id, body)).unwrap();
                                    }
                                    Some(Body::ServiceResponse(response)) => {
                                        if let Some(pending) = state.pending.lock().await.remove(&frame.id) { let _ = pending.send(proto::Frame::with(frame.id, Body::ServiceResponse(response))); }
                                    }
                                    Some(Body::Error(error)) => {
                                        if let Some(pending) = state.pending.lock().await.remove(&frame.id) { let _ = pending.send(proto::Frame::with(frame.id, Body::Error(error))); }
                                    }
                                    _ => panic!("Unexpected fixture frame"),
                                }
                            }
                        }
                    }
                });
            }
        });
        Self { url, state, task }
    }
    pub async fn command(
        &self,
        node: &str,
        generation: u64,
        op: proto::runner_request::Op,
    ) -> proto::Frame {
        let id = self.state.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.state.pending.lock().await.insert(id, tx);
        let out = self
            .state
            .connections
            .lock()
            .await
            .get(node)
            .unwrap()
            .clone();
        out.send(proto::Frame::with(
            id,
            Body::RunnerRequest(proto::RunnerRequest {
                session_id: SESSION.into(),
                lease_generation: generation,
                op: Some(op),
            }),
        ))
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap()
    }
    pub async fn disconnect(&self, node: &str) {
        self.state
            .disconnects
            .lock()
            .await
            .remove(node)
            .unwrap()
            .send(())
            .unwrap();
    }
    pub async fn bundle(&self, jid: &str, bundle: proto::Bundle) {
        self.state.bundles.lock().await.insert(jid.into(), bundle);
    }
    pub async fn sends(&self) -> Vec<(tokio::time::Instant, Vec<u8>)> {
        self.state.sends.lock().await.clone()
    }
}
impl Drop for Hub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn config(node: &str, url: &str, history: bool) -> signal_node::config::Resolved {
    let file = format!(
        r#"node_id="{node}"
 [polymorfa]
 url="{url}"
 credential="fixture-project-principal"
 sessions=["{SESSION}"]
 request_timeout_ms=1000
 reconnect_min_ms=10
 reconnect_max_ms=50
 [storage]
 driver="memory"
 master_key="CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="
 [http]
 listen="127.0.0.1:0"
 secret="{APP_SECRET}"
 [leases]
 ttl_ms=500
 renew_interval_ms=100
 [delivery]
 ack_timeout_ms=250
 [history]
 deliver={history}
 "#
    );
    Config::from_toml(&file).unwrap().resolve().unwrap()
}
pub async fn start(hub: &Hub, node: &str, backend: Backend, history: bool) -> signal_node::Running {
    let running = signal_node::start(config(node, &hub.url, history), backend)
        .await
        .unwrap();
    wait(|| {
        running
            .node
            .session(SESSION)
            .is_some_and(|s| s.is_claimed())
    })
    .await;
    running
}
pub async fn wait(test: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !test() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
pub async fn peer(
    scope: &str,
) -> (
    Arc<
        wacore_signal_ops::SignalOps<
            wacore_recordstore::RecordSignalStore<
                wacore_recordstore::MemoryRecordStore,
                wacore_recordstore::AesGcmSealer,
            >,
        >,
    >,
    proto::Bundle,
) {
    use wacore_recordstore::{AesGcmSealer, LeaseStore, MemoryRecordStore, RecordSignalStore};
    let records = Arc::new(MemoryRecordStore::new());
    let lease = records
        .acquire(scope, "peer", 0, 60000)
        .await
        .unwrap()
        .unwrap();
    let store = Arc::new(RecordSignalStore::new(
        records,
        Arc::new(AesGcmSealer::new(&[7; 32])),
        lease.fence,
    ));
    let ops = Arc::new(wacore_signal_ops::SignalOps::create(store).await.unwrap());
    let identity = ops.public_identity().await;
    let pre = ops.generate_prekeys(1).await.unwrap().remove(0);
    let bundle = proto::Bundle {
        registration_id: identity.registration_id,
        device_id: 1,
        identity_key: identity.identity_key.to_vec(),
        signed_pre_key_id: identity.signed_prekey.id,
        signed_pre_key: identity.signed_prekey.public_key.to_vec(),
        signed_pre_key_signature: identity.signed_prekey.signature.to_vec(),
        pre_key: Some(proto::PreKey {
            id: pre.id,
            public_key: pre.public_key.to_vec(),
        }),
    };
    (ops, bundle)
}
pub async fn pair<S: wacore_signal_ops::ServiceStore>(ops: &wacore_signal_ops::SignalOps<S>) {
    use hmac::Mac;
    use wacore::libsignal::protocol::{KeyPair, PublicKey};
    use waproto::whatsapp as wa;
    let mut rng = rand10::make_rng::<rand10::rngs::StdRng>();
    let account = KeyPair::generate(&mut rng);
    let identity = ops.public_identity().await;
    let device = KeyPair::new(
        PublicKey::from_djb_public_key_bytes(&identity.identity_key).unwrap(),
        KeyPair::generate(&mut rng).private_key,
    );
    let details = signal_node::message::encode(&wa::ADVDeviceIdentity {
        raw_id: Some(1),
        timestamp: Some(0),
        key_index: Some(1),
        account_type: Some(wa::ADVEncryptionType::E2EE),
        device_type: Some(wa::ADVEncryptionType::E2EE),
    });
    let signed = signal_node::message::encode(&wacore::adv::test_util::signed_identity(
        &account,
        &device,
        &details,
        wacore::adv::test_util::account_prefix(Some(wa::ADVEncryptionType::E2EE)),
        None,
        true,
    ));
    let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&identity.adv_secret).unwrap();
    mac.update(&signed);
    let container = signal_node::message::encode(&wa::ADVSignedDeviceIdentityHMAC {
        details: Some(signed),
        hmac: Some(mac.finalize().into_bytes().to_vec()),
        account_type: Some(wa::ADVEncryptionType::E2EE),
    });
    ops.sign_pairing(&container).await.unwrap();
}
