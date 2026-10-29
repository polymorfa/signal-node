use signal_node::store::{PostgresStore, SqliteStore};
use wacore::store::traits::SignalStore;
use wacore_recordstore::{LeaseStore, Namespace, RecordStore, WriteOp, is_fence_lost};

#[tokio::test]
async fn sqlite_runs_every_recordstore_check() {
    let store = SqliteStore::connect("sqlite::memory:", 1).await.unwrap();
    wacore_recordstore::conformance::run_all(&store).await;
}
#[tokio::test]
async fn sqlite_two_pools_fence_takeover_and_exclusive_batches() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-state");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("store-{}.sqlite", rand::random::<u64>()));
    let url = format!("sqlite://{}", path.display());
    let first = SqliteStore::connect(&url, 2).await.unwrap();
    let second = SqliteStore::connect(&url, 2).await.unwrap();
    let a = first
        .acquire("scope", "first", 1000, 100)
        .await
        .unwrap()
        .unwrap();
    assert!(
        second
            .acquire("scope", "second", 1099, 100)
            .await
            .unwrap()
            .is_none()
    );
    let b = second
        .acquire("scope", "second", 1100, 100)
        .await
        .unwrap()
        .unwrap();
    assert!(b.fence.generation > a.fence.generation);
    let write = WriteOp::Put {
        ns: Namespace::Device,
        key: "key".into(),
        value: b"sealed-fixture".to_vec(),
    };
    assert!(is_fence_lost(
        &first
            .write(&a.fence, std::slice::from_ref(&write))
            .await
            .unwrap_err()
    ));
    second.write(&b.fence, &[write]).await.unwrap();
    assert!(first.renew(&a, 1101, 100).await.unwrap().is_none());
    assert_eq!(
        first
            .get("scope", Namespace::Device, "key")
            .await
            .unwrap()
            .unwrap(),
        b"sealed-fixture"
    );
    drop(first);
    drop(second);
    let _ = std::fs::remove_file(path);
}
#[tokio::test]
async fn postgres_runs_every_recordstore_check() {
    let Ok(url) = std::env::var("SIGNAL_NODE_TEST_POSTGRES_URL") else {
        assert!(
            std::env::var("CI").is_err(),
            "CI must provide PostgreSQL conformance database"
        );
        eprintln!("PostgreSQL conformance not run: SIGNAL_NODE_TEST_POSTGRES_URL unset");
        return;
    };
    let store = PostgresStore::connect(&url, 8).await.unwrap();
    wacore_recordstore::conformance::run_all(&store).await;
}

#[tokio::test]
async fn sql_records_cannot_be_swapped_between_scope_namespace_or_key() {
    use std::sync::Arc;
    use wacore_recordstore::{AesGcmSealer, RecordSignalStore};
    let records = Arc::new(SqliteStore::connect("sqlite::memory:", 1).await.unwrap());
    let a = records
        .acquire("a", "holder", 0, 1000)
        .await
        .unwrap()
        .unwrap();
    let b = records
        .acquire("b", "holder", 0, 1000)
        .await
        .unwrap()
        .unwrap();
    let sealer = Arc::new(AesGcmSealer::new(&[7; 32]));
    let first = RecordSignalStore::new(records.clone(), sealer.clone(), a.fence.clone());
    let second = RecordSignalStore::new(records.clone(), sealer, b.fence.clone());
    first
        .put_session("alice", b"sealed-secret-fixture")
        .await
        .unwrap();
    let raw = records
        .get("a", Namespace::Session, "alice")
        .await
        .unwrap()
        .unwrap();
    assert!(!raw.windows(21).any(|p| p == b"sealed-secret-fixture"));
    records
        .write(
            &a.fence,
            &[
                WriteOp::Put {
                    ns: Namespace::Session,
                    key: "mallory".into(),
                    value: raw.clone(),
                },
                WriteOp::Put {
                    ns: Namespace::Device,
                    key: "local".into(),
                    value: raw.clone(),
                },
            ],
        )
        .await
        .unwrap();
    records
        .write(
            &b.fence,
            &[WriteOp::Put {
                ns: Namespace::Session,
                key: "alice".into(),
                value: raw,
            }],
        )
        .await
        .unwrap();
    assert!(first.get_session("mallory").await.is_err());
    assert!(first.load_device().await.is_err());
    assert!(second.get_session("alice").await.is_err());
    assert_eq!(
        first.get_session("alice").await.unwrap().unwrap().as_ref(),
        b"sealed-secret-fixture"
    );
}

#[tokio::test]
async fn released_sql_fences_cannot_write_before_the_next_takeover() {
    let store = SqliteStore::connect("sqlite::memory:", 1).await.unwrap();
    let lease = store
        .acquire("released", "a", 0, 1000)
        .await
        .unwrap()
        .unwrap();
    store.release(&lease).await.unwrap();
    assert!(is_fence_lost(
        &store
            .write(
                &lease.fence,
                &[WriteOp::Put {
                    ns: Namespace::Device,
                    key: "local".into(),
                    value: vec![1]
                }]
            )
            .await
            .unwrap_err()
    ));
    if let Ok(url) = std::env::var("SIGNAL_NODE_TEST_POSTGRES_URL") {
        let store = PostgresStore::connect(&url, 2).await.unwrap();
        let scope = format!("released-{}", rand::random::<u64>());
        let lease = store.acquire(&scope, "a", 0, 1000).await.unwrap().unwrap();
        store.release(&lease).await.unwrap();
        assert!(is_fence_lost(
            &store
                .write(
                    &lease.fence,
                    &[WriteOp::Put {
                        ns: Namespace::Device,
                        key: "local".into(),
                        value: vec![1]
                    }]
                )
                .await
                .unwrap_err()
        ));
    }
}
