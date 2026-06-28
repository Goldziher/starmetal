#![cfg(feature = "backend-fs")]

use bytes::Bytes;
use starmetal_core::config::StorageConfig;
use starmetal_core::ports::StoragePort;
use starmetal_storage::OpenDalStorage;

#[tokio::test]
async fn from_config_builds_fs_backend_with_explicit_root() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig {
        backend: "fs".to_string(),
        ..Default::default()
    };
    config.options.insert(
        "root".to_string(),
        tempdir.path().to_string_lossy().to_string(),
    );

    let storage = OpenDalStorage::from_config(&config).expect("fs backend should build");
    storage
        .put("pkg/file", Bytes::from_static(b"value"))
        .await
        .expect("put should succeed");

    let value = storage.get("pkg/file").await.expect("get should succeed");
    assert_eq!(value, Some(Bytes::from_static(b"value")));
}
