#![cfg(feature = "backend-memory")]

use bytes::Bytes;
use starmetal_core::config::StorageConfig;
use starmetal_core::ports::StoragePort;
use starmetal_storage::OpenDalStorage;

fn create_memory_storage() -> OpenDalStorage {
    let builder = opendal::services::Memory::default();
    let operator = opendal::Operator::new(builder)
        .expect("build memory operator")
        .finish();
    OpenDalStorage::new(operator)
}

#[tokio::test]
async fn put_and_get() {
    let storage = create_memory_storage();
    let data = Bytes::from_static(b"hello starmetal");

    storage
        .put("test/key.txt", data.clone())
        .await
        .expect("put should succeed");

    let result = storage
        .get("test/key.txt")
        .await
        .expect("get should succeed");

    assert_eq!(
        result,
        Some(data),
        "retrieved data should match stored data"
    );
}

#[tokio::test]
async fn get_nonexistent_returns_none() {
    let storage = create_memory_storage();

    let result = storage
        .get("does/not/exist.txt")
        .await
        .expect("get should succeed even for missing key");

    assert_eq!(result, None, "missing key should return None");
}

#[tokio::test]
async fn exists_check() {
    let storage = create_memory_storage();
    let data = Bytes::from_static(b"content");

    assert!(
        !storage
            .exists("check/key.txt")
            .await
            .expect("exists should succeed"),
        "key should not exist before put"
    );

    storage
        .put("check/key.txt", data)
        .await
        .expect("put should succeed");

    assert!(
        storage
            .exists("check/key.txt")
            .await
            .expect("exists should succeed"),
        "key should exist after put"
    );
}

#[tokio::test]
async fn delete_key() {
    let storage = create_memory_storage();
    let data = Bytes::from_static(b"to be deleted");

    storage
        .put("del/key.txt", data)
        .await
        .expect("put should succeed");

    assert!(
        storage
            .exists("del/key.txt")
            .await
            .expect("exists should succeed"),
        "key should exist after put"
    );

    storage
        .delete("del/key.txt")
        .await
        .expect("delete should succeed");

    assert!(
        !storage
            .exists("del/key.txt")
            .await
            .expect("exists should succeed"),
        "key should not exist after delete"
    );

    let result = storage
        .get("del/key.txt")
        .await
        .expect("get should succeed");

    assert_eq!(result, None, "deleted key should return None on get");
}

#[tokio::test]
async fn list_prefix_keys() {
    let storage = create_memory_storage();

    storage
        .put("pypi/requests/2.31.0/file.tar.gz", Bytes::from_static(b"a"))
        .await
        .expect("put should succeed");
    storage
        .put("pypi/requests/2.31.0/file.whl", Bytes::from_static(b"b"))
        .await
        .expect("put should succeed");
    storage
        .put("npm/lodash/4.17.21/file.tgz", Bytes::from_static(b"c"))
        .await
        .expect("put should succeed");

    let pypi_keys = storage
        .list_prefix("pypi/requests/2.31.0/")
        .await
        .expect("list_prefix should succeed");

    assert_eq!(
        pypi_keys.len(),
        2,
        "should list 2 keys under pypi/requests/2.31.0/"
    );

    let npm_keys = storage
        .list_prefix("npm/")
        .await
        .expect("list_prefix should succeed");

    assert!(
        !npm_keys.is_empty(),
        "should list at least 1 key under npm/"
    );

    let empty_keys = storage
        .list_prefix("cargo/")
        .await
        .expect("list_prefix should succeed");

    assert!(
        empty_keys.is_empty(),
        "should list 0 keys under non-existent prefix"
    );
}

#[tokio::test]
async fn from_config_builds_memory_backend() {
    let config = StorageConfig {
        backend: "memory".to_string(),
        ..Default::default()
    };
    let storage = OpenDalStorage::from_config(&config).expect("memory backend should build");

    storage
        .put("key", Bytes::from_static(b"value"))
        .await
        .expect("put should succeed");
    let value = storage.get("key").await.expect("get should succeed");

    assert_eq!(value, Some(Bytes::from_static(b"value")));
}
