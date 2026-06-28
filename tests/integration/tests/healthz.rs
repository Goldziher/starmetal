use starmetal_integration_tests::TestServer;

#[tokio::test]
async fn healthz_returns_ok() {
    let server = TestServer::start().await;

    let response = reqwest::get(format!("{}/healthz", server.base_url()))
        .await
        .expect("request failed");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.expect("failed to read body"), "ok");

    server.shutdown();
}
