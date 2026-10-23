// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
#![cfg(windows)]

use oan_identity_gateway::runtime_connector::AuthenticatedRuntimeConnector;
use oan_identity_gateway::runtime_connector::{local_runtime_transport, RuntimeIpcTransport};
use serde_json::json;
use std::process::{Command, Stdio};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ServerOptions;

#[tokio::test]
async fn gateway_transport_exchanges_one_bounded_frame_with_windows_runtime_pipe() {
    let path = format!(r"\\.\pipe\oan-gateway-{}", std::process::id());
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&path)
        .unwrap();
    let task = tokio::spawn(async move {
        server.connect().await.unwrap();
        let mut bytes = Vec::new();
        let mut reader = BufReader::new(server);
        reader.read_until(b'\n', &mut bytes).await.unwrap();
        assert_eq!(bytes, b"{\"test\":true}\n");
        let mut server = reader.into_inner();
        server.write_all(b"{\"ok\":true}\n").await.unwrap();
        server.flush().await.unwrap();
    });
    let transport =
        local_runtime_transport(&format!("pipe:{path}"), None, Some(std::process::id())).unwrap();
    let result = transport
        .round_trip(b"{\"test\":true}".to_vec())
        .await
        .unwrap();
    assert_eq!(result, b"{\"ok\":true}\n");
    task.await.unwrap();
    assert!(local_runtime_transport("pipe:runtime", None, None).is_err());
}

#[tokio::test]
async fn gateway_transport_rejects_wrong_runtime_process_before_sending_frame() {
    let path = format!(r"\\.\pipe\oan-gateway-owner-{}", std::process::id());
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&path)
        .unwrap();
    let transport =
        local_runtime_transport(&format!("pipe:{path}"), None, Some(std::process::id() + 1))
            .unwrap();
    assert_eq!(
        transport.round_trip(b"{}".to_vec()).await.unwrap_err(),
        "runtime_ipc_owner_mismatch"
    );
    drop(server);
}

#[tokio::test]
#[ignore = "requires sibling oan-identity-runtime build and Node >=22.13; run explicitly for cross-language IPC acceptance"]
async fn gateway_connects_to_actual_node_runtime_pipe() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../oan-identity-runtime/test-cases/windows-ipc-host.mjs");
    if !script.exists() {
        panic!("Runtime cross-language fixture missing");
    }
    let pipe = format!(r"\\.\pipe\oan-gateway-node-{}", std::process::id());
    let token = "gateway-test-bearer-with-more-than-thirty-two-characters";
    let mut child = Command::new("node")
        .arg(script)
        .arg(&pipe)
        .arg(token)
        .arg("gateway-test")
        .arg("tenant-test")
        .stdout(Stdio::piped())
        .spawn()
        .expect("start Node Runtime fixture");
    let mut ready = String::new();
    use std::io::BufRead;
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "READY");
    let transport =
        local_runtime_transport(&format!("pipe:{pipe}"), None, Some(child.id())).unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        transport,
        token.into(),
        "gateway-test".into(),
        Some("tenant-test".into()),
    )
    .unwrap();
    let envelope = json!({"resource":"test"});
    let context = connector
        .verify_authenticated(&envelope, "did:oan:audience", "req-1", "sha256:test")
        .await
        .unwrap();
    assert_eq!(context.subject_did, "did:oan:fixture");
    let signed = connector
        .sign_authenticated(&json!({"kind":"gateway-response"}))
        .await
        .unwrap();
    assert_eq!(signed["fixtureSigned"], true);
    child.kill().unwrap();
    child.wait().unwrap();
}
