// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
#![cfg(windows)]

use oan_identity_gateway::runtime_connector::{local_runtime_transport, RuntimeIpcTransport};
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
