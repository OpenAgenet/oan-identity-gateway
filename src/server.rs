// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Protected Gateway HTTP ingress. Runtime is the source of authenticated
//! principal data; the Gateway only routes an already verified request.

use crate::{
    config::Config,
    envelope::{response_signing_intent, VerifiedProxyEnvelope},
    runtime_connector::{local_runtime_transport, AuthenticatedRuntimeConnector},
    verify_verified_delegation,
};
use base64::Engine;
use serde_json::Value;
use sha2::Digest;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::{timeout, Duration},
};

const MAX_REQUEST: usize = 256 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn serve(config: Config) -> Result<(), String> {
    config.validate().map_err(|e| e.to_string())?;
    let bind = config.ingress_bind.clone().ok_or("ingress_bind_required")?;
    let bearer = config
        .runtime_bearer
        .clone()
        .ok_or("runtime_bearer_required")?;
    let caller_id = config.caller_id.clone().ok_or("caller_id_required")?;
    let backend_token = config
        .backend_auth_token
        .clone()
        .ok_or("backend_auth_token_required")?;
    let listener = TcpListener::bind(&bind)
        .await
        .map_err(|_| "ingress_bind_failed")?;
    let shared = Arc::new(config);
    loop {
        let (mut socket, _) = listener
            .accept()
            .await
            .map_err(|_| "ingress_accept_failed")?;
        let cfg = shared.clone();
        let bearer = bearer.clone();
        let caller_id = caller_id.clone();
        let backend_token = backend_token.clone();
        tokio::spawn(async move {
            if let Err(code) = handle(&mut socket, cfg, bearer, caller_id, backend_token).await {
                let _ = write_error(&mut socket, 502, &code).await;
            }
        });
    }
}

async fn handle(
    socket: &mut tokio::net::TcpStream,
    config: Arc<Config>,
    bearer: String,
    caller_id: String,
    backend_token: String,
) -> Result<(), String> {
    let (method, target, headers, body) = read_request(socket).await?;
    let encoded = headers
        .get("x-oan-envelope")
        .ok_or("missing_oan_envelope")?;
    let envelope: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "invalid_oan_envelope")?,
    )
    .map_err(|_| "invalid_oan_envelope")?;
    let request_id = headers
        .get("x-oan-request-id")
        .ok_or("missing_oan_request_id")?
        .clone();
    let payload_digest = format!("sha256:{:x}", sha2::Sha256::digest(&body));
    let target_did = envelope
        .get("targetResourceDid")
        .and_then(Value::as_str)
        .ok_or("target_resource_missing")?;
    let route = config
        .route(
            envelope
                .get("tenantId")
                .and_then(Value::as_str)
                .ok_or("tenant_missing")?,
            target_did,
        )
        .map_err(|_| "tenant_route_denied")?;
    let connector = AuthenticatedRuntimeConnector::new(
        local_runtime_transport(
            &config.runtime_endpoint,
            config.runtime_owner_uid,
            config.runtime_owner_pid,
        )?,
        bearer,
        caller_id.clone(),
        envelope
            .get("tenantId")
            .and_then(Value::as_str)
            .map(str::to_owned),
    )
    .map_err(|_| "runtime_credentials_invalid")?;
    let context = connector
        .verify_authenticated(&envelope, target_did, &request_id, &payload_digest)
        .await
        .map_err(|_| "runtime_verification_failed")?;
    let proxy_did = config
        .gateway_did
        .as_deref()
        .ok_or("gateway_did_required")?;
    // Ordinary forwarding preserves the original end-to-end signed caller and
    // does not require a delegation. If a delegation artifact is supplied,
    // however, it must be Runtime-verified before the Gateway accepts it.
    if envelope
        .get("delegationDigest")
        .and_then(Value::as_str)
        .is_some()
    {
        verify_verified_delegation(
            &context.subject_did,
            proxy_did,
            target_did,
            context.delegation_verified,
            context.delegation_digest.as_deref(),
        )
        .map_err(|_| "delegation_verification_failed")?;
    }
    let verified = VerifiedProxyEnvelope {
        original_caller_did: context.subject_did.clone(),
        proxy_did: proxy_did.to_owned(),
        target_resource_did: target_did.to_owned(),
        tenant_id: envelope
            .get("tenantId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        request_id: request_id.clone(),
        payload_digest: payload_digest.clone(),
        delegation_digest: envelope
            .get("delegationDigest")
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    let url = url::Url::parse(&format!("http://gateway.invalid{target}"))
        .map_err(|_| "invalid_target")?;
    let mut destination =
        reqwest::Url::parse(&route.destination).map_err(|_| "destination_invalid")?;
    destination.set_path(url.path());
    destination.set_query(url.query());
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "backend_client_init_failed")?;
    let mut request = client
        .request(method.parse().map_err(|_| "invalid_method")?, destination)
        .body(body);
    request = request
        .header(
            "x-oan-gateway-envelope",
            serde_json::to_string(&verified).map_err(|_| "envelope_encode_failed")?,
        )
        .header("x-oan-sidecar-token", backend_token)
        .header("x-oan-verified-principal", context.subject_did)
        .header("x-oan-request-id", request_id);
    // Preserve only protocol semantics that are safe to forward. Identity,
    // proxy and forwarding headers are constructed above and must never be
    // inherited from the untrusted caller.
    for (name, value) in &headers {
        let allowed = matches!(
            name.as_str(),
            "content-type"
                | "accept"
                | "a2a-version"
                | "mcp-protocol-version"
                | "mcp-session-id"
                | "last-event-id"
                | "cache-control"
        );
        if allowed {
            request = request.header(name, value);
        }
    }
    let response = request.send().await.map_err(|_| "backend_unavailable")?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let bytes = response.bytes().await.map_err(|_| "backend_read_failed")?;
    let response_digest = format!("sha256:{:x}", sha2::Sha256::digest(&bytes));
    let response_intent = response_signing_intent(&verified, status.as_u16(), &response_digest);
    let signed_response = connector
        .sign_authenticated(&response_intent)
        .await
        .map_err(|_| "response_signing_failed")?;
    let encoded_response = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&signed_response).map_err(|_| "response_signing_failed")?);
    let head = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nX-OAN-Response-Envelope: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", status.as_u16(), bytes.len(), content_type, encoded_response);
    socket
        .write_all(head.as_bytes())
        .await
        .map_err(|_| "response_write_failed")?;
    socket
        .write_all(&bytes)
        .await
        .map_err(|_| "response_write_failed")?;
    Ok(())
}

async fn read_request(
    socket: &mut tokio::net::TcpStream,
) -> Result<(String, String, HashMap<String, String>, Vec<u8>), String> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end;
    loop {
        let n = timeout(IO_TIMEOUT, socket.read(&mut chunk))
            .await
            .map_err(|_| "ingress_read_timeout")?
            .map_err(|_| "ingress_read_failed")?;
        if n == 0 {
            return Err("ingress_connection_closed".into());
        };
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > MAX_REQUEST {
            return Err("request_too_large".into());
        };
        if let Some(p) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = p + 4;
            break;
        }
    }
    let head = String::from_utf8(bytes[..header_end].to_vec()).map_err(|_| "invalid_http")?;
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or("invalid_http")?;
    let mut parts = first.split_whitespace();
    let method = parts.next().ok_or("invalid_http")?.to_owned();
    let target = parts.next().ok_or("invalid_http")?.to_owned();
    if parts.next() != Some("HTTP/1.1")
        || parts.next().is_some()
        || target.starts_with("http://")
        || target.starts_with("https://")
    {
        return Err("invalid_target".into());
    };
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':').ok_or("invalid_http")?;
        let key = k.trim().to_ascii_lowercase();
        if headers.insert(key, v.trim().to_owned()).is_some() {
            return Err("duplicate_header".into());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0usize);
    if header_end + length > MAX_REQUEST {
        return Err("request_too_large".into());
    };
    while bytes.len() < header_end + length {
        let n = timeout(IO_TIMEOUT, socket.read(&mut chunk))
            .await
            .map_err(|_| "ingress_read_timeout")?
            .map_err(|_| "ingress_read_failed")?;
        if n == 0 {
            return Err("ingress_connection_closed".into());
        };
        bytes.extend_from_slice(&chunk[..n]);
    }
    Ok((
        method,
        target,
        headers,
        bytes[header_end..header_end + length].to_vec(),
    ))
}

async fn write_error<W: AsyncWrite + Unpin>(
    socket: &mut W,
    status: u16,
    code: &str,
) -> Result<(), String> {
    let body = format!("{{\"error\":\"{}\"}}", code);
    let head=format!("HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",status,body.len());
    socket
        .write_all(head.as_bytes())
        .await
        .map_err(|_| "response_write_failed")?;
    socket
        .write_all(body.as_bytes())
        .await
        .map_err(|_| "response_write_failed")?;
    Ok(())
}
