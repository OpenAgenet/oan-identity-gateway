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
use futures_util::StreamExt;
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

pub fn has_terminal_response_proof(bytes: &[u8]) -> bool {
    bytes
        .windows(b"event: oan-response-proof\ndata: ".len())
        .any(|window| window == b"event: oan-response-proof\ndata: ")
        || bytes
            .windows(b"event: oan-response-proof\r\ndata: ".len())
            .any(|window| window == b"event: oan-response-proof\r\ndata: ")
}

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
            let mut response_started = false;
            if let Err(code) = handle(
                &mut socket,
                cfg,
                bearer,
                caller_id,
                backend_token,
                &mut response_started,
            )
            .await
            {
                eprintln!("gateway request failed: {code}");
                if !response_started {
                    let _ = write_error(&mut socket, 502, &code).await;
                }
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
    response_started: &mut bool,
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
    // Compare the signed HTTP context before dispatch; Runtime subsequently
    // verifies the signature covering this payload. Legacy unbound profiles
    // remain compatible; the reference host requires the new binding.
    if let Some(binding) = envelope.pointer("/message/payload/httpBinding") {
        let expected = serde_json::json!({"method": method, "target": target,
            "mcpSessionId": headers.get("mcp-session-id").map(String::as_str).unwrap_or("")});
        if binding != &expected {
            return Err("http_request_binding_mismatch".into());
        }
    }
    let request_id = headers
        .get("x-oan-request-id")
        .ok_or("missing_oan_request_id")?
        .clone();
    let payload_digest = format!("sha256:{:x}", sha2::Sha256::digest(&body));
    let target_did = envelope
        .get("targetResourceDid")
        .and_then(Value::as_str)
        .ok_or("target_resource_missing")?;
    let claimed_tenant = envelope
        .get("tenantId")
        .and_then(Value::as_str)
        .ok_or("tenant_missing")?;
    let connector = AuthenticatedRuntimeConnector::new(
        local_runtime_transport(
            &config.runtime_endpoint,
            config.runtime_owner_uid,
            config.runtime_owner_pid,
        )?,
        bearer,
        caller_id.clone(),
        Some(claimed_tenant.to_owned()),
    )
    .map_err(|_| "runtime_credentials_invalid")?;
    let context = connector
        .verify_authenticated(&envelope, target_did, &request_id, &payload_digest)
        .await
        .map_err(|error| {
            eprintln!("Runtime request verification failed: {error}");
            "runtime_verification_failed"
        })?;
    // Only the authenticated Runtime response may select a tenant route.
    let authenticated_tenant = context.tenant_id.as_deref().ok_or("tenant_missing")?;
    let route = config
        .route(authenticated_tenant, target_did)
        .map_err(|_| "tenant_route_denied")?;
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
        if context.delegation_digest.as_deref()
            != envelope.get("delegationDigest").and_then(Value::as_str)
        {
            return Err("delegation_verification_failed".into());
        }
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
        tenant_id: authenticated_tenant.to_owned(),
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
    if config.forward_verified_envelope {
        // This is the exact envelope verified above, never a caller supplied
        // principal. The downstream ingress must independently verify it using
        // its own replay store before dispatching a business handler.
        request = request.header("x-oan-envelope", encoded);
    }
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
    // The receiver ingress may still be binding during a fresh scenario run.
    // Retry only connection failures for a bounded window; HTTP responses,
    // including proof-less 5xx responses, are never retried here.
    let mut response = None;
    for attempt in 0..20 {
        match request
            .try_clone()
            .ok_or("backend_request_clone_failed")?
            .send()
            .await
        {
            Ok(value) => {
                // A freshly restarted downstream may accept the TCP connection
                // before its protocol worker is ready.  Its temporary 502 has
                // no receiver-owned response proof.  Retry this narrow shape
                // only for a bounded window; proof-bearing responses and all
                // other HTTP statuses are returned immediately.
                if value.status() == reqwest::StatusCode::BAD_GATEWAY
                    && !value.headers().contains_key("x-oan-response-envelope")
                    && attempt < 19
                {
                    eprintln!("gateway proofless 502 retry {}", attempt + 1);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                response = Some(value);
                break;
            }
            Err(error) if attempt < 19 => {
                eprintln!("gateway backend connect retry {}: {}", attempt + 1, error);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(_) => break,
        }
    }
    let response = response.ok_or("backend_unavailable")?;
    let status = response.status();
    eprintln!(
        "gateway upstream response status={} content_type={} proof_header={}",
        status.as_u16(),
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        response.headers().contains_key("x-oan-response-envelope")
    );
    if config.outbound_passthrough {
        // Egress cannot replace the receiver's identity proof with its own.
        // Preserve the bounded wire body (including terminal SSE proof) and
        // only the protocol/response-proof headers needed by the native client.
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let receiver_proof = response
            .headers()
            .get("x-oan-response-envelope")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let response_session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "backend_read_failed")?;
            if bytes.len() + chunk.len() > MAX_REQUEST * 4 {
                return Err("response_too_large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        // Passthrough is safe only when the downstream has already produced
        // a terminal proof.  A native A2A backend has no Sidecar proof, so it
        // must fall through and receive a Gateway-owned proof instead of
        // silently returning an unverifiable response.
        let stream_proof = has_terminal_response_proof(&bytes);
        if receiver_proof.is_some() || stream_proof {
            let mut head = format!("HTTP/1.1 {}\r\n", status.as_u16());
            head.push_str(&format!("Content-Type: {content_type}\r\n"));
            if let Some(value) = response_session.as_deref() {
                head.push_str(&format!("Mcp-Session-Id: {value}\r\n"));
            }
            if let Some(value) = receiver_proof {
                head.push_str(&format!("X-OAN-Response-Envelope: {value}\r\n"));
            }
            head.push_str(&format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            ));
            socket
                .write_all(head.as_bytes())
                .await
                .map_err(|_| "response_write_failed")?;
            socket
                .write_all(&bytes)
                .await
                .map_err(|_| "response_write_failed")?;
            return Ok(());
        }

        // A caller-owned egress Gateway is configured as a proof-preserving
        // relay and has no signing authority. If the receiver failed to
        // produce a terminal proof, fail closed instead of trying to sign the
        // response locally (which would both misrepresent the signer and
        // surface a misleading IPC schema error).
        if config.outbound_passthrough {
            return Err("response_proof_missing".into());
        }

        // The response was buffered above, so sign this exact body rather
        // than trying to consume the reqwest stream a second time.
        let response_digest = format!("sha256:{:x}", sha2::Sha256::digest(&bytes));
        let response_intent = response_signing_intent(&verified, status.as_u16(), &response_digest);
        let signed_response = connector
            .sign_authenticated(&response_intent)
            .await
            .map_err(|error| {
                eprintln!("gateway response signing failed: {error}");
                "response_signing_failed"
            })?;
        let encoded_response = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&signed_response).map_err(|_| "response_signing_failed")?);
        let session_header = response_session
            .as_deref()
            .or_else(|| headers.get("mcp-session-id").map(String::as_str))
            .map(|v| format!("Mcp-Session-Id: {v}\r\n"))
            .unwrap_or_default();
        let is_stream = content_type.starts_with("text/event-stream");
        if is_stream {
            *response_started = true;
            socket
                .write_all(format!("HTTP/1.1 {}\r\nTransfer-Encoding: chunked\r\nContent-Type: {}\r\n{}Cache-Control: no-store\r\nConnection: close\r\n\r\n", status.as_u16(), content_type, session_header).as_bytes())
                .await
                .map_err(|_| "response_write_failed")?;
            write_chunk(socket, &bytes).await?;
            write_chunk(
                socket,
                format!(
                    "\nevent: oan-response-proof\ndata: {}\n\n",
                    encoded_response
                )
                .as_bytes(),
            )
            .await?;
            socket
                .write_all(b"0\r\n\r\n")
                .await
                .map_err(|_| "response_write_failed")?;
            return Ok(());
        }
        let session_header = response_session
            .as_deref()
            .or_else(|| headers.get("mcp-session-id").map(String::as_str))
            .map(|v| format!("Mcp-Session-Id: {v}\r\n"))
            .unwrap_or_default();
        let head = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}X-OAN-Response-Envelope: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", status.as_u16(), bytes.len(), content_type, session_header, encoded_response);
        socket
            .write_all(head.as_bytes())
            .await
            .map_err(|_| "response_write_failed")?;
        socket
            .write_all(&bytes)
            .await
            .map_err(|_| "response_write_failed")?;
        return Ok(());
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let is_stream = content_type.starts_with("text/event-stream");
    let session_header = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| format!("Mcp-Session-Id: {v}\r\n"))
        .unwrap_or_default();
    let receiver_proof = response
        .headers()
        .get("x-oan-response-envelope")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "backend_read_failed")?;
        if bytes.len() + chunk.len() > MAX_REQUEST * 4 {
            return Err("response_too_large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    // A Sidecar may already have produced the terminal proof for this exact
    // response. Preserve it through the Gateway so an MCP caller can verify
    // the second-hop `sidecar-response` proof. Only sign below when the
    // downstream response is genuinely unsigned (for example a native A2A
    // backend), in which case the Gateway is the authorized fallback signer.
    let stream_proof = has_terminal_response_proof(&bytes);
    if receiver_proof.is_some() || stream_proof {
        *response_started = true;
        if is_stream {
            socket.write_all(format!("HTTP/1.1 {}\r\nTransfer-Encoding: chunked\r\nContent-Type: {}\r\n{}Cache-Control: no-store\r\nConnection: close\r\n\r\n", status.as_u16(), content_type, session_header).as_bytes()).await.map_err(|_| "response_write_failed")?;
            write_chunk(socket, &bytes).await?;
            socket
                .write_all(b"0\r\n\r\n")
                .await
                .map_err(|_| "response_write_failed")?;
            return Ok(());
        }
        let proof_header = receiver_proof
            .map(|value| format!("X-OAN-Response-Envelope: {value}\r\n"))
            .unwrap_or_default();
        let head = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}{}Cache-Control: no-store\r\nConnection: close\r\n\r\n", status.as_u16(), bytes.len(), content_type, session_header, proof_header);
        socket
            .write_all(head.as_bytes())
            .await
            .map_err(|_| "response_write_failed")?;
        socket
            .write_all(&bytes)
            .await
            .map_err(|_| "response_write_failed")?;
        return Ok(());
    }
    let response_digest = format!("sha256:{:x}", sha2::Sha256::digest(&bytes));
    let response_intent = response_signing_intent(&verified, status.as_u16(), &response_digest);
    let signed_response = connector
        .sign_authenticated(&response_intent)
        .await
        .map_err(|error| {
            eprintln!("gateway response signing failed: {error}");
            "response_signing_failed"
        })?;
    let encoded_response = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&signed_response).map_err(|_| "response_signing_failed")?);
    if is_stream {
        *response_started = true;
        socket.write_all(format!("HTTP/1.1 {}\r\nTransfer-Encoding: chunked\r\nContent-Type: {}\r\n{}Cache-Control: no-store\r\nConnection: close\r\n\r\n", status.as_u16(), content_type, session_header).as_bytes()).await.map_err(|_| "response_write_failed")?;
        write_chunk(socket, &bytes).await?;
        write_chunk(
            socket,
            format!(
                "\nevent: oan-response-proof\ndata: {}\n\n",
                encoded_response
            )
            .as_bytes(),
        )
        .await?;
        socket
            .write_all(b"0\r\n\r\n")
            .await
            .map_err(|_| "response_write_failed")?;
        return Ok(());
    }
    let head = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\n{}X-OAN-Response-Envelope: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", status.as_u16(), bytes.len(), content_type, session_header, encoded_response);
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

async fn write_chunk(socket: &mut tokio::net::TcpStream, bytes: &[u8]) -> Result<(), String> {
    socket
        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await
        .map_err(|_| "response_write_failed")?;
    socket
        .write_all(bytes)
        .await
        .map_err(|_| "response_write_failed")?;
    socket
        .write_all(b"\r\n")
        .await
        .map_err(|_| "response_write_failed".to_string())
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
    if headers.contains_key("transfer-encoding") {
        return Err("unsupported_transfer_encoding".into());
    }
    let length = match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| "invalid_content_length")?,
        None => 0,
    };
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
