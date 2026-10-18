// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Protected connector contract. No unauthenticated network implementation is provided.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;

pub const IPC_VERSION: &str = "oan-runtime-ipc-v1";
const MAX_FRAME_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedRuntimeContext {
    pub subject_did: String,
    pub audience_did: String,
    pub request_id: String,
    pub payload_digest: String,
    #[serde(default)]
    pub delegation_digest: Option<String>,
    #[serde(default)]
    pub delegation_verified: bool,
    #[serde(default)]
    pub response_signing_supported: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcVerifyRequest {
    pub version: String,
    pub operation: String,
    pub bearer: String,
    pub envelope: Value,
    pub expected_audience: String,
    pub expected_request_id: String,
    pub expected_payload_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_did: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcVerifiedContext {
    pub version: String,
    pub caller_id: String,
    pub tenant_id: Option<String>,
    pub context: VerifiedRuntimeContext,
    pub input_digest: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcSignRequest {
    pub version: String,
    pub operation: String,
    pub bearer: String,
    pub intent: Value,
    pub expected_caller_id: String,
    pub expected_tenant_id: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IpcSignedResult {
    pub version: String,
    pub caller_id: String,
    pub tenant_id: Option<String>,
    pub signed: Value,
    pub input_digest: String,
}

pub trait RuntimeIpcTransport: Send + Sync {
    fn round_trip(
        &self,
        frame: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

/// A trusted host implements this only after authenticating the Runtime channel.
/// The Runtime must verify evidence, session, audience, digest, time and replay.
pub trait RuntimeVerifier: Send + Sync {
    fn verify_request(
        &self,
        envelope: &Value,
        expected_audience: &str,
        expected_request_id: &str,
        expected_payload_digest: &str,
    ) -> impl std::future::Future<Output = Result<VerifiedRuntimeContext, String>> + Send;
}

/// Secure default until protected IPC and its versioned wire contract are implemented.
pub struct UnavailableRuntime;
impl RuntimeVerifier for UnavailableRuntime {
    async fn verify_request(
        &self,
        _: &Value,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<VerifiedRuntimeContext, String> {
        Err("runtime_connector_not_configured".into())
    }
}

pub struct UnixRuntimeTransport {
    pub path: String,
    pub owner_uid: Option<u32>,
}
impl RuntimeIpcTransport for UnixRuntimeTransport {
    #[cfg(unix)]
    async fn round_trip(&self, frame: Vec<u8>) -> Result<Vec<u8>, String> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = std::fs::metadata(&self.path).map_err(|_| "runtime_ipc_unavailable")?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("runtime_ipc_acl_invalid".into());
        }
        if let Some(uid) = self.owner_uid {
            if metadata.uid() != uid {
                return Err("runtime_ipc_owner_mismatch".into());
            }
        }
        let mut socket = UnixStream::connect(&self.path)
            .await
            .map_err(|_| "runtime_ipc_unavailable")?;
        socket
            .write_all(&frame)
            .await
            .map_err(|_| "runtime_ipc_write_failed")?;
        socket
            .write_all(b"\n")
            .await
            .map_err(|_| "runtime_ipc_write_failed")?;
        let mut reader = BufReader::new(socket);
        let mut line = Vec::new();
        reader
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| "runtime_ipc_read_failed")?;
        if line.len() > MAX_FRAME_BYTES {
            return Err("ipc_frame_too_large".into());
        }
        if let Ok(value) = serde_json::from_slice::<Value>(&line) {
            if let Some(code) = value.get("code").and_then(Value::as_str) {
                return Err(code.into());
            }
        }
        Ok(line)
    }
    #[cfg(not(unix))]
    async fn round_trip(&self, _frame: Vec<u8>) -> Result<Vec<u8>, String> {
        Err("runtime_ipc_unavailable_on_platform".into())
    }
}

pub struct AuthenticatedRuntimeConnector<T> {
    transport: T,
    bearer: String,
    caller_id: String,
    tenant_id: Option<String>,
}
impl<T: RuntimeIpcTransport> AuthenticatedRuntimeConnector<T> {
    pub fn new(
        transport: T,
        bearer: String,
        caller_id: String,
        tenant_id: Option<String>,
    ) -> Result<Self, String> {
        if !(32..=512).contains(&bearer.len()) || caller_id.is_empty() {
            return Err("invalid_ipc_credentials".into());
        }
        Ok(Self {
            transport,
            bearer,
            caller_id,
            tenant_id,
        })
    }
    pub async fn verify_authenticated(
        &self,
        envelope: &Value,
        audience: &str,
        request_id: &str,
        payload_digest: &str,
    ) -> Result<VerifiedRuntimeContext, String> {
        let req = IpcVerifyRequest {
            version: IPC_VERSION.into(),
            operation: "verify_request".into(),
            bearer: self.bearer.clone(),
            envelope: envelope.clone(),
            expected_audience: audience.into(),
            expected_request_id: request_id.into(),
            expected_payload_digest: payload_digest.into(),
            callback_did: None,
        };
        let frame = serde_json::to_vec(&req).map_err(|_| "ipc_schema_invalid")?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err("ipc_frame_too_large".into());
        }
        let raw = self.transport.round_trip(frame).await?;
        let response: IpcVerifiedContext =
            serde_json::from_slice(&raw).map_err(|_| "ipc_schema_invalid")?;
        if response.version != IPC_VERSION
            || response.caller_id != self.caller_id
            || response.tenant_id != self.tenant_id
            || response.context.audience_did != audience
            || response.context.request_id != request_id
            || response.context.payload_digest != payload_digest
            || response.input_digest != input_digest(envelope, audience, request_id, payload_digest)
        {
            return Err("ipc_result_binding_mismatch".into());
        }
        Ok(response.context)
    }

    pub async fn sign_authenticated(&self, intent: &Value) -> Result<Value, String> {
        let req = IpcSignRequest {
            version: IPC_VERSION.into(),
            operation: "sign_request".into(),
            bearer: self.bearer.clone(),
            intent: intent.clone(),
            expected_caller_id: self.caller_id.clone(),
            expected_tenant_id: self.tenant_id.clone(),
        };
        let frame = serde_json::to_vec(&req).map_err(|_| "ipc_schema_invalid")?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err("ipc_frame_too_large".into());
        }
        let raw = self.transport.round_trip(frame).await?;
        let response: IpcSignedResult =
            serde_json::from_slice(&raw).map_err(|_| "ipc_schema_invalid")?;
        if response.version != IPC_VERSION
            || response.caller_id != self.caller_id
            || response.tenant_id != self.tenant_id
            || response.input_digest
                != sign_input_digest(intent, &self.caller_id, self.tenant_id.as_deref())
        {
            return Err("ipc_result_binding_mismatch".into());
        }
        Ok(response.signed)
    }
}

fn input_digest(
    envelope: &Value,
    audience: &str,
    request_id: &str,
    payload_digest: &str,
) -> String {
    let value = serde_json::json!({"envelope": envelope, "audience": audience, "requestId": request_id, "payloadDigest": payload_digest});
    format!(
        "sha256:{:x}",
        sha2::Sha256::digest(canonical_json(&value).as_bytes())
    )
}
fn sign_input_digest(intent: &Value, caller_id: &str, tenant_id: Option<&str>) -> String {
    let value = serde_json::json!({"intent": intent, "callerId": caller_id, "tenantId": tenant_id});
    format!(
        "sha256:{:x}",
        sha2::Sha256::digest(canonical_json(&value).as_bytes())
    )
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => serde_json::to_string(v).unwrap_or_else(|_| "\"\"".into()),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            format!(
                "{{{}}}",
                entries
                    .iter()
                    .map(|(k, v)| format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(v)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

/// Outbound signing is a separate host operation, not arbitrary byte signing.
/// The connector binds tenant/caller through the authenticated IPC channel.
pub trait RuntimeSigner: Send + Sync {
    fn sign_intent(
        &self,
        intent: &Value,
    ) -> impl std::future::Future<Output = Result<Value, String>> + Send;
}
