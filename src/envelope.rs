// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_protocol::identity_runtime::IdentityMessageContext;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
/// Unverified declaration, to be carried in an existing signed envelope body.
/// No constructor or deserializer confers authentication or delegation authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyIdentityContext {
    pub message: IdentityMessageContext,
    pub original_caller_did: String,
    pub proxy_did: String,
    pub target_resource_did: String,
    pub delegation_digest: Option<String>,
}

/// The verified forwarding envelope created only after Runtime authentication.
/// The Gateway never derives this from caller-controlled headers.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedProxyEnvelope {
    pub original_caller_did: String,
    pub proxy_did: String,
    pub target_resource_did: String,
    pub tenant_id: String,
    pub request_id: String,
    pub payload_digest: String,
    pub delegation_digest: Option<String>,
}

/// Build the exact response intent that is handed to Runtime for signing.
/// Every identity and correlation field from the verified request is carried
/// into the proof so a response cannot be detached from its caller, proxy,
/// target, tenant or delegated scope.
pub fn response_signing_intent(
    request: &VerifiedProxyEnvelope,
    status: u16,
    response_digest: &str,
) -> Value {
    json!({
        "kind": "gateway-response",
        "requestId": request.request_id,
        "requestPayloadDigest": request.payload_digest,
        "payloadDigest": response_digest,
        "audienceDid": request.original_caller_did,
        "originalCallerDid": request.original_caller_did,
        "proxyDid": request.proxy_did,
        "targetResourceDid": request.target_resource_did,
        "tenantId": request.tenant_id,
        "delegationDigest": request.delegation_digest,
        "status": status,
    })
}
