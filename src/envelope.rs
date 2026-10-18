// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_protocol::identity_runtime::IdentityMessageContext;
use serde::{Deserialize, Serialize};
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
