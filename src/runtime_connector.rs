// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

//! Protected connector contract. No unauthenticated network implementation is provided.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedRuntimeContext {
    pub subject_did: String,
    pub audience_did: String,
    pub request_id: String,
    pub payload_digest: String,
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

/// Outbound signing is a separate host operation, not arbitrary byte signing.
/// The connector binds tenant/caller through the authenticated IPC channel.
pub trait RuntimeSigner: Send + Sync {
    fn sign_intent(
        &self,
        intent: &Value,
    ) -> impl std::future::Future<Output = Result<Value, String>> + Send;
}
