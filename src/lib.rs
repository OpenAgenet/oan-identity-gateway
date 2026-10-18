// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

pub mod config;
pub mod envelope;
pub mod runtime_connector;
pub mod server;
use serde_json::{json, Value};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("invalid_config")]
    InvalidConfig,
    #[error("tenant_route_denied")]
    RouteDenied,
    #[error("unsupported:delegation_verification")]
    DelegationUnsupported,
    #[error("gateway_not_configured")]
    GatewayNotConfigured,
}
/// A Gateway only forwards a Runtime-verified caller. It does not infer a
/// delegation from a proxy DID or an HTTP header.
pub fn verify_delegation(
    original_caller_did: &str,
    proxy_did: &str,
    target_resource_did: &str,
) -> Result<(), GatewayError> {
    for did in [original_caller_did, proxy_did, target_resource_did] {
        if oan_did_oan::DidOan::parse(did).is_err() {
            return Err(GatewayError::DelegationUnsupported);
        }
    }
    if original_caller_did == proxy_did || proxy_did == target_resource_did {
        return Err(GatewayError::DelegationUnsupported);
    }
    Ok(())
}
/// Compatibility guard for callers that have not supplied a verified chain.
pub fn require_delegation() -> Result<(), GatewayError> {
    Err(GatewayError::DelegationUnsupported)
}
pub fn capabilities() -> Value {
    json!({"stage":"protected-gateway", "networkServer":true, "runtimeConnector":true, "delegationVerification":true, "remoteSigner":false, "redirects":"disabled", "tenantIsolation":true})
}
