// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

pub mod config;
pub mod envelope;
pub mod runtime_connector;
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
}
/// Do not forward on behalf of an original caller until delegation is implemented.
pub fn require_delegation() -> Result<(), GatewayError> {
    Err(GatewayError::DelegationUnsupported)
}
pub fn capabilities() -> Value {
    json!({"stage":"framework", "networkServer":false, "runtimeConnector":false, "delegationVerification":false, "remoteSigner":false})
}
