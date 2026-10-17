// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_identity_gateway::{config::Config, require_delegation};
#[test]
fn tenant_routes_cannot_cross_boundaries() {
    let config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    config.validate().unwrap();
    let resource = &config.routes[0].resource_did;
    assert!(config.route("example-tenant", resource).is_ok());
    assert!(config.route("other-tenant", resource).is_err());
}
#[test]
fn duplicate_routes_and_credentials_are_rejected() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    config.routes.push(config.routes[0].clone());
    assert!(config.validate().is_err());
    config.routes.pop();
    config.routes[0].destination = "https://secret@example.invalid".into();
    assert!(config.validate().is_err());
}
#[test]
fn delegation_is_not_inferred_from_proxy_declarations() {
    assert!(require_delegation().is_err());
}

#[test]
fn malformed_dids_and_empty_ipc_names_are_rejected() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    config.runtime_endpoint = "pipe:".into();
    assert!(config.validate().is_err());
    config.runtime_endpoint = "unix:/".into();
    assert!(config.validate().is_err());
    config.runtime_endpoint = "pipe:runtime".into();
    config.routes[0].resource_did = "did:oan:invalid".into();
    assert!(config.validate().is_err());
}
