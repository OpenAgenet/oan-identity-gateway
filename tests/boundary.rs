// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_identity_gateway::{
    config::Config,
    envelope::{response_signing_intent, VerifiedProxyEnvelope},
    require_delegation,
};
use serde_json::Value;
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

#[test]
fn response_intent_binds_original_proxy_target_tenant_and_request_digest() {
    let request = VerifiedProxyEnvelope {
        original_caller_did: "did:oan:HmxwA:caller1111111111111111111111111111111".into(),
        proxy_did: "did:oan:HmxwA:proxy11111111111111111111111111111111".into(),
        target_resource_did: "did:oan:HmxwA:target111111111111111111111111111111".into(),
        tenant_id: "tenant-a".into(),
        request_id: "request-1".into(),
        payload_digest: "sha256:request".into(),
        delegation_digest: Some("sha256:delegation".into()),
    };
    let intent = response_signing_intent(&request, 200, "sha256:response");
    assert_eq!(
        intent["originalCallerDid"],
        Value::String(request.original_caller_did.clone())
    );
    assert_eq!(intent["proxyDid"], Value::String(request.proxy_did.clone()));
    assert_eq!(
        intent["targetResourceDid"],
        Value::String(request.target_resource_did.clone())
    );
    assert_eq!(intent["tenantId"], Value::String("tenant-a".into()));
    assert_eq!(
        intent["requestPayloadDigest"],
        Value::String("sha256:request".into())
    );
    assert_eq!(
        intent["payloadDigest"],
        Value::String("sha256:response".into())
    );
    assert_eq!(
        intent["delegationDigest"],
        Value::String("sha256:delegation".into())
    );
}
