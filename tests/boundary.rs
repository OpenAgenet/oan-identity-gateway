// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use oan_identity_gateway::server::has_terminal_response_proof;
use oan_identity_gateway::{
    config::Config,
    envelope::{response_signing_intent, VerifiedProxyEnvelope},
    require_delegation,
    runtime_connector::{AuthenticatedRuntimeConnector, RuntimeIpcTransport, IPC_VERSION},
};
use serde_json::Value;

struct IpcEcho {
    response: Vec<u8>,
}
impl RuntimeIpcTransport for IpcEcho {
    async fn round_trip(&self, _frame: Vec<u8>) -> Result<Vec<u8>, String> {
        Ok(self.response.clone())
    }
}
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

#[test]
fn response_intent_is_a_complete_gateway_response_binding() {
    let request = VerifiedProxyEnvelope {
        original_caller_did: "did:oan:HmxwA:caller1111111111111111111111111111111".into(),
        proxy_did: "did:oan:HmxwA:proxy11111111111111111111111111111111".into(),
        target_resource_did: "did:oan:HmxwA:target111111111111111111111111111111".into(),
        tenant_id: "tenant-b".into(),
        request_id: "request-7".into(),
        payload_digest: "sha256:request-7".into(),
        delegation_digest: None,
    };
    let intent = response_signing_intent(&request, 202, "sha256:response-7");
    assert_eq!(intent["kind"], Value::String("gateway-response".into()));
    assert_eq!(
        intent["audienceDid"],
        Value::String(request.original_caller_did.clone())
    );
    assert_eq!(intent["requestId"], Value::String("request-7".into()));
    assert_eq!(intent["status"], Value::from(202));
    assert!(intent["delegationDigest"].is_null());
    assert_ne!(intent["payloadDigest"], intent["requestPayloadDigest"]);
}

#[tokio::test]
async fn authenticated_ipc_rejects_nested_principal_substitution() {
    let envelope =
        serde_json::json!({"subjectDid":"did:oan:HmxwA:caller1111111111111111111111111111111"});
    let audience = "did:oan:HmxwA:target111111111111111111111111111111";
    let request_id = "request-nested-principal";
    let payload_digest = "sha256:nested-principal";
    let input_digest = oan_identity_gateway::runtime_connector::input_digest(
        &envelope,
        audience,
        request_id,
        payload_digest,
    );
    let response = serde_json::to_vec(&serde_json::json!({
        "version": IPC_VERSION,
        "callerId": "process-a",
        "tenantId": "tenant-a",
        "context": {
            "subjectDid": envelope["subjectDid"],
            "audienceDid": audience,
            "requestId": request_id,
            "payloadDigest": payload_digest,
            "callerId": "forged-process",
            "tenantId": "tenant-a"
        },
        "inputDigest": input_digest
    }))
    .unwrap();
    let connector = AuthenticatedRuntimeConnector::new(
        IpcEcho { response },
        "b".repeat(32),
        "process-a".into(),
        Some("tenant-a".into()),
    )
    .unwrap();
    assert_eq!(
        connector
            .verify_authenticated(&envelope, audience, request_id, payload_digest)
            .await
            .unwrap_err(),
        "ipc_result_binding_mismatch"
    );
}

#[test]
fn chained_envelope_forwarding_is_explicit_opt_in() {
    let source = include_str!("../examples/config.json");
    let config: Config = serde_json::from_str(source).unwrap();
    assert!(!config.forward_verified_envelope);
    let mut value: Value = serde_json::from_str(source).unwrap();
    value["forwardVerifiedEnvelope"] = Value::Bool(true);
    let configured: Config = serde_json::from_value(value).unwrap();
    assert!(configured.forward_verified_envelope);
    configured.validate().unwrap();
}

#[test]
fn outbound_gateway_requires_end_to_end_envelope_forwarding() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    config.outbound_passthrough = true;
    assert!(config.validate().is_err());
    config.forward_verified_envelope = true;
    config.validate().unwrap();
}

#[test]
fn passthrough_requires_a_receiver_terminal_proof() {
    assert!(!has_terminal_response_proof(
        br#"{"jsonrpc":"2.0","result":{}}"#
    ));
    assert!(has_terminal_response_proof(
        b"event: message\ndata: {}\n\nevent: oan-response-proof\ndata: proof\n\n"
    ));
    assert!(has_terminal_response_proof(
        b"event: oan-response-proof\r\ndata: proof\r\n\r\n"
    ));
}

#[test]
fn backend_budget_preserves_default_and_rejects_unbounded_values() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    assert_eq!(config.backend_timeout_secs, 30);
    for value in [1, 120, 300] {
        config.backend_timeout_secs = value;
        assert!(config.validate().is_ok());
    }
    for value in [0, 301, u64::MAX] {
        config.backend_timeout_secs = value;
        assert!(config.validate().is_err());
    }
}

#[test]
fn serving_preflight_requires_host_configuration_without_demo_metadata() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    config.ingress_bind = Some("127.0.0.1:47891".into());
    config.runtime_bearer = Some("a".repeat(32));
    config.backend_auth_token = Some("b".repeat(32));
    config.caller_id = Some("independent-host".into());
    assert!(config.validate_serving().is_ok());
    config.runtime_bearer = None;
    assert!(config.validate_serving().is_err());
    config.runtime_bearer = Some("a".repeat(32));
    config.backend_auth_token = None;
    assert!(config.validate_serving().is_err());
    config.backend_auth_token = Some("b".repeat(32));
    config.caller_id = Some(" ".into());
    assert!(config.validate_serving().is_err());
}

#[test]
fn serving_preflight_rejects_empty_route_table() {
    let mut config: Config = serde_json::from_str(include_str!("../examples/config.json")).unwrap();
    config.routes.clear();
    assert!(config.validate_serving().is_err());
}
