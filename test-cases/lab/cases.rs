// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
mod fixtures;
use fixtures::*;
use oan_identity_gateway::{
    capabilities,
    config::{Config, TenantRoute},
    require_delegation,
    runtime_connector::{RuntimeVerifier, UnavailableRuntime},
};
use serde_json::json;

#[test]
fn gw_01_current_gateway_rejects_actual_http_lab_destinations() {
    let m = manifest();
    for name in resource_names() {
        let actor = &m["resources"][name];
        let doc = document(actor);
        let destination = actor["registeredAccess"]["url"].as_str().unwrap();
        assert!(doc["service"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["serviceEndpoint"] == destination));
        let config = Config {
            runtime_endpoint: "unix:/tmp/oan-lab-runtime.sock".into(),
            gateway_did: None,
            ingress_bind: None,
            runtime_bearer: None,
            backend_auth_token: None,
            caller_id: None,
            runtime_owner_uid: Some(0),
            runtime_owner_pid: None,
            allow_loopback_http: false,
            routes: vec![TenantRoute {
                tenant_id: name.into(),
                resource_did: actor["did"].as_str().unwrap().into(),
                destination: destination.into(),
            }],
        };
        assert!(
            config.validate().is_err(),
            "HTTP lab endpoints must not be silently relabelled HTTPS"
        );
    }
}
// Synthetic HTTPS URLs below are CONFIG VALIDATION ONLY, never contacted or advertised.
fn https_config() -> Config {
    let m = manifest();
    Config {
        runtime_endpoint: "unix:/tmp/oan-lab-runtime.sock".into(),
        gateway_did: None,
        ingress_bind: None,
        runtime_bearer: None,
        backend_auth_token: None,
        caller_id: None,
        runtime_owner_uid: Some(0),
        runtime_owner_pid: None,
        allow_loopback_http: false,
        routes: resource_names()
            .into_iter()
            .enumerate()
            .map(|(i, name)| TenantRoute {
                tenant_id: if i < 3 { "lab-a" } else { "lab-b" }.into(),
                resource_did: m["resources"][name]["did"].as_str().unwrap().into(),
                destination: format!("https://gateway-test.invalid/{name}"),
            })
            .collect(),
    }
}
#[test]
fn gw_02_tenant_routing_uses_resource_dids_not_controller_authority() {
    let config = https_config();
    config.validate().unwrap();
    let m = manifest();
    for route in &config.routes {
        assert!(config.route(&route.tenant_id, &route.resource_did).is_ok());
        assert!(config
            .route(
                if route.tenant_id == "lab-a" {
                    "lab-b"
                } else {
                    "lab-a"
                },
                &route.resource_did
            )
            .is_err());
        assert!(config
            .route(
                &route.tenant_id,
                m["controllers"]["controller-a"]["did"].as_str().unwrap()
            )
            .is_err());
    }
}
#[test]
fn gw_03_duplicate_routes_and_unsafe_destinations_rejected() {
    let config = https_config();
    let mut duplicate = config.clone();
    duplicate.routes.push(duplicate.routes[0].clone());
    assert!(duplicate.validate().is_err());
    for value in [
        "http://127.0.0.1:4201/mcp",
        "https://key@gateway-test.invalid/",
        "https://gateway-test.invalid/#fragment",
        "file:///etc/passwd",
    ] {
        let mut bad = config.clone();
        bad.routes[0].destination = value.into();
        assert!(bad.validate().is_err());
    }
}
#[tokio::test]
async fn gw_04_claimed_proxy_or_controller_identity_never_grants_delegation() {
    let m = manifest();
    assert!(require_delegation().is_err());
    assert!(UnavailableRuntime.verify_request(&json!({"originalCallerDid":m["resources"]["hermes-a"]["did"],"proxyDid":m["controllers"]["controller-b"]["did"],"claimedVerified":true}),m["resources"]["mcp"]["did"].as_str().unwrap(),"request","sha256:test-only").await.is_err());
    assert_eq!(capabilities()["networkServer"], true);
    assert_eq!(capabilities()["runtimeConnector"], true);
    assert_eq!(
        capabilities()["delegationVerification"],
        "runtime-evidence-required"
    );
    assert_eq!(capabilities()["responseBinding"], true);
    assert_eq!(capabilities()["remoteSigner"], false);
}
#[test]
#[ignore = "BLOCKED: explicit reviewed local HTTP policy or real TLS ingress, network server and Runtime IPC required"]
fn gw_05_real_a2a_mcp_hermes_forwarding() {
    panic!("not implemented; config-only routing does not forward traffic");
}
#[test]
#[ignore = "BLOCKED: delegation verifier and request/response binding implementation required"]
fn gw_06_tenant_delegation_replay_and_response_substitution() {
    panic!("not implemented");
}
