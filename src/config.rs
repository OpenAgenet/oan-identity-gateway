// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use crate::GatewayError;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRoute {
    pub tenant_id: String,
    pub resource_did: String,
    pub destination: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub runtime_endpoint: String,
    pub routes: Vec<TenantRoute>,
    #[serde(default)]
    pub gateway_did: Option<String>,
    #[serde(default)]
    pub ingress_bind: Option<String>,
    #[serde(default)]
    pub runtime_bearer: Option<String>,
    #[serde(default)]
    pub backend_auth_token: Option<String>,
    #[serde(default)]
    pub caller_id: Option<String>,
    #[serde(default)]
    pub runtime_owner_uid: Option<u32>,
    #[serde(default)]
    pub runtime_owner_pid: Option<u32>,
    #[serde(default)]
    pub allow_loopback_http: bool,
}
impl Config {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if !((self.runtime_endpoint.starts_with("unix:/") && self.runtime_endpoint.len() > 6)
            || (self.runtime_endpoint.starts_with(r"pipe:\\.\pipe\")
                && self.runtime_endpoint.len() > r"pipe:\\.\pipe\".len()))
        {
            return Err(GatewayError::InvalidConfig);
        }
        let mut unique = std::collections::HashSet::new();
        for route in &self.routes {
            if route.tenant_id.is_empty()
                || oan_did_oan::DidOan::parse(&route.resource_did).is_err()
                || !unique.insert((&route.tenant_id, &route.resource_did))
            {
                return Err(GatewayError::InvalidConfig);
            }
            let url =
                url::Url::parse(&route.destination).map_err(|_| GatewayError::InvalidConfig)?;
            let loopback_http = self.allow_loopback_http
                && url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
            if (!loopback_http && url.scheme() != "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(GatewayError::InvalidConfig);
            }
        }
        if let Some(bind) = &self.ingress_bind {
            let url = url::Url::parse(&format!("http://{bind}"))
                .map_err(|_| GatewayError::InvalidConfig)?;
            if !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
                || url.path() != "/"
                || url.port().is_none()
            {
                return Err(GatewayError::InvalidConfig);
            }
        }
        for token in [&self.runtime_bearer, &self.backend_auth_token] {
            if let Some(value) = token {
                if !(32..=512).contains(&value.len()) {
                    return Err(GatewayError::InvalidConfig);
                }
            }
        }
        if let Some(did) = &self.gateway_did {
            oan_did_oan::DidOan::parse(did).map_err(|_| GatewayError::InvalidConfig)?;
        }
        if self.runtime_endpoint.starts_with("unix:") && self.runtime_owner_uid.is_none() {
            return Err(GatewayError::InvalidConfig);
        }
        if self.runtime_endpoint.starts_with("pipe:") && self.runtime_owner_pid.is_none() {
            return Err(GatewayError::InvalidConfig);
        }
        Ok(())
    }
    /// Tenant identity must come from authenticated transport, not a request field.
    pub fn route(
        &self,
        authenticated_tenant: &str,
        resource_did: &str,
    ) -> Result<&TenantRoute, GatewayError> {
        self.routes
            .iter()
            .find(|r| r.tenant_id == authenticated_tenant && r.resource_did == resource_did)
            .ok_or(GatewayError::RouteDenied)
    }
}
