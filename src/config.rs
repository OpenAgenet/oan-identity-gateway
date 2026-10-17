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
}
impl Config {
    pub fn validate(&self) -> Result<(), GatewayError> {
        if !((self.runtime_endpoint.starts_with("unix:/") && self.runtime_endpoint.len() > 6)
            || (self.runtime_endpoint.starts_with("pipe:") && self.runtime_endpoint.len() > 5))
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
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(GatewayError::InvalidConfig);
            }
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
