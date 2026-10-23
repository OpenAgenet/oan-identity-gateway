<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!-- Initial author: JINLIANG XU; Email: jlxufly@gmail.com -->
# Gateway integration test cases

Gateway is currently a tenant-route and delegation boundary framework, not a working forward proxy. The lab provides genuine registered resource identities and local HTTP services. Current Gateway Config requires HTTPS destinations: directly pointing it at the lab is **unsupported** and is tested as such.

## Run

```sh
cargo test --test lab_cases
cargo test
cargo fmt --check
```

`tests/lab_cases.rs` loads the cases in this directory. Public identity fixtures are read from the private lab checkout; keys stay in the trusted Runtime/test host. Tests make no outbound requests or registration writes. Ignored E2E cases fail if explicitly forced with `cargo test --test lab_cases -- --include-ignored`; they are not success placeholders.

## Cases

| ID | Scenario | Action and expected result | State |
|---|---|---|---|
| GW-01 | Five actual registered HTTP loopback endpoints | Read exact DID-document endpoint; Config rejects HTTP destination under current policy | Implemented compatibility-gap regression; do not label as forwarding success |
| GW-02 | Separate lab-a / lab-b tenant routes | A2A/MCP assigned lab-a, Hermes lab-b; match only authenticated tenant + resource DID; wrong tenant and controller DID cannot select route | Implemented routing-only check; synthetic `https://gateway-test.invalid` is never contacted |
| GW-03 | Invalid/duplicate routes | Reject duplicate tenant-resource, HTTP under current policy, embedded credentials, fragment and file scheme | Implemented config check |
| GW-04 | Proxy/controller declaration and unavailable Runtime | Declared originalCallerDid or controller does not supply delegation; no request accepted through UnavailableRuntime; capabilities stay false | Implemented fail-closed check |
| GW-05 | Actual A2A, MCP and Hermes forwarding via tenant ingress | Exact target DID/endpoint; native requests execute once; preserve protocol framing; missing or wrong tenant rejected before native call | Ignored/blocked: backend policy/TLS, network server, Runtime IPC |
| GW-06 | Delegated request/result security | Resource-signed proof binds original caller, proxy DID, target, operation, service, digest, expiry and scope; validate delegation and result; replay and response substitution rejected | Ignored/blocked: actual delegation and envelope verification |
| GW-07 | OAN-aware peer vs legacy peer | Clearly distinguish authenticated OAN agent from gateway's own identity; legacy caller identity mapping requires explicit trust source; legacy backend cannot be reported as holding a resource key | Planned mode-specific acceptance |
| GW-08 | Multi-tenant key ownership | Same target in two tenants with independent access; no key-ref swap, model key leakage, cross-tenant replay or request-derived trusted tenant | Planned authenticated ingress + Runtime policy tests |
| GW-09 | Streams / task lifecycle | Real A2A/Hermes SSE and MCP results preserve IDs/backpressure/cancel; reject reordered, truncated and substituted signed stream | Planned network/profile implementation |
| GW-10 | Recovery / outage | Runtime/peer failure never falls back to unsigned mode; reconnect/restart retains replay policy; no automatic registration/new identity | Planned durable host and proxy tests |

## Resolve the local-backend gap before GW-05

Choose and review one explicit path in `oan-design-docs`: (a) a local lab TLS ingress with real test certificates and certificate validation, or (b) a narrowly scoped opt-in local HTTP backend policy restricted to literal loopback and explicit ports, separate from public transport security. The current tests do **not** change this production rule. Never just change `http` to `https` in the DID document or disable TLS verification to make Config pass. `.invalid` routes are config-only test inputs and carry no claim of deployment.

A Gateway acting as itself may sign only under its own registered identity. The lab's controllers are not proxy identities, and top-level controller authority is not signed business delegation. A new real proxy test identity will be needed when that mode is implemented, through a separately authorized workflow; these tests generate none. An opaque pass-through cannot claim to verify another agent's response or replace resource signatures with gateway signatures.

## Next executable integration

Freeze authenticated ingress/tenant context and Runtime IPC, resolve the loopback policy, then enable a real MCP HTTP route. Add official MCP-client positive and fault cases with independent lab ledger observations. Implement explicit delegation before on-behalf-of forwarding, then A2A and pinned Hermes streams. Route lookup succeeding is only config validation; full L2 must reject direct/alternate-path bypass and verify actual signed results at the original caller.

## Shared laboratory contract

Use a sibling checkout of `oan-agent-integration-lab`, or set `OAN_LAB_ROOT` to its absolute path. Baseline: lab commit `35ad408`, five resource packages `0.1.0.2`; later metadata changes are read from the manifest rather than fixed hashes. Node 22.13+ and Rust 1.96+ are the component baselines. Keep dependency repositories (`oan-sdk-ts`, `oan-protocol-common`) beside these repositories as required by their existing build configuration.

| Lab actor | Resource kind / wire protocol | Same-host service | Controller |
|---|---|---|---|
| a2a-a | agent_service / A2A 1.0 | http://127.0.0.1:4101/ | controller-a |
| a2a-b | agent_service / A2A 1.0 | http://127.0.0.1:4102/ | controller-a |
| mcp | mcp_server / SDK-negotiated MCP Streamable HTTP | http://127.0.0.1:4201/mcp | controller-a |
| hermes-a | agent_service / pinned native Hermes A2A adapter | http://127.0.0.1:4301/ | controller-b |
| hermes-b | agent_service / pinned native Hermes A2A adapter | http://127.0.0.1:4302/ | controller-b |

`config/oan-identities.json` is the source of real DIDs and relative paths. Reuse the resource key for peer communication; controller keys authorize registration/document updates and are not proxy delegation. These tests never create new DIDs, register resources, change production nodes, deploy services, or print private keys. Do not copy lab keys into these component repositories. The private lab checkout retains the owner-approved test keys.

Default tests are offline. A missing lab fixture is a **failure**, not a synthetic identity fallback. Scheduled network or server tests require a separately prepared lab. Loopback always means the caller's current host. Existing shared OS-user fixtures cannot prove isolation against a hostile local process.

## Result and evidence rules

- `implemented`: executable test of existing public component code. State the exact scope; a passing boundary unit test is not a proxy/handshake pass.
- `opt-in`: requires an explicit switch, public read-only network requests or a prepared external lab.
- `blocked`: named missing implementation; displayed as skipped/ignored, never counted as passed. Do not remove the gate until the real implementation and acceptance assertions exist.
- Unit test doubles only exercise specified binding gates. A pre-authenticated session fixture does not prove a handshake. Loading a saved VC does not verify the issuer or governance chain.
- L0 is registration/discovery/endpoint resolution. L1 additionally needs real DID/VC/trust/status checks. Independent mutual verification needs signed peer possession and final confirmation. L2 additionally binds actual requests and responses, policy, time, audience, correlation and replay, and prevents bypass before effects.
- No test may silently downgrade L2 to L1 or native protocol success. Expired/unavailable evidence is unknown/rejected, never authenticated.

## Future end-to-end fault matrix

For each enabled A2A, MCP HTTP, MCP stdio and Hermes entry point: positive call executes exactly once; altered request, wrong audience, wrong sender, controller-key substitution, wrong operation/service/session/request, expired proof, forged principal and bypass execute zero times. Replay executes only its first valid attempt. Response tampering/substitution executes once but the caller rejects the result as untrusted. Use unique markers and read the actual lab ledger separately from component reports. Responses bind the request digest and peer DID; streaming tests bind task/request, sequence, previous digest and signed terminal state, including truncation, reordering, cancellation and disconnect. Restart tests require durable replay state and reject a previously consumed nonce after process restart.

Future live Hermes tests use the pinned upstream adapter in transport mode, no model. Full gateway/model behavior and autonomous Skill execution are separate optional checks. MCP stdio must use the official client and process ownership rules; it is not remote mutual authentication merely because messages carry DIDs. Existing OAuth/Bearer and MCP headers must retain their protocol semantics.
