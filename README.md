<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# OAN Identity Gateway

An OAN identity gateway for enterprise, multi-tenant, private-network, and remote-signer deployments. It provides a verifiable delegated boundary between network forwarding and business identity.

`oan-identity-gateway` is a deployment-layer component and does not replace `oan-identity-runtime`. It calls the Runtime or a user-configured KMS/HSM/remote signer through controlled interfaces and does not duplicate identity stores, DID/VC verification, or message-signing logic.

## Scope

The Gateway will be implemented as real deployment needs emerge and will cover:

- public/private forwarding for private-network agents, MCP servers, and services;
- tenant isolation, delegated identities, and audit records;
- WebSocket/HTTP transport, reconnects, request IDs, and message correlation;
- binding the original caller DID, proxy DID, target resource DID, request ID, payload digest, validity period, delegation digest, and proxy signature;
- separating channel authentication from business-message identity;
- user-controlled KMS/HSM and remote-signer integration.

Gateway channel authentication is not automatically resource-identity authentication. A plain DID header, `x-forwarded-for`, or proxy declaration is not sufficient proof of the caller.

## Deployment Boundary

The Gateway is normally deployed in an enterprise- or user-controlled cloud, private network, or edge environment. OAN Root, Registrar, and Discovery services continue to provide registration, discovery, and governance trust anchors without handling user long-term private keys.

If a hosted Gateway is offered in the future, its tenant boundary, signing subject, key location, user authorization, audit, and revocation behavior must be explicit, and verification, message relay, and remote signing must remain separate.

## Planned Layers

- `transport`: HTTP/WebSocket, reconnects, fragmentation, and request IDs
- `identity-envelope`: original caller, proxy, target resource, and payload-digest binding
- `tenant-policy`: tenant routing, authorization, and audit
- `runtime-connector`: controlled connection to `oan-identity-runtime`
- `signer-connector`: user-configured KMS/HSM/remote signer

## Reference

The network proxy layer may draw on ANP Proxy Gateway/Receiver, fragmentation, and reconnect practices. OAN identity, DID, VC, ResourcePackage, and Root/Registrar/Discovery evidence remain governed by OAN implementations.

## Development status

A buildable development framework is now present. This is not yet a production identity service or a complete mutual-authentication implementation. Detailed design, development planning, and framework reviews are maintained separately in `oan-design-docs`. Source code uses English by default.

## License

This repository is licensed under `Apache-2.0` to support OAN ecosystem adoption.


Community Skill identity verification does not require this component. It uses the local Runtime/SDK workflow to exchange public challenge messages. This component retains its protocol/network enforcement role; its presence alone does not implement mutual authentication. Dedicated Hermes/OpenClaw plugins are not prerequisites for their compatible Skill-based path.
