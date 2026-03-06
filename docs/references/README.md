# RFC References

This directory contains offline copies of RFCs that define the security
standards used in this project's AuthBridge token exchange flow.

## RFCs

| RFC | Title | Relevance |
| --- | ----- | --------- |
| [RFC 7515](rfc7515.html) | JSON Web Signature (JWS) | Foundation for JWT signature verification; used by `pkg/auth/jwt.go` to validate access tokens via JWKS |
| [RFC 7519](rfc7519.html) | JSON Web Token (JWT) | Core token format for access tokens issued by Keycloak; claims structure used throughout the demo |
| [RFC 8693](rfc8693.xml) | OAuth 2.0 Token Exchange | Defines the token exchange grant type used by AuthBridge's ext-proc to swap tokens between services |
| [RFC 8705](rfc8705.xml) | OAuth 2.0 Mutual-TLS Client Authentication | mTLS-based client authentication; relates to SPIFFE X509-SVIDs used as client certificates |
| [RFC 9068](rfc9068.xml) | JWT Profile for OAuth 2.0 Access Tokens | Standardizes JWT access token format; Keycloak issues tokens following this profile |

## How these RFCs fit together

The AuthBridge flow uses these standards in sequence:

1. A user authenticates with Keycloak and receives a **JWT access token**
   (RFC 7519, RFC 9068)
2. The token is **signed** using JWS (RFC 7515); services verify signatures
   via Keycloak's JWKS endpoint
3. When a service calls another service, the Envoy ext-proc performs
   **token exchange** (RFC 8693) to obtain a new token scoped to the
   target service's audience
4. Services authenticate to Keycloak using **mTLS with SPIFFE SVIDs**
   as client certificates (RFC 8705)
