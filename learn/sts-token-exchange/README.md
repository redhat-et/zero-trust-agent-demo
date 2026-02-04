# STS token exchange learning project

Learn how to implement RFC 8693 OAuth 2.0 Token Exchange with Keycloak.

## Status: Planned

This project is scaffolded but tasks are not yet defined.

## Learning objectives

By completing this project, you will understand:

1. What RFC 8693 Token Exchange is and why it exists
2. How to configure Keycloak for token exchange
3. How to call the token exchange endpoint
4. How audience transformation works
5. How subject and actor claims are preserved

## Prerequisites

- Completed: jwt-validation project
- Keycloak with token exchange enabled
- Understanding of OAuth 2.0 basics

## Key concepts to explore

- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token` - the original token to exchange
- `audience` - the target service for the new token
- `requested_token_type` - what kind of token you want back

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Keycloak Token Exchange Documentation](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)
