# MinIO OIDC learning project

Learn how to configure MinIO with OIDC authentication and use STS for temporary credentials.

## Status: Planned

This project is scaffolded but tasks are not yet defined.

## Learning objectives

By completing this project, you will understand:

1. How to configure MinIO with an OIDC provider (Keycloak)
2. How MinIO maps JWT claims to policies
3. How to use AssumeRoleWithWebIdentity with MinIO
4. How to create MinIO policies that match Keycloak groups

## Prerequisites

- Completed: jwt-validation project
- MinIO server (can run locally with Docker)
- Keycloak configured with appropriate clients

## Key concepts to explore

- MinIO OIDC configuration (`identity_openid`)
- Claim-based policy assignment
- Role policies vs claim policies
- MinIO STS endpoint

## References

- [MinIO OIDC Integration](https://blog.min.io/minio-openid-connect-integration/)
- [MinIO AssumeRoleWithWebIdentity](https://min.io/docs/minio/linux/developers/security-token-service/AssumeRoleWithWebIdentity.html)
