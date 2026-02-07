# AWS STS AssumeRole learning project

Learn how to exchange JWTs for temporary AWS credentials using AssumeRoleWithWebIdentity.

## Status: Planned

This project is scaffolded but tasks are not yet defined.

## Learning objectives

By completing this project, you will understand:

1. How OIDC federation with AWS works
2. How to configure an IAM OIDC identity provider
3. How to create IAM roles with web identity trust policies
4. How to call AssumeRoleWithWebIdentity with a JWT
5. How to use session policies for fine-grained access

## Prerequisites

- Completed: jwt-validation project
- AWS account OR LocalStack for local testing
- Keycloak configured as OIDC provider

## Key concepts to explore

- IAM OIDC Identity Provider
- Trust policies with `sts:AssumeRoleWithWebIdentity`
- Session policies for scoped access
- Temporary credentials (AccessKeyId, SecretAccessKey, SessionToken)

## References

- [SPIFFE OIDC Federation with AWS](https://spiffe.io/docs/latest/keyless/oidc-federation-aws/)
- [AWS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
