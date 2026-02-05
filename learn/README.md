# Learning projects

This directory contains small, focused projects for learning specific concepts before integrating them into the main demo. Each project isolates a single technique or pattern.

## Approach

These projects follow the **Guided Project Construction** methodology:

- Scaffolding and one example are provided
- You complete a sequence of tasks to build understanding
- Focus on understanding WHY before HOW

## Projects

| Project | Concepts | Status |
| ------- | -------- | ------ |
| [jwt-validation](jwt-validation/) | JWKS fetching, JWT parsing, claim extraction, signature verification | Completed |
| [sts-token-exchange](sts-token-exchange/) | RFC 8693 token exchange with Keycloak | Ready |
| [envoy-ext-proc](envoy-ext-proc/) | Writing Envoy external processor in Go | Ready |
| [aws-sts-assume-role](aws-sts-assume-role/) | AssumeRoleWithWebIdentity, session policies | Planned |
| [minio-oidc](minio-oidc/) | MinIO OIDC configuration, STS API | Planned |

## Recommended order

1. **jwt-validation** - Learn JWT structure, JWKS, and signature verification
2. **sts-token-exchange** - Learn RFC 8693 token exchange with Keycloak
3. **envoy-ext-proc** - Learn how to write an Envoy external processor
4. **aws-sts-assume-role** / **minio-oidc** - Learn resource credential exchange (optional)

## Prerequisites

Most projects require Keycloak running. You can use the existing demo setup:

```bash
# Port-forward Keycloak from the cluster
kubectl port-forward service/keycloak-service -n keycloak 8080:8080
```

## How to use

1. Read the project's README.md
2. Study the provided example code
3. Complete the tasks in order
4. Each task builds on the previous one
5. Check your work against the success criteria
