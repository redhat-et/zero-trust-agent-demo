# Learning projects

This directory contains small, focused projects for learning specific concepts before integrating them into the main demo. Each project isolates a single technique or pattern.

## Approach

These projects follow the **Guided Project Construction** methodology:

- Scaffolding and one example are provided
- You complete a sequence of tasks to build understanding
- Focus on understanding WHY before HOW

## Projects

| Project | Concepts | Status |
|---------|----------|--------|
| [jwt-validation](jwt-validation/) | JWKS fetching, JWT parsing, claim extraction, signature verification | Ready |
| [sts-token-exchange](sts-token-exchange/) | RFC 8693 token exchange with Keycloak | Planned |
| [aws-sts-assume-role](aws-sts-assume-role/) | AssumeRoleWithWebIdentity, session policies | Planned |
| [minio-oidc](minio-oidc/) | MinIO OIDC configuration, STS API | Planned |
| [envoy-ext-proc](envoy-ext-proc/) | Writing Envoy external processor in Go | Planned |

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
