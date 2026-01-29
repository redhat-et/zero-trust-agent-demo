# Session context: OpenShift Keycloak deployment

## Status

Phase 4a complete on branch `phase4-keycloak-oauth`. Ready to deploy to OpenShift.

## What's working

- Keycloak OAuth login/logout in dashboard
- JWT claims (groups) passed through service chain to OPA
- OPA policy uses JWT groups instead of hardcoded user mappings
- Kind deployment with host Keycloak (via `host.containers.internal`)

## Next steps: OpenShift deployment

### Keycloak deployment

1. Deploy Keycloak in separate namespace (e.g., `keycloak`)
2. Use existing realm JSON: `deploy/keycloak/realm-spiffe-demo.json`
3. Expose via OpenShift Route (automatic TLS)
4. Update realm redirect URLs to include dashboard Route

### Dashboard configuration

Update OIDC settings for OpenShift Routes:

```yaml
SPIFFE_DEMO_OIDC_ISSUER_URL: https://keycloak-keycloak.apps.<cluster>/realms/spiffe-demo
SPIFFE_DEMO_OIDC_REDIRECT_URL: https://dashboard-spiffe-demo.apps.<cluster>/auth/callback
```

### Files to create/modify

- `deploy/k8s/overlays/openshift/` - new overlay for OpenShift
- `deploy/keycloak/realm-spiffe-demo.json` - add OpenShift redirect URLs
- Consider: Keycloak Operator vs simple Deployment

### Key differences from Kind

| Aspect | Kind | OpenShift |
|--------|------|-----------|
| Keycloak access | host.containers.internal:8180 | Route with TLS |
| Dashboard access | port-forward localhost:8080 | Route with TLS |
| TLS | None (HTTP) | Automatic edge termination |
| /etc/hosts hack | Required | Not needed |

### Realm redirect URLs to add

```json
"redirectUris": [
  "http://localhost:8080/*",
  "https://dashboard-spiffe-demo.apps.<cluster>/*"
]
```

## Reference commits

```
7b7f4a3 Fix badge colors for document sensitivity levels
1b78a6e Enable OIDC in Kind mock overlay with host Keycloak
fa6bebf Update Kind config for OIDC testing
40bac90 Add OIDC configuration to Kind overlays
d7eefbb Pass JWT claims through service chain for OPA authorization
238640d Add Keycloak OAuth integration for dashboard authentication
```

## Reference docs

- `docs/dev/PHASE4_IDENTITY_FEDERATION.md` - full Phase 4 plan
- `docs/deployment/openshift.md` - existing OpenShift deployment notes
