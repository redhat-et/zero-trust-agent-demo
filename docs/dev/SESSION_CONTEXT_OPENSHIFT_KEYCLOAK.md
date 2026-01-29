# Session context: OpenShift Keycloak deployment

## Status

Phase 4b complete on branch `phase4-keycloak-oauth`. OpenShift OIDC deployment working.

## What's working

- Keycloak OAuth login/logout in dashboard
- JWT claims (groups) passed through service chain to OPA
- OPA policy uses JWT groups instead of hardcoded user mappings
- Kind deployment with host Keycloak (via `host.containers.internal`)
- OpenShift OIDC overlay (`deploy/k8s/overlays/openshift-oidc/`)
- Keycloak 26.5 with SPIFFE identity support (preview feature)

## OpenShift deployment

### Quick start

```bash
# 1. Get your cluster domain
CLUSTER_DOMAIN=$(oc get ingresses.config/cluster -o jsonpath='{.spec.domain}')
echo "Cluster domain: $CLUSTER_DOMAIN"

# 2. Generate files from templates
cd deploy/k8s/overlays/openshift-oidc
sed "s/CLUSTER_DOMAIN/$CLUSTER_DOMAIN/g" oidc-urls-configmap.yaml.template > oidc-urls-configmap.yaml
sed "s/CLUSTER_DOMAIN/$CLUSTER_DOMAIN/g" keycloak-realm-patch.yaml.template > keycloak-realm-patch.yaml
cd -

# 3. Deploy
oc apply -k deploy/k8s/overlays/openshift-oidc

# 4. Wait for pods
oc wait --for=condition=Ready pods -l app=keycloak -n spiffe-demo --timeout=120s
oc wait --for=condition=Ready pods -l app=web-dashboard -n spiffe-demo --timeout=60s

# 5. Get URLs
echo "Dashboard: https://web-dashboard-spiffe-demo.$CLUSTER_DOMAIN"
echo "Keycloak:  https://keycloak-spiffe-demo.$CLUSTER_DOMAIN"
```

### Files created

| File | Purpose |
| ---- | ------- |
| `deploy/k8s/overlays/openshift-oidc/kustomization.yaml` | Main overlay extending `../openshift` |
| `deploy/k8s/overlays/openshift-oidc/keycloak-route.yaml` | Route for Keycloak with TLS |
| `deploy/k8s/overlays/openshift-oidc/oidc-urls-configmap.yaml.template` | Template for OIDC URLs |
| `deploy/k8s/overlays/openshift-oidc/keycloak-realm-patch.yaml.template` | Template for realm with redirect URIs |
| `deploy/k8s/overlays/openshift-oidc/oidc-urls-configmap.yaml` | Generated (gitignored) |
| `deploy/k8s/overlays/openshift-oidc/keycloak-realm-patch.yaml` | Generated (gitignored) |

### Key differences from Kind

| Aspect | Kind | OpenShift |
| ------ | ---- | --------- |
| Keycloak access | host.containers.internal:8180 | Route with TLS |
| Dashboard access | port-forward localhost:8080 | Route with TLS |
| TLS | None (HTTP) | Automatic edge termination |
| /etc/hosts hack | Required | Not needed |
| OIDC URLs | Hardcoded localhost | ConfigMap per cluster |

### Realm redirect URIs

The OpenShift overlay patches the Keycloak realm to include a wildcard redirect URI:

```json
"redirectUris": [
  "http://localhost:8080/*",
  "https://web-dashboard-spiffe-demo.apps.*/*"
]
```

This allows the dashboard on any OpenShift cluster domain.

## Next steps

1. Consider adding `openshift-oidc-storage` overlay for ODF integration
1. Explore Keycloak 26.5 SPIFFE client authentication for agent identity
1. Phase 5: Federate agent SPIFFE IDs with Keycloak for unified identity

## Reference commits

```text
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
