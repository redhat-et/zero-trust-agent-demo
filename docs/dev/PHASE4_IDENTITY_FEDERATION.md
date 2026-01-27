# Phase 4: Identity Federation with FreeIPA and Keycloak

## Status: PLANNED

## Overview

Phase 4 introduces production-grade identity management by integrating:
- **FreeIPA** as the central identity store (LDAP + Kerberos + DNS)
- **Keycloak** as the OIDC Identity Provider for human authentication
- **SPIRE** continues to handle workload identity (services and agents)

This eliminates hardcoded users from the codebase and establishes proper separation between:
- **Identity** (who you are) - managed in FreeIPA/Keycloak
- **Policy** (what you can do) - managed in OPA

## Goals

1. **Centralized User Management**: Users and their departments managed in FreeIPA
2. **OAuth2/OIDC Authentication**: Users authenticate via Keycloak
3. **JWT-Based Authorization**: User departments flow as JWT claims
4. **Dynamic User Provisioning**: Adding users requires no code changes
5. **Maintain Workload Identity**: SPIRE continues issuing SVIDs to services/agents

---

## Architecture Overview

### Current State (Demo)

```
┌──────────────────────────────────────────────────────────────┐
│                     HARDCODED DATA                           │
├──────────────────────────────────────────────────────────────┤
│  users.go              │  user_permissions.rego              │
│  ──────────            │  ──────────────────────             │
│  alice: [eng, fin]     │  alice: [eng, fin]                  │
│  bob: [fin, admin]     │  bob: [fin, admin]                  │
│  carol: [hr]           │  carol: [hr]                        │
│                        │                                     │
│  agents.go             │  agent_permissions.rego             │
│  ──────────            │  ──────────────────────             │
│  gpt4: [eng, fin]      │  gpt4: [eng, fin]                   │
│  claude: [all]         │  claude: [all]                      │
│  summarizer: [fin]     │  summarizer: [fin]                  │
└──────────────────────────────────────────────────────────────┘
```

### Target State (Phase 4)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          IDENTITY LAYER                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐       sync        ┌─────────────────┐              │
│  │    FreeIPA      │ ─────────────────▶│    Keycloak     │              │
│  │  (LDAP + DNS)   │                   │  (OIDC IdP)     │              │
│  ├─────────────────┤                   ├─────────────────┤              │
│  │ Users:          │                   │ Issues JWTs:    │              │
│  │  - alice        │                   │  {              │              │
│  │  - bob          │                   │    sub: alice,  │              │
│  │  - carol        │                   │    groups: [..] │              │
│  │  - david (new!) │                   │  }              │              │
│  │                 │                   │                 │              │
│  │ Groups:         │                   │                 │              │
│  │  - engineering  │                   │                 │              │
│  │  - finance      │                   │                 │              │
│  │  - admin        │                   │                 │              │
│  │  - hr           │                   │                 │              │
│  └─────────────────┘                   └─────────────────┘              │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                         SPIRE                                   │    │
│  │  Issues SVIDs to workloads:                                     │    │
│  │  - spiffe://example.com/service/user-service                    │    │
│  │  - spiffe://example.com/service/agent-service                   │    │
│  │  - spiffe://example.com/agent/reviewer  (new agent workload!)   │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                          POLICY LAYER                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    OPA Policies (Rego)                          │    │
│  │                                                                 │    │
│  │  # User departments now come from JWT claims (input)            │    │
│  │  user_depts := input.user_departments                           │    │
│  │                                                                 │    │
│  │  # Agent capabilities still defined in policy                   │    │
│  │  agent_capabilities := {                                        │    │
│  │      "gpt4": ["engineering", "finance"],                        │    │
│  │      "reviewer": ["engineering", "hr"],  ← Policy decision      │    │
│  │  }                                                              │    │
│  │                                                                 │    │
│  │  # Permission intersection logic unchanged                      │    │
│  │  effective := user_depts ∩ agent_caps                           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### Identity vs Policy Separation

| Aspect | Users | Agents |
|--------|-------|--------|
| **Identity Source** | FreeIPA/Keycloak | SPIRE |
| **Attributes** | Groups (departments) - from LDAP | Capabilities - from OPA policy |
| **Why?** | User groups are identity facts (HR manages) | Agent capabilities are security policy decisions |
| **Adding new** | FreeIPA only (no code changes) | SPIRE registration + OPA policy |

### User SPIFFE IDs Are Logical

Users don't get real SVIDs from SPIRE. The "user SPIFFE ID" (e.g., `spiffe://example.com/user/alice`) is a **naming convention** constructed from the JWT subject claim:

```go
// In user-service, after validating JWT
userSPIFFEID := fmt.Sprintf("spiffe://%s/user/%s", trustDomain, jwt.Subject)
```

This provides a consistent naming format for OPA policy evaluation.

### JWT Claims Carry User Departments

```json
{
  "iss": "https://keycloak.example.com/realms/demo",
  "sub": "alice",
  "groups": ["engineering", "finance"],
  "exp": 1706000000
}
```

The `groups` claim (synced from FreeIPA) replaces the hardcoded `user_departments` map in Rego.

---

## Task Groups

### Group A: FreeIPA Deployment

#### Task A1: Deploy FreeIPA Server

**Objective**: Deploy FreeIPA as the central identity store.

**Option 1: Kubernetes Deployment (Development)**
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: freeipa
  namespace: identity
spec:
  serviceName: freeipa
  replicas: 1
  template:
    spec:
      containers:
      - name: freeipa
        image: freeipa/freeipa-server:fedora-39
        env:
        - name: IPA_SERVER_HOSTNAME
          value: ipa.demo.example.com
        - name: IPA_SERVER_INSTALL_OPTS
          value: "--unattended --realm=DEMO.EXAMPLE.COM --ds-password=... --admin-password=..."
        ports:
        - containerPort: 443
        - containerPort: 389
        - containerPort: 636
        volumeMounts:
        - name: data
          mountPath: /data
```

**Option 2: OpenShift with IdM Operator (Production)**
```yaml
apiVersion: idm.redhat.com/v1alpha1
kind: IDM
metadata:
  name: demo-idm
spec:
  realm: DEMO.EXAMPLE.COM
  adminPassword:
    secretRef: idm-admin-password
```

**Estimated effort**: 4-6 hours

#### Task A2: Create Users and Groups in FreeIPA

**Objective**: Create the demo users and department groups.

**Script**: `scripts/setup-freeipa-users.sh`
```bash
#!/bin/bash
# Run inside FreeIPA container or with ipa CLI configured

# Create groups (departments)
ipa group-add engineering --desc="Engineering Department"
ipa group-add finance --desc="Finance Department"
ipa group-add admin --desc="Administration"
ipa group-add hr --desc="Human Resources"

# Create users
ipa user-add alice --first=Alice --last=Smith --email=alice@example.com
ipa user-add bob --first=Bob --last=Jones --email=bob@example.com
ipa user-add carol --first=Carol --last=Williams --email=carol@example.com
ipa user-add david --first=David --last=Brown --email=david@example.com

# Assign users to groups
ipa group-add-member engineering --users=alice
ipa group-add-member finance --users=alice,bob
ipa group-add-member admin --users=bob
ipa group-add-member hr --users=carol
ipa group-add-member engineering --users=david
ipa group-add-member hr --users=david
```

**Estimated effort**: 1-2 hours

---

### Group B: Keycloak Deployment

#### Task B1: Deploy Keycloak

**Objective**: Deploy Keycloak as the OIDC Identity Provider.

**Option 1: Kubernetes with Operator**
```yaml
apiVersion: k8s.keycloak.org/v2alpha1
kind: Keycloak
metadata:
  name: keycloak
  namespace: identity
spec:
  instances: 1
  hostname:
    hostname: keycloak.demo.example.com
  http:
    tlsSecret: keycloak-tls
```

**Option 2: Red Hat SSO on OpenShift**
```yaml
apiVersion: keycloak.org/v1alpha1
kind: Keycloak
metadata:
  name: sso
  namespace: identity
spec:
  instances: 1
  externalAccess:
    enabled: true
```

**Estimated effort**: 3-4 hours

#### Task B2: Configure LDAP Federation

**Objective**: Connect Keycloak to FreeIPA for user synchronization.

**Keycloak Admin Console Steps**:
1. Go to User Federation → Add provider → ldap
2. Configure connection:
   - Vendor: Red Hat Directory Server
   - Connection URL: `ldaps://freeipa.identity.svc:636`
   - Users DN: `cn=users,cn=accounts,dc=demo,dc=example,dc=com`
   - Bind DN: `uid=admin,cn=users,cn=accounts,dc=demo,dc=example,dc=com`
   - Bind Credential: (from secret)
3. Configure Sync Settings:
   - Import Users: ON
   - Sync Registrations: ON
   - Periodic Full Sync: ON (every 1 hour)
4. Map LDAP groups to Keycloak groups:
   - Add mapper: group-ldap-mapper
   - LDAP Groups DN: `cn=groups,cn=accounts,dc=demo,dc=example,dc=com`
   - Group Name LDAP Attribute: cn

**Estimated effort**: 2-3 hours

#### Task B3: Configure OIDC Client for Dashboard

**Objective**: Register web-dashboard as an OIDC client.

**Keycloak Admin Console Steps**:
1. Create Client:
   - Client ID: `spiffe-demo-dashboard`
   - Client Protocol: openid-connect
   - Root URL: `https://dashboard.demo.example.com`
2. Configure Client:
   - Access Type: public (for SPA) or confidential (for server-side)
   - Valid Redirect URIs: `https://dashboard.demo.example.com/*`
   - Web Origins: `https://dashboard.demo.example.com`
3. Configure Mappers:
   - Add "groups" mapper to include groups in JWT
   - Token Claim Name: `groups`
   - Full group path: OFF

**Client Secret** (if confidential):
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-client-secret
  namespace: spiffe-demo
data:
  client-secret: <base64-encoded-secret>
```

**Estimated effort**: 2-3 hours

---

### Group C: Dashboard OAuth Integration

#### Task C1: Add OAuth2 Login Flow

**Objective**: Replace dropdown user selection with Keycloak login.

**New Dependencies**:
```go
go get golang.org/x/oauth2
go get github.com/coreos/go-oidc/v3
```

**OAuth Configuration**:
```go
// pkg/auth/oidc.go
type OIDCConfig struct {
    IssuerURL    string `mapstructure:"issuer_url"`
    ClientID     string `mapstructure:"client_id"`
    ClientSecret string `mapstructure:"client_secret"`
    RedirectURL  string `mapstructure:"redirect_url"`
}

func NewOIDCProvider(cfg OIDCConfig) (*oidc.Provider, error) {
    provider, err := oidc.NewProvider(context.Background(), cfg.IssuerURL)
    if err != nil {
        return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
    }
    return provider, nil
}

func NewOAuth2Config(cfg OIDCConfig, provider *oidc.Provider) *oauth2.Config {
    return &oauth2.Config{
        ClientID:     cfg.ClientID,
        ClientSecret: cfg.ClientSecret,
        RedirectURL:  cfg.RedirectURL,
        Endpoint:     provider.Endpoint(),
        Scopes:       []string{oidc.ScopeOpenID, "profile", "groups"},
    }
}
```

**Estimated effort**: 6-8 hours

#### Task C2: Add Login/Logout Endpoints

**Objective**: Handle OAuth2 authorization code flow.

**New Endpoints**:
```go
// web-dashboard/cmd/serve.go

// GET /auth/login - Redirect to Keycloak
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    state := generateRandomState()
    s.stateStore.Set(state, time.Now().Add(10*time.Minute))

    url := s.oauth2Config.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GET /auth/callback - Handle Keycloak redirect
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
    state := r.URL.Query().Get("state")
    if !s.stateStore.Validate(state) {
        http.Error(w, "Invalid state", http.StatusBadRequest)
        return
    }

    code := r.URL.Query().Get("code")
    token, err := s.oauth2Config.Exchange(r.Context(), code)
    if err != nil {
        http.Error(w, "Token exchange failed", http.StatusInternalServerError)
        return
    }

    // Extract ID token and verify
    rawIDToken := token.Extra("id_token").(string)
    idToken, err := s.verifier.Verify(r.Context(), rawIDToken)
    if err != nil {
        http.Error(w, "Token verification failed", http.StatusUnauthorized)
        return
    }

    // Extract claims
    var claims struct {
        Subject string   `json:"sub"`
        Name    string   `json:"name"`
        Groups  []string `json:"groups"`
    }
    idToken.Claims(&claims)

    // Create session
    session := s.sessionStore.Create(claims.Subject, claims.Name, claims.Groups, token)
    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    session.ID,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
    })

    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// POST /auth/logout - Clear session
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
    cookie, _ := r.Cookie("session")
    if cookie != nil {
        s.sessionStore.Delete(cookie.Value)
    }

    // Redirect to Keycloak logout
    logoutURL := fmt.Sprintf("%s/protocol/openid-connect/logout?redirect_uri=%s",
        s.oidcConfig.IssuerURL, url.QueryEscape(s.oidcConfig.RedirectURL))
    http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}
```

**Estimated effort**: 4-5 hours

#### Task C3: Update Dashboard UI

**Objective**: Replace user dropdown with login button and user info display.

**Template Changes** (`internal/assets/templates/index.html`):
```html
<!-- Before: Dropdown -->
<select id="user-select">
  <option value="alice">Alice</option>
  <option value="bob">Bob</option>
</select>

<!-- After: Login button or user info -->
{{if .User}}
  <div class="user-info">
    <span>Logged in as: {{.User.Name}}</span>
    <span class="departments">{{range .User.Departments}}{{.}} {{end}}</span>
    <form action="/auth/logout" method="POST">
      <button type="submit">Logout</button>
    </form>
  </div>
{{else}}
  <a href="/auth/login" class="login-button">Login with Keycloak</a>
{{end}}
```

**Estimated effort**: 3-4 hours

---

### Group D: Service Updates

#### Task D1: Propagate JWT Claims Through Service Chain

**Objective**: Pass user identity from dashboard through to OPA.

**Flow**:
```
Dashboard (has JWT)
    → User Service (validates JWT, extracts claims)
        → Document Service (receives user info in request)
            → OPA (evaluates with user departments from request)
```

**User Service Changes**:
```go
// Validate JWT and extract claims
func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
    // Get JWT from Authorization header
    authHeader := r.Header.Get("Authorization")
    token := strings.TrimPrefix(authHeader, "Bearer ")

    // Verify token
    idToken, err := s.verifier.Verify(r.Context(), token)
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Extract claims
    var claims struct {
        Subject string   `json:"sub"`
        Groups  []string `json:"groups"`
    }
    idToken.Claims(&claims)

    // Construct user SPIFFE ID (logical, not a real SVID)
    userSPIFFEID := fmt.Sprintf("spiffe://%s/user/%s", s.trustDomain, claims.Subject)

    // Call document service with user info
    req := DocumentAccessRequest{
        CallerSPIFFEID:  userSPIFFEID,
        UserDepartments: claims.Groups,  // NEW: departments from JWT
        DocumentID:      r.FormValue("document_id"),
    }
    // ...
}
```

**Estimated effort**: 4-5 hours

#### Task D2: Update OPA Policy to Use JWT Claims

**Objective**: Read user departments from input instead of hardcoded map.

**Policy Changes** (`opa-service/policies/delegation.rego`):
```rego
# Before: Hardcoded lookup
user_depts := users.get_departments(caller.name)

# After: From JWT claims in input
user_depts := input.user_departments
```

**Updated Input Schema**:
```json
{
  "input": {
    "caller_spiffe_id": "spiffe://demo.example.com/user/alice",
    "user_departments": ["engineering", "finance"],
    "document_id": "DOC-001",
    "delegation": {
      "user_spiffe_id": "spiffe://demo.example.com/user/alice",
      "user_departments": ["engineering", "finance"],
      "agent_spiffe_id": "spiffe://demo.example.com/agent/gpt4"
    }
  }
}
```

**Backward Compatibility**: Keep `user_permissions.rego` for fallback/testing:
```rego
# Use JWT claims if provided, otherwise fall back to hardcoded (for testing)
get_user_departments(user_name) := input.user_departments if {
    input.user_departments
}

get_user_departments(user_name) := user_departments[user_name] if {
    not input.user_departments
    user_departments[user_name]
}
```

**Estimated effort**: 3-4 hours

#### Task D3: Remove Hardcoded Users from Go Code

**Objective**: Clean up user-service to not load sample users.

**Changes**:
- Remove `loadSampleUsers()` from `user-service/internal/store/users.go`
- Replace in-memory store with Keycloak/LDAP client (optional, can just use JWT)
- Update `/users` endpoint to list users from Keycloak Admin API (optional)

**Estimated effort**: 2-3 hours

---

### Group E: Testing and Validation

#### Task E1: End-to-End OAuth Flow Test

**Objective**: Verify complete login → access → logout flow.

**Test Script**: `scripts/test-oauth-flow.sh`
```bash
#!/bin/bash

echo "=== Testing OAuth2/OIDC Flow ==="

# 1. Start browser login (manual step)
echo "1. Open https://dashboard.demo.example.com in browser"
echo "2. Click 'Login with Keycloak'"
echo "3. Enter credentials: alice / <password>"

# 2. Verify session created
echo "4. Check that user info shows: Alice [engineering, finance]"

# 3. Test document access
echo "5. Select DOC-001 (Engineering Roadmap)"
echo "6. Click 'Direct Access' - should succeed"

# 4. Test delegation
echo "7. Select GPT-4 agent"
echo "8. Select DOC-001"
echo "9. Click 'Delegated Access' - should succeed"

# 5. Test denied access
echo "10. Select DOC-003 (Admin Policies)"
echo "11. Click 'Direct Access' - should fail (Alice not in admin)"
```

**Estimated effort**: 2-3 hours

#### Task E2: JWT Claim Verification Tests

**Objective**: Unit tests for JWT validation and claim extraction.

**Test File**: `pkg/auth/oidc_test.go`
```go
func TestExtractClaims(t *testing.T) {
    // Create mock JWT
    claims := jwt.MapClaims{
        "sub":    "alice",
        "groups": []string{"engineering", "finance"},
        "exp":    time.Now().Add(time.Hour).Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, _ := token.SignedString([]byte("test-secret"))

    // Extract and verify
    extracted, err := ExtractClaims(tokenString, testVerifier)
    require.NoError(t, err)
    assert.Equal(t, "alice", extracted.Subject)
    assert.ElementsMatch(t, []string{"engineering", "finance"}, extracted.Groups)
}
```

**Estimated effort**: 3-4 hours

---

## Implementation Priority

### P0 - Foundation (Must Complete First)

| Task | Effort | Description |
|------|--------|-------------|
| A1 | 4-6h | Deploy FreeIPA |
| A2 | 1-2h | Create users and groups |
| B1 | 3-4h | Deploy Keycloak |
| B2 | 2-3h | Configure LDAP federation |

### P1 - Core Integration

| Task | Effort | Description |
|------|--------|-------------|
| B3 | 2-3h | Configure OIDC client |
| C1 | 6-8h | Add OAuth2 login flow |
| C2 | 4-5h | Login/logout endpoints |
| D1 | 4-5h | Propagate JWT claims |
| D2 | 3-4h | Update OPA policy |

### P2 - Polish and Cleanup

| Task | Effort | Description |
|------|--------|-------------|
| C3 | 3-4h | Update dashboard UI |
| D3 | 2-3h | Remove hardcoded users |
| E1 | 2-3h | End-to-end testing |
| E2 | 3-4h | JWT unit tests |

---

## Timeline Estimate

| Phase | Effort | Description |
|-------|--------|-------------|
| P0 | 10-15 hours | Identity infrastructure |
| P1 | 20-25 hours | OAuth integration |
| P2 | 10-14 hours | UI and cleanup |
| **Total** | **40-54 hours** | Complete Phase 4 |

---

## Success Criteria

- [ ] FreeIPA running with demo users and groups
- [ ] Keycloak federated with FreeIPA
- [ ] Dashboard redirects to Keycloak for login
- [ ] JWT contains user's groups from FreeIPA
- [ ] User departments used from JWT claims (not hardcoded)
- [ ] Agent capabilities still defined in OPA policy
- [ ] Adding new user to FreeIPA works without code changes
- [ ] Permission intersection works with dynamic user data
- [ ] Logout clears session in both dashboard and Keycloak

---

## Dependencies

- Phase 3 complete (mTLS, observability)
- DNS resolution for FreeIPA and Keycloak hostnames
- TLS certificates for identity services
- Persistent storage for FreeIPA and Keycloak databases

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| FreeIPA complex to deploy on K8s | High | Use OpenShift IdM Operator or external FreeIPA |
| LDAP sync latency | Medium | Configure frequent sync, accept eventual consistency |
| JWT token size with many groups | Low | Use group references instead of full group list |
| Session management complexity | Medium | Use established session library (gorilla/sessions) |

---

## References

- [FreeIPA Documentation](https://www.freeipa.org/page/Documentation)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Keycloak LDAP Federation](https://www.keycloak.org/docs/latest/server_admin/#_ldap)
- [Go OIDC Library](https://github.com/coreos/go-oidc)
- [OAuth 2.0 for Browser-Based Apps (RFC)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- [Red Hat SSO on OpenShift](https://access.redhat.com/documentation/en-us/red_hat_single_sign-on/)

---

## Appendix: Adding Users and Agents After Phase 4

### Adding a New User (e.g., David)

**Before Phase 4** (current demo):
1. Edit `user-service/internal/store/users.go`
2. Edit `opa-service/policies/user_permissions.rego`
3. Edit `deploy/k8s/opa-policies-configmap.yaml`
4. Rebuild and redeploy services

**After Phase 4**:
1. Add user to FreeIPA: `ipa user-add david --first=David --last=Brown`
2. Assign to groups: `ipa group-add-member engineering --users=david`
3. Wait for Keycloak sync (or trigger manual sync)
4. **Done** - no code changes, no redeployment

### Adding a New Agent (e.g., Reviewer)

The process remains similar because agent capabilities are **policy decisions**, not identity:

1. Create agent workload deployment (`deploy/k8s/reviewer-agent.yaml`)
2. Register SPIFFE ID (`deploy/spire/clusterspiffeids.yaml`)
3. Define capabilities in OPA policy (`agent_permissions.rego`)
4. Add to agent-service store for UI listing (`agents.go`)
5. Update OPA ConfigMap
6. Deploy

**Why agents don't go in LDAP**: Agent capabilities are security policy decisions ("what should this agent be allowed to do?"), not identity attributes. They're managed by the security team, not HR.
