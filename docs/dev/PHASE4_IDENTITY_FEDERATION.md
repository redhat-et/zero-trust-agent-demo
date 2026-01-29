# Phase 4: Identity federation with Keycloak

## Status: PHASE 4a COMPLETE

## Overview

Phase 4 introduces OAuth2/OIDC authentication using Keycloak, implemented in progressive stages:

- **Phase 4a**: Keycloak with local users (realm JSON import)
- **Phase 4b**: FreeIPA integration (LDAP federation)
- **Phase 4c**: Agent OAuth via SPIFFE (when Keycloak support matures)

This eliminates hardcoded users from the codebase and establishes proper separation between:

- **Identity** (who you are) - managed in Keycloak/FreeIPA
- **Policy** (what you can do) - managed in OPA

## Architecture evolution

### Current state (demo)

```text
┌──────────────────────────────────────────────────────────────┐
│                     HARDCODED DATA                            │
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

### Phase 4a target (Keycloak local users)

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         IDENTITY LAYER                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                      KEYCLOAK                                │    │
│  │                                                              │    │
│  │  Realm: spiffe-demo (imported from JSON)                    │    │
│  │  ├─ Users: alice, bob, carol, david                         │    │
│  │  ├─ Groups: engineering, finance, admin, hr                 │    │
│  │  └─ Client: spiffe-demo-dashboard                           │    │
│  │                                                              │    │
│  │  Issues JWTs with group claims:                             │    │
│  │  { sub: "alice", groups: ["engineering", "finance"] }       │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                         SPIRE                                │    │
│  │  Issues X.509 SVIDs to workloads (unchanged):               │    │
│  │  - spiffe://demo.example.com/service/user-service           │    │
│  │  - spiffe://demo.example.com/service/agent-service          │    │
│  │  - spiffe://demo.example.com/agent/gpt4                     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 4b target (FreeIPA integration)

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         IDENTITY LAYER                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐       LDAP sync     ┌─────────────────┐        │
│  │    FreeIPA      │ ───────────────────▶│    Keycloak     │        │
│  │  (LDAP + DNS)   │                     │  (OIDC IdP)     │        │
│  ├─────────────────┤                     ├─────────────────┤        │
│  │ Users:          │                     │ Federated users │        │
│  │  - alice        │                     │ from LDAP       │        │
│  │  - bob          │                     │                 │        │
│  │  - carol        │                     │ Issues JWTs     │        │
│  │  - david (new!) │                     │ with LDAP       │        │
│  │                 │                     │ groups          │        │
│  │ Groups:         │                     │                 │        │
│  │  - engineering  │                     │                 │        │
│  │  - finance      │                     │                 │        │
│  └─────────────────┘                     └─────────────────┘        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 4c target (agent OAuth via SPIFFE)

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         IDENTITY SOURCES                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  FreeIPA (Users)                    SPIRE (Workloads)               │
│  ├─ alice [eng, fin]                ├─ service/user-service         │
│  ├─ bob [fin, admin]                ├─ service/agent-service        │
│  └─ carol [hr]                      ├─ agent/gpt4                   │
│                                     └─ agent/claude                  │
│         │                                    │                       │
│         │ LDAP sync                          │ JWT SVID              │
│         ▼                                    ▼                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                      KEYCLOAK                                │    │
│  │  ┌──────────────────┐    ┌───────────────────────────────┐  │    │
│  │  │ LDAP Federation  │    │ SPIFFE Client Authenticator   │  │    │
│  │  │ (humans)         │    │ (agents - preview feature)    │  │    │
│  │  └────────┬─────────┘    └─────────────┬─────────────────┘  │    │
│  │           │                            │                     │    │
│  │           ▼                            ▼                     │    │
│  │  ┌─────────────────────────────────────────────────────────┐│    │
│  │  │           Unified OAuth Token Issuance                  ││    │
│  │  │  - User tokens: { sub: "alice", groups: [...] }        ││    │
│  │  │  - Agent tokens: { sub: "gpt4", capabilities: [...] }  ││    │
│  │  └─────────────────────────────────────────────────────────┘│    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Key insight from Keycloak's new SPIFFE support**: Keycloak **consumes** JWT SVIDs
from SPIRE (validates against SPIRE's JWKS endpoint), then issues OAuth tokens.
SPIRE remains the identity source for workloads; Keycloak bridges SPIFFE → OAuth.

References:

- [Keycloak Federated Client Authentication](https://www.keycloak.org/2026/01/federated-client-authentication)
- [Authenticating MCP OAuth Clients with SPIFFE](https://blog.christianposta.com/authenticating-mcp-oauth-clients-with-spiffe/)

---

## Phase 4a: Keycloak with local users

### Goals

1. Deploy Keycloak in Kind cluster
2. Import realm with demo users and groups via JSON
3. Add OAuth2 login flow to dashboard
4. Pass JWT claims through service chain to OPA
5. Remove hardcoded user lookups from OPA policies

### Task groups

#### Group A: Keycloak deployment

##### Task A1: Create Keycloak realm JSON

**Objective**: Define realm configuration for reproducible setup.

**File**: `deploy/keycloak/realm-spiffe-demo.json`

```json
{
  "realm": "spiffe-demo",
  "enabled": true,
  "sslRequired": "external",
  "registrationAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": false,
  "editUsernameAllowed": false,
  "bruteForceProtected": true,
  "roles": {
    "realm": [
      { "name": "engineering", "description": "Engineering department" },
      { "name": "finance", "description": "Finance department" },
      { "name": "admin", "description": "Administration" },
      { "name": "hr", "description": "Human Resources" }
    ]
  },
  "groups": [
    { "name": "engineering", "realmRoles": ["engineering"] },
    { "name": "finance", "realmRoles": ["finance"] },
    { "name": "admin", "realmRoles": ["admin"] },
    { "name": "hr", "realmRoles": ["hr"] }
  ],
  "users": [
    {
      "username": "alice",
      "email": "alice@example.com",
      "firstName": "Alice",
      "lastName": "Smith",
      "enabled": true,
      "credentials": [{ "type": "password", "value": "alice123", "temporary": false }],
      "groups": ["engineering", "finance"]
    },
    {
      "username": "bob",
      "email": "bob@example.com",
      "firstName": "Bob",
      "lastName": "Jones",
      "enabled": true,
      "credentials": [{ "type": "password", "value": "bob123", "temporary": false }],
      "groups": ["finance", "admin"]
    },
    {
      "username": "carol",
      "email": "carol@example.com",
      "firstName": "Carol",
      "lastName": "Williams",
      "enabled": true,
      "credentials": [{ "type": "password", "value": "carol123", "temporary": false }],
      "groups": ["hr"]
    },
    {
      "username": "david",
      "email": "david@example.com",
      "firstName": "David",
      "lastName": "Brown",
      "enabled": true,
      "credentials": [{ "type": "password", "value": "david123", "temporary": false }],
      "groups": ["engineering", "hr"]
    }
  ],
  "clients": [
    {
      "clientId": "spiffe-demo-dashboard",
      "name": "SPIFFE Demo Dashboard",
      "enabled": true,
      "publicClient": true,
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": false,
      "rootUrl": "http://localhost:8080",
      "baseUrl": "/",
      "redirectUris": [
        "http://localhost:8080/*",
        "http://dashboard.spiffe-demo.svc:8080/*"
      ],
      "webOrigins": ["+"],
      "protocol": "openid-connect",
      "defaultClientScopes": ["openid", "profile", "email", "groups"]
    }
  ],
  "clientScopes": [
    {
      "name": "groups",
      "description": "User group memberships",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "true"
      },
      "protocolMappers": [
        {
          "name": "groups",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "consentRequired": false,
          "config": {
            "full.path": "false",
            "introspection.token.claim": "true",
            "userinfo.token.claim": "true",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "groups"
          }
        }
      ]
    }
  ]
}
```

##### Task A2: Keycloak Kubernetes deployment

**Objective**: Deploy Keycloak with realm import.

**File**: `deploy/k8s/base/keycloak.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: keycloak-realm
  namespace: spiffe-demo
data:
  realm-spiffe-demo.json: |
    # Contents from realm JSON file
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: spiffe-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:26.0
        args:
        - start-dev
        - --import-realm
        env:
        - name: KC_BOOTSTRAP_ADMIN_USERNAME
          value: admin
        - name: KC_BOOTSTRAP_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: keycloak-admin
              key: password
        - name: KC_PROXY_HEADERS
          value: xforwarded
        - name: KC_HTTP_ENABLED
          value: "true"
        ports:
        - containerPort: 8080
          name: http
        volumeMounts:
        - name: realm-config
          mountPath: /opt/keycloak/data/import
          readOnly: true
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
      volumes:
      - name: realm-config
        configMap:
          name: keycloak-realm
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: spiffe-demo
spec:
  selector:
    app: keycloak
  ports:
  - port: 8080
    targetPort: 8080
    name: http
---
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-admin
  namespace: spiffe-demo
type: Opaque
stringData:
  password: admin123  # Change in production
```

##### Task A3: Keycloak ingress/route

**For Kind with ingress-nginx**:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: keycloak
  namespace: spiffe-demo
spec:
  ingressClassName: nginx
  rules:
  - host: keycloak.localhost
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: keycloak
            port:
              number: 8080
```

---

#### Group B: Dashboard OAuth integration

##### Task B1: Add OIDC configuration

**Objective**: Configure dashboard for Keycloak OIDC.

**New file**: `pkg/auth/oidc.go`

```go
package auth

import (
    "context"
    "fmt"

    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)

type OIDCConfig struct {
    IssuerURL    string `mapstructure:"issuer_url"`
    ClientID     string `mapstructure:"client_id"`
    ClientSecret string `mapstructure:"client_secret"`
    RedirectURL  string `mapstructure:"redirect_url"`
}

type OIDCProvider struct {
    provider     *oidc.Provider
    oauth2Config *oauth2.Config
    verifier     *oidc.IDTokenVerifier
}

func NewOIDCProvider(ctx context.Context, cfg OIDCConfig) (*OIDCProvider, error) {
    provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
    if err != nil {
        return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
    }

    oauth2Config := &oauth2.Config{
        ClientID:     cfg.ClientID,
        ClientSecret: cfg.ClientSecret,
        RedirectURL:  cfg.RedirectURL,
        Endpoint:     provider.Endpoint(),
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
    }

    verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

    return &OIDCProvider{
        provider:     provider,
        oauth2Config: oauth2Config,
        verifier:     verifier,
    }, nil
}

func (p *OIDCProvider) AuthCodeURL(state string) string {
    return p.oauth2Config.AuthCodeURL(state)
}

func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
    return p.oauth2Config.Exchange(ctx, code)
}

func (p *OIDCProvider) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
    return p.verifier.Verify(ctx, rawIDToken)
}

type Claims struct {
    Subject string   `json:"sub"`
    Name    string   `json:"name"`
    Email   string   `json:"email"`
    Groups  []string `json:"groups"`
}

func (p *OIDCProvider) ExtractClaims(idToken *oidc.IDToken) (*Claims, error) {
    var claims Claims
    if err := idToken.Claims(&claims); err != nil {
        return nil, fmt.Errorf("failed to extract claims: %w", err)
    }
    return &claims, nil
}
```

##### Task B2: Add login/logout endpoints

**Objective**: Handle OAuth2 authorization code flow.

**Updates to**: `web-dashboard/cmd/serve.go`

```go
// GET /auth/login - Redirect to Keycloak
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    state := generateSecureState()
    s.stateStore.Set(state, time.Now().Add(10*time.Minute))

    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        HttpOnly: true,
        Secure:   r.TLS != nil,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   600,
    })

    url := s.oidcProvider.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GET /auth/callback - Handle Keycloak redirect
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
    // Verify state
    stateCookie, err := r.Cookie("oauth_state")
    if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
        http.Error(w, "Invalid state", http.StatusBadRequest)
        return
    }

    // Exchange code for token
    code := r.URL.Query().Get("code")
    token, err := s.oidcProvider.Exchange(r.Context(), code)
    if err != nil {
        s.log.Error("Token exchange failed", "error", err)
        http.Error(w, "Authentication failed", http.StatusInternalServerError)
        return
    }

    // Extract and verify ID token
    rawIDToken, ok := token.Extra("id_token").(string)
    if !ok {
        http.Error(w, "No ID token in response", http.StatusInternalServerError)
        return
    }

    idToken, err := s.oidcProvider.Verify(r.Context(), rawIDToken)
    if err != nil {
        http.Error(w, "Token verification failed", http.StatusUnauthorized)
        return
    }

    // Extract claims
    claims, err := s.oidcProvider.ExtractClaims(idToken)
    if err != nil {
        http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
        return
    }

    // Create session
    session := s.sessionStore.Create(claims.Subject, claims.Name, claims.Groups)
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    session.ID,
        HttpOnly: true,
        Secure:   r.TLS != nil,
        SameSite: http.SameSiteStrictMode,
        Path:     "/",
    })

    // Store access token for API calls
    s.tokenStore.Set(session.ID, token)

    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// POST /auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
    cookie, _ := r.Cookie("session_id")
    if cookie != nil {
        s.sessionStore.Delete(cookie.Value)
        s.tokenStore.Delete(cookie.Value)
    }

    // Clear session cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    "",
        HttpOnly: true,
        MaxAge:   -1,
        Path:     "/",
    })

    // Redirect to Keycloak logout (optional, for SSO logout)
    // logoutURL := fmt.Sprintf("%s/protocol/openid-connect/logout?...", issuerURL)
    http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
```

##### Task B3: Session management

**New file**: `pkg/auth/session.go`

```go
package auth

import (
    "crypto/rand"
    "encoding/hex"
    "sync"
    "time"
)

type Session struct {
    ID         string
    Username   string
    Name       string
    Groups     []string
    CreatedAt  time.Time
    ExpiresAt  time.Time
}

type SessionStore struct {
    mu       sync.RWMutex
    sessions map[string]*Session
    ttl      time.Duration
}

func NewSessionStore(ttl time.Duration) *SessionStore {
    store := &SessionStore{
        sessions: make(map[string]*Session),
        ttl:      ttl,
    }
    go store.cleanup()
    return store
}

func (s *SessionStore) Create(username, name string, groups []string) *Session {
    s.mu.Lock()
    defer s.mu.Unlock()

    id := generateSessionID()
    session := &Session{
        ID:        id,
        Username:  username,
        Name:      name,
        Groups:    groups,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(s.ttl),
    }
    s.sessions[id] = session
    return session
}

func (s *SessionStore) Get(id string) *Session {
    s.mu.RLock()
    defer s.mu.RUnlock()

    session, ok := s.sessions[id]
    if !ok || time.Now().After(session.ExpiresAt) {
        return nil
    }
    return session
}

func (s *SessionStore) Delete(id string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.sessions, id)
}

func (s *SessionStore) cleanup() {
    ticker := time.NewTicker(time.Minute)
    for range ticker.C {
        s.mu.Lock()
        for id, session := range s.sessions {
            if time.Now().After(session.ExpiresAt) {
                delete(s.sessions, id)
            }
        }
        s.mu.Unlock()
    }
}

func generateSessionID() string {
    b := make([]byte, 32)
    rand.Read(b)
    return hex.EncodeToString(b)
}
```

##### Task B4: Update dashboard UI

**Objective**: Replace user dropdown with login button.

**Template changes**: Show login button or user info based on session.

```html
{{if .Session}}
  <div class="user-info">
    <span class="user-name">{{.Session.Name}}</span>
    <span class="user-groups">
      {{range .Session.Groups}}
        <span class="badge">{{.}}</span>
      {{end}}
    </span>
    <form action="/auth/logout" method="POST" class="inline">
      <button type="submit" class="btn-logout">Logout</button>
    </form>
  </div>
{{else}}
  <a href="/auth/login" class="btn-login">Login with Keycloak</a>
{{end}}
```

---

#### Group C: Service chain updates

##### Task C1: Pass JWT claims to OPA

**Objective**: User departments flow from JWT to OPA policy.

**Update document-service request**:

```go
type AuthorizationRequest struct {
    CallerSPIFFEID  string   `json:"caller_spiffe_id"`
    DocumentID      string   `json:"document_id"`
    UserDepartments []string `json:"user_departments,omitempty"`
    Delegation      *struct {
        UserSPIFFEID    string   `json:"user_spiffe_id"`
        UserDepartments []string `json:"user_departments"`
        AgentSPIFFEID   string   `json:"agent_spiffe_id"`
    } `json:"delegation,omitempty"`
}
```

##### Task C2: Update OPA policy

**Objective**: Read user departments from input instead of hardcoded map.

**File**: `opa-service/policies/delegation.rego`

```rego
package demo.authorization

import rego.v1

# Get user departments - prefer input, fall back to hardcoded for testing
get_user_departments(user_name) := input.user_departments if {
    input.user_departments
}

get_user_departments(user_name) := data.users.departments[user_name] if {
    not input.user_departments
    data.users.departments[user_name]
}

# For delegated access, prefer delegation.user_departments
get_delegated_user_departments := input.delegation.user_departments if {
    input.delegation.user_departments
}

get_delegated_user_departments := data.users.departments[user_name] if {
    not input.delegation.user_departments
    user_name := extract_name(input.delegation.user_spiffe_id)
    data.users.departments[user_name]
}
```

---

### Phase 4a success criteria

- [x] Keycloak deployed in Kind with realm imported
- [x] Demo users (alice, bob, carol, david) can log in
- [x] JWT contains groups claim matching user's groups
- [x] Dashboard shows logged-in user with their departments
- [x] Direct access works using JWT groups (not hardcoded)
- [x] Delegated access works with JWT groups
- [x] Logout clears session

---

## Phase 4b: FreeIPA integration

### Goals

1. Deploy FreeIPA as central identity store
2. Configure Keycloak LDAP federation
3. Users managed in FreeIPA, synced to Keycloak
4. Adding users requires no code changes

### Task groups

#### Group A: FreeIPA deployment

##### Task A1: Deploy FreeIPA server

Kubernetes StatefulSet (development):

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
          value: "--unattended --realm=DEMO.EXAMPLE.COM"
        ports:
        - containerPort: 443
        - containerPort: 389
        - containerPort: 636
```

OpenShift IdM Operator (production):

```yaml
apiVersion: idm.redhat.com/v1alpha1
kind: IDM
metadata:
  name: demo-idm
spec:
  realm: DEMO.EXAMPLE.COM
```

##### Task A2: Create users and groups

**Script**: `scripts/setup-freeipa-users.sh`

```bash
#!/bin/bash
# Create groups (departments)
ipa group-add engineering --desc="Engineering Department"
ipa group-add finance --desc="Finance Department"
ipa group-add admin --desc="Administration"
ipa group-add hr --desc="Human Resources"

# Create users
ipa user-add alice --first=Alice --last=Smith
ipa user-add bob --first=Bob --last=Jones
ipa user-add carol --first=Carol --last=Williams
ipa user-add david --first=David --last=Brown

# Assign to groups
ipa group-add-member engineering --users=alice,david
ipa group-add-member finance --users=alice,bob
ipa group-add-member admin --users=bob
ipa group-add-member hr --users=carol,david
```

#### Group B: Keycloak LDAP federation

##### Task B1: Configure LDAP user federation

**Keycloak admin console steps**:

1. User Federation → Add provider → ldap
2. Configure:
   - Vendor: Red Hat Directory Server
   - Connection URL: `ldaps://freeipa.identity.svc:636`
   - Users DN: `cn=users,cn=accounts,dc=demo,dc=example,dc=com`
   - Bind DN: `uid=admin,cn=users,cn=accounts,...`
3. Sync Settings:
   - Import Users: ON
   - Periodic Full Sync: ON (every 1 hour)
4. Add group mapper:
   - LDAP Groups DN: `cn=groups,cn=accounts,...`

##### Task B2: Remove local users from realm

Once LDAP federation works, remove the hardcoded users from `realm-spiffe-demo.json`
and let Keycloak sync from FreeIPA.

### Phase 4b success criteria

- [ ] FreeIPA running with demo users and groups
- [ ] Keycloak syncs users from FreeIPA
- [ ] Login with FreeIPA credentials works
- [ ] Adding user to FreeIPA appears in Keycloak after sync
- [ ] Group membership changes reflect in JWT claims

---

## Phase 4c: Agent OAuth via SPIFFE

### Goals

1. Enable SPIRE OIDC Discovery endpoint
2. Add Keycloak SPIFFE client authenticator
3. Agents authenticate using JWT SVIDs
4. Agents receive OAuth tokens for API access

### Prerequisites

- Keycloak SPIFFE support exits preview (or accept preview status for demo)
- SPIRE configured for JWT SVID issuance

### Architecture

```text
Agent Workload
    │
    │ 1. Request JWT SVID
    ▼
SPIRE Agent ──────────────────┐
    │                         │
    │ 2. JWT SVID             │ 3. JWKS for validation
    ▼                         ▼
Agent ──────────────────▶ Keycloak
    │   client_assertion      │
    │   (JWT SVID)            │ 4. Validate against
    │                         │    SPIRE OIDC endpoint
    │◀────────────────────────┘
    │   5. OAuth access token
    ▼
Protected Resource (with OAuth token)
```

### Task groups

#### Group A: SPIRE OIDC configuration

##### Task A1: Enable SPIRE OIDC Discovery

**Update SPIRE server config**:

```yaml
server:
  oidc_discovery:
    enabled: true
    domain: spire.demo.example.com
    # Exposes /.well-known/openid-configuration and /keys
```

##### Task A2: Expose SPIRE OIDC endpoint

```yaml
apiVersion: v1
kind: Service
metadata:
  name: spire-oidc
  namespace: spire
spec:
  selector:
    app: spire-server
  ports:
  - port: 443
    targetPort: 8443
    name: oidc
```

#### Group B: Keycloak SPIFFE authenticator

##### Task B1: Install SPIFFE client authenticator SPI

Based on Christian Posta's implementation, add the SPI JAR to Keycloak:

```dockerfile
FROM quay.io/keycloak/keycloak:26.0
COPY spiffe-svid-authenticator.jar /opt/keycloak/providers/
```

##### Task B2: Configure SPIFFE identity provider

In Keycloak admin:

1. Authentication → Flows → Create new flow for SPIFFE
2. Add "SPIFFE SVID Client Authenticator" execution
3. Configure:
   - SPIRE OIDC Issuer: `https://spire.demo.example.com`
   - JWKS URL: `https://spire.demo.example.com/keys`

##### Task B3: Create agent clients

Register each agent as a Keycloak client:

```json
{
  "clientId": "spiffe://demo.example.com/agent/gpt4",
  "enabled": true,
  "clientAuthenticatorType": "spiffe-svid-jwt",
  "serviceAccountsEnabled": true,
  "attributes": {
    "spiffe.trust_domain": "demo.example.com"
  }
}
```

#### Group C: Agent code updates

##### Task C1: Add OAuth token acquisition

```go
func (a *Agent) GetOAuthToken(ctx context.Context) (*oauth2.Token, error) {
    // Get JWT SVID from SPIRE
    jwtSVID, err := a.spiffeClient.FetchJWTSVID(ctx, []string{"keycloak"})
    if err != nil {
        return nil, fmt.Errorf("failed to get JWT SVID: %w", err)
    }

    // Exchange for OAuth token
    data := url.Values{
        "grant_type":            {"client_credentials"},
        "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:spiffe-svid-jwt"},
        "client_assertion":      {jwtSVID.Marshal()},
    }

    resp, err := http.PostForm(a.keycloakTokenURL, data)
    // ... parse OAuth token from response
}
```

### Phase 4c success criteria

- [ ] SPIRE OIDC endpoint accessible
- [ ] Keycloak validates JWT SVIDs against SPIRE
- [ ] Agents can exchange SVIDs for OAuth tokens
- [ ] OAuth tokens contain agent capabilities
- [ ] APIs accept OAuth tokens from agents

---

## Implementation priority

### Phase 4a (start here)

| Task | Description                          |
| ---- | ------------------------------------ |
| A1   | Create realm JSON with users/groups |
| A2   | Deploy Keycloak in Kind              |
| A3   | Add ingress for Keycloak             |
| B1   | Add OIDC provider package            |
| B2   | Add login/logout endpoints           |
| B3   | Add session management               |
| B4   | Update dashboard UI                  |
| C1   | Pass JWT claims through services     |
| C2   | Update OPA to use input claims       |

### Phase 4b (after 4a works)

| Task | Description                          |
| ---- | ------------------------------------ |
| A1   | Deploy FreeIPA                       |
| A2   | Create users/groups in FreeIPA       |
| B1   | Configure Keycloak LDAP federation   |
| B2   | Remove local users from realm        |

### Phase 4c (optional, when SPIFFE support matures)

| Task  | Description                                |
| ----- | ------------------------------------------ |
| A1-A2 | Enable SPIRE OIDC                          |
| B1-B3 | Configure Keycloak SPIFFE authenticator    |
| C1    | Update agents for OAuth token acquisition  |

---

## Development approach

### Local development with Kind (host Keycloak)

The recommended setup runs Keycloak on the host machine while services run in Kind.
This allows the browser to access Keycloak at the same URL as the in-cluster services.

**Prerequisites:**

- Kind cluster with Podman backend
- Add `127.0.0.1 host.containers.internal` to `/etc/hosts` on macOS

#### Start Keycloak on host

```bash
podman run -d \
  --name keycloak-local \
  -p 8180:8080 \
  -v $(pwd)/deploy/keycloak:/opt/keycloak/data/import:Z \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HOSTNAME_STRICT=false \
  -e KC_HTTP_ENABLED=true \
  quay.io/keycloak/keycloak:26.1 \
  start-dev --import-realm
```

Key settings:

- `KC_HOSTNAME_STRICT=false`: Allows Keycloak to respond with the requested host
  in the issuer URL (both `localhost:8180` and `host.containers.internal:8180`)
- Port 8180 to avoid conflicts with dashboard on 8080

#### Build and load images

```bash
make build

# Build container images
for svc in opa-service document-service user-service agent-service web-dashboard; do
  podman build -t localhost/spiffe-demo/$svc:latest -f $svc/Dockerfile .
done

# Load into Kind
for svc in opa-service document-service user-service agent-service web-dashboard; do
  kind load docker-image localhost/spiffe-demo/$svc:latest --name spiffe-demo
done
```

#### Deploy to Kind

```bash
kubectl apply -k deploy/k8s/overlays/mock
```

The mock overlay configures services to use `host.containers.internal:8180` for OIDC.

#### Port-forward dashboard

```bash
kubectl port-forward -n spiffe-demo svc/web-dashboard 8080:8080
```

#### Test OAuth flow

```bash
open http://localhost:8080
# Click "Login with Keycloak"
# Enter: alice / alice123 (or bob/carol/david)
```

### Testing OAuth flow locally (without Kind)

```bash
# Start Keycloak as above, then:
./scripts/run-local.sh

# Keycloak admin console
open http://localhost:8180/admin
# Login: admin / admin

# Test login flow
open http://localhost:8080
# Click "Login with Keycloak"
# Enter: alice / alice123
```

---

## Dependencies

- Phase 3 complete (mTLS working, CI/CD ready)
- Kind cluster with ingress-nginx
- Go dependencies: `golang.org/x/oauth2`, `github.com/coreos/go-oidc/v3`

---

## References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Keycloak Realm Export/Import](https://www.keycloak.org/server/importExport)
- [Keycloak Federated Client Authentication (SPIFFE)](https://www.keycloak.org/2026/01/federated-client-authentication)
- [Go OIDC Library](https://github.com/coreos/go-oidc)
- [Authenticating MCP OAuth Clients with SPIFFE](https://blog.christianposta.com/authenticating-mcp-oauth-clients-with-spiffe/)
- [FreeIPA Documentation](https://www.freeipa.org/page/Documentation)
