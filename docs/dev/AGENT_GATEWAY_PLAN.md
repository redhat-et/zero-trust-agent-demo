# Agent gateway implementation plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development
> (if subagents available) or superpowers:executing-plans to implement this plan.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hardcoded agents and direct service calls with dynamic
AgentCard CR discovery and a unified agent gateway, so the dashboard
routes all agent operations through agent-service.

**Architecture:** Agent-service watches AgentCard CRs via the K8s
dynamic client, registers discovered agents in its store, and proxies
all A2A invocations. The dashboard drops direct summarizer/reviewer
URLs and uses a single `/api/invoke` endpoint through agent-service.

**Tech Stack:** Go 1.21+, k8s.io/client-go (dynamic), Cobra/Viper,
a2a-go SDK, existing SPIFFE/OPA infrastructure

**Spec:** `docs/dev/AGENT_GATEWAY_DESIGN.md`

---

## File structure

### New files

```text
(none — all changes are to existing files)
```

### Modified files

```text
agent-service/internal/store/agents.go         # Remove hardcoded agents, drop Capabilities
agent-service/cmd/serve.go                     # Add action field, update invoke to use s3_url
pkg/a2abridge/discovery.go                     # Replace Deployment-label with AgentCard CR
pkg/a2abridge/client.go                        # Accept message text instead of document_id
web-dashboard/cmd/serve.go                     # Remove summarizer/reviewer URLs, add /api/invoke
web-dashboard/internal/assets/static/js/app.js # Route summarize/review through /api/invoke
web-dashboard/internal/assets/templates/index.html # Unify AI actions with agent dropdown
```

---

### Task 1: Agent store — remove hardcoded agents and Capabilities

**Files:**

- Modify: `agent-service/internal/store/agents.go`

- [ ] **Step 1: Remove Capabilities field from Agent struct**

Edit `agent-service/internal/store/agents.go`. Remove the
`Capabilities` field from the `Agent` struct and add `Version`:

```go
type Agent struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	SPIFFEID    string         `json:"spiffe_id,omitempty"`
	Source      AgentSource    `json:"source"`
	A2AURL      string         `json:"a2a_url,omitempty"`
	Version     string         `json:"version,omitempty"`
	AgentCard   *a2a.AgentCard `json:"-"`
}
```

- [ ] **Step 2: Remove loadSampleAgents and update NewAgentStore**

Remove the entire `loadSampleAgents` method. Update `NewAgentStore`
to no longer call it (and remove the `trustDomain` parameter since
it was only used by `loadSampleAgents`):

```go
func NewAgentStore() *AgentStore {
	return &AgentStore{
		agents: make(map[string]*Agent),
	}
}
```

- [ ] **Step 3: Build and fix compilation errors**

```bash
cd /Users/panni/work/zero-trust-agent-demo
go build ./agent-service/...
```

This will fail because `agent-service/cmd/serve.go` passes
`trustDomain` to `NewAgentStore`. Fix the call site at line 137:

```go
store: store.NewAgentStore(),
```

Also fix any references to `agent.Capabilities` in `serve.go`
(log messages at lines 224, 367, 658). Remove or replace with
`agent.Description`.

- [ ] **Step 4: Verify build**

```bash
go build ./agent-service/...
```

Expected: builds without errors.

- [ ] **Step 5: Commit**

```bash
git add agent-service/
git commit -s -m "refactor(agent-service): remove hardcoded agents and Capabilities field"
```

---

### Task 2: Discovery — replace Deployment-label with AgentCard CR

**Files:**

- Modify: `pkg/a2abridge/discovery.go`

- [ ] **Step 1: Replace discovery implementation**

Rewrite `pkg/a2abridge/discovery.go` to use the K8s dynamic client
to list AgentCard CRs instead of querying Deployments.

Key changes:

- Replace `kubernetes.Interface` with `dynamic.Interface`
- Define `agentCardGVR` as
  `schema.GroupVersionResource{Group: "agent.kagenti.dev", Version: "v1alpha1", Resource: "agentcards"}`
- `DiscoveryConfig` keeps `Namespace` and `Scheme`, drops `TrustDomain`
- Remove `LabelType`, `LabelProtocol`, `AnnotationDescription`
  constants, `labelSelector`, `resolvePort`, `extractCapabilities`
- `Discover()` method:
  1. Lists AgentCard CRs in the namespace
  2. For each CR, extracts from `status.card`: `name`, `description`,
     `url`, `version`
  3. Extracts from `status.bindingStatus.message`: SPIFFE ID
     (parse with regex `spiffe://\S+`)
  4. Agent ID = CR `.metadata.labels["app.kubernetes.io/name"]`
     (set by Kagenti operator)
  5. A2A URL = `status.card.url` + `/a2a` (the CR already has the
     full in-cluster URL)
  6. Returns `[]DiscoveredAgent` with `Capabilities` removed

```go
package a2abridge

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var agentCardGVR = schema.GroupVersionResource{
	Group:    "agent.kagenti.dev",
	Version:  "v1alpha1",
	Resource: "agentcards",
}

var spiffeIDRegex = regexp.MustCompile(`spiffe://\S+`)

// DiscoveredAgent holds the result of discovering a single A2A agent.
type DiscoveredAgent struct {
	ID          string
	Name        string
	Description string
	SPIFFEID    string
	A2AURL      string
	Version     string
}

// AgentDiscovery discovers A2A agents from Kagenti AgentCard CRs.
type AgentDiscovery struct {
	client    dynamic.Interface
	namespace string
	log       *slog.Logger
}

// DiscoveryConfig holds configuration for agent discovery.
type DiscoveryConfig struct {
	Namespace string
}

// NewAgentDiscovery creates a new discovery instance using in-cluster config.
func NewAgentDiscovery(cfg DiscoveryConfig, log *slog.Logger) (*AgentDiscovery, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	client, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &AgentDiscovery{
		client:    client,
		namespace: cfg.Namespace,
		log:       log,
	}, nil
}

// Discover lists AgentCard CRs and extracts agent metadata.
func (d *AgentDiscovery) Discover(ctx context.Context) ([]DiscoveredAgent, error) {
	list, err := d.client.Resource(agentCardGVR).Namespace(d.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list AgentCards: %w", err)
	}

	var agents []DiscoveredAgent
	for _, item := range list.Items {
		labels := item.GetLabels()
		agentID := labels["app.kubernetes.io/name"]
		if agentID == "" {
			agentID = item.GetName()
		}

		status, ok := item.Object["status"].(map[string]any)
		if !ok {
			d.log.Warn("AgentCard has no status", "name", item.GetName())
			continue
		}

		card, ok := status["card"].(map[string]any)
		if !ok {
			d.log.Warn("AgentCard has no card in status", "name", item.GetName())
			continue
		}

		name, _ := card["name"].(string)
		description, _ := card["description"].(string)
		url, _ := card["url"].(string)
		version, _ := card["version"].(string)

		if url == "" {
			d.log.Warn("AgentCard has no URL", "name", item.GetName())
			continue
		}

		// Extract SPIFFE ID from binding status message
		var spiffeID string
		if binding, ok := status["bindingStatus"].(map[string]any); ok {
			if msg, ok := binding["message"].(string); ok {
				if match := spiffeIDRegex.FindString(msg); match != "" {
					spiffeID = match
				}
			}
		}

		agents = append(agents, DiscoveredAgent{
			ID:          agentID,
			Name:        name,
			Description: description,
			SPIFFEID:    spiffeID,
			A2AURL:      url + "/a2a",
			Version:     version,
		})

		d.log.Info("Discovered AgentCard",
			"id", agentID,
			"name", name,
			"url", url,
			"spiffe_id", spiffeID)
	}

	return agents, nil
}
```

- [ ] **Step 2: Update imports in go.mod if needed**

```bash
cd /Users/panni/work/zero-trust-agent-demo
go mod tidy
```

- [ ] **Step 3: Fix compilation in agent-service/cmd/serve.go**

Update `NewAgentDiscovery` call (around line 148) to match the new
signature:

```go
discovery, err := a2abridge.NewAgentDiscovery(
	a2abridge.DiscoveryConfig{
		Namespace: cfg.DiscoveryNamespace,
	},
	log.Logger,
)
```

Update `discoverAgents` (around line 633) to match the new
`DiscoveredAgent` struct (no `Capabilities`, no `Card`, add `Version`):

```go
s.store.Register(&store.Agent{
	ID:          discovered.ID,
	Name:        discovered.Name,
	SPIFFEID:    discovered.SPIFFEID,
	Description: discovered.Description,
	Source:      store.SourceDiscovered,
	A2AURL:      discovered.A2AURL,
	Version:     discovered.Version,
})
```

Remove the `Scheme` and `TrustDomain` references from the discovery
config setup. Remove `--discovery-scheme` flag and its viper binding
(lines 40, 45). Remove `DiscoveryScheme` from Config struct (line 54).

- [ ] **Step 4: Build and verify**

```bash
go build ./agent-service/... && go build ./...
```

Expected: builds without errors.

- [ ] **Step 5: Commit**

```bash
git add pkg/a2abridge/discovery.go agent-service/cmd/serve.go go.mod go.sum
git commit -s -m "refactor(discovery): replace Deployment-label polling with AgentCard CR"
```

---

### Task 3: A2A client — accept message text for gateway mode

**Files:**

- Modify: `pkg/a2abridge/client.go`

- [ ] **Step 1: Add MessageText field to InvokeRequest**

Edit `pkg/a2abridge/client.go`. Add `MessageText` to `InvokeRequest`
and update `Invoke` to use it when set:

```go
type InvokeRequest struct {
	AgentURL      string
	Card          *a2a.AgentCard
	DocumentID    string // Legacy: used by Go agents
	MessageText   string // New: used by gateway mode (e.g., "Summarize s3://...")
	ReviewType    string
	BearerToken   string
	UserSPIFFEID  string
	AgentSPIFFEID string
}
```

In the `Invoke` method, change the message construction (around
line 46-58) to use `MessageText` when set:

```go
var msg *a2a.Message
if req.MessageText != "" {
	// Gateway mode: send plain text message
	msg = a2a.NewMessage(a2a.MessageRoleUser, a2a.TextPart{Text: req.MessageText})
} else {
	// Legacy mode: send structured DataPart
	data := map[string]any{
		"document_id": req.DocumentID,
	}
	if req.ReviewType != "" {
		data["review_type"] = req.ReviewType
	}
	msg = a2a.NewMessage(a2a.MessageRoleUser, &a2a.DataPart{Data: data})
}
```

- [ ] **Step 2: Build and verify**

```bash
go build ./...
```

Expected: builds without errors.

- [ ] **Step 3: Commit**

```bash
git add pkg/a2abridge/client.go
git commit -s -m "feat(a2abridge): add MessageText field for gateway-mode invocations"
```

---

### Task 4: Agent-service invoke — add action field and s3_url construction

**Files:**

- Modify: `agent-service/cmd/serve.go`

- [ ] **Step 1: Add Action field to InvokeRequest**

Edit `agent-service/cmd/serve.go`. Add `Action` to the `InvokeRequest`
struct (around line 497):

```go
type InvokeRequest struct {
	UserSPIFFEID    string   `json:"user_spiffe_id"`
	DocumentID      string   `json:"document_id"`
	Action          string   `json:"action,omitempty"` // "summarize", "review", etc.
	UserDepartments []string `json:"user_departments,omitempty"`
	ReviewType      string   `json:"review_type,omitempty"`
}
```

- [ ] **Step 2: Update handleInvoke to construct A2A message with s3_url**

In `handleInvoke` (around line 576), after authorization succeeds
and `accessResult` is available, extract `s3_url` from the document
metadata and construct the message text:

```go
// Extract s3_url from document metadata if available
var s3URL string
if doc, ok := accessResult.Document.(map[string]any); ok {
	if u, ok := doc["s3_url"].(string); ok {
		s3URL = u
	}
}

// Build A2A message text
action := req.Action
if action == "" {
	action = "summarize" // default action
}
// capitalize helper (strings.Title is deprecated)
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

messageText := ""
if s3URL != "" {
	messageText = fmt.Sprintf("%s %s", capitalize(action), s3URL)
} else {
	messageText = fmt.Sprintf("%s document %s", capitalize(action), req.DocumentID)
}

invokeResult, err := s.a2aClient.Invoke(ctx, &a2abridge.InvokeRequest{
	AgentURL:      agent.A2AURL,
	Card:          agent.AgentCard,
	DocumentID:    req.DocumentID,
	MessageText:   messageText,
	ReviewType:    req.ReviewType,
	BearerToken:   bearerToken,
	UserSPIFFEID:  req.UserSPIFFEID,
	AgentSPIFFEID: agent.SPIFFEID,
})
```

- [ ] **Step 3: Build and verify**

```bash
go build ./agent-service/...
```

Expected: builds without errors.

- [ ] **Step 4: Commit**

```bash
git add agent-service/cmd/serve.go
git commit -s -m "feat(agent-service): add action field and s3_url message construction"
```

---

### Task 5: Dashboard — remove direct summarizer/reviewer URLs

**Files:**

- Modify: `web-dashboard/cmd/serve.go`

- [ ] **Step 1: Remove summarizer/reviewer flags and config fields**

In `web-dashboard/cmd/serve.go`:

Remove lines 39-40 (flag declarations):

```go
serveCmd.Flags().String("summarizer-service-url", ...)
serveCmd.Flags().String("reviewer-service-url", ...)
```

Remove lines 49-50 (viper bindings):

```go
v.BindPFlag("summarizer_service_url", ...)
v.BindPFlag("reviewer_service_url", ...)
```

Remove from Config struct (lines 63-64):

```go
SummarizerServiceURL  string ...
ReviewerServiceURL    string ...
```

Remove defaults (lines 113-118):

```go
if cfg.SummarizerServiceURL == "" { ... }
if cfg.ReviewerServiceURL == "" { ... }
```

Remove from Dashboard struct (lines 75-76):

```go
summarizerServiceURL string
reviewerServiceURL   string
```

Remove from dashboard initializer (lines 157-158):

```go
summarizerServiceURL: cfg.SummarizerServiceURL,
reviewerServiceURL:   cfg.ReviewerServiceURL,
```

Remove from startup logs (lines 239-240):

```go
log.Info("Summarizer service", ...)
log.Info("Reviewer service", ...)
```

- [ ] **Step 2: Remove handleSummarize and handleReview handlers**

Delete the entire `handleSummarize` function (lines 983-1087) and
`handleReview` function (lines 1089-1195).

Remove the route registrations (lines 197-198):

```go
mux.HandleFunc("/api/summarize", dashboard.handleSummarize)
mux.HandleFunc("/api/review", dashboard.handleReview)
```

- [ ] **Step 3: Add handleInvoke handler**

Add a new handler that proxies invoke requests to agent-service:

```go
func (d *Dashboard) handleInvoke(w http.ResponseWriter, r *http.Request) {
	d.log.Info("Invoke request", "remote", r.RemoteAddr)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UserID     string `json:"user_id"`
		AgentID    string `json:"agent_id"`
		DocumentID string `json:"document_id"`
		Action     string `json:"action"`
		ReviewType string `json:"review_type,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.AgentID == "" || req.DocumentID == "" {
		http.Error(w, "agent_id and document_id required", http.StatusBadRequest)
		return
	}

	// Get user departments from session if OIDC enabled
	var userDepartments []string
	if d.oidcEnabled {
		if cookie, err := r.Cookie("session_id"); err == nil {
			if session := d.sessionStore.Get(cookie.Value); session != nil {
				userDepartments = session.Groups
			}
		}
	}

	userSPIFFEID := "spiffe://" + d.trustDomain + "/user/" + req.UserID

	d.broadcastLog(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Component: "DASHBOARD",
		Level:     "INFO",
		Message:   fmt.Sprintf("Invoking agent %s: action=%s, user=%s, doc=%s", req.AgentID, req.Action, req.UserID, req.DocumentID),
		Color:     "white",
	})

	// Build request for agent-service
	invokeReq := map[string]any{
		"user_spiffe_id": userSPIFFEID,
		"document_id":    req.DocumentID,
		"action":         req.Action,
	}
	if req.ReviewType != "" {
		invokeReq["review_type"] = req.ReviewType
	}
	if len(userDepartments) > 0 {
		invokeReq["user_departments"] = userDepartments
	}
	body, _ := json.Marshal(invokeReq)

	url := fmt.Sprintf("%s/agents/%s/invoke", d.agentServiceURL, req.AgentID)
	d.log.Info("Calling agent-service invoke", "url", url)
	outReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	outReq.Header.Set("Content-Type", "application/json")
	if token := d.getAccessToken(r); token != "" {
		outReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := d.httpClient.Do(outReq)
	if err != nil {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "ERROR",
			Message:   fmt.Sprintf("Agent invocation failed: %v", err),
			Color:     "red",
		})
		http.Error(w, "Request failed", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode == http.StatusForbidden || result["granted"] == false {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "WARN",
			Message:   fmt.Sprintf("Agent invocation DENIED: %v", result["reason"]),
			Color:     "red",
		})
	} else if result["granted"] == true {
		d.broadcastLog(LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Component: "DASHBOARD",
			Level:     "INFO",
			Message:   fmt.Sprintf("Agent %s completed %s successfully", req.AgentID, req.Action),
			Color:     "green",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(result)
}
```

Register the route (replace the two removed routes):

```go
mux.HandleFunc("/api/invoke", dashboard.handleInvoke)
```

- [ ] **Step 4: Update handleStatus to remove direct service checks**

In `handleStatus`, remove the `summarizer-service` and
`reviewer-service` entries from the `services` map (lines 724-725).

- [ ] **Step 5: Build and verify**

```bash
go build ./web-dashboard/...
```

Expected: builds without errors.

- [ ] **Step 6: Commit**

```bash
git add web-dashboard/cmd/serve.go
git commit -s -m "feat(dashboard): replace direct agent calls with unified /api/invoke"
```

---

### Task 6: Dashboard JavaScript — route through /api/invoke

**Files:**

- Modify: `web-dashboard/internal/assets/static/js/app.js`

- [ ] **Step 1: Update loadAgents to show name and description**

In `loadAgents` (around line 62), change the label from
`capabilities.join` to `description`:

```javascript
this.populateSelect('agent-select', this.agents, a => ({
    value: a.id,
    label: `${a.name}${a.description ? ' — ' + a.description : ''}`
}), true);
```

- [ ] **Step 2: Update handleSummarize to use /api/invoke**

Replace the `handleSummarize` method (around line 425):

```javascript
async handleSummarize() {
    const userId = document.getElementById('user-select')?.value;
    const agentSelect = document.getElementById('agent-select');
    const agentId = agentSelect?.value;
    const documentId = document.getElementById('document-select')?.value;

    if (!userId || userId === '__no_user__' || !documentId) {
        this.log('error', 'Please select a user and document for summarization');
        return;
    }

    if (!agentId) {
        this.log('error', 'Please select an agent for summarization');
        return;
    }

    this.log('info', `Initiating AI summarization: Agent=${agentId}, User=${userId}, Document=${documentId}`);
    this.showProcessingIndicator('Summarizing document with AI...', agentId);

    try {
        const response = await fetch('/api/invoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: agentId,
                user_id: userId,
                document_id: documentId,
                action: 'summarize'
            })
        });

        const result = await response.json();
        this.displayInvokeResult(result, 'summary');
    } catch (err) {
        this.log('error', `Summarization failed: ${err.message}`);
        this.hideProcessingIndicator();
    }
}
```

- [ ] **Step 3: Update handleReview to use /api/invoke**

Replace the `handleReview` method (around line 452):

```javascript
async handleReview() {
    const userId = document.getElementById('user-select')?.value;
    const agentSelect = document.getElementById('agent-select');
    const agentId = agentSelect?.value;
    const documentId = document.getElementById('document-select')?.value;

    if (!userId || userId === '__no_user__' || !documentId) {
        this.log('error', 'Please select a user and document for review');
        return;
    }

    if (!agentId) {
        this.log('error', 'Please select an agent for review');
        return;
    }

    const reviewType = 'general';

    this.log('info', `Initiating AI review (${reviewType}): Agent=${agentId}, User=${userId}, Document=${documentId}`);
    this.showProcessingIndicator('Reviewing document with AI...', agentId);

    try {
        const response = await fetch('/api/invoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                agent_id: agentId,
                user_id: userId,
                document_id: documentId,
                action: 'review',
                review_type: reviewType
            })
        });

        const result = await response.json();
        this.displayInvokeResult(result, 'review');
    } catch (err) {
        this.log('error', `Review failed: ${err.message}`);
        this.hideProcessingIndicator();
    }
}
```

- [ ] **Step 4: Update showProcessingIndicator**

Change the method to use the agent ID dynamically (around line 482):

```javascript
showProcessingIndicator(message, agentId) {
    const panel = document.getElementById('result-panel');
    if (!panel) return;

    const summarizeBtn = document.getElementById('summarize-btn');
    const reviewBtn = document.getElementById('review-btn');
    if (summarizeBtn) summarizeBtn.disabled = true;
    if (reviewBtn) reviewBtn.disabled = true;

    panel.className = 'result-panel-inline processing';
    panel.innerHTML = `
        <div class="processing-indicator">
            <div class="spinner"></div>
            <h4>${message}</h4>
            <p>Using agent: <strong>${agentId}</strong></p>
            <p class="processing-note">This may take 10-30 seconds depending on document size...</p>
        </div>
    `;
}
```

- [ ] **Step 5: Add displayInvokeResult method**

Add after `displayAIResult` (keep `displayAIResult` for now as
backward compat):

```javascript
displayInvokeResult(result, type) {
    this.hideProcessingIndicator();

    const panel = document.getElementById('result-panel');
    if (!panel) return;

    const isGranted = result.granted === true;
    panel.className = `result-panel-inline ${isGranted ? 'granted' : 'denied'}`;

    if (isGranted && result.result) {
        const htmlContent = this.markdownToHtml(result.result);
        panel.innerHTML = `
            <h4>${type === 'summary' ? 'Document Summary' : 'Document Review'}</h4>
            <p style="color: var(--rh-gray); font-size: 12px;">Agent: ${result.agent} | State: ${result.state || 'completed'}</p>
            <div class="ai-content">${htmlContent}</div>
        `;
    } else {
        panel.innerHTML = `
            <h4>${type === 'summary' ? 'Summarization' : 'Review'} Denied</h4>
            <p>${result.reason || 'Permission denied'}</p>
            <div class="alert alert-info" style="margin-top: 16px; margin-bottom: 0;">
                <strong>Zero Trust:</strong> Both user AND agent must have the required permissions.
            </div>
        `;
    }
}
```

- [ ] **Step 6: Update updateButtonStates**

Summarize and Review buttons should require an agent to be selected:

In `updateButtonStates` (around line 285), add after the delegateBtn
logic:

```javascript
const summarizeBtn = document.getElementById('summarize-btn');
const reviewBtn = document.getElementById('review-btn');
if (summarizeBtn) {
    summarizeBtn.disabled = !hasRealUser || !hasAgent;
}
if (reviewBtn) {
    reviewBtn.disabled = !hasRealUser || !hasAgent;
}
```

- [ ] **Step 7: Commit**

```bash
git add web-dashboard/internal/assets/static/js/app.js
git commit -s -m "feat(dashboard-js): route summarize/review through /api/invoke"
```

---

### Task 7: Dashboard HTML — unify AI actions with agent dropdown

**Files:**

- Modify: `web-dashboard/internal/assets/templates/index.html`

- [ ] **Step 1: Remove the separate AI Agent Actions section**

Remove lines 115-132 (the section divider, heading, helper text,
summarize/review buttons, and hardcoded capability note). Replace
with the buttons inline alongside delegate:

```html
                    <div class="action-row">
                        <button id="direct-access-btn" class="btn btn-primary">
                            Direct Access
                        </button>
                        <button id="delegate-btn" class="btn btn-success" disabled>
                            Delegate to Agent
                        </button>
                        <button id="summarize-btn" class="btn btn-info" disabled>
                            Summarize
                        </button>
                        <button id="review-btn" class="btn btn-warning" disabled>
                            Review
                        </button>
                    </div>
                    <small style="color: var(--rh-gray); font-size: 12px; margin-top: 8px; display: block;">
                        Select an agent to enable Delegate, Summarize, and Review actions.
                        Permissions are intersected at the OPA policy level.
                    </small>
```

- [ ] **Step 2: Build and verify**

```bash
go build ./web-dashboard/...
```

Expected: builds without errors (templates are embedded at compile
time).

- [ ] **Step 3: Commit**

```bash
git add web-dashboard/internal/assets/templates/index.html
git commit -s -m "feat(dashboard-html): unify AI actions with agent dropdown"
```

---

### Task 8: Run full lint and test suite

- [ ] **Step 1: Run Go linter**

```bash
make lint
```

Expected: no new lint errors (pre-existing `signedcard.go` issue OK).

- [ ] **Step 2: Run Go tests**

```bash
make test
```

Expected: all existing tests pass.

- [ ] **Step 3: Run Go vet**

```bash
make vet
```

Expected: no issues.

- [ ] **Step 4: Run OPA policy tests**

```bash
make test-policies
```

Expected: all 19 policy tests pass (no policy changes in this branch).

- [ ] **Step 5: Fix any issues and commit**

```bash
git add <fixed-files>
git commit -s -m "fix: address lint and test issues"
```

Only commit if fixes were needed.

---

### Task 9: Local development — static agents fallback

**Files:**

- Modify: `agent-service/cmd/serve.go`

- [ ] **Step 1: Add --static-agents flag**

Add a flag for loading agents from a JSON file (for local dev
without K8s):

```go
serveCmd.Flags().String("static-agents", "", "Path to JSON file with static agent definitions")
v.BindPFlag("static_agents", serveCmd.Flags().Lookup("static-agents"))
```

Add to Config struct:

```go
StaticAgents string `mapstructure:"static_agents"`
```

- [ ] **Step 2: Add loadStaticAgents helper**

Add after `runServe`:

```go
func loadStaticAgents(path string, agentStore *store.AgentStore, log *logger.Logger) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read static agents file: %w", err)
	}

	var agents []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		A2AURL      string `json:"a2a_url"`
	}
	if err := json.Unmarshal(data, &agents); err != nil {
		return fmt.Errorf("failed to parse static agents: %w", err)
	}

	for _, a := range agents {
		agentStore.Register(&store.Agent{
			ID:          a.ID,
			Name:        a.Name,
			Description: a.Description,
			Source:      store.SourceStatic,
			A2AURL:      a.A2AURL,
		})
		log.Info("Loaded static agent", "id", a.ID, "name", a.Name)
	}
	return nil
}
```

- [ ] **Step 3: Call loadStaticAgents in runServe**

Add after the store is created (after line 137), before the
discovery loop:

```go
if cfg.StaticAgents != "" {
	if err := loadStaticAgents(cfg.StaticAgents, svc.store, log); err != nil {
		return fmt.Errorf("failed to load static agents: %w", err)
	}
}
```

- [ ] **Step 4: Build and verify**

```bash
go build ./agent-service/...
```

Expected: builds without errors.

- [ ] **Step 5: Commit**

```bash
git add agent-service/cmd/serve.go
git commit -s -m "feat(agent-service): add --static-agents flag for local development"
```

---

### Task 10: Run final verification

- [ ] **Step 1: Build all services**

```bash
make build
```

Expected: all services build.

- [ ] **Step 2: Run full test suite**

```bash
make test && make test-policies && make lint && make vet
```

Expected: all pass.

- [ ] **Step 3: Smoke test locally (optional)**

```bash
# Start OPA
make run-opa &

# Start agent-service with a static agents file
echo '[{"id":"test-agent","name":"Test Agent","description":"Local test","a2a_url":"http://localhost:8000/a2a"}]' > /tmp/agents.json
./bin/agent-service serve --mock-spiffe --static-agents /tmp/agents.json &

# Verify agent list
curl http://localhost:8080/agents | jq .

# Clean up
kill %1 %2
```

Expected: agent-service starts with the test agent from the JSON file.
