// SPIFFE/SPIRE Zero Trust Demo - Dashboard Application

class Dashboard {
    constructor() {
        this.users = [];
        this.agents = [];
        this.documents = [];
        this.eventSource = null;
        this.consoleElement = null;

        this.init();
    }

    async init() {
        this.consoleElement = document.getElementById('console');

        // Load initial data
        await Promise.all([
            this.loadUsers(),
            this.loadAgents(),
            this.loadDocuments()
        ]);

        // Connect to SSE for real-time updates
        this.connectSSE();

        // Check service status
        this.checkStatus();
        setInterval(() => this.checkStatus(), 30000);

        // Setup event listeners
        this.setupEventListeners();

        this.log('info', 'Dashboard initialized');
    }

    async loadUsers() {
        try {
            const response = await fetch('/api/users');
            if (response.ok) {
                this.users = await response.json();
                // Only populate if user-select is a <select> element (not hidden input in OIDC mode)
                const userSelect = document.getElementById('user-select');
                if (userSelect && userSelect.tagName === 'SELECT') {
                    this.populateSelect('user-select', this.users, u => ({
                        value: u.id,
                        label: `${u.name} (${u.departments.join(', ')})`
                    }), false, true);  // addNone=false, addNoUser=true
                }
                this.log('success', `Loaded ${this.users.length} users`);
            }
        } catch (err) {
            this.log('error', `Failed to load users: ${err.message}`);
        }
    }

    async loadAgents() {
        try {
            const response = await fetch('/api/agents');
            if (response.ok) {
                this.agents = await response.json();
                this.populateSelect('agent-select', this.agents, a => ({
                    value: a.id,
                    label: `${a.name} (${a.capabilities.join(', ')})`
                }), true);
                this.log('success', `Loaded ${this.agents.length} agents`);
            }
        } catch (err) {
            this.log('error', `Failed to load agents: ${err.message}`);
        }
    }

    async loadDocuments() {
        try {
            const response = await fetch('/api/documents');
            if (response.ok) {
                this.documents = await response.json();
                this.populateSelect('document-select', this.documents, d => {
                    const dept = d.required_department || (d.required_departments || []).join(', ') || 'public';
                    return {
                        value: d.id,
                        label: `${d.title} [${dept}]`
                    };
                });
                this.renderDocumentList();
                this.log('success', `Loaded ${this.documents.length} documents`);
            }
        } catch (err) {
            this.log('error', `Failed to load documents: ${err.message}`);
        }
    }

    populateSelect(id, items, mapper, addNone = false, addNoUser = false) {
        const select = document.getElementById(id);
        if (!select) return;

        select.innerHTML = '';

        if (addNone) {
            const option = document.createElement('option');
            option.value = '';
            option.textContent = '(None - Direct Access)';
            select.appendChild(option);
        }

        if (addNoUser) {
            const option = document.createElement('option');
            option.value = '__no_user__';
            option.textContent = '(No User - Agent Only)';
            select.appendChild(option);
        }

        items.forEach(item => {
            const mapped = mapper(item);
            const option = document.createElement('option');
            option.value = mapped.value;
            option.textContent = mapped.label;
            select.appendChild(option);
        });
    }

    renderDocumentList() {
        const container = document.getElementById('document-list');
        if (!container) return;

        container.innerHTML = this.documents.map(doc => {
            const dept = doc.required_department || (doc.required_departments || []).join(', ') || 'public';
            return `
                <div class="document-card">
                    <div class="title">${doc.title}</div>
                    <div class="meta">
                        <span class="spiffe-id">${doc.id}</span>
                        <span class="badge badge-${this.getSensitivityClass(doc.sensitivity)}">${doc.sensitivity}</span>
                    </div>
                    <div class="meta">Required: ${dept}</div>
                </div>
            `;
        }).join('');
    }

    getSensitivityClass(sensitivity) {
        switch (sensitivity) {
            case 'critical': return 'danger';
            case 'high': return 'warning';
            case 'medium': return 'info';
            default: return 'success';
        }
    }

    connectSSE() {
        // Close existing connection if any
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }

        this.eventSource = new EventSource('/events');

        this.eventSource.onopen = () => {
            this.updateConnectionStatus(true);
            console.log('SSE connection established');
        };

        this.eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.type === 'log') {
                    this.addLogEntry(data.log);
                }
            } catch (err) {
                console.error('Failed to parse SSE message:', err);
            }
        };

        this.eventSource.onerror = (err) => {
            console.error('SSE error:', err);
            this.updateConnectionStatus(false);
            // Close the errored connection before reconnecting
            if (this.eventSource) {
                this.eventSource.close();
                this.eventSource = null;
            }
            setTimeout(() => this.connectSSE(), 5000);
        };
    }

    updateConnectionStatus(connected) {
        const status = document.getElementById('connection-status');
        if (status) {
            status.className = `status-dot ${connected ? 'healthy' : 'offline'}`;
            status.title = connected ? 'Connected' : 'Disconnected';
        }
    }

    addLogEntry(entry) {
        if (!this.consoleElement) return;

        const div = document.createElement('div');
        div.className = `console-entry ${entry.level.toLowerCase()}`;

        const timestamp = new Date(entry.timestamp).toLocaleTimeString();
        div.textContent = `[${timestamp}] [${entry.component}] ${entry.message}`;

        this.consoleElement.appendChild(div);
        this.consoleElement.scrollTop = this.consoleElement.scrollHeight;
    }

    log(level, message) {
        this.addLogEntry({
            timestamp: new Date().toISOString(),
            component: 'DASHBOARD',
            level: level.toUpperCase(),
            message
        });
    }

    async checkStatus() {
        try {
            const response = await fetch('/api/status');
            if (response.ok) {
                const status = await response.json();
                this.updateServiceStatus(status.services);
            }
        } catch (err) {
            console.error('Failed to check status:', err);
        }
    }

    updateServiceStatus(services) {
        for (const [name, status] of Object.entries(services)) {
            const element = document.getElementById(`status-${name}`);
            if (element) {
                element.className = `status-dot ${status === 'healthy' ? 'healthy' : 'offline'}`;
                element.title = status;
            }
        }
    }

    setupEventListeners() {
        // Direct access button
        const directBtn = document.getElementById('direct-access-btn');
        if (directBtn) {
            directBtn.addEventListener('click', () => this.handleDirectAccess());
        }

        // Delegated access button
        const delegateBtn = document.getElementById('delegate-btn');
        if (delegateBtn) {
            delegateBtn.addEventListener('click', () => this.handleDelegatedAccess());
        }

        // Clear console button
        const clearBtn = document.getElementById('clear-console-btn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearConsole());
        }

        // Agent select change
        const agentSelect = document.getElementById('agent-select');
        if (agentSelect) {
            agentSelect.addEventListener('change', () => this.updateButtonStates());
        }

        // User select change
        const userSelect = document.getElementById('user-select');
        if (userSelect) {
            userSelect.addEventListener('change', () => this.updateButtonStates());
        }

        this.updateButtonStates();
    }

    updateButtonStates() {
        const userSelect = document.getElementById('user-select');
        const agentSelect = document.getElementById('agent-select');
        const directBtn = document.getElementById('direct-access-btn');
        const delegateBtn = document.getElementById('delegate-btn');

        const userId = userSelect?.value;
        const agentId = agentSelect?.value;
        const isNoUser = userId === '__no_user__';
        // In OIDC mode, user-select is a hidden input with the logged-in user
        const isOIDCMode = userSelect && userSelect.tagName === 'INPUT';
        const hasRealUser = userId && !isNoUser;
        const hasAgent = agentId && agentId !== '';

        if (directBtn) {
            // Direct access only when real user selected and no agent
            directBtn.disabled = !hasRealUser || hasAgent;
        }
        if (delegateBtn) {
            // In OIDC mode, we always delegate with the logged-in user
            if (isOIDCMode) {
                delegateBtn.disabled = !hasAgent;
                delegateBtn.textContent = 'Delegate to Agent';
            } else {
                // Delegate/Agent access when agent is selected
                delegateBtn.disabled = !hasAgent;
                // Update button text based on user selection
                if (isNoUser && hasAgent) {
                    delegateBtn.textContent = 'Agent Access (No User)';
                } else {
                    delegateBtn.textContent = 'Delegate to Agent';
                }
            }
        }
    }

    async handleDirectAccess() {
        const userId = document.getElementById('user-select')?.value;
        const documentId = document.getElementById('document-select')?.value;

        if (!userId || !documentId) {
            this.log('error', 'Please select a user and document');
            return;
        }

        this.log('info', `Initiating direct access: User=${userId}, Document=${documentId}`);

        try {
            const response = await fetch('/api/access-direct', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, document_id: documentId })
            });

            const result = await response.json();
            this.displayResult(result, response.ok);
        } catch (err) {
            this.log('error', `Request failed: ${err.message}`);
        }
    }

    async handleDelegatedAccess() {
        const userId = document.getElementById('user-select')?.value;
        const agentId = document.getElementById('agent-select')?.value;
        const documentId = document.getElementById('document-select')?.value;

        if (!agentId || !documentId) {
            this.log('error', 'Please select an agent and document');
            return;
        }

        const isNoUser = userId === '__no_user__';

        if (isNoUser) {
            this.log('warn', `Agent ${agentId} attempting access WITHOUT user delegation: Document=${documentId}`);
        } else if (!userId) {
            this.log('error', 'Please select a user or "No User" option');
            return;
        } else {
            this.log('info', `Initiating delegated access: User=${userId} -> Agent=${agentId}, Document=${documentId}`);
        }

        try {
            const requestBody = {
                agent_id: agentId,
                document_id: documentId
            };
            // Only include user_id if a real user is selected
            if (!isNoUser && userId) {
                requestBody.user_id = userId;
            }

            const response = await fetch('/api/access-delegated', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });

            const result = await response.json();
            this.displayResult(result, response.ok);
        } catch (err) {
            this.log('error', `Request failed: ${err.message}`);
        }
    }

    displayResult(result, success) {
        const panel = document.getElementById('result-panel');
        if (!panel) return;

        panel.className = `result-panel-inline ${success ? 'granted' : 'denied'}`;

        if (success && result.granted) {
            panel.innerHTML = `
                <h4>Access Granted</h4>
                <p>${result.reason}</p>
                ${result.document ? `
                    <div class="document-content">
                        <strong>${result.document.title}</strong>
                        <div style="margin-top: 8px;">${result.document.content || 'Document content available'}</div>
                    </div>
                ` : ''}
            `;
        } else {
            panel.innerHTML = `
                <h4>Access Denied</h4>
                <p>${result.reason || result.error || 'Permission denied'}</p>
                <div class="alert alert-info" style="margin-top: 16px; margin-bottom: 0;">
                    <strong>Zero Trust:</strong> Both user AND agent must have the required permissions.
                </div>
            `;
        }
    }

    clearConsole() {
        if (this.consoleElement) {
            this.consoleElement.innerHTML = '';
            this.log('info', 'Console cleared');
        }
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new Dashboard();
});
