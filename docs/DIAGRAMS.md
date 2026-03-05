# AuthBridge flow diagrams

These diagrams illustrate the token exchange and delegation mechanisms
demonstrated by the AuthBridge test suite (`scripts/test-authbridge.sh`).

Each diagram is provided in both ASCII and Mermaid formats.

## Direct token exchange (Tests 1-3)

Basic client_credentials → token exchange flow without any agent chain.

```text
┌──────────────┐     (1) client_credentials      ┌──────────────┐
│              │ ──────────────────────────────▶ │              │
│ agent-service│     token (aud: agent-service)  │   Keycloak   │
│              │ ◀────────────────────────────── │              │
│              │                                 │              │
│              │  (2) token exchange             │              │
│              │    (subject_token + audience=   │              │
│              │     document-service)           │              │
│              │ ──────────────────────────────▶ │              │
│              │     new token (aud:             │              │
│              │      document-service)          │              │
│              │ ◀────────────────────────────── │              │
└──────────────┘                                 └──────────────┘
```

```mermaid
sequenceDiagram
    participant AS as agent-service
    participant KC as Keycloak

    AS->>KC: (1) client_credentials grant
    KC-->>AS: token (aud: agent-service)

    AS->>KC: (2) token exchange<br/>(subject_token + audience=document-service)
    KC-->>AS: new token (aud: document-service)
```

## OPA permission intersection (Tests 4-5)

Why DOC-001 is allowed but DOC-004 is denied.

```text
         Alice                    GPT-4 Agent
    ┌─────────────┐          ┌─────────────────┐
    │ engineering │          │  engineering    │
    │ finance     │          │  finance        │
    └──────┬──────┘          └────────┬────────┘
           │                          │
           └──────────┬───────────────┘
                      ▼
              ┌───────────────┐
              │  Intersection │
              │ ───────────── │
              │ engineering ✓ │
              │ finance     ✓ │
              └───────┬───────┘
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
  ┌─────────────┐          ┌─────────────┐
  │   DOC-001   │          │   DOC-004   │
  │ engineering │          │     hr      │
  │             │          │             │
  │  GRANTED    │          │  DENIED     │
  └─────────────┘          └─────────────┘
```

```mermaid
graph TD
    A["Alice<br/>engineering, finance"] --> I["Intersection"]
    G["GPT-4 Agent<br/>engineering, finance"] --> I
    I --> EF["Effective permissions:<br/>engineering, finance"]
    EF --> D1["DOC-001<br/>requires: engineering"]
    EF --> D4["DOC-004<br/>requires: hr"]
    D1 --> R1["GRANTED"]
    D4 --> R4["DENIED"]

    style R1 fill:#2d6,stroke:#333,color:#fff
    style R4 fill:#d33,stroke:#333,color:#fff
```

## Agent capability restriction (Bob + Summarizer)

Why Bob is denied access to DOC-003 (Admin Policies) through the
Summarizer agent — even though Bob has admin permissions. The Summarizer
agent only has finance capabilities, so the intersection excludes admin.

```text
          Bob                    Summarizer Agent
    ┌─────────────┐          ┌─────────────────┐
    │ finance     │          │  finance        │
    │ admin       │          │                 │
    └──────┬──────┘          └────────┬────────┘
           │                          │
           └──────────┬───────────────┘
                      ▼
              ┌───────────────┐
              │  Intersection │
              │ ───────────── │
              │ finance     ✓ │
              │ admin       ✗ │
              └───────┬───────┘
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
  ┌─────────────┐          ┌─────────────┐
  │   DOC-002   │          │   DOC-003   │
  │   finance   │          │    admin    │
  │             │          │             │
  │  GRANTED    │          │  DENIED     │
  └─────────────┘          └─────────────┘

  Bob has finance,           Bob has admin, but
  Summarizer has finance     Summarizer does NOT
  -> intersection includes   -> intersection excludes
     finance                    admin
```

```mermaid
graph TD
    B["Bob<br/>finance, admin"] --> I["Intersection"]
    S["Summarizer Agent<br/>finance"] --> I
    I --> EF["Effective permissions:<br/>finance only"]
    EF --> D2["DOC-002 (Q4 Financial Report)<br/>requires: finance"]
    EF --> D3["DOC-003 (Admin Policies)<br/>requires: admin"]
    D2 --> R2["GRANTED"]
    D3 --> R3["DENIED"]

    style R2 fill:#2d6,stroke:#333,color:#fff
    style R3 fill:#d33,stroke:#333,color:#fff
    style S fill:#e85,stroke:#333,color:#fff
```

## AuthBridge sidecar architecture (Test 6)

What's inside each AI agent pod.

```text
┌─ summarizer-service Pod ─────────────────────────────────┐
│                                                          │
│  ┌─────────────────┐   ┌──────────────────────────────┐  │
│  │   proxy-init    │   │  SPIRE Agent (CSI socket)    │  │
│  │  (init: iptables│   └──────────┬───────────────────┘  │
│  │   redirect)     │              │                      │
│  └─────────────────┘              │ JWT SVID             │
│                                   ▼                      │
│  ┌─────────────────┐   ┌──────────────────┐              │
│  │  spiffe-helper  │──▶│ /opt/jwt_svid    │              │
│  │                 │   │     .token       │              │
│  └─────────────────┘   └────────┬─────────┘              │
│                                 │                        │
│  ┌─────────────────┐            │ SPIFFE ID              │
│  │    client-      │◀───────────┘                        │
│  │  registration   │──▶ Keycloak (register client)       │
│  │                 │──▶ /shared/client-id.txt            │
│  │                 │──▶ /shared/client-secret.txt        │
│  └─────────────────┘                                     │
│                                                          │
│  ┌─────────────────┐   ┌──────────────────┐              │
│  │  summarizer-    │   │   envoy-proxy    │              │
│  │  service        │   │                  │              │
│  │  (app code -    │──▶│ outbound:15123   │──▶ network   │
│  │   auth-unaware) │   │  (token exchange)│              │
│  └─────────────────┘   └──────────────────┘              │
│         ▲                        ▲                       │
│         │    iptables redirect   │                       │
│         └────────────────────────┘                       │
└──────────────────────────────────────────────────────────┘
```

```mermaid
graph TD
    subgraph Pod["summarizer-service Pod"]
        PI["proxy-init<br/>(init: iptables redirect)"]

        SPIRE["SPIRE Agent<br/>(CSI socket)"]
        SH["spiffe-helper"]
        SVID["/opt/jwt_svid.token"]
        CR["client-registration"]
        SHARED["/shared/<br/>client-id.txt<br/>client-secret.txt"]

        APP["summarizer-service<br/>(auth-unaware app code)"]
        ENVOY["envoy-proxy<br/>:15123 outbound<br/>(token exchange)"]

        SPIRE -->|JWT SVID| SH
        SH --> SVID
        SVID -->|SPIFFE ID| CR
        CR -->|register| KC
        CR --> SHARED

        APP -->|"iptables redirect"| ENVOY
    end

    KC["Keycloak"]
    NET["Network"]
    ENVOY --> NET

    style APP fill:#69b,stroke:#333,color:#fff
    style ENVOY fill:#e85,stroke:#333,color:#fff
```

## A2A delegation flow end-to-end (Tests 8, 10, 12)

The full chain with header/token transformation at each hop.

```text
 User: Alice                    Agent: Summarizer
 Depts: engineering, finance    Caps: finance

 ┌────────────┐  POST /agents/summarizer/invoke
 │   agent-   │  + Bearer token
 │  service   │  + body: {doc: DOC-002, user: alice}
 └─────┬──────┘
       │
       │ A2A call with CallMeta headers:
       │   Authorization: Bearer <agent-svc-token>
       │   X-Delegation-User: spiffe://.../user/alice
       │   X-Delegation-Agent: spiffe://.../agent/summarizer
       ▼
 ┌────────────────────────────────────────────────┐
 │         summarizer-service Pod                 │
 │                                                │
 │  ┌──────────────┐                              │
 │  │ summarizer   │  GET /documents/DOC-002      │
 │  │ (auth-       │  + X-Delegation-User (from   │
 │  │  unaware)    │    context, via Transport)   │
 │  │              │  + X-Delegation-Agent        │
 │  └──────┬───────┘                              │
 │         │ iptables ──────────────┐             │
 │         ▼                       ▼              │
 │  ┌──────────────────────────────────────┐      │
 │  │          envoy ext-proc              │      │
 │  │                                      │      │
 │  │  1. Reads X-Delegation-* headers     │      │
 │  │  2. Exchanges token:                 │      │
 │  │     sub: <UUID> (unchanged)          │      │
 │  │     azp: .../agent/summarizer        │      │
 │  │     aud: agent-svc -> document-svc   │      │
 │  │  3. Replaces Authorization header    │      │
 │  │  4. Passes X-Delegation-* through    │      │
 │  └──────────────────┬───────────────────┘      │
 │                     │                          │
 └─────────────────────┼──────────────────────────┘
                       │
                       ▼
 ┌─────────────────────────────────────────┐
 │         document-service                │
 │                                         │
 │  1. Validates JWT (aud=document-service)│
 │  2. sub is UUID, not SPIFFE ID          │
 │     -> falls back to X-Delegation-*     │
 │  3. Calls OPA with:                     │
 │     user:  spiffe://.../user/alice      │
 │     agent: spiffe://.../agent/summarizer│
 │  4. OPA: alice ^ summarizer = {finance} │
 │     DOC-002 needs finance -> GRANTED    │
 └─────────────────────────────────────────┘
```

```mermaid
sequenceDiagram
    participant AS as agent-service
    participant SUM as summarizer<br/>(auth-unaware)
    participant ENV as envoy ext-proc<br/>(sidecar)
    participant KC as Keycloak
    participant DS as document-service
    participant OPA as OPA

    Note over AS: User: Alice (engineering, finance)<br/>Agent: Summarizer (finance)

    AS->>SUM: A2A invoke DOC-002<br/>+ Authorization: Bearer token<br/>+ X-Delegation-User: .../user/alice<br/>+ X-Delegation-Agent: .../agent/summarizer

    SUM->>ENV: GET /documents/DOC-002<br/>+ X-Delegation-User (from context)<br/>+ X-Delegation-Agent<br/>(iptables redirect)

    ENV->>KC: Token exchange<br/>(audience=document-service)
    KC-->>ENV: New JWT (aud: document-service)

    ENV->>DS: GET /documents/DOC-002<br/>+ Authorization: Bearer (exchanged)<br/>+ X-Delegation-User: .../user/alice<br/>+ X-Delegation-Agent: .../agent/summarizer

    DS->>DS: JWT sub is UUID, not SPIFFE ID<br/>Falls back to X-Delegation-* headers

    DS->>OPA: Check policy<br/>user=alice, agent=summarizer, doc=DOC-002
    OPA-->>DS: alice ∩ summarizer = {finance}<br/>DOC-002 needs finance → GRANTED

    DS-->>ENV: 200 OK + document content
    ENV-->>SUM: 200 OK
    SUM-->>AS: A2A result (summary text)
```

## Token claim transformation (Test 12)

Before/after view of the token exchange.

```text
        BEFORE exchange                    AFTER exchange
   (summarizer's own token)          (for document-service)
 ┌─────────────────────────┐     ┌─────────────────────────┐
 │                         │     │                         │
 │ sub: 55fc5e1e-e6fd-...  │ --> │ sub: 55fc5e1e-e6fd-...  │  same
 │                         │     │                         │
 │ azp: spiffe://...       │ --> │ azp: spiffe://...       │  same
 │      /agent/summarizer  │     │      /agent/summarizer  │
 │                         │     │                         │
 │ aud: agent-service,     │     │ aud: document-service   │  CHANGED
 │      user-service       │     │                         │
 │                         │     │                         │
 └─────────────────────────┘     └─────────────────────────┘

    Token identifies WHO              Token identifies WHO
    (summarizer) and its              (same) but grants access
    original audiences                to document-service

 ┌──────────────────────────────────────────────────────────┐
 │  Delegation travels ALONGSIDE the token, not inside it:  │
 │    X-Delegation-User:  spiffe://.../user/alice           │
 │    X-Delegation-Agent: spiffe://.../agent/summarizer     │
 └──────────────────────────────────────────────────────────┘
```

```mermaid
graph LR
    subgraph Before["BEFORE exchange<br/>(summarizer's own token)"]
        B_SUB["sub: 55fc5e1e-e6fd-..."]
        B_AZP["azp: .../agent/summarizer"]
        B_AUD["aud: agent-service,<br/>user-service"]
    end

    subgraph After["AFTER exchange<br/>(for document-service)"]
        A_SUB["sub: 55fc5e1e-e6fd-..."]
        A_AZP["azp: .../agent/summarizer"]
        A_AUD["aud: document-service"]
    end

    B_SUB -->|same| A_SUB
    B_AZP -->|same| A_AZP
    B_AUD -->|"CHANGED"| A_AUD

    subgraph Headers["Delegation headers (separate from JWT)"]
        H1["X-Delegation-User: .../user/alice"]
        H2["X-Delegation-Agent: .../agent/summarizer"]
    end

    style A_AUD fill:#e85,stroke:#333,color:#fff
    style B_AUD fill:#69b,stroke:#333,color:#fff
    style Headers fill:#feb,stroke:#333
```

## What the agent code sees vs what actually happens

The "zero trust invisible" point — agent code is auth-unaware.

```text
  What the summarizer code does:        What actually happens:
 ┌──────────────────────────┐    ┌────────────────────────────────┐
 │                          │    │                                │
 │  doc, err := http.Get(   │    │  1. DelegationTransport adds   │
 │    docServiceURL +       │    │    X-Delegation-User header    │
 │    "/documents/DOC-002") │    │    X-Delegation-Agent header   │
 │                          │    │                                │
 │  // That's it.           │    │  2. iptables redirects to      │
 │  // No tokens.           │    │    envoy :15123                │
 │  // No auth headers.     │    │                                │
 │  // No SPIFFE.           │    │  3. ext-proc exchanges token   │
 │  // No delegation.       │    │    (client_credentials ->      │
 │                          │    │     document-service audience) │
 │                          │    │                                │
 │                          │    │  4. Request arrives at         │
 │                          │    │    document-service with:      │
 │                          │    │    - Valid JWT                 │
 │                          │    │    - Delegation headers        │
 │                          │    │    - OPA evaluates policy      │
 └──────────────────────────┘    └────────────────────────────────┘

         3 lines of Go               4 infrastructure layers
```

```mermaid
graph TD
    subgraph App["What the agent code does<br/>(3 lines of Go)"]
        CODE["doc, err := http.Get(<br/>docServiceURL +<br/>&quot;/documents/DOC-002&quot;)<br/><br/>// No tokens<br/>// No auth headers<br/>// No SPIFFE<br/>// No delegation"]
    end

    subgraph Infra["What actually happens<br/>(4 infrastructure layers)"]
        L1["1. DelegationTransport<br/>adds X-Delegation-* headers"]
        L2["2. iptables redirects<br/>to envoy :15123"]
        L3["3. ext-proc exchanges token<br/>(audience=document-service)"]
        L4["4. Request arrives with:<br/>Valid JWT + Delegation headers<br/>OPA evaluates policy"]

        L1 --> L2 --> L3 --> L4
    end

    CODE -.->|"invisible to app"| L1

    style App fill:#69b,stroke:#333,color:#fff
    style CODE fill:#69b,stroke:#333,color:#fff
    style Infra fill:#feb,stroke:#333
```
