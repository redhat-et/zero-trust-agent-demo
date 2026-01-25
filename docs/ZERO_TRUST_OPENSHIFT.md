# Zero Trust security for agentic AI on OpenShift

**OpenShift provides a strong foundation for Zero Trust agentic AI deployments through native SPIFFE/SPIRE support, Red Hat Advanced Cluster Security, and a rich ecosystem of CNCF tools.** The convergence of Zero Trust architecture with agentic AI introduces new challenges—AI agents operate at machine speed, authenticate hundreds of times per second, and communicate via emerging protocols like MCP and A2A that require purpose-built security controls. Organizations deploying AI agents on OpenShift should implement a layered approach: workload identity via SPIFFE/SPIRE, service mesh encryption with OpenShift Service Mesh's Ambient mode, policy enforcement through OPA or Kyverno, and dedicated AI/MCP gateways like Envoy AI Gateway or LiteLLM for agent-specific traffic management.

---

## Core Zero Trust principles align directly with AI agent security needs

Zero Trust's foundational principle—**"never trust, always verify"**—becomes even more critical for autonomous AI agents that can take actions without human oversight. NIST SP 800-207, published in August 2020, defines seven tenets that form the architectural basis: all data sources are resources, all communication is secured regardless of network location, access is per-session and dynamically determined, and continuous monitoring improves security posture. The Policy Decision Point (PDP), Policy Administrator (PA), and Policy Enforcement Point (PEP) form the core logical components where access decisions are made, executed, and enforced.

CISA's Zero Trust Maturity Model version 2.0 (April 2023) organizes implementation around **five pillars**: Identity, Devices, Networks, Applications/Workloads, and Data, with three cross-cutting capabilities (Visibility & Analytics, Automation & Orchestration, Governance). For AI workloads, the Applications & Workloads pillar is particularly relevant, encompassing DevSecOps integration, secure application delivery, and application-specific threat protections. Organizations progress through four maturity levels—Traditional, Initial, Advanced, and Optimal—with the Optimal level requiring fully automated attribute assignment, dynamic policies, and real-time risk analytics.

NIST SP 800-207A (September 2023) specifically addresses cloud-native environments, emphasizing a critical paradigm shift: security controls must move from network parameters to **identity-based policies** enforceable regardless of service location. This document explicitly references SPIFFE for workload identity and service mesh implementations for policy enforcement—both available natively on OpenShift.

---

## Agentic AI introduces unique security challenges MCP and A2A protocols are racing to address

Two protocols now dominate the agentic AI communication landscape: Anthropic's **Model Context Protocol (MCP)** for agent-to-tool communication and Google's **Agent-to-Agent (A2A)** protocol for multi-agent collaboration. MCP, donated to the Linux Foundation's Agentic AI Foundation in December 2025, standardizes how AI systems integrate with external data sources and tools using JSON-RPC 2.0 over various transports (stdio, HTTP+SSE, Streamable HTTP). The A2A protocol, announced at Google Cloud Next in April 2025 with support from **150+ organizations**, enables agents to discover capabilities, delegate tasks, and coordinate work.

Security researchers have identified critical vulnerabilities in both ecosystems:

- **Prompt injection**: Malicious instructions in tool responses manipulate agent behavior
- **Tool poisoning**: Compromised tool metadata exfiltrates data silently
- **Token exposure**: OAuth tokens and API keys logged or stored insecurely
- **Privilege escalation**: High-privilege servers acting on low-privilege user requests

MCP's security model requires explicit user consent for data access, treats tool descriptions as untrusted, and mandates approval before tool invocation. A2A implements **Agent Cards**—cryptographically signable JSON metadata documents declaring identity, capabilities, and authentication requirements—supporting OAuth 2.0, mTLS, OpenID Connect, and API keys.

Neither protocol is secure by default. Zero Trust implementation for MCP requires TLS 1.2+, mutual TLS for known clients, per-tool least-privilege access, token validation on every request, and audit logging with correlation IDs. For A2A, organizations must validate Agent Card signatures, enforce task-level authorization, and scope task access per authenticated client.

---

## Framework security gaps require custom implementation

LangChain/LangGraph, CrewAI, and AutoGen—the dominant agentic AI frameworks—provide minimal built-in security. LangGraph Platform offers custom authentication handlers via decorators and resource-level RBAC, but developers must implement JWT validation, token management, and authorization logic themselves. CrewAI and AutoGen provide no native authentication framework; enterprise deployments require external authentication layers.

| Framework | Built-in Auth | Authorization | Audit Logging |
|-----------|--------------|---------------|---------------|
| LangGraph | Custom handlers | Resource-level RBAC | Via LangSmith |
| CrewAI | None | Manual | Manual |
| AutoGen | None | Manual | Manual |

The OWASP Top 10 for Agentic Applications (December 2025) identifies **Agent Goal Hijack** (ASI01), **Tool Misuse** (ASI02), and **Identity & Privilege Abuse** (ASI03) as the top three risks. Practical mitigation requires implementing centralized secrets management (HashiCorp Vault), PKI for agent identities, SIEM integration, and human-in-the-loop for sensitive operations.

---

## CNCF provides the building blocks for Zero Trust Kubernetes deployments

The Cloud Native Computing Foundation has graduated multiple projects essential for Zero Trust implementation on Kubernetes and OpenShift:

**SPIFFE/SPIRE** (graduated 2018) provides the identity foundation. SPIFFE defines a standardized workload identity format (`spiffe://<trust-domain>/<workload-identifier>`) with SPIFFE Verifiable Identity Documents (SVIDs)—short-lived X.509 certificates or JWTs. SPIRE automates issuance, attestation, and rotation, solving the "Secret Zero" problem by bootstrapping identity from the environment without static credentials.

**Service meshes** provide mTLS and policy enforcement:
- **Istio** (graduated 2022): NIST reference architecture, comprehensive authorization policies, FIPS-compliant implementations via Tetrate
- **Linkerd** (graduated 2017): Zero-config mTLS, Rust-based micro-proxy, **5-10% performance overhead** (lowest among meshes)
- **Cilium** (graduated 2021): eBPF-powered enforcement with Layer 7 visibility without sidecars, WireGuard encryption

**Policy engines** enforce Zero Trust policies at the Kubernetes API level:
- **OPA/Gatekeeper** (graduated 2018): Policy Decision Point using Rego language, extensive constraint templates
- **Kyverno** (incubating 2020): Kubernetes-native YAML policies, image signature verification via Sigstore integration

| Layer | Recommended CNCF Project | Zero Trust Role |
|-------|-------------------------|-----------------|
| Identity | SPIFFE/SPIRE | Workload identity, mTLS foundation |
| Network | Cilium | eBPF microsegmentation, L3-L7 policies |
| Encryption | Istio/Linkerd | Service mesh mTLS |
| Policy | Kyverno or OPA | Admission control, supply chain verification |
| Supply Chain | Sigstore (OpenSSF) | Image signing, transparency logs |

---

## Red Hat OpenShift delivers enterprise Zero Trust through native integration

Red Hat positions OpenShift Platform Plus as a **"zero trust-aligned foundation"** aligned with OMB M-22-09 requirements. The platform provides multiple layers of native security:

**Security Context Constraints (SCCs)** enforce pod-level least privilege. The default `restricted` SCC requires non-root execution, drops capabilities (KILL, MKNOD, SYS_CHROOT, SETUID, SETGID), and enforces SELinux. OpenShift 4.11+ includes `restricted-v2` for Pod Security Standards compliance.

**Network Policies** via OVN-Kubernetes implement microsegmentation. IPsec provides transparent pod-to-pod encryption, and Admin Network Policy (ANP) enables cluster-wide enforcement.

**OpenShift Service Mesh 3.2** (GA) introduces **Istio Ambient mode** with ztunnel—a Rust-based, per-node Layer 4 proxy that provides mTLS by default with **90%+ memory reduction** and **50%+ CPU reduction** compared to sidecar architecture. Waypoint proxies add optional Layer 7 capabilities.

**Zero Trust Workload Identity Manager** (Tech Preview, OpenShift 4.18+) deploys SPIRE via an operator, providing SPIRE Server, Agent (DaemonSet), SPIFFE CSI Driver, and OIDC Discovery Provider. This enables dynamic, short-lived cryptographic identities that replace static secrets.

**Red Hat Advanced Cluster Security** (StackRox) provides:
- Network policy generation via `roxctl netpol generate`
- 100+ built-in policies based on CIS Benchmarks and NIST guidelines
- Scanner V4 for unified vulnerability management
- Cosign signature verification at runtime

---

## Gateway architectures must layer Zero Trust, AI, and MCP capabilities

Modern agentic AI deployments require three gateway types working in concert:

**Zero Trust Network Access (ZTNA) gateways** replace VPNs with continuous verification and per-application access. Unlike VPNs that grant broad network access after authentication, ZTNA enforces identity-based policies, device posture checks, and context-aware authorization on every request.

**AI gateways** extend API gateways with LLM-specific capabilities: **token-based rate limiting** (versus request-based), multi-provider routing with failover, cost tracking per team/project, and content safety filtering. Envoy AI Gateway (CNCF) provides a two-tier architecture—centralized authentication at Tier 1, fine-grained model control at Tier 2—with native support for OpenAI, Anthropic, AWS Bedrock, and Azure OpenAI.

**MCP gateways** manage agent-tool communication. IBM ContextForge provides the most comprehensive open source implementation: protocol version selection, federation via mDNS/Redis, REST-to-MCP virtualization, and OpenTelemetry observability. Docker MCP Gateway orchestrates MCP servers in isolated containers with lifecycle management and credential injection.

**Recommended open source stack for OpenShift:**

| Function | Project | Key Capability |
|----------|---------|----------------|
| Primary Gateway | Envoy Gateway + AI Extension | Gateway API, AI/MCP support, FIPS via Tetrate |
| LLM Management | LiteLLM | 100+ providers, virtual keys, spend tracking |
| MCP Gateway | ContextForge or Envoy AI Gateway | Federation, REST virtualization |
| Service Mesh | OpenShift Service Mesh 3.2 | Ambient mode mTLS |

The integration pattern layers these capabilities: ZTNA for identity verification and device posture at the edge, AI Gateway for token management and cost control, MCP Gateway for tool access governance, and service mesh for internal encryption.

---

## Best practices for implementing Zero Trust in containerized AI agent environments

**Start with identity as the foundation.** Deploy SPIFFE/SPIRE via OpenShift's Zero Trust Workload Identity Manager to provide cryptographic identities for all AI agents and services. Configure workload attestation using Kubernetes labels, service accounts, and container image hashes.

**Implement default-deny networking.** Begin with deny-all network policies, then explicitly allow required traffic paths. Use RHACS to analyze existing traffic patterns and generate least-privilege policies automatically. Enable IPsec or WireGuard for pod-to-pod encryption.

**Enable mTLS everywhere.** Deploy OpenShift Service Mesh with `STRICT` PeerAuthentication mode. For greenfield deployments, use Ambient mode for reduced overhead; for existing applications, traditional sidecar mode provides immediate encryption without code changes.

**Enforce supply chain security.** Sign all container images using Red Hat Trusted Artifact Signer (enterprise Sigstore). Configure Kyverno or RHACS admission policies to block unsigned images. Store signatures in Rekor transparency logs for audit.

**Secure AI-specific communication.** For MCP:
- Run MCP servers in isolated, sandboxed environments
- Implement OAuth 2.1 with PKCE for client flows
- Use short-lived, scoped tokens bound to specific operations
- Log all tool invocations with correlation IDs

For A2A:
- Validate Agent Card cryptographic signatures
- Enforce task-level authorization
- Require TLS 1.2+ with mTLS for high-trust agent pairs
- Implement anomaly detection for agent behavior

**Apply policy-as-code governance.** Use Kyverno for Kubernetes-native policies or OPA/Gatekeeper for complex Rego-based rules. Implement CI/CD policy checks to prevent policy violations before deployment.

**Enable comprehensive observability.** Integrate Hubble (Cilium) for network flow visibility, LangSmith for agent tracing, and OpenTelemetry for distributed tracing across gateways and services. Feed logs to SIEM for security event correlation.

---

## Conclusion

Deploying secure agentic AI on OpenShift requires treating AI agents as first-class security principals with unique requirements—machine-speed authentication, agent-to-agent trust, and tool access governance. The combination of CNCF projects (SPIFFE/SPIRE, Cilium, Kyverno) with Red Hat's integrated offerings (RHACS, Service Mesh, ZTWIM) provides a complete Zero Trust foundation.

The critical insight is that MCP and A2A protocols are not secure by default; organizations must implement defense-in-depth with dedicated gateways, continuous verification, and behavioral monitoring. As the CNCF's October 2025 guidance states: "Securing AI on Kubernetes does not require reinventing the wheel—it involves applying well-known security best practices from the cloud-native ecosystem using a purpose-built toolset." The purpose-built toolset now exists; the implementation path is clear.