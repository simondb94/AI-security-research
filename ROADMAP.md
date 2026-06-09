# Roadmap

Planned research areas and upcoming content for this repository.

This roadmap reflects the threat landscape as of June 2026 and is ordered by urgency and strategic value. It will be updated as priorities shift.

---

## Near-term (Q3 2026)

### MCP Security Deep Dive
A dedicated file expanding the MCP coverage now split across `Agentic-AI-Threats.md` and `AI-Coding-Agent-Security.md`:
* MCP architecture and trust model
* Full vulnerability taxonomy with detection logic
* Trust boundary failure analysis (building on TrustFall / SymJack)
* Approved server registry framework and per-tool hardening guides
* KQL detections for MCP abuse in Microsoft Sentinel

### Agent Sandboxing and Containment Patterns
Given that prompt injection may be unsolvable at the model layer, containment becomes the primary defence. Planned coverage:
* Sandboxed execution patterns for coding agents
* CI/CD gating patterns (post-merge-only invocation, branch restrictions)
* Least privilege scoping for agent file and network access
* Evaluation notes on Microsoft RAMPART and similar pre-ship testing frameworks

### Detection Engineering Playbook, AI Incidents
Structured response playbooks for AI-specific incident types:
* Suspected coding agent RCE (TrustFall / SymJack class)
* Suspected prompt injection affecting an agent
* Suspected memory poisoning
* Suspected NHI / agentic identity credential compromise
* Suspected RAG knowledge base poisoning

---

## Medium-term (Q4 2026)

### Agentic Identity Governance Maturity Model
A tiered maturity framework distinguishing traditional NHI governance from agentic identity governance:
* Ephemeral identity provisioning (TTL, purpose, per-task Agent IDs)
* SPIFFE/SPIRE and PKCE adoption patterns
* Self-assessment criteria and migration path per maturity level

### AI Governance Frameworks for SOC Teams
A practical guide to operationalising AI governance from a Detection & Response perspective:
* NIST AI RMF mapped to detection controls
* EU AI Act security-relevant requirements
* Internal AI deployment security review checklist

### KQL Detection Library, AI Threats
A standalone, well-documented library of production-quality KQL detections covering all detection ideas in `Detection-Ideas.md`, plus watchlist-based approved MCP/NHI registries and UEBA integration for behavioural baselining.

---

## Longer-term (2027 horizon)

### Gulf Market AI Security Context
AI governance and security requirements specific to UAE, Saudi Arabia, and wider Gulf markets, increasingly relevant as regulatory frameworks mature:
* UAE AI regulatory landscape
* Saudi Vision 2030 AI security implications
* DIFC and ADGM data protection requirements as they apply to AI deployments

### MITRE ATT&CK + ATLAS Unified Threat Mapping
A combined mapping showing how traditional ATT&CK attack chains incorporate ATLAS techniques when AI systems are present, useful for communicating AI-specific risk to stakeholders operating within the ATT&CK vocabulary.

### Agentic AI in the SOC, Risks and Controls
As SOC vendors deploy agentic AI for triage and automated response, the SOC itself becomes subject to the agentic threat model:
* Threat model for SOC AI deployments
* Detection logic for compromised SOC agents
* Vendor assessment criteria and human-oversight circuit breakers

---

## Framework evolution watch

Areas where the framework landscape is actively developing, tracking these matters for staying ahead:

* **MITRE ATLAS expansion**, current framework predates widespread agentic deployment; an update or successor covering agentic pipelines and agentic identity is anticipated
* **OWASP NHI Top 10 and OWASP Agentic (ASI) categories**, actively developed; warrant dedicated documents as they stabilise
* **Prompt injection as an unsolvable problem**, research direction arguing model-layer defences will always be incomplete, shifting emphasis to runtime containment
* **Authorisation propagation in agent chains**, emerging as a distinct problem class from injection itself
* **NIST AI RMF and EU AI Act operational guidance**, enforcement and implementation guidance relevant to security teams. Note: EU AI Act enforcement provisions begin August 2026, a near-term compliance milestone worth tracking for any deployment touching the EU market

---

*This roadmap is a living document. Priorities are adjusted as the threat landscape evolves. Contributions and suggestions welcome via GitHub Issues.*
