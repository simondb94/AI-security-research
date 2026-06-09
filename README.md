# AI Security Research

Practitioner research notes on AI security, agentic AI threat modelling, non human identity (NHI) governance, AI coding agent attack surfaces, and detection engineering for emerging AI threats.

Maintained by a SOC Analyst actively specialising in Detection & Response for AI systems.

This is not vendor content. Everything here is written from inside a SOC, with detection and response as the primary lens.

---

## What is in this repository

| File | Description |
|---|---|
| [OWASP-LLM-Top10.md](OWASP-LLM-Top10.md) | OWASP Top 10 for LLM Applications, each vulnerability mapped to real world attack examples, detection angles and SOC relevance |
| [OWASP-Agentic-Top10-2026.md](OWASP-Agentic-Top10-2026.md) | OWASP Top 10 for Agentic Applications 2026, distinct from the LLM Top 10, covering risks specific to autonomous AI systems |
| [MITRE-ATLAS-Overview.md](MITRE-ATLAS-Overview.md) | MITRE ATLAS framework, AI/ML-specific ATT&CK tactics and techniques, mapped to traditional TTPs and SOC relevance |
| [Agentic-AI-Threats.md](Agentic-AI-Threats.md) | Emerging threat landscape for autonomous AI agents, indirect prompt injection, memory poisoning, MCP vulnerabilities, supply chain attacks, identity risks |
| [AI-Coding-Agent-Security.md](AI-Coding-Agent-Security.md) | In the wild RCE techniques against agentic coding tools, TrustFall, SymJack, Semantic Kernel CVEs, and what they mean for defenders |
| [NHI-Security.md](NHI-Security.md) | Non Human Identity and agentic identity security, the fastest-growing attack surface in enterprise environments |
| [Detection-Ideas.md](Detection-Ideas.md) | KQL and detection logic concepts for AI-specific threats, written for Microsoft Sentinel, adaptable to other SIEMs. Each detection now carries an explicit validation status |
| [ROADMAP.md](ROADMAP.md) | Planned research areas and upcoming content |
| [CHANGELOG.md](CHANGELOG.md) | Update history |

---

## Why this repository exists

Traditional security frameworks, ATT&CK, CVSS, SIEM rules, were not built for systems that reason, act autonomously, and operate at machine speed. Through the first half of 2026 the gap became operational. Industry reporting now consistently places agentic AI and machine identity abuse among the top enterprise attack surfaces, with [KPMG's 2026 cybersecurity report](https://www.cybersecurity-insiders.com/kpmg-2026-cybersecurity-report-ciso-priorities/) naming non human identity governance as a load-bearing CISO priority ahead of AI safety itself. The scale problem is no longer abstract, [ManageEngine's Identity Security Outlook 2026](https://www.helpnetsecurity.com/2026/01/07/identity-security-outlook-2026-report/) found nearly half of surveyed organisations reporting machine-to-human identity ratios above 100:1, with some sectors reaching 500:1, while [Rubrik Zero Labs places the enterprise average at 45:1 and Entro Labs measured 144:1 in cloud-native environments](https://thehackernews.com/expert-insights/2026/05/the-non-human-identity-crisis-why-your.html). At the same time, the first wave of named, in the wild RCE techniques against AI coding agents has arrived.

SIEM and EDR tooling built for human behaviour patterns cannot reliably detect an agent doing exactly what it was designed to do, under an attacker's direction. This repository is a working effort to bridge that gap. Every note is written with a detection or response angle in mind. The goal is to be useful to a Detection & Response engineer sitting a shift today.

---

## Frameworks and references

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MITRE ATLAS (Adversarial Threat Landscape for AI Systems)](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://airc.nist.gov/RMF)
- [Microsoft AI Red Team](https://learn.microsoft.com/en-us/security/ai-red-team/)

---

## Scope

- **LLM security**, prompt injection, model extraction, output manipulation, supply chain
- **Agentic AI security**, autonomous agent attack vectors, multi agent pipeline threats, memory poisoning
- **AI coding agent security**, in the wild RCE techniques, MCP trust boundary attacks, framework CVEs
- **Non Human and agentic identity**, AI agent credentials, ephemeral identity, machine identity detection
- **Detection engineering**, KQL-based detection logic, logging requirements, SOC integration

---

## Validation status

Detection content in this repository is graded honestly:

- **Concept**, written from threat analysis, not yet executed against telemetry
- **Lab-validated**, executed against synthetic or demo telemetry, sample output included
- **Field-informed**, shaped by patterns observed in production environments (sanitised, no client data)

As of June 2026 the majority of detections are at Concept stage. Lab validation is the current priority, see [ROADMAP.md](ROADMAP.md).

---

## Licence

Released under the [MIT Licence](LICENSE). Reuse, adapt, and fork freely, attribution appreciated. Detection logic is provided as-is and must be adapted and tested in your own environment before operational use.

---

## Status

Active. Updated regularly as the threat landscape evolves.

See [CHANGELOG.md](CHANGELOG.md) for update history and [ROADMAP.md](ROADMAP.md) for planned additions.

> Repository initiated: March 2026
> Last reviewed: June 2026
