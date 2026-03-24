# LLM and AI Security Research

Personal research notes on Large Language Model LLM security, AI threat modelling and emerging attack surfaces in agentic AI systems.

Maintained by a SOC Analyst, interested in Detection and Response, actively training into AI security specialisation.

---

## What's in this repository

| File | Description |
|------|-------------|
| [OWASP-LLM-Top10.md](./OWASP-LLM-Top10.md) | OWASP Top 10 for LLMs - each vulnerability mapped to real world attack examples, detection angles and SOC relevance |
| [MITRE-ATLAS-Overview.md](./MITRE-ATLAS-Overview.md) | MITRE ATLAS framework - AI/ML specific ATT&CK tactics and techniques with notes on how they map to traditional TTPs |
| [Agentic-AI-Threats.md](./Agentic-AI-Threats.md) | Emerging threat landscape for autonomous AI agents - attack vectors, identity risks and prompt injection in agentic pipelines |
| [Detection-Ideas.md](./Detection-Ideas.md) | Draft KQL and detection logic concepts for AI specific threats in a SOC context |

---

## Why this repository exists

AI security is where cybersecurity was in 2013. The threats are real, the attack surface is expanding rapidly and qualified defenders are almost non existent.

Traditional security frameworks, ATT&CK, CVSS, SIEM rules, were not built for systems that reason, hallucinate and take autonomous actions. This repository is my working effort to bridge that gap, mapping what I know from SOC operations onto the new threat surfaces that AI systems introduce.

The goal is not to be theoretical. Every note here is written with a detection or response angle in mind also.

---

## Frameworks referenced

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS (Adversarial Threat Landscape for AI Systems)](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf)
- [Microsoft AI Red Team](https://learn.microsoft.com/en-us/security/ai-red-team/)

---

## Status

Active and updated regularly. This is a living document - notes evolve as the threat landscape does.

> Started: March 2026
