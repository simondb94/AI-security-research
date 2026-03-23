# MITRE ATLAS — AI/ML Threat Landscape

Reference: [MITRE ATLAS](https://atlas.mitre.org/)  
Last reviewed: March 2026

MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is the AI-specific equivalent of ATT&CK. It documents the tactics, techniques, and procedures (TTPs) used by adversaries to attack machine learning systems.

If you know ATT&CK, ATLAS is a direct translation into AI/ML threat space. This document maps them together where applicable.

---

## Why ATLAS matters for SOC analysts

Traditional ATT&CK covers how attackers compromise systems. ATLAS covers how attackers compromise the **AI models and pipelines** running on those systems.

As organisations deploy AI into production — for threat detection, fraud prevention, content moderation, autonomous decision-making — those AI systems become targets in their own right. An adversary who can manipulate your AI-based threat detection system doesn't need to evade your detections — they can make your detections wrong.

---

## ATLAS Tactic Overview

ATLAS organises adversary behaviour into tactics — the *why* behind an action. Below each tactic is mapped to its ATT&CK equivalent where one exists, with notes on what it means in practice.

---

### AML.TA0001 — Reconnaissance
**ATT&CK equivalent:** Reconnaissance (TA0043)

The adversary gathers information about the target AI system before attacking it. Unlike traditional recon, AI recon often involves **probing the model's behaviour** to infer its architecture, training data, or decision boundaries.

**Techniques include:**
- **AML.T0000 — Active Scanning:** Querying the model with structured inputs to map its behaviour and identify exploitable patterns
- **AML.T0001 — Published Model Documentation:** Reviewing public papers, model cards, or GitHub repos to understand the model's architecture and training approach
- **AML.T0002 — Published Training Data:** Identifying the datasets a model was trained on — enabling more targeted poisoning or extraction attacks

**SOC note:** Unusual high-volume query patterns against an AI API — especially systematic, structured probing that doesn't resemble normal user behaviour — is a recon indicator. Treat it like port scanning.

---

### AML.TA0002 — Resource Development
**ATT&CK equivalent:** Resource Development (TA0042)

The adversary acquires or develops the tools and infrastructure needed to attack the AI system — crafting adversarial examples, building surrogate models, or obtaining training data.

**Techniques include:**
- **AML.T0017 — Develop Capabilities:** Building tools specifically designed to attack AI systems — adversarial example generators, model inversion tools
- **AML.T0019 — Obtain Capabilities:** Acquiring existing attack tools from public research or underground markets

**SOC note:** This phase is largely invisible from a defender's perspective — it happens off your network. Awareness matters more than detection here.

---

### AML.TA0004 — Initial Access
**ATT&CK equivalent:** Initial Access (TA0001)

How the adversary first gains the ability to interact with or influence the target AI system.

**Techniques include:**
- **AML.T0010 — ML Supply Chain Compromise:** Inserting malicious code or poisoned data into the ML pipeline via a third-party dependency, pre-trained model, or dataset
- **AML.T0012 — Valid Accounts:** Using legitimate credentials to access the ML platform, training infrastructure, or model API
- **AML.T0049 — Exploit Public-Facing Application:** Exploiting vulnerabilities in the interface that exposes the AI model to users

**SOC note:** Supply chain compromise is the highest-risk initial access vector for AI systems — a poisoned pre-trained model is invisible until it misbehaves. Treat model downloads and dataset imports with the same scrutiny as installing third-party software.

---

### AML.TA0005 — Execution
**ATT&CK equivalent:** Execution (TA0002)

The adversary causes their malicious code, payload, or instruction to run within the AI system or its pipeline.

**Techniques include:**
- **AML.T0011 — User Execution:** A user or automated system runs a poisoned model, script, or dataset introduced by the adversary
- **AML.T0047 — LLM Prompt Injection:** The adversary's instructions are executed by the LLM as part of its normal inference process — the model itself becomes the execution environment

**SOC note:** Prompt injection (OWASP LLM01) lives here in ATLAS terms. The LLM executing attacker instructions is functionally equivalent to a user executing a malicious binary — the mechanism is different but the outcome is the same.

---

### AML.TA0006 — Persistence
**ATT&CK equivalent:** Persistence (TA0003)

The adversary maintains ongoing access or influence over the AI system, even across model updates or retraining cycles.

**Techniques include:**
- **AML.T0020 — Poison Training Data:** Introducing malicious examples into the training dataset such that every subsequent model trained on that data carries the adversary's backdoor
- **AML.T0018 — Backdoor ML Model:** Embedding a hidden trigger in the model weights — the model behaves normally until a specific input activates the backdoor

**SOC note:** Backdoored models are the AI equivalent of a rootkit — persistent, hard to detect, and potentially surviving full system reinstallation (retraining). Standard AV/EDR will not detect a compromised model. Model behaviour testing after every training cycle is the equivalent of running integrity checks.

---

### AML.TA0009 — Collection
**ATT&CK equivalent:** Collection (TA0009)

The adversary extracts valuable information from the AI system — training data, model weights, proprietary logic, or user data processed by the model.

**Techniques include:**
- **AML.T0035 — ML Model Inference API Access:** Using repeated queries to extract information about the model's decision boundaries or training data
- **AML.T0037 — Data from Information Repositories:** Accessing data stores used to train or augment the model
- **AML.T0040 — Extract ML Model:** Reconstructing a functional copy of a proprietary model through systematic querying — known as **model extraction** or **model stealing**

**SOC note:** Model extraction attacks look like high-volume, systematically varied API queries. A stolen model bypasses all future security controls applied to the original — the adversary now has their own unconstrained copy. Alert on query volume anomalies and diversity anomalies (unusually varied inputs from a single source).

---

### AML.TA0010 — Exfiltration
**ATT&CK equivalent:** Exfiltration (TA0010)

The adversary removes data or model artefacts from the target environment.

**Techniques include:**
- **AML.T0024 — Exfiltration via ML Inference API:** Using the model's own outputs as a covert channel to leak data — the model is prompted to encode sensitive information into its responses in a way the attacker can decode
- **AML.T0025 — Exfiltrate via Cyber Means:** Standard data exfiltration of model weights, training data, or pipeline artefacts once access is obtained

**SOC note:** Covert exfiltration via model outputs is a novel channel that traditional DLP tools are not designed to detect. Monitoring output entropy, volume, and structural patterns over time is the current best approach.

---

### AML.TA0040 — ML Attack Staging
*No direct ATT&CK equivalent — AI-specific*

Preparation activities specific to ML attacks that don't map neatly to traditional staging.

**Techniques include:**
- **AML.T0043 — Craft Adversarial Data:** Generating inputs specifically designed to cause the model to misclassify, misbehave, or reveal information
- **AML.T0044 — Obtain Attack Model:** Acquiring a surrogate model (a copy or approximation of the target) to develop and test attacks offline before deploying them against the real system

---

## ATLAS vs ATT&CK — Key differences

| Dimension | ATT&CK | ATLAS |
|-----------|--------|-------|
| Target | Systems, networks, endpoints | AI/ML models and pipelines |
| Execution environment | OS, applications | Model inference, training pipeline |
| Persistence mechanism | Registry keys, scheduled tasks, rootkits | Poisoned training data, backdoored model weights |
| Detection tooling | SIEM, EDR, network monitoring | Model monitoring, data provenance, output analysis |
| Primary data source | Incident reports, threat intel | Academic research, red team exercises |
| Maturity | Very mature (20+ years) | Early stage (launched 2021, actively expanding) |

---

## The key insight for SOC analysts

ATT&CK assumes the attacker wants to **compromise the infrastructure** the AI runs on.

ATLAS assumes the attacker wants to **compromise the AI itself** — making it malfunction, misbehave, or work for them rather than for you.

As AI systems become integrated into security operations (AI-assisted triage, AI-driven SOAR, autonomous detection), an adversary who can manipulate the AI has effectively compromised your SOC without ever touching your endpoints.

This is why understanding ATLAS is not optional for Detection & Response engineers. It is the threat model for the tools you will increasingly be defending with — and defending against.

---

*These notes are a working reference — not a comprehensive academic treatment. See [atlas.mitre.org](https://atlas.mitre.org) for the full framework, case studies, and technique detail.*
