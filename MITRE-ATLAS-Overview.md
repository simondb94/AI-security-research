# MITRE ATLAS, Adversarial Threat Landscape for AI Systems

Last reviewed: June 2026

MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is a knowledge base of adversary tactics, techniques, and case studies for AI and machine learning systems. It is structured analogously to MITRE ATT&CK and is designed to complement it, ATT&CK covers attacks on traditional IT infrastructure, ATLAS covers attacks on AI/ML systems specifically.

This document maps ATLAS tactics and techniques to their SOC relevance, traditional ATT&CK equivalents where applicable, and detection considerations from a practitioner perspective. Tactic and technique IDs below are verified against atlas.mitre.org as of June 2026; note that ATLAS tactic IDs do not run in display order (the matrix opens with AML.TA0002 Reconnaissance), and the framework is actively expanding, re-verify IDs against the live site before citing them elsewhere.

---

## Relationship to MITRE ATT&CK

ATLAS uses the same conceptual structure as ATT&CK, Tactics (the adversary's goal) and Techniques (the method used to achieve it). Many ATLAS techniques are novel to AI systems. Others are traditional techniques applied to AI-specific targets.

Understanding both frameworks together is essential for 2026 SOC operations. AI systems are increasingly integrated into enterprise infrastructure, which means:

* Traditional ATT&CK techniques are used to compromise the systems that host AI components
* ATLAS techniques are used to attack the AI components themselves
* A complete attack chain often uses both

---

## ATLAS Tactics

### AML.TA0002, Reconnaissance

**Objective:** Gather information about the target AI system to inform attack planning.

**Key techniques:**
* **AML.T0006, Active Scanning:** Probing the victim system directly to gather targeting information
* **AML.T0004, Search Application Repositories:** Identifying AI-enabled applications and their characteristics through public app stores and repositories
* **AML.T0014, Discover AI Model Family:** Determining the underlying model architecture or base model (e.g., identifying that a product is built on a specific foundation model)

**ATT&CK equivalent:** TA0043 Reconnaissance

**SOC relevance:**
High-volume, structurally varied API calls are a reconnaissance indicator. Attackers probe model capabilities before mounting extraction or evasion attacks. Behavioural baselining of API usage patterns is the primary detective control.

---

### AML.TA0003, Resource Development

**Objective:** Establish resources required to conduct AI-targeted attacks.

**Key techniques:**
* **AML.T0002, Acquire Public ML Artifacts:** Obtaining public models, datasets, and related artefacts to support attack development
* **AML.T0005, Create Proxy ML Model:** Building a surrogate model trained on outputs from the target model, a foundation for transfer attacks
* **AML.T0008, Acquire Infrastructure:** Standing up the infrastructure used to mount the attack

**ATT&CK equivalent:** TA0042 Resource Development

**SOC relevance:**
Limited direct visibility from most SOC positions. The value is awareness, understanding that attackers who subsequently mount evasion or extraction attacks have likely done this groundwork.

---

### AML.TA0004, Initial Access

**Objective:** Gain initial access to the target ML system or its supporting infrastructure.

**Key techniques:**
* **AML.T0010, ML Supply Chain Compromise:** Compromising ML models, datasets, or frameworks before they reach the target organisation, via poisoned pre-trained models, malicious libraries, or compromised model repositories
* **AML.T0012, Valid Accounts:** Using legitimate credentials to access ML platforms, model APIs, or training infrastructure

**ATT&CK equivalent:** TA0001 Initial Access

**SOC relevance:**
Supply chain compromise is the hardest initial access vector to detect. The artefact (model, library, dataset) appears legitimate and passes standard checks. Integrity verification, provenance tracking, and SBOM practices are the primary preventive controls. For Valid Accounts, standard identity monitoring applies, with additional attention to service accounts associated with AI workloads.

---

### AML.TA0000, AI Model Access

**Objective:** Gain a level of access to the target model itself, the distinctive ATLAS tactic with no direct ATT&CK equivalent.

**Key techniques:**
* **AML.T0040, AI Model Inference API Access:** Accessing the model through its inference API, the foundation for discovery, extraction, and evasion attacks
* **AML.T0047, AI-Enabled Product or Service:** Reaching the model indirectly through a product or service built on top of it

**SOC relevance:**
Most attacks against deployed models route through this tactic. API gateway logging and per-identity rate limiting are the control points.

---

### AML.TA0005, Execution

**Objective:** Execute adversary-controlled code or commands within the AI/ML environment.

**Key techniques:**
* **AML.T0011, User Execution:** Tricking a user into running malicious model-related code, malicious Jupyter notebooks, poisoned model loading scripts
* **AML.T0050, Command and Scripting Interpreter:** Abusing interpreters within the AI environment to execute adversary commands
* **AML.T0051, LLM Prompt Injection:** Injecting instructions that the model executes as if legitimate, the technique underpinning the most operationally significant attacks of 2025–2026

**ATT&CK equivalent:** TA0002 Execution

**SOC relevance:**
Prompt injection is execution without code. Detection requires logging model inputs and outputs and the triggering context for agent actions, not just infrastructure-level execution events.

---

### AML.TA0006, Persistence

**Objective:** Maintain access or influence over the AI/ML system across restarts, updates, or defensive actions.

**Key techniques:**
* **AML.T0020, Poison Training Data:** Injecting malicious examples into training data so that subsequent model retraining re-embeds the attacker's influence
* **AML.T0018, Backdoor ML Model:** Embedding hidden behaviour in the model that activates under specific trigger conditions and survives normal operation

**ATT&CK equivalent:** TA0003 Persistence

**SOC relevance:**
Training data poisoning is a persistence mechanism, even if a compromised model is retrained, the poisoned training data re-introduces the vulnerability. Data provenance and integrity controls on training datasets are the relevant detective controls. Backdoored models are particularly challenging, the malicious behaviour lives in the weights, not in separate code.

---

### AML.TA0007, Defence Evasion

**Objective:** Avoid detection by AI-specific and traditional security controls.

**Key techniques:**
* **AML.T0015, Evade ML Model:** Crafting inputs specifically designed to evade an ML-based detection or classification system, adversarial examples that fool the model while appearing normal to humans
* **AML.T0054, LLM Jailbreak:** Bypassing model safety controls to unlock restricted functions or outputs

**ATT&CK equivalent:** TA0005 Defence Evasion

**SOC relevance:**
ML-based security controls (malware classifiers, anomaly detection, threat scoring) are subject to adversarial evasion. Attackers who understand that a SOC uses ML-based detection may specifically craft attacks to exploit model blind spots. Defence-in-depth, not relying solely on ML-based detection for any critical control, is the relevant principle.

---

### AML.TA0008, Discovery

**Objective:** Learn about the target AI system's capabilities, limitations, and environment.

**Key techniques:**
* **AML.T0013, Discover ML Model Ontology:** Identifying the model's input/output structure, task type, and capabilities
* **AML.T0063, Discover AI Model Outputs:** Characterising what the model exposes in its responses

**ATT&CK equivalent:** TA0007 Discovery

**SOC relevance:**
Anomalous API call patterns, high volume, structurally varied, originating from a single source, are the primary detection signal for this tactic. See Detection-Ideas.md Detection 1.

---

### AML.TA0009, Collection

**Objective:** Collect data from the AI system or its environment.

**Key techniques:**
* **AML.T0036, Data from Information Repositories:** Harvesting data from repositories the AI system or its environment exposes
* **AML.T0040, AI Model Inference API Access (in collection use):** High-volume systematic querying to extract model knowledge, the same access technique reused for collection

**ATT&CK equivalent:** TA0009 Collection

**SOC relevance:**
Model extraction and training data reconstruction attacks use this tactic. The attack surface is the inference API itself. Rate limiting, query logging, and velocity anomaly detection are the relevant controls.

---

### AML.TA0010, Exfiltration

**Objective:** Steal data from the AI system or its connected data stores.

**Key techniques:**
* **AML.T0025, Exfiltration via Cyber Means:** Using conventional channels, or the AI system as an intermediary, to transfer data to attacker-controlled endpoints
* **AML.T0024, Exfiltration via AI Inference API:** Querying the model to surface information from its training data or context, the model's own outputs become the exfiltration channel

**ATT&CK equivalent:** TA0010 Exfiltration

**SOC relevance:**
Exfiltration via agent actions is the most operationally significant vector in 2026. A compromised agent exfiltrates using its own legitimate credentials and channels, bypassing DLP controls designed for human-generated transfers. Agent action logging with content inspection is the relevant detective control.

---

### AML.TA0011, Impact

**Objective:** Manipulate, disrupt, or destroy AI system capabilities or the data it depends on.

**Key techniques:**
* **AML.T0031, Erode ML Model Integrity:** Degrading the model's accuracy or reliability through adversarial inputs, data poisoning, or sustained manipulation
* **AML.T0029, Denial of ML Service:** Overwhelming the ML system with requests to degrade availability, analogous to DoS against traditional services
* **AML.T0034, Cost Harvesting:** Driving up the victim's inference costs through mass querying, financial impact as the objective

**ATT&CK equivalent:** TA0040 Impact

**SOC relevance:**
For SOC teams using ML-based detection, model integrity attacks are directly operational, an attack that degrades the SOC's own detection model could suppress alerts across an entire class of threats.

---

## ATLAS case studies, selected examples

ATLAS maintains a case study library of real world AI attacks. Notable examples with SOC relevance:

| Case Study | Tactic | Relevance |
|------------|--------|-----------|
| Microsoft Tay chatbot manipulation (2016) | Impact, model integrity erosion via adversarial user inputs | Demonstrates that user-generated content can persistently alter model behaviour |
| GPT-2 training data extraction (2021) | Collection, training data reconstruction via inference API | Shows that LLMs can surface verbatim training data through systematic probing |
| Indirect prompt injection in LLM agents (2023–2026) | Execution, Exfiltration | Demonstrated across multiple production AI assistant deployments, a mature attack class |
| Adversarial patches against computer vision (multiple) | Defence Evasion | Physical world adversarial examples that fool ML classifiers, relevant to AI-based physical security |

---

## Mapping ATLAS to detection priorities

| ATLAS Tactic | Primary Detection Approach | Tooling |
|--------------|---------------------------|---------|
| Reconnaissance | API call velocity anomaly, structured probing detection | SIEM, API gateway logs |
| Initial Access (Supply Chain) | Dependency integrity verification, SBOM, model provenance | DevSecOps pipeline controls |
| Execution (Prompt Injection, Backdoor) | Input/output logging, trigger-response behaviour monitoring | Custom monitoring, red team exercises |
| Persistence (Training Data Poisoning) | Pre-training data integrity scanning, RAG pre-ingestion scanning | Custom tooling (see Detection 4) |
| Defence Evasion | Defence-in-depth, multiple overlapping detection methods, do not rely solely on ML classifiers | Architecture |
| Collection / Exfiltration | Agent action logging, output content inspection, DLP on API responses | SIEM, DLP, agent telemetry |
| Impact (DoS, Cost Harvesting) | API rate limiting, consumption anomaly detection | API gateway, SIEM |

---

## ATLAS and the 2026 SOC

MITRE ATLAS was published when most AI attacks were research-grade. In 2026, indirect prompt injection, model extraction, and RAG poisoning are operational attack techniques observed in production environments. The Spring 2025 release expanded generative AI coverage substantially, adding techniques for RAG poisoning, prompt crafting, and AI supply chain compromise, and the framework has continued expanding through 2026.

The framework provides a shared vocabulary for communicating AI threats to stakeholders who understand ATT&CK, which is its primary practical value for Detection & Response engineers today.

**Forward look:**
The AI security community has discussed the need for further ATLAS expansion to fully account for agentic AI, multi agent pipelines, and NHI-specific attack paths. Engineers who understand both the existing framework and its gaps are well-positioned to contribute to that evolution.

**Real world ATT&CK mapping (June 2026):**
Anthropic published an analysis mapping a year's worth of AI-enabled cyber threats onto MITRE ATT&CK, examining accounts banned for malicious cyber activity between March 2025 and March 2026, with results feeding Verizon's 2026 Data Breach Investigations Report (DBIR). This is a useful reference for understanding how AI-enabled attacks map onto the established ATT&CK tactics and techniques that SOC teams already use, and for seeing where existing frameworks hold up versus where they strain. The GTG-1002 campaign (see [AI-Coding-Agent-Security.md](./AI-Coding-Agent-Security.md)) is the highest-profile worked example of AI executing ATT&CK tactics autonomously.

---

## References

* [MITRE ATLAS](https://atlas.mitre.org/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [ATLAS Case Studies](https://atlas.mitre.org/studies/)
* [ATLAS Techniques](https://atlas.mitre.org/techniques/)

---

*This document reflects MITRE ATLAS as of June 2026. The framework is actively developed, check atlas.mitre.org for the latest tactics, techniques, and case studies. Tactic and technique IDs were corrected against the live framework in June 2026.*
