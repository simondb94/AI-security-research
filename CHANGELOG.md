# Changelog

All significant updates to this repository are documented here.

Format: `[YYYY-MM-DD], Change description`

---

## June 2026

**[2026-06-09], Verification sweep and real world case studies**

Final pre-launch verification pass against latest available sources. Added verified, corroborated real world material; rejected one unverifiable breach claim encountered during the sweep.

* `AI-Coding-Agent-Security.md`, Added GTG-1002 case study (Anthropic-disclosed Chinese state-sponsored campaign that weaponised Claude Code, ~30 global targets, 80–90% AI-executed, MCP-routed, jailbreak + task decomposition evasion)
* `OWASP-LLM-Top10.md`, Added named CVE examples: EchoLeak (CVE-2025-32711, CVSS 9.3) and CVE-2025-53773 (CVSS 9.6)
* `MITRE-ATLAS-Overview.md`, Added reference to Anthropic's mapping of 832 banned malicious-activity accounts (Mar 2025–Mar 2026) onto MITRE ATT&CK, published in part via Verizon 2026 DBIR
* `ROADMAP.md`, Added EU AI Act enforcement milestone (August 2026)

**[2026-06-09], In the wild coding agent attacks and agentic identity update**

This update reflects the most significant development since spring 2026: agentic AI attacks moved from theoretical/emerging to named, in the wild remote code execution techniques affecting production tooling.

**New file added:**
* `AI-Coding-Agent-Security.md`, Dedicated coverage of in the wild RCE techniques against agentic coding tools: TrustFall (one-keypress MCP RCE in Claude Code, Cursor, Gemini CLI, Copilot CLI), SymJack (symlink-hijack RCE across six-plus agents), Semantic Kernel CVE-2026-25592 / CVE-2026-26030 (prompt injection to host RCE), and the persistent Copilot backdoor chain. Includes Microsoft RAMPART (defensive testing framework) and the unifying "implicit trust" analysis

**Updated files:**
* `README.md`, Added coding agent security to scope and file index; refreshed positioning for the H1 2026 landscape
* `Agentic-AI-Threats.md`, Added June update banner; strengthened MCP section with confirmed in the wild exploitation (RSAC Azure tenant takeover, TrustFall/SymJack)
* `NHI-Security.md`, Added agentic identity as a distinct class from traditional NHI (ephemeral, self-directed, SPIFFE/SPIRE, PKCE, per-task Agent IDs)
* `Detection-Ideas.md`, Added Detection 10 (coding agent config tampering / MCP auto-execution) and Detection 11 (vulnerable framework retrospective hunt for the Semantic Kernel CVE class)
* `OWASP-LLM-Top10.md`, `OWASP-Agentic-Top10-2026.md`, `MITRE-ATLAS-Overview.md`, Review dates refreshed to June 2026; content confirmed current

---

## April 2026

**[2026-04-12], Major update: Agentic and NHI coverage expansion**

Expanded the repository to reflect the threat landscape as of RSAC 2026 and the crystallisation of agentic AI and NHI security as the dominant enterprise security concerns of 2026.

**New files added:**
* `NHI-Security.md`, Non Human Identity security: threat vectors, detection logic, governance framework
* `OWASP-Agentic-Top10-2026.md`, OWASP Top 10 for Agentic Applications 2026, mapped to SOC relevance and detection angles

**Updated files:**
* `README.md`, Repositioned scope (LLM → AI Security / Agentic / NHI), new positioning statement and file index
* `Agentic-AI-Threats.md`, Added MCP vulnerability classes, memory poisoning, supply chain attacks; updated threat matrix
* `Detection-Ideas.md`, Added Detections 6–9 (NHI credential anomaly, MCP tool invocation anomaly, memory store anomalous write, dormant NHI reactivation)
* `OWASP-LLM-Top10.md`, Added cross-reference table to Agentic Top 10
* `MITRE-ATLAS-Overview.md`, Expanded all tactic entries with SOC relevance and detection priority mapping

**Structural additions:**
* `CHANGELOG.md` (this file)
* `ROADMAP.md`

---

## March 2026

**[2026-03-24], Repository published**

Initial public release covering:
* OWASP LLM Top 10
* MITRE ATLAS overview
* Agentic AI threat landscape (initial version)
* Detection ideas, 5 initial detections

---

*Updates are dated when committed. This is a living repository, entries will be added as the threat landscape develops.*
