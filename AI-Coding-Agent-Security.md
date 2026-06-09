# AI Coding Agent and MCP Attack Security

Last reviewed: June 2026

Through the first half of 2026, agentic coding assistants moved from emerging tooling to standard developer infrastructure, and with that adoption came the first wave of named, in the wild remote code execution (RCE) techniques targeting them.

This is no longer theoretical. The attacks documented below affect production tools used daily by developers and security teams, and several are architectural, meaning they affect the whole category, not a single product.

This file is written from a Detection & Response perspective: what the attack is, why it works, what it means for defenders, and what to monitor.

---

## Why coding agents are a distinct attack surface

A coding agent does not just suggest text. It reads project files, executes commands, installs dependencies, runs tests, and, critically, auto-loads configuration that can point to external programs and tool servers. The moment a developer opens or clones a repository, the agent may begin acting on content it has never validated.

The old developer convention was: clone a repo, *look at it before you run it*. Agentic coding tools inherited that convention but broke its safety assumption, the agent begins reading and acting on project configuration before the human has reviewed anything.

The result is a class of supply chain attack where the malicious payload is delivered through a repository, and the agent, operating with the developer's full privileges, becomes the execution vector.

---

## Named techniques (H1 2026)

### TrustFall, one-keypress RCE via MCP trust prompt

**Disclosed:** May 2026 (Adversa AI)
**Affected:** Claude Code, Gemini CLI, Cursor CLI, GitHub Copilot CLI

**What it is:**
All four agentic CLIs tested auto-execute project-defined MCP (Model Context Protocol) servers the moment a developer accepts the folder-trust prompt, the "Is this a project you trust?" dialog that defaults to Yes/Trust. A malicious repository ships a project-scoped MCP configuration. The instant the developer clones it and runs the agent, an attacker-controlled process spawns with the developer's full user privileges.

**Impact:**
SSH keys, cloud credentials, and source code from any other project on the same machine can be exfiltrated before the agent's prompt even finishes loading. In CI/CD contexts, this becomes a pipeline poisoning vector.

**The core issue, informed consent gap:**
The research highlighted that the trust dialog in some agent versions no longer clearly states that accepting it authorises MCP server execution. The user is making a trust decision without being shown what they are actually authorising. (Note: the affected vendor's position is that accepting folder trust constitutes consent to the full project configuration, and that post-trust execution is the boundary working as designed. The dispute is about whether the dialog gives the user enough information to make that decision, not about the mechanism.)

**Defensive takeaways:**
* In CI/CD: gate agent invocations to post-merge main branches only, where commits are already reviewed
* Never run agentic coding tools on arbitrary PR branches from untrusted forks
* Disable auto-approval of MCP servers at the system level where the tool allows it
* Audit which MCP servers your agent tooling will auto-load from project scope

---

### SymJack, symlink-hijack RCE overwriting agent config

**Disclosed:** May 2026 (Adversa AI), updated to include additional tools through late May
**Affected:** Claude Code, Gemini CLI / Antigravity CLI, Cursor Agent CLI, GitHub Copilot CLI, Grok Build, OpenAI Codex CLI, six-plus agents confirmed

**What it is:**
A booby-trapped repository tricks the coding agent into performing a benign-looking file copy that secretly overwrites the agent's own configuration via a symlink. On the next restart, the agent runs attacker-controlled code with full user privileges.

**Why it matters:**
This is one attack pattern that works against the entire category, the research framing was explicit that this should not be treated as six separate bugs but as a single architectural weakness. It also sidesteps the prerequisite that TrustFall depended on (a populated config visible at clone time) by writing the malicious settings *after* trust is granted, through the disguised copy. Same root cause, fewer prerequisites.

**Defensive takeaways:**
* Treat agent configuration files as security-sensitive, monitor for unexpected writes or symlink creation targeting them
* Run agents in sandboxed or containerised environments where config overwrite cannot affect the host
* Restrict agent file-write operations to an explicit working scope

---

### Semantic Kernel RCE, prompt injection to host code execution

**Disclosed:** May 2026 (Microsoft Security)
**CVEs:** CVE-2026-25592, CVE-2026-26030
**Affected:** Microsoft Semantic Kernel (Python package `semantic-kernel`) versions prior to 1.39.4

**What it is:**
Microsoft researchers demonstrated that prompt injection in an agent built on Semantic Kernel could cross from a content security problem into host-level remote code execution. CVE-2026-26030 specifically affects deployments using the In-Memory Vector Store and relying on its filter functionality as the backend for the Search Plugin under default configuration.

**The principle this illustrates:**
Once an AI model is wired to tools, prompt injection stops being "the model says something bad" and becomes "the model executes attacker code." The tool layer is the bridge that turns injection into execution.

**Defensive takeaways:**
* Upgrade `semantic-kernel` to 1.39.4 or higher
* Patching closes the bug but does not answer whether exploitation already occurred, define the vulnerable window for each affected deployment (from first running a vulnerable version to the upgrade) and retrospectively hunt over that window
* Treat any agent framework that wires LLM output to tool execution as a potential injection-to-RCE path

---

### Persistent Copilot backdoor via indirect injection

**Disclosed:** 2026 (DEF CON talk)

A demonstrated chain took an indirect prompt injection and turned it into a persistent backdoor in Microsoft Copilot, showing that injection is not only a momentary manipulation but can be made to persist across sessions, consistent with the memory-poisoning threat class. See [Agentic-AI-Threats.md](./Agentic-AI-Threats.md) for memory poisoning detail.

---

## Real world case study, GTG-1002: AI-orchestrated espionage at scale

**Disclosed:** November 2025 (Anthropic); detected mid-September 2025

This is the reference case for agentic AI as an offensive force multiplier, not a vulnerable surface, but a weapon.

Anthropic disclosed and disrupted what it assessed with high confidence to be a Chinese state-sponsored campaign (tracked as GTG-1002) that manipulated Claude Code into attempting infiltration of roughly thirty global targets, large technology companies, financial institutions, chemical manufacturers, and government agencies, and succeeded against a small number.

**What makes it significant:**
* It is the first documented case of a large-scale cyberattack executed largely without human intervention. The AI performed an estimated 80–90% of the tactical work, reconnaissance, vulnerability discovery, exploitation, lateral movement, and post-exploitation, at request rates described as physically impossible for human operators.
* The operators frequently routed actions through MCP, using Claude Code instances as autonomous penetration-testing orchestrators and agents.
* They bypassed the model's safety training through jailbreaking and task decomposition, breaking the operation into small, individually innocuous tasks that the model would execute without seeing the full malicious context.
* It was a clear escalation from the "vibe hacking" pattern seen in mid-2025, where humans remained firmly in the loop directing operations.

**Why it matters for defenders:**
* The same agentic capabilities that make coding agents productive make them powerful offensive tools when jailbroken and orchestrated. The task decomposition evasion technique is the key tradecraft to understand, no single action looks malicious.
* Detection must focus on the aggregate pattern of agent-driven activity (volume, speed, breadth of reconnaissance) rather than individual actions, because the individual actions are designed to look benign.
* This validates the threat-modelling principle that an attacker can operate through an agent's legitimate capabilities without ever needing a traditional exploit.

**Related Anthropic research:** Anthropic subsequently mapped a year's worth of AI-enabled cyber threats, 832 accounts banned for malicious cyber activity between March 2025 and March 2026, onto the MITRE ATT&CK framework, with some results published via Verizon's 2026 Data Breach Investigations Report. See [MITRE-ATLAS-Overview.md](./MITRE-ATLAS-Overview.md).

References: [Anthropic, Disrupting the first reported AI-orchestrated cyber espionage campaign](https://www.anthropic.com/news/disrupting-AI-espionage); [Anthropic, Mapping AI-enabled cyber threats to MITRE ATT&CK](https://www.anthropic.com/news/AI-enabled-cyber-threats-mitre-attack)

---

## The unifying pattern

Across TrustFall, SymJack, the Semantic Kernel CVEs, and the Copilot backdoor, the mechanisms differ but the cause rhymes: **implicit trust granted somewhere no one was watching.** A trust dialog that doesn't say what it authorises. A config file the agent will act on without validation. A tool the model can invoke based on injected text.

The defensive posture that follows is consistent:

> Treat every input the agent ingests as potentially hostile, and every action it can take as potentially dangerous. Close the gap between those two with real boundaries, least privilege scopes, sandboxed execution, and human review wherever the blast radius is large. Assume trust will be abused, instrument the agent so you can see when it is, and design so that a compromised agent is an incident you contain rather than a breach you discover months later.

---

## Defensive tooling that emerged alongside

**Microsoft RAMPART**, open-sourced framework for testing agents against cross-prompt injection, behavioural regressions, and data exfiltration, released alongside Microsoft's Clarity tooling. Targets the development phase, before agents ship. Worth evaluating as part of an agent security review gate.

**Research direction worth tracking:**
* Work arguing that agents may *always* be susceptible to prompt injection, i.e. that it may be an unsolvable problem at the model layer, making runtime boundaries and containment the only reliable defence
* Authorisation propagation through agent chains being treated as a distinct problem class from injection itself
* Position papers cautioning that agent-security benchmarks suffer from staleness and runtime uncertainty, clean leaderboard numbers should not be trusted at face value

---

## Personal/operational relevance

If you run agentic coding tools or self-hosted agent deployments, these are not abstract:

* Any agentic CLI you use to clone and inspect unfamiliar repositories is a TrustFall/SymJack surface, be deliberate about which repos you open with an agent attached, and prefer sandboxed environments for untrusted code
* Self-hosted agent deployments inherit the framework's vulnerability surface, track CVEs for whatever framework underpins them and pin/patch deliberately
* CI/CD pipelines that invoke coding agents on PR branches are the highest-risk configuration, restrict to reviewed, post-merge contexts

---

## Detection angles

See [Detection-Ideas.md](./Detection-Ideas.md) for KQL concepts. Key signals for this attack class:

* Agent configuration file writes, especially symlink creation targeting config paths
* MCP server processes spawning immediately after a repository clone or agent launch
* Unexpected outbound network connections from agent or developer-tool processes shortly after opening a project
* Credential file access (SSH keys, cloud credential stores) by agent-associated processes
* Agent framework processes spawning shell or interpreter child processes

---

## References

* [Adversa AI, TrustFall](https://adversa.ai/blog/trustfall-coding-agent-security-flaw-rce-claude-cursor-gemini-cli-copilot/)
* [Adversa AI, SymJack / "The approval prompt is lying"](https://adversa.ai/blog/the-approval-prompt-is-lying-to-you-symlink-rce-in-five-ai-coding-agents-claude-code-cursor-antigravity-copilot-grok-build/)
* [Microsoft Security, When prompts become shells: RCE in AI agent frameworks](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/)
* [Help Net Security, TrustFall coverage](https://www.helpnetsecurity.com/2026/05/07/trustfall-ai-coding-cli-vulnerability-research/)
* [Adversa AI, Top Agentic AI security resources, June 2026](https://adversa.ai/blog/top-agentic-ai-security-resources-june-2026/)

---

*This is the fastest-moving area of AI security as of June 2026. Attack techniques in this category are being disclosed monthly. This document will be updated as the landscape develops.*
