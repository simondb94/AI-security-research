# OWASP Top 10 for Agentic Applications 2026

Last reviewed: June 2026

The OWASP Top 10 for Agentic Applications, published by the OWASP GenAI Security Project's Agentic Security Initiative (ASI), is a separate and distinct framework from the OWASP Top 10 for LLM Applications. Where the LLM Top 10 addresses risks in language model deployments, this framework addresses risks specific to autonomous AI systems that plan, act, and make decisions across complex workflows, systems that do not just generate content, but execute actions with real world consequences.

The official risk identifiers are ASI01 through ASI10. This document maps each risk to its SOC relevance, detection angles, and practical mitigation guidance.

---

## ASI01:2026, Agent Goal Hijack

**Description:**
An adversary redirects an agent's goals, plans, or decision path through injected instructions or poisoned content, causing the agent to pursue outcomes its operator never intended. Prompt injection, direct or indirect, is the dominant mechanism, but the risk is defined by the outcome: the agent's objective itself is captured.

**Why it is more severe than LLM prompt injection:**
In a standard LLM, a successful injection produces a bad response. In an agentic context, it captures the agent's goal, and every subsequent action the agent takes, using its legitimate credentials and permissions, serves the attacker's objective. The actions are authorised. The intent is adversarial.

**SOC relevance:**
* Any content source the agent reads is an attack surface
* Logs will show authorised agent actions, the signal is behavioural deviation from the assigned task scope, not a policy violation

**Detection angle:**
Log agent action context alongside the action itself, what triggered the action, what input the agent was processing at the time. Alert on actions that are semantically disconnected from the assigned task.

**Mitigation:**
* Treat all retrieved external content as untrusted
* Implement input sanitisation at the retrieval layer before content is passed to the model
* Require explicit human approval for high-consequence actions regardless of trigger source

---

## ASI02:2026, Tool Misuse and Exploitation

**Description:**
An agent uses its connected tools in unsafe ways, through unsafe chaining, ambiguous instructions, or manipulated tool outputs, or an attacker exploits the tool interfaces themselves to gain access or cause harm. Increasingly this surface is mediated by Model Context Protocol (MCP).

**MCP-specific risks:**
* Prompt injection delivered through MCP tool responses, the tool response contains adversarial instructions that the agent processes as trusted content
* Agents connecting to unapproved MCP servers discovered at runtime
* Tool call sequences that individually appear benign but collectively constitute a policy violation
* Confused deputy, an agent with broad tool permissions manipulated into using tools outside its intended scope, authenticated by the agent's own credentials

**Detection angle:**
* Maintain an approved MCP server registry, alert on any agent connecting to a server not on the list
* Log all MCP tool calls with full input/output context
* Apply rate limiting and anomaly detection to tool invocation patterns

**Mitigation:**
* Validate all MCP server responses before passing to the agent as trusted context
* Restrict agent tool access to an explicit approved list, no dynamic tool discovery in production
* Implement tool call authorisation, certain tool invocations require secondary approval

---

## ASI03:2026, Identity and Privilege Abuse

**Description:**
An attacker exploits delegated trust, inherited credentials, or role chains, agents operating with delegated human identity, over-broad service account identity, or no clearly defined identity, to gain unauthorised access or take unauthorised actions.

**The accountability gap:**
When an agent takes a harmful action using a human user's delegated token, who is accountable? The user who authorised the delegation? The developer who deployed the agent? The platform that hosts it? This ambiguity is exploited by attackers who use agents as proxies precisely because the accountability chain is unclear.

**Why this is endemic:**
Scoping permissions precisely takes time and domain knowledge. Under deadline pressure, developers grant broad access and move on. The agent works. The security debt is invisible until exploitation. Industry surveys through 2025 and 2026 consistently report that the overwhelming majority of non human identities carry privileges beyond what their function requires, see [NHI-Security.md](./NHI-Security.md) for sourced figures.

**Detection angle:**
Ensure all agent actions are logged with the agent's own identity, not only the delegating human's identity. The audit trail must distinguish "user did X" from "agent acting on behalf of user did X via Y trigger." Baseline what resources each agent actually accesses in normal operation and alert on access outside that baseline, even if technically permitted.

**Mitigation:**
* Every agent should have its own distinct identity, not operate under a human user's credentials
* Implement dedicated agent identity scopes that are distinguishable in logs from human activity
* Require explicit, time-limited delegation tokens rather than persistent access grants
* Enforce least privilege scoping at deployment and review agent permissions on a defined schedule

---

## ASI04:2026, Agentic Supply Chain Vulnerabilities

**Description:**
Compromised or tampered third-party agents, tools, plugins, registries, MCP servers, or update channels introduce risk that executes within the agent's legitimate execution environment, using the agent's permissions, making malicious activity indistinguishable from normal operation.

**Current threat landscape:**
Community skill and tool registries for agentic frameworks have been observed distributing malicious packages that exfiltrate credentials and execute commands. The malicious activity mimics intended agent behaviour and evades behavioural detection because it uses the same execution pathway. The TrustFall and SymJack techniques (see [AI-Coding-Agent-Security.md](./AI-Coding-Agent-Security.md)) exploit exactly this trust boundary.

**Detection angle:**
* Maintain a software bill of materials (SBOM) for all agent deployments
* Monitor for unexpected network calls from agent processes, particularly to infrastructure not in the expected operational scope
* Treat framework and MCP server updates as software releases requiring security review

**Mitigation:**
* Pin all dependency versions explicitly
* Operate a private, vetted registry for agent skills and tools rather than consuming community registries directly
* Review and approve all component updates before production deployment

---

## ASI05:2026, Unexpected Code Execution

**Description:**
Agent-generated or agent-invoked code becomes a path to unintended execution, system compromise, or sandbox escape. Coding agents, code-interpreter tools, and any agent permitted to write or run code carry this risk by design, the capability that makes them useful is the capability that makes them dangerous.

**Why this matters in 2026:**
The first half of 2026 produced named, in the wild RCE techniques against production AI coding agents, exploiting configuration auto-execution and trust boundary failures to run attacker code on developer machines. See [AI-Coding-Agent-Security.md](./AI-Coding-Agent-Security.md) for the dedicated treatment.

**SOC relevance:**
Code execution by an agent process looks like the agent doing its job. The signal is in the lineage, what triggered the execution, what the code does next, and whether child processes, file writes, or network connections fall outside the agent's expected pattern.

**Detection angle:**
* Monitor agent processes spawning shells or interpreters, correlate with the triggering context
* Alert on writes to agent configuration paths by unexpected processes
* In CI/CD, alert on agent-invoked execution on non-main branches or from untrusted inputs

**Mitigation:**
* Execute agent-generated code only inside sandboxes with no default network egress
* Require human review before agent-written code reaches production execution paths
* Disable auto-execution of tools and servers on repository open or project load

---

## ASI06:2026, Memory and Context Poisoning

**Description:**
An adversary corrupts an agent's stored context, long term memory, embeddings, RAG stores, or shared memory in multi agent systems, to bias future reasoning and actions persistently.

**Why this is distinct from goal hijack:**
Goal hijack affects the current task. Memory poisoning affects all future sessions until the memory is explicitly cleared. The attack is temporally decoupled from its effect, the injection event may be days before any visible malicious action.

**Detection angle:**
Monitor writes to agent memory stores. Apply the same injection pattern detection used for input scanning to content being written to memory. Audit memory contents on a regular schedule. See Detection-Ideas.md Detections 4 and 8.

**Mitigation:**
* Treat agent memory stores as privileged data stores, apply access controls and audit logging
* Implement semantic validation before writing to long term memory
* Provide a clear mechanism to audit and selectively clear agent memory

---

## ASI07:2026, Insecure Inter-Agent Communication

**Description:**
In multi agent architectures, agents pass instructions and context to each other. If there is no robust authorisation and integrity mechanism between agents, a compromised or manipulated agent can issue instructions to downstream agents that would never be authorised if they originated from a human user.

**Attack scenario:**
An attacker manipulates an orchestrator agent through indirect prompt injection. The orchestrator issues modified instructions to a specialist communication agent. The communication agent sends phishing emails to all contacts in the user's address book, because it received what appeared to be a legitimate instruction from the orchestrator.

**Detection angle:**
Log inter-agent communications with enough fidelity to reconstruct the full instruction chain. Implement instruction integrity validation, downstream agents should verify that received instructions are consistent with the original task scope before executing.

**Mitigation:**
* Treat inter-agent instructions with the same scepticism as external inputs
* Implement cryptographic signing or structured authorisation tokens for inter-agent communications in high-trust pipelines
* Each agent should validate received instructions against its own defined scope, not execute anything it receives blindly

---

## ASI08:2026, Cascading Agent Failures

**Description:**
A failure, compromise, or bad decision in one agent propagates through connected agents, tools, and systems, producing system-level impact far beyond the initial fault. Autonomy plus interconnection means failures are no longer isolated mistakes, they are chain reactions.

**Why agentic systems are prone to this:**
Agents act at machine speed, trust each other's outputs, and frequently share memory, tools, and credentials. A single poisoned context or hijacked goal at the top of a pipeline can be amplified by every downstream agent acting correctly on bad input.

**SOC relevance:**
The blast radius of an agentic incident is defined by architecture, not by the initial compromise. Incident response for agentic systems must assume propagation and trace the full chain, not just the first affected agent.

**Detection angle:**
* Monitor for bursts of correlated agent activity across multiple systems within short windows
* Define and alert on blast-radius thresholds, the number of systems an agent pipeline touches per task

**Mitigation:**
* Architectural isolation between agents, compromise of one must not cascade by default
* Circuit breakers, rate limits and kill switches at pipeline level, not just per agent
* Test policy or autonomy expansions against replayed production agent activity in an isolated environment before deployment, gate expansion on blast-radius caps holding

---

## ASI09:2026, Human-Agent Trust Exploitation

**Description:**
Agents present as confident, fluent, and authoritative, which leads humans to trust their outputs and recommendations without independent verification. Attackers exploit this by manipulating the agent into delivering adversarial recommendations through a trusted interface, the human becomes the final step of the attack chain.

**The autonomy trade-off:**
The value of an agentic system is its ability to operate without constant human supervision. The risk is that oversight degrades into rubber-stamping, approval gates that exist on paper but are clicked through in practice because the agent is usually right.

**Mitigation approach:**
Implement tiered authorisation based on action consequence, and design approval steps that surface the evidence, not just the recommendation:

| Action Category | Examples | Authorisation Required |
|-----------------|----------|----------------------|
| Low consequence | Read files, retrieve information, draft responses | Agent autonomous |
| Medium consequence | Send messages, create records, call external APIs | Logged and reviewable |
| High consequence | Delete data, execute code, financial transactions | Explicit human approval |
| Irreversible | Permanent deletion, external data sharing, privilege changes | Human approval + audit trail |

---

## ASI10:2026, Rogue Agents

**Description:**
An agent's decision-making process is seized or drifts to the point where the agent itself operates as a malicious or misaligned actor, pursuing objectives contrary to its operator's intent while continuing to look superficially legitimate. This is the convergence point of the preceding nine risks, a hijacked goal, poisoned memory, or compromised supply chain component that has matured into persistent adversarial behaviour.

**SOC relevance:**
A rogue agent is the insider threat model applied to software, legitimate credentials, legitimate access, malicious intent. Detection rests on behavioural deviation over time, not on any single malicious event.

**Detection angle:**
* Maintain per-agent behavioural baselines and alert on sustained drift, not just point anomalies
* Audit agent memory and configuration on a schedule, rogue behaviour usually has a persistent artefact
* Correlate agent activity across sessions, rogue patterns emerge in the aggregate

**Mitigation:**
* Rigid operational constraints and guardrails defined at deployment
* Kill switches that operate independently of the agent's own execution environment
* Scheduled re-validation of agent behaviour against its original task definition

---

## Cross-cutting: logging and observability

Not a numbered risk, but the precondition for detecting all ten. The absence of AI-specific logging, agent decisions, tool invocations, memory reads and writes, inter-agent communications, retrieved context, means attacks are undetectable and unattributable.

| Log Source | Minimum Required Data |
|------------|----------------------|
| LLM API gateway | Request and response pairs, token counts, caller identity, latency, model version |
| Agent action log | Action type, target resource, triggering input, authorising identity, timestamp |
| Memory store | Read and write events, content hash, triggering agent, timestamp |
| Tool invocations | Tool name, input parameters, response, invoking agent, timestamp |
| Inter-agent communications | Sender agent, receiver agent, instruction content, timestamp |
| Identity and IAM | NHI creations, permission grants, access events for all AI-associated identities |

For Detection & Response engineers, defining these logging requirements and building the pipelines is a higher-value contribution than any individual detection rule. The rules depend on the data. The data does not exist by default.

---

## Relationship to OWASP LLM Top 10

The two frameworks are complementary, not redundant. LLM risks (prompt injection, model extraction, insecure output handling) remain relevant in agentic deployments. The Agentic Top 10 addresses the additional risk layer introduced by autonomy, tool access, persistent memory, multi agent orchestration, and real world action capability. ASI07, ASI08, and ASI10 in particular have no LLM Top 10 equivalent, they exist only because agents act.

Both frameworks should inform the security posture of any agentic AI deployment.

---

## References

* [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
* [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
* [Microsoft: Addressing the OWASP Top 10 Risks in Agentic AI with Copilot Studio](https://www.microsoft.com/en-us/security/blog/2026/03/30/addressing-the-owasp-top-10-risks-in-agentic-ai-with-microsoft-copilot-studio/)
* [Bessemer Venture Partners: Securing AI Agents 2026](https://www.bvp.com/atlas/securing-ai-agents-the-defining-cybersecurity-challenge-of-2026)

---

*This document reflects the OWASP Top 10 for Agentic Applications (ASI01–ASI10) as of June 2026. The framework is actively developed, check the OWASP GenAI Security Project for updates. An earlier version of this document used informal category labels; it was corrected in June 2026 to match the official ASI taxonomy.*
