# OWASP Top 10 for Agentic Applications 2026

Last reviewed: June 2026

The OWASP Top 10 for Agentic Applications is a separate and distinct framework from the OWASP Top 10 for LLM Applications. Where the LLM Top 10 addresses risks in language model deployments, this framework addresses risks specific to autonomous AI systems that plan, act, and make decisions across complex workflows, systems that do not just generate content, but execute actions with real world consequences.

This document maps each risk to its SOC relevance, detection angles, and practical mitigation guidance.

---

## AA1:2026, Prompt Injection in Agentic Contexts

**Description:** 
An adversary manipulates an agent's inputs, via direct user input or via content the agent retrieves from external sources (indirect prompt injection), causing the agent to take actions outside its intended scope or contrary to its operator's intent.

**Why it is more severe in agentic contexts:** 
In a standard LLM, a successful prompt injection produces a bad response. In an agentic context, it causes the agent to take real actions, send emails, execute code, modify files, call APIs, using its legitimate credentials and permissions. The action is authorised. The intent is adversarial.

**SOC relevance:** 
* Any content source the agent reads is an attack surface
* Logs will show authorised agent actions, the signal is behavioural deviation from expected task scope, not a policy violation

**Detection angle:** 
Log agent action context alongside the action itself, what triggered the action, what input the agent was processing at the time. Alert on actions that are semantically disconnected from the assigned task.

**Mitigation:** 
* Treat all retrieved external content as untrusted
* Implement input sanitisation at the retrieval layer before content is passed to the model
* Require explicit human approval for high-consequence actions regardless of trigger source

---

## AA2:2026, Excessive Agency

**Description:** 
An agent is granted permissions, tool access, or capabilities beyond what is required for its defined function. When the agent is manipulated or malfunctions, the blast radius is proportional to its permissions.

**Why this is endemic:** 
Scoping permissions precisely takes time and domain knowledge. Under deadline pressure, developers grant broad access and move on. The agent works. The security debt is invisible until exploitation.

**SOC relevance:** 
* Over-privileged agents are the AI equivalent of the over-privileged service account, a known, manageable risk with documented mitigation
* 97% of NHIs carry excessive privileges as of 2026

**Detection angle:** 
Baseline what resources each agent actually accesses in normal operation. Alert on access to resources outside that baseline, even if the access is technically permitted.

**Mitigation:** 
* Enforce least privilege scoping at deployment, define the minimum permissions required and grant only those
* Implement just-in-time access for sensitive operations, permissions granted for a specific task and revoked immediately after
* Review agent permissions on a defined schedule, quarterly at minimum

---

## AA3:2026, Insufficient Authorisation Between Agents

**Description:** 
In multi agent architectures, agents pass instructions and context to each other. If there is no robust authorisation mechanism between agents, a compromised or manipulated agent can issue instructions to downstream agents that would not be authorised if they originated from a human user.

**Attack scenario:** 
An attacker manipulates an orchestrator agent through indirect prompt injection. The orchestrator issues modified instructions to a specialist communication agent. The communication agent sends phishing emails to all contacts in the user's address book, because it received what appeared to be a legitimate instruction from the orchestrator.

**Detection angle:** 
Log inter-agent communications. Implement instruction integrity validation, downstream agents should verify that received instructions are consistent with the original task scope before executing.

**Mitigation:** 
* Treat inter-agent instructions with the same scepticism as external inputs
* Implement cryptographic signing or structured authorisation tokens for inter-agent communications in high-trust pipelines
* Each agent should validate received instructions against its own defined scope, not execute anything it receives blindly

---

## AA4:2026, Memory and Context Manipulation

**Description:** 
An adversary manipulates an agent's memory stores, long term memory, retrieved context, or shared memory in multi agent systems, to influence future agent behaviour persistently.

**Why this is distinct from prompt injection:** 
Prompt injection affects a single session. Memory manipulation affects all future sessions until the memory is explicitly cleared. The attack is temporally decoupled from its effect, the injection event may be days before any visible malicious action.

**Detection angle:** 
Monitor writes to agent memory stores. Apply the same injection pattern detection used for input scanning to content being written to memory. Audit memory contents on a regular schedule.

**Mitigation:** 
* Treat agent memory stores as privileged data stores, apply access controls and audit logging
* Implement semantic validation before writing to long term memory
* Provide a clear mechanism to audit and selectively clear agent memory

---

## AA5:2026, Supply Chain Vulnerabilities in Agent Components

**Description:** 
The libraries, frameworks, plugins, and community-contributed skills that power AI agents introduce supply chain risk. A malicious or compromised component executes within the agent's legitimate execution environment, using the agent's permissions, making its activity indistinguishable from normal operation.

**Current threat landscape:** 
Community skill registries for agentic frameworks have been observed distributing malicious packages that exfiltrate credentials and execute commands. The malicious activity mimics intended agent behaviour and evades behavioural detection because it uses the same execution pathway.

**Detection angle:** 
* Maintain a software bill of materials (SBOM) for all agent deployments
* Monitor for unexpected network calls from agent processes, particularly to infrastructure not in the expected operational scope
* Treat framework updates as software releases requiring security review

**Mitigation:** 
* Pin all dependency versions explicitly
* Operate a private, vetted registry for agent skills and tools rather than consuming community registries directly
* Review and approve all component updates before production deployment

---

## AA6:2026, Sensitive Data Exposure via Agent Access

**Description:** 
Agents with broad data access permissions may expose sensitive information through their outputs, logs, or retrieved context, intentionally through exploitation or unintentionally through misconfiguration.

**Key exposure scenarios:** 
* An agent summarises a document that contains PII and includes that PII in its response, which is logged in plaintext
* A RAG-enabled agent retrieves documents beyond its intended scope due to overly broad vector store permissions
* An agent's conversation history, including retrieved sensitive content, is stored without appropriate access controls

**SOC relevance:** 
Data Loss Prevention (DLP) controls built for human-generated data transfers do not intercept agent-generated outputs as reliably. Agents can exfiltrate via API call, email, file write, or conversation log, all of which may bypass existing DLP rules.

**Detection angle:** 
Apply content inspection to agent outputs, not just agent inputs. Flag outputs containing patterns consistent with PII, credentials, or internal classification markers.

---

## AA7:2026, Insecure Tool Invocation and MCP Abuse

**Description:** 
Agents interact with external services and data sources through tool interfaces, increasingly via Model Context Protocol (MCP). Insufficient validation of tool inputs and outputs, absence of an approved tool registry, or misconfigured tool permissions create an exploitable attack surface at the tool layer.

**MCP-specific risks:** 
* Malicious MCP servers registered in community registries
* Prompt injection delivered through MCP tool responses (the tool response contains adversarial instructions)
* Agents connecting to unapproved MCP servers discovered at runtime
* Tool call sequences that individually appear benign but collectively constitute a policy violation

**Detection angle:** 
* Maintain an approved MCP server registry, alert on any agent connecting to a server not on the list
* Log all MCP tool calls with full input/output context
* Apply rate limiting and anomaly detection to tool invocation patterns

**Mitigation:** 
* Validate all MCP server responses before passing to the agent as trusted context
* Restrict agent tool access to an explicit approved list, no dynamic tool discovery in production
* Implement tool call authorisation, certain tool invocations require secondary approval

---

## AA8:2026, Inadequate Human Oversight and Control

**Description:** 
Autonomous agents making consequential decisions without sufficient human oversight create conditions where errors, manipulations, or misaligned behaviour escalate without a circuit breaker.

**The autonomy trade-off:** 
The value of an agentic system is its ability to operate without constant human supervision. The risk is that this same property allows errors and attacks to propagate and complete before a human can intervene.

**Mitigation approach:** 
Implement tiered authorisation based on action consequence:

| Action Category | Examples | Authorisation Required |
|-----------------|----------|----------------------|
| Low consequence | Read files, retrieve information, draft responses | Agent autonomous |
| Medium consequence | Send messages, create records, call external APIs | Logged and reviewable |
| High consequence | Delete data, execute code, financial transactions | Explicit human approval |
| Irreversible | Permanent deletion, external data sharing, privilege changes | Human approval + audit trail |

---

## AA9:2026, Identity and Authorisation Confusion

**Description:** 
Agents operating with delegated human identity, service account identity, or no clearly defined identity create ambiguity about who or what authorised a given action, undermining both security controls and accountability.

**The accountability gap:** 
When an agent takes a harmful action using a human user's delegated token, who is accountable? The user who authorised the delegation? The developer who deployed the agent? The platform that hosts it? This ambiguity is exploited by attackers who use agents as proxies precisely because the accountability chain is unclear.

**Detection angle:** 
Ensure all agent actions are logged with the agent's own identity, not only the delegating human's identity. The audit trail must distinguish "user did X" from "agent acting on behalf of user did X via Y trigger."

**Mitigation:** 
* Every agent should have its own distinct identity, not operate under a human user's credentials
* Implement dedicated agent identity scopes that are distinguishable in logs from human activity
* Require explicit, time-limited delegation tokens rather than persistent access grants

---

## AA10:2026, Lack of AI-Specific Logging and Observability

**Description:** 
The absence of AI-specific logging, covering agent decisions, tool invocations, memory reads and writes, inter-agent communications, and retrieved context, means that attacks, errors, and policy violations are undetectable and unattributable.

**Current state:** 
Most SOCs in 2026 have no AI-specific logging configured, no detection rules for AI threats, and no defined logging requirements for AI deployments. Security teams are operating blind on the fastest-growing attack surface in enterprise environments.

**What needs to be logged:**

| Log Source | Minimum Required Data |
|------------|----------------------|
| LLM API gateway | Request and response pairs, token counts, caller identity, latency, model version |
| Agent action log | Action type, target resource, triggering input, authorising identity, timestamp |
| Memory store | Read and write events, content hash, triggering agent, timestamp |
| Tool invocations | Tool name, input parameters, response, invoking agent, timestamp |
| Inter-agent communications | Sender agent, receiver agent, instruction content, timestamp |
| Identity and IAM | NHI creations, permission grants, access events for all AI-associated identities |

**SOC priority:** 
For Detection & Response engineers, defining these logging requirements and building the pipelines to deliver the data to a SIEM is a higher-value contribution than any individual detection rule. The rules depend on the data. The data does not exist by default.

---

## Relationship to OWASP LLM Top 10

The OWASP Top 10 for LLMs and the OWASP Top 10 for Agentic Applications are complementary, not redundant. LLM risks (prompt injection, model extraction, insecure output handling) remain relevant in agentic deployments. The Agentic Top 10 addresses the additional risk layer introduced by autonomy, tool access, persistent memory, multi agent orchestration, and real world action capability.

Both frameworks should inform the security posture of any agentic AI deployment.

---

## References

* [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
* [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
* [Microsoft: Addressing OWASP Agentic Top 10 with Copilot Studio](https://www.microsoft.com/en-us/security/blog/2026/03/30/addressing-the-owasp-top-10-risks-in-agentic-ai-with-microsoft-copilot-studio/)
* [Bessemer Venture Partners: Securing AI Agents 2026](https://www.bvp.com/atlas/securing-ai-agents-the-defining-cybersecurity-challenge-of-2026)

---

*This document reflects the OWASP Agentic Top 10 as of June 2026. The framework is actively developed, check the OWASP GenAI Security Project for updates.*
