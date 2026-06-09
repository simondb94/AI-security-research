# Detection Ideas, AI Security Threats

Last reviewed: June 2026

Draft detection concepts for AI-specific threats. These are not production-ready rules, they are starting points for detection engineering, written from a SOC analyst perspective.

Where KQL is shown, it assumes a Microsoft Sentinel environment. Logic is illustrative, field names, table names, and thresholds will vary by deployment. Adapt to your environment before use.

**Validation status convention.** Each detection is tagged so the reader knows how far it has been tested:

- **Concept**, derived from threat analysis, not yet run against telemetry
- **Lab-validated**, executed against synthetic or demo telemetry, sample output included
- **Field-informed**, shaped by patterns observed in production (sanitised)

Honesty matters more than a long list. A query that has never been run is a hypothesis, not a detection, and is labelled as such.

---

## Detection 1, Anomalous LLM API call volume (model extraction / DoS)

**Status:** Concept

**Threat mapped to:** MITRE ATLAS AML.T0035 ML Model Inference API Access, OWASP LLM10 Unbounded Consumption

**Rationale:** Model extraction attacks and resource exhaustion attacks both produce high-volume API call patterns. Legitimate users do not typically send thousands of structurally varied requests in rapid succession. Flagging velocity anomalies is a low-complexity, high value first signal.

```
// Detect unusual spike in LLM API calls from a single source
// Adjust threshold and time window based on your environment baseline
AzureDiagnostics
| where ResourceType == "OPENAI" or Category == "RequestResponse"
| where TimeGenerated > ago(1h)
| summarize
    CallCount = count(),
    UniqueEndpoints = dcount(requestUri_s)
    by CallerIPAddress, bin(TimeGenerated, 5m)
| where CallCount > 500  // tune to your baseline
| project TimeGenerated, CallerIPAddress, CallCount, UniqueEndpoints
| order by CallCount desc
```

**What to tune:**

- Baseline normal call volume per user/IP over 30 days
- Set threshold at mean + 3 standard deviations
- Separate thresholds for internal service accounts vs external IPs

---

## Detection 2, LLM output containing instruction-like patterns (prompt injection indicator)

**Status:** Concept

**Threat mapped to:** OWASP LLM01 Prompt Injection, OWASP LLM07 System Prompt Leakage

**Rationale:** Outputs that structurally resemble instructions in response to user queries may indicate successful system prompt extraction or injection. High false positive rate expected, use as a hunting query rather than a live alert.

```
// Hunt for LLM outputs that resemble instruction/prompt content
// Assumes LLM request/response pairs are logged to a custom table
LLMApplicationLogs_CL
| where TimeGenerated > ago(24h)
| where ResponseText_s matches regex
    @"(?i)(ignore (all )?(previous|prior|above) instructions|you are now|your new instructions|system prompt|forget everything)"
| project TimeGenerated, UserId_s, SessionId_s, RequestText_s, ResponseText_s
| order by TimeGenerated desc
```

**Notes:**

- Requires your application to log LLM inputs and outputs, advocate for this as a standard requirement for any LLM deployment
- Output logging raises data privacy considerations, ensure PII is handled appropriately
- Tune regex based on observed prompt injection attempts in your environment

---

## Detection 3, AI agent action outside expected scope

**Status:** Concept

**Threat mapped to:** OWASP LLM06 Excessive Agency, OWASP Agentic AA2 Excessive Agency, ATLAS AML.TA0005 Execution

**Rationale:** In agentic deployments, agents should have a well-defined operational scope. Actions outside that scope, unexpected file paths, emails to external domains, calls to new API endpoints, are high-fidelity indicators of manipulation or misconfiguration.

```
// Detect AI agent actions outside expected operational scope
// Requires agent telemetry forwarded to Sentinel
AIAgentTelemetry_CL
| where TimeGenerated > ago(1h)
| where ActionType_s in ("SendEmail", "WriteFile", "ExecuteCode", "ExternalAPICall")
| where ActionType_s == "SendEmail"
    and not (EmailRecipientDomain_s in ("yourdomain.com", "approveddomain.com"))
| project
    TimeGenerated,
    AgentId_s,
    AgentName_s,
    ActionType_s,
    EmailRecipient_s,
    EmailRecipientDomain_s,
    TriggerContext_s
| order by TimeGenerated desc
```

**What to build toward:** Agent action logging is immature in most deployments. Advocating for standardised agent telemetry, action type, target resource, triggering context, authorising identity, is a detection engineering priority. You cannot detect what you cannot see.

---

## Detection 4, Potential RAG poisoning (document with embedded instructions)

**Status:** Concept

**Threat mapped to:** OWASP LLM08 Vector and Embedding Weaknesses, OWASP Agentic AA4 Memory and Context Manipulation, ATLAS AML.T0020 Poison Training Data

**Rationale:** Documents ingested into a RAG system should not contain instruction-like language. Flagging suspicious documents before they are indexed provides a preventive control.

```
# Pre-ingestion content scan, run before adding documents to RAG vector store
import re

INJECTION_PATTERNS = [
    r"(?i)ignore (all )?(previous|prior|above) instructions",
    r"(?i)you (are|must|should|will) (now|always|never)",
    r"(?i)when (asked|answering|responding).{0,50}(always|never|must)",
    r"(?i)system:\s",
    r"(?i)assistant:\s",
    r"(?i)forget (everything|all|your instructions)",
    r"(?i)new (persona|role|identity|instructions)",
    r"(?i)(cc|bcc|forward|email).{0,30}@",  # embedded exfil instructions
]

def scan_document_for_injection(text: str, doc_name: str) -> list:
    findings = []
    for pattern in INJECTION_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            findings.append({
                "document": doc_name,
                "pattern": pattern,
                "matches": matches
            })
    return findings
```

**Notes:**

- Sophisticated injections use encoding, whitespace manipulation, or semantic tricks to evade simple regex
- Consider semantic similarity scoring, flag document sections that are semantically similar to known injection prompts. This is the obvious next research artefact, a small embedding-based classifier scored against a corpus of known injection strings, tracked in ROADMAP.md

---

## Detection 5, New AI service account or agent credential (shadow AI visibility)

**Status:** Concept

**Threat mapped to:** OWASP Agentic AA9 Identity and Authorisation Confusion, NHI Shadow AI

**Rationale:** Shadow AI agents deployed without security review are unmonitored attack surfaces. Alerting on new service principal registrations associated with AI services provides visibility into deployments that may have bypassed governance.

```
// Alert on new service principal with AI-related names or permissions
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in (
    "Add service principal",
    "Add application",
    "Add app role assignment"
)
| where TargetResources has_any (
    "openai", "cognitive", "llm", "gpt", "ai-", "-ai",
    "agent", "copilot", "anthropic", "gemini", "bedrock", "mcp"
)
| project
    TimeGenerated,
    OperationName,
    InitiatedBy = InitiatedBy.user.userPrincipalName,
    TargetResource = tostring(TargetResources[0].displayName),
    Result
| order by TimeGenerated desc
```

---

## Detection 6, NHI credential anomaly (behavioural baseline deviation)

**Status:** Concept

**Threat mapped to:** NHI Security, OWASP Agentic AA9 Identity and Authorisation Confusion

**Rationale:** Non human identities operate within predictable patterns. A service account that always accesses two APIs suddenly accessing fifteen is a high-fidelity signal. This detection requires a baseline period before use as a live alert.

```
// Detect NHI access pattern deviation from established baseline
// Build baseline over 30 days, compare current window against it
let BaselineWindow = 30d;
let AlertWindow = 1h;
let Baseline =
    SigninLogs
    | where TimeGenerated between (ago(BaselineWindow) .. ago(AlertWindow))
    | where UserType == "ServicePrincipal" or UserType == "ManagedIdentity"
    | summarize
        AvgResourcesPerHour = dcount(ResourceDisplayName) / (BaselineWindow / 1h),
        KnownResources = make_set(ResourceDisplayName),
        KnownIPs = make_set(IPAddress)
        by UserPrincipalName;
let Current =
    SigninLogs
    | where TimeGenerated > ago(AlertWindow)
    | where UserType == "ServicePrincipal" or UserType == "ManagedIdentity"
    | summarize
        CurrentResources = make_set(ResourceDisplayName),
        CurrentIPs = make_set(IPAddress),
        AccessCount = count()
        by UserPrincipalName;
Current
| join kind=inner Baseline on UserPrincipalName
| extend
    NewResources = set_difference(CurrentResources, KnownResources),
    NewIPs = set_difference(CurrentIPs, KnownIPs)
| where array_length(NewResources) > 0
    or array_length(NewIPs) > 0
| project
    UserPrincipalName,
    AccessCount,
    NewResources,
    NewIPs,
    AvgResourcesPerHour
| order by array_length(NewResources) desc
```

---

## Detection 7, MCP tool invocation anomaly

**Status:** Concept

**Threat mapped to:** OWASP Agentic AA7 Insecure Tool Invocation and MCP Abuse

**Rationale:** Agents communicating with MCP servers outside an approved list, or invoking tools at unusual frequency, may indicate MCP tool poisoning, confused deputy exploitation, or an agent operating outside defined scope.

```
// Detect agent MCP tool calls to unapproved servers or unusual invocation patterns
// Requires MCP telemetry forwarded to Sentinel
MCPAuditLogs_CL
| where TimeGenerated > ago(1h)
| extend ServerName = tostring(parse_json(Details_s).mcpServer)
| where ServerName !in (
    "approved-server-1",
    "approved-server-2",
    "approved-internal-tools"
    // populate with your approved MCP server list
)
| summarize
    CallCount = count(),
    UniqueTools = dcount(ToolName_s),
    UniqueAgents = dcount(AgentId_s)
    by ServerName, bin(TimeGenerated, 15m)
| order by CallCount desc
```

**Companion query, high-frequency tool call anomaly:**

```
MCPAuditLogs_CL
| where TimeGenerated > ago(1h)
| summarize
    CallCount = count(),
    UniqueTargets = dcount(TargetResource_s)
    by AgentId_s, ToolName_s, bin(TimeGenerated, 5m)
| where CallCount > 100  // tune to your environment baseline
| project TimeGenerated, AgentId_s, ToolName_s, CallCount, UniqueTargets
| order by CallCount desc
```

---

## Detection 8, Agent memory store anomalous write

**Status:** Concept

**Threat mapped to:** OWASP Agentic AA4 Memory and Context Manipulation, ATLAS AML.T0020 Poison Training Data

**Rationale:** Agent memory stores should receive writes containing factual, task-relevant content. Writes containing instruction-like language, external contact information, or patterns consistent with prompt injection indicate attempted memory poisoning.

```
# Memory write validation, run before committing content to agent long-term memory
import re

MEMORY_POISON_PATTERNS = [
    r"(?i)(always|never|must|should) (cc|bcc|forward|email|send|notify)",
    r"(?i)ignore (any|all|future|subsequent) (instructions|requests|rules)",
    r"(?i)(when|whenever|if) (asked|queried|requested).{0,100}(always|never)",
    r"(?i)your (new|updated|current) (instructions|persona|role|identity)",
    r"(?i)(remember|note|important).{0,50}(always|never|must|do not)",
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # any email address
    r"https?://(?!approved-domain\.com)[^\s]+",  # external URLs not on approved list
]

def validate_memory_write(content: str, agent_id: str) -> dict:
    findings = []
    for pattern in MEMORY_POISON_PATTERNS:
        if re.search(pattern, content):
            findings.append(pattern)
    return {
        "agent_id": agent_id,
        "approved": len(findings) == 0,
        "flagged_patterns": findings,
        "content_preview": content[:200]
    }
```

---

## Detection 9, Dormant NHI credential sudden reactivation

**Status:** Concept (logic corrected June 2026, see note)

**Threat mapped to:** NHI Security, credential theft and stale credential exploitation

**Rationale:** Service accounts and API keys for deprecated agents or services are rarely decommissioned. Attackers performing reconnaissance can identify and exploit long-dormant credentials. Sudden reactivation after 30+ days of inactivity is a high-fidelity signal.

```
// Flag NHIs that were inactive for 30+ days and have now reactivated
// Logic: an NHI qualifies if its only recent activity is inside the alert window,
// and before that its last sign-in was more than DormantThreshold ago.
let DormantThreshold = 30d;
let AlertWindow = 24h;
let HistoryWindow = 180d;
// NHIs active in the recent alert window
let RecentlyActive =
    SigninLogs
    | where TimeGenerated > ago(AlertWindow)
    | where UserType in ("ServicePrincipal", "ManagedIdentity")
    | distinct UserPrincipalName;
// NHIs that had NO activity in the dormancy window before the alert window
// (i.e. silent from DormantThreshold ago back to HistoryWindow ago,
//  and silent through to the start of the alert window)
let WasDormant =
    SigninLogs
    | where TimeGenerated between (ago(HistoryWindow) .. ago(DormantThreshold))
    | where UserType in ("ServicePrincipal", "ManagedIdentity")
    | summarize LastSeenBeforeDormancy = max(TimeGenerated) by UserPrincipalName
    | join kind=leftanti (
        // exclude anything that was active during the dormancy period itself
        SigninLogs
        | where TimeGenerated between (ago(DormantThreshold) .. ago(AlertWindow))
        | where UserType in ("ServicePrincipal", "ManagedIdentity")
        | distinct UserPrincipalName
    ) on UserPrincipalName;
RecentlyActive
| join kind=inner WasDormant on UserPrincipalName
| extend DormantDays = datetime_diff('day', now(), LastSeenBeforeDormancy)
| project UserPrincipalName, LastSeenBeforeDormancy, DormantDays
| order by DormantDays desc
```

**Note on the correction:** an earlier version of this query could never return rows. It excluded every identity seen in the last 30 days, then joined that against identities required to have signed in within the last 24 hours, a window that sits inside the 30 days, so the two sets could never intersect. The corrected logic separates three windows cleanly: a history window to establish the prior baseline, a dormancy window that must be silent, and a short alert window that must show the reactivation. This is a good worked example of why a query that reads correctly still has to be run, set logic on overlapping time windows is exactly where these detections fail silently.

---

## Detection 10, AI coding agent config tampering and MCP auto-execution (TrustFall / SymJack class)

**Status:** Concept

**Threat mapped to:** OWASP Agentic AA5 Supply Chain, AA7 MCP Abuse; see AI-Coding-Agent-Security.md

**Rationale:** The TrustFall and SymJack techniques (H1 2026) achieve RCE on developer machines by causing agentic coding tools to auto-execute MCP servers or overwrite their own configuration after a repository is cloned. The high-fidelity signals are: agent config file writes (especially via symlink), MCP server processes spawning immediately after an agent launches, and credential-store access by agent-associated processes.

```
// Endpoint detection, agent config tampering and suspicious child processes
// Requires EDR/Defender for Endpoint telemetry in Sentinel (DeviceProcessEvents, DeviceFileEvents)
let AgentProcesses = dynamic([
    "claude", "cursor", "gemini", "copilot", "codex", "grok"
]);
// Agent process spawning a shell or interpreter shortly after launch
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where InitiatingProcessFileName has_any (AgentProcesses)
| where FileName in~ ("bash", "sh", "zsh", "powershell.exe", "cmd.exe", "python", "node")
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

```
// Companion, writes/symlinks targeting agent config paths
DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType in ("FileCreated", "FileModified", "SymbolicLinkCreated")
| where FolderPath has_any (".claude", ".cursor", ".gemini", ".config/mcp", ".mcp")
    or FileName has_any ("mcp.json", "settings.json", "config.json")
| where InitiatingProcessFileName !in~ ("trusted-installer-process")  // tune allowlist
| project TimeGenerated, DeviceName, AccountName,
    ActionType, FolderPath, FileName, InitiatingProcessFileName
| order by TimeGenerated desc
```

**What to tune:**

- Build an allowlist of legitimate processes that write to agent config (the agent's own update mechanism, your provisioning tooling)
- Correlate config writes with subsequent outbound network connections from the same host within a short window, that correlation is the strong signal
- In CI/CD, alert on any agent process invoked on a non-main branch

---

## Detection 11, Vulnerable agent framework retrospective hunt (Semantic Kernel CVE class)

**Status:** Concept

**Threat mapped to:** OWASP LLM03 / Agentic AA5 Supply Chain; CVE-2026-25592, CVE-2026-26030

**Rationale:** Patching an agent framework CVE closes the bug but does not tell you whether you were exploited during the vulnerable window. For each affected deployment, define the window (from first running a vulnerable version to the upgrade) and hunt over it.

```
// Concept, hunt for anomalous tool/process execution during a known vulnerable window
// Replace window bounds with the actual vulnerable period for the deployment
let VulnWindowStart = datetime(2026-05-01T00:00:00Z);  // first vulnerable version deployed
let VulnWindowEnd = datetime(2026-05-08T00:00:00Z);    // upgrade applied
DeviceProcessEvents
| where TimeGenerated between (VulnWindowStart .. VulnWindowEnd)
| where InitiatingProcessCommandLine has "semantic-kernel"
    or InitiatingProcessFileName has "python"
| where FileName in~ ("bash", "sh", "powershell.exe", "cmd.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Note:** This is a hunting concept, not a live alert, run it once per affected deployment after patching, as part of post-patch assurance.

---

## Logging requirements, the precondition for all of the above

Detection is only possible if the right data is being collected. For AI security specifically, advocate for the following log sources:

| Log Source | What to Capture | Why |
|---|---|---|
| LLM API gateway | Request and response pairs, token counts, caller identity, latency, model version | Prompt injection detection, model extraction, abuse detection |
| Agent action log | Action type, target resource, triggering input, authorising identity | Scope violation detection, exfiltration detection |
| Agent memory store | Read and write events, content written, triggering agent, timestamp | Memory poisoning detection |
| MCP tool invocations | Server name, tool name, input parameters, response, invoking agent | MCP abuse detection, tool scope validation |
| Vector store / RAG | Document ingest events, query logs, retrieval results | RAG poisoning detection, data lineage |
| Inter-agent comms | Sender agent, receiver agent, instruction content, timestamp | Goal hijacking detection |
| IAM / identity | Service principal creations, permission grants for AI workloads | Shadow AI detection, NHI lifecycle |
| Model training pipeline | Dataset access, training job parameters, model version registry | Supply chain and poisoning detection |

**The honest state of play in most SOCs as of June 2026:** The majority of organisations have none of these log sources configured, forwarded to a SIEM, or covered by detection rules. The first step is not writing detection logic, it is defining the logging requirements and building the pipeline. Detection engineers who can do both are the rarest and most valuable profile in AI security right now.

---

*These are working notes from a Detection & Response perspective. All detection logic is conceptual unless explicitly tagged otherwise, and requires adaptation to your specific environment, tooling, and baseline. Current as of June 2026.*
