# Detection Ideas, AI Security Threats

Last reviewed: March 2026

Draft detection concepts for AI specific threats. These are not production ready rules, they are starting points for detection engineering, written from a SOC analyst perspective.

Where KQL is shown, it assumes a Microsoft Sentinel environment. Logic is illustrative - field names, table names and thresholds will vary by deployment.

---

## Detection 1, Anomalous LLM API call volume, potential model extraction or DoS

**Threat mapped to:** MITRE ATLAS AML.T0035 ML Model Inference API Access, OWASP LLM10 Unbounded Consumption

**Rationale:**
Model extraction attacks and resource exhaustion attacks both produce high volume API call patterns. Legitimate users don't typically send thousands of structurally varied requests in rapid succession. Flagging velocity anomalies is a low complexity, high value first signal.

**Concept:**
```kql
// Detect unusual spike in LLM API calls from a single source
// Adjust threshold and timewindow based on your environment baseline
AzureDiagnostics
| where ResourceType == "OPENAI" or Category == "RequestResponse"
| where TimeGenerated > ago(1h)
| summarize CallCount = count(), UniqueEndpoints = dcount(requestUri_s) 
    by CallerIPAddress, bin(TimeGenerated, 5m)
| where CallCount > 500  // tune to your baseline
| project TimeGenerated, CallerIPAddress, CallCount, UniqueEndpoints
| order by CallCount desc
```

**What to tune:**
- Baseline normal call volume per user / IP over 30 days
- Set threshold at mean + 3 standard deviations
- Separate alert thresholds for internal service accounts vs external IPs

---

## Detection 2, LLM output containing instruction like patterns, potential prompt injection indicator

**Threat mapped to:** OWASP LLM01 Prompt Injection, OWASP LLM07 System Prompt Leakage

**Rationale:**
If an LLM application logs its outputs, outputs that structurally resemble instructions, imperative verbs, rule lists, "you must / you must not" patterns, in response to user queries may indicate successful system prompt extraction or injection. This is a heuristic not a definitive signal, high false positive rate expected but useful as a hunting query.

**Concept:**
```kql
// Hunt for LLM outputs that resemble instruction/prompt content
// Assumes LLM request/response pairs are logged to a custom table
LLMApplicationLogs_CL
| where TimeGenerated > ago(24h)
| where ResponseText_s matches regex @"(?i)(ignore (all )?(previous|prior|above) instructions|you are now|your new instructions|system prompt|forget everything)"
| project TimeGenerated, UserId_s, SessionId_s, RequestText_s, ResponseText_s
| order by TimeGenerated desc
```

**Notes:**
- This query depends on your application logging LLM inputs and outputs, advocate for this as a standard logging requirement for any LLM deployment
- Output logging raises data privacy considerations, important to ensure PII is handled appropriately
- Tune regex patterns based on observed prompt injection attempts in your environment

---

## Detection 3, AI agent action outside expected scope

**Threat mapped to:** OWASP LLM06 Excessive Agency, ATLAS AML.TA0005 Execution

**Rationale:**
In agentic AI deployments, agents should have a well defined operational scope. Actions outside that scope, unexpected file paths accessed, emails sent to external domains, API calls to new endpoints are high fidelity indicators of manipulation or misconfiguration.

**Concept, requires agent action logging:**
```kql
// Detect AI agent actions outside expected operational scope
// Requires agent telemetry to be forwarded to Sentinel
AIAgentTelemetry_CL
| where TimeGenerated > ago(1h)
| where ActionType_s in ("SendEmail", "WriteFile", "ExecuteCode", "ExternalAPICall")
// Flag emails sent to domains not in approved list
| where ActionType_s == "SendEmail" 
    and not (EmailRecipientDomain_s in ("yourdomain.com", "approveddomain.com"))
| project TimeGenerated, AgentId_s, AgentName_s, ActionType_s, 
          EmailRecipient_s, EmailRecipientDomain_s, TriggerContext_s
| order by TimeGenerated desc
```

**What to build toward:**
Agent action logging is immature in most deployments as of 2026. Advocating for standardised agent telemetry, action type, target resource, triggering context, authorising identity is a detection engineering priority. You cannot detect what you cannot see.

---

## Detection 4, Potential RAG poisoning indicator, document with embedded instructions

**Threat mapped to:** OWASP LLM08 Vector and Embedding Weaknesses, ATLAS AML.T0020 Poison Training Data

**Rationale:**
Documents ingested into a RAG system should not contain instruction like language. A legitimate business document rarely contains phrases like "When answering questions about X, always Y." Flagging documents with embedded instruction patterns before they are indexed provides a preventive control.

**Concept preingestion scan:**
```python
# Python pseudo code for preingestion content inspection
# Run against documents before adding to RAG vector store

import re

INJECTION_PATTERNS = [
    r"(?i)ignore (all )?(previous|prior|above) instructions",
    r"(?i)you (are|must|should|will) (now|always|never)",
    r"(?i)when (asked|answering|responding).{0,50}(always|never|must)",
    r"(?i)system:\s",
    r"(?i)assistant:\s",
    r"(?i)forget (everything|all|your instructions)",
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
- This is a starting point, sophisticated injections use encoding, whitespace manipulation or semantic tricks to evade simple regex
- Consider semantic similarity scoring - flag document sections that are semantically similar to known injection prompts using an embedding model
- This logic is a good candidate for a GitHub project demonstrating practical AI security tooling

---

## Detection 5, New AI service account or agent credential, visibility control

**Threat mapped to:** OWASP LLM06 Excessive Agency, Agentic AI, Shadow AI

**Rationale:**
Shadow AI agents deployed without security review represent an unmonitored attack surface. Alerting on new service account creations associated with LLM or AI service principals provides visibility into agent deployments that may have bypassed governance processes.

**Concept:**
```kql
// Alert on new service principal / app registration with AI related names or permissions
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in ("Add service principal", "Add application", "Add app role assignment")
| where TargetResources has_any ("openai", "cognitive", "llm", "gpt", "ai-", "-ai", "agent", "copilot")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

**What this catches:**
New AI service principals being registered, potentially indicating a new agent deployment. Combine with a review workflow, any new AI service principal triggers a security review ticket before it is granted production access.

---

## Logging requirements, what you need before any of this works

Detection is only possible if the right data is being collected. For AI security specifically, advocate for:

| Log source | What to capture | Why |
|------------|-----------------|-----|
| LLM API gateway | Request + response pairs, token counts, caller identity, latency | Enables prompt injection detection, model extraction detection, abuse detection |
| AI agent telemetry | Action type, target resource, triggering input, authorising identity | Enables scope violation detection, exfiltration detection |
| Vector store / RAG | Document ingest events, query logs, retrieval results | Enables RAG poisoning detection, data lineage |
| Model training pipeline | Dataset access, training job parameters, model version registry | Enables supply chain and poisoning detection |
| Identity / IAM | Service principal creations, permission grants for AI workloads | Enables shadow AI detection, excessive agency detection |

**The honest state of play in most SOCs as of March 2026:** Very few organisations have any of these log sources configured, forwarded to a SIEM or covered by detection rules. This is the gap. Engineers who can define these requirements, build the log pipelines and write the detection logic are ahead of the field.

---

*These are working notes from a Detection and Response perspective. Detection logic is conceptual and requires adaptation to specific environments.*
