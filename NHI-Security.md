# Non Human Identity (NHI) Security

Last reviewed: June 2026

Non Human Identities are the service accounts, API keys, OAuth tokens, machine certificates, SSH keys, and AI agent credentials that power modern enterprise automation. They authenticate silently, operate continuously, and in most organisations sit entirely outside formal identity governance.

In 2026, NHI security has moved from niche IAM concern to the central axis of enterprise cybersecurity.

> **June 2026 update, agentic identity is emerging as a distinct class.** The field is increasingly drawing a line between traditional NHIs (static, narrowly scoped, tied to a single system, service accounts, API keys) and *agentic identities* (dynamic, ephemeral, self-directed, acting autonomously across multiple systems). AI agents technically fall under the NHI umbrella but functionally behave differently enough that legacy NHI governance does not fit them. Emerging patterns: ephemeral, on-demand provisioning with TTL and purpose attached; PKCE for public agents; SPIFFE/SPIRE X.509 SVIDs for mTLS on internal agents; and per-task Agent IDs rather than long-lived credentials. This is a live area, the category implications are still settling through 2026.

---

## The scale of the problem

* Non human identities now outnumber human identities in enterprise environments by ratios of 100:1, with hyper-automated organisations reaching 500:1
* 68% of IT security incidents involve machine identities
* 50% of enterprises have already experienced a breach directly attributable to unmanaged NHIs
* 97% of NHIs carry excessive privileges beyond what their function requires
* Only 15% of organisations feel highly confident in their ability to prevent NHI-based attacks
* 71% of NHIs are not rotated within recommended timeframes
* The average enterprise now holds over 250, 000 NHIs across cloud environments

The identity governance programmes built over the last decade were designed for humans with managers, onboarding processes, and eventual offboarding. Machine identities have none of these properties. They are created under deadline pressure, granted broad permissions for convenience, and then never revisited.

---

## Why AI agents have accelerated the crisis

Every AI agent deployment mints new non human identities. A single agentic workflow can create dozens of new credentials in an afternoon, API keys to authenticate to downstream services, OAuth tokens for SaaS integrations, service accounts for cloud resource access.

In most organisations these credentials are:
* Created once and never rotated
* Granted excessive permissions because scoping takes time
* Owned by nobody, no accountable human identity
* Not inventoried in any CMDB or secrets management system
* Invisible to the SOC

The 2026 NHI Reality Report found that AI service-related secrets in public GitHub repositories surged 81% year-over-year in 2025, reaching 1.27 million exposed incidents. Developers move fast. Security posture degrades silently.

---

## Attack vectors against NHIs

### 1. Credential harvesting from configuration files and repositories

Hardcoded credentials remain endemic. Agents are deployed with API keys embedded in configuration files, environment variables, or source code. When those files are committed to a repository, even briefly, the credentials are exposed.

**Attack scenario:** 
A developer pushes a configuration file containing an AI agent's Azure OpenAI API key to a private GitHub repository. An automated secret scanning tool operated by a threat actor detects it within minutes. The API key provides access to the organisation's LLM deployment, including all conversation history and the ability to make API calls billed to the organisation's account.

---

### 2. Lateral movement via over-privileged agent credentials

AI agents are frequently granted administrative-scope permissions because determining minimum required permissions is time-consuming. A compromised agent credential therefore provides an attacker with a pivot point into systems the agent was never intended to touch.

**Attack scenario:** 
An AI coding assistant is granted contributor access to all repositories in an Azure DevOps organisation. An attacker who compromises the agent's service principal can enumerate, clone, and modify all codebases, including injecting malicious code into production pipelines, with no MFA challenge and no login alert that resembles human behaviour.

---

### 3. Stale credential exploitation

NHIs are rarely decommissioned. Service accounts for deprecated applications, API keys from former vendors, tokens for integrations that no longer exist, these persist indefinitely in most environments. Attackers performing reconnaissance can identify and exploit credentials that have not been used in months or years, knowing they are unlikely to be monitored.

---

### 4. Confused deputy via AI agent identity

An AI agent operating with broad permissions can be manipulated into performing actions on behalf of an attacker without the attacker ever needing to possess the credentials directly. The agent is the deputy. The attacker manipulates the agent's inputs (via prompt injection or indirect prompt injection) and the agent's own credentials execute the attack.

The attacker never touches the credentials. There is no credential theft event to detect. The audit trail shows the authorised agent doing its job.

This is the attack class that legacy identity security tooling is structurally blind to.

---

### 5. Token hijacking in multi agent pipelines

In multi agent architectures, agents pass tokens and context between each other to authenticate and authorise downstream actions. An attacker who can intercept or inject into inter-agent communication can obtain tokens that grant access to the entire pipeline's permissions, potentially spanning multiple systems.

---

## Detection approaches

### Detection: Anomalous NHI access patterns

Establish a behavioural baseline for each non human identity and alert on deviation.

```kql
// Detect service account activity outside established baseline
// Requires behavioural baselines, build over 30 days before enabling as alert
SigninLogs
| where TimeGenerated > ago(1h)
| where UserType == "ServicePrincipal" or UserType == "ManagedIdentity"
| summarize 
    AccessCount = count(),
    UniqueResources = dcount(ResourceDisplayName),
    UniqueLocations = dcount(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 15m)
| where UniqueResources > 10  // tune to baseline
    or UniqueLocations > 3    // service accounts rarely change IP
| project TimeGenerated, UserPrincipalName, AccessCount, UniqueResources, UniqueLocations
| order by UniqueResources desc
```

---

### Detection: New AI agent service principal registration

```kql
// Alert on new service principal with AI-related naming or permissions
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in (
    "Add service principal",
    "Add application",
    "Add app role assignment",
    "Add delegated permission grant"
)
| where TargetResources has_any (
    "openai", "cognitive", "llm", "gpt", "ai-", "-ai",
    "agent", "copilot", "anthropic", "gemini", "bedrock"
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

### Detection: Dormant NHI sudden reactivation

```kql
// Flag service accounts with no activity for 30+ days that suddenly authenticate
let DormantThreshold = 30d;
let RecentWindow = 1d;
let RecentActivity = 
    SigninLogs
    | where TimeGenerated > ago(RecentWindow)
    | where UserType == "ServicePrincipal"
    | distinct UserPrincipalName;
let DormantAccounts =
    SigninLogs
    | where TimeGenerated between (ago(90d) .. ago(DormantThreshold))
    | summarize LastSeen = max(TimeGenerated) by UserPrincipalName
    | where UserPrincipalName !in (
        SigninLogs
        | where TimeGenerated > ago(DormantThreshold)
        | distinct UserPrincipalName
    );
RecentActivity
| join kind=inner DormantAccounts on UserPrincipalName
| project UserPrincipalName, LastSeen, ReactivatedAt = now()
| order by LastSeen asc
```

---

### Detection: Secrets exposed in repository commits (hunting query concept)

```kql
// Hunt for GitHub audit events indicating secret exposure
// Requires GitHub Advanced Security logs forwarded to Sentinel
GitHubAuditLogs_CL
| where TimeGenerated > ago(24h)
| where Action_s in (
    "secret_scanning_alert.created",
    "push_protection.bypass",
    "secret_scanning.alert_resolved_false_positive"
)
| project TimeGenerated, Actor_s, Repository_s, Action_s, SecretType_s
| order by TimeGenerated desc
```

---

## NHI governance framework, minimum viable programme

| Control | Description | Priority |
|---------|-------------|----------|
| **Inventory** | Enumerate all NHIs, service accounts, API keys, tokens, certificates, AI agent credentials, into a centralised registry | Critical |
| **Ownership** | Every NHI must have a named human owner accountable for its lifecycle | Critical |
| **Least privilege** | Each NHI scoped to minimum permissions required for its defined function only | Critical |
| **Rotation schedule** | Credentials rotated on defined schedule, weekly for high-privilege, monthly minimum for all others | High |
| **Secrets management** | All credentials stored in a secrets vault (Azure Key Vault, HashiCorp Vault), no hardcoded credentials permitted | High |
| **Decommissioning process** | Formal process for revoking NHI credentials when the associated service or agent is retired | High |
| **Anomaly detection** | Behavioural baselines established for each NHI, alert on deviation from normal access patterns | High |
| **AI agent registry** | Dedicated inventory for AI agent identities separate from traditional service accounts, tracks agent function, permissions, data access, and owning team | Medium |
| **Just-in-time access** | For high-privilege operations, NHIs granted time-bound access that expires automatically | Medium |

---

## The honest SOC reality, April 2026

Most SOCs have no visibility into NHIs whatsoever. There is no asset inventory, no behavioural baseline, no rotation schedule, and no decommissioning process. The credentials exist across cloud consoles, configuration files, shared password managers, and developers' local environments.

The detection logic above assumes logging and telemetry that most organisations have not yet implemented. The first step is not detection, it is visibility. You cannot detect what you cannot see.

For Detection & Response engineers in 2026, the highest-value contribution is not writing a KQL rule. It is defining the logging requirements, building the pipeline, and making the invisible visible.

---

## Frameworks and further reading

* [OWASP Non-Human Identity Top 10](https://owasp.org/www-project-non-human-identities-top-10/)
* [Gartner: Identity and Access Management Adapts to AI Agents (Top Cybersecurity Trends 2026)](https://www.gartner.com/en/newsroom/press-releases/2026-02-05-gartner-identifies-the-top-cybersecurity-trends-for-2026)
* [CSA: State of Non-Human Identity and AI Security 2026](https://cloudsecurityalliance.org/artifacts/state-of-nhi-and-ai-security-survey-report)
* [CyberArk: Machine Identity Security](https://www.cyberark.com/what-is/machine-identity-security/)

---

*NHI security is the fastest-evolving area of the 2026 threat landscape. This document reflects the state of knowledge as of June 2026 and will be updated as the field develops.*
