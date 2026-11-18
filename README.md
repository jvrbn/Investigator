# 🔒 Security Investigation Automation System

Run **scenario-driven security investigations with GitHub Copilot** across Microsoft Sentinel, Microsoft Defender XDR, Microsoft Graph, Azure, and threat-intelligence services. Instead of starting with tables or scripts, describe the security question: Copilot selects an investigation skill, collects read-only evidence through MCP, correlates the results, and recommends the next pivot.

> This repository provides investigation workflows; it does **not** grant access to your environment. Tenant administrators must assign the roles and consent described in [Configure access](#3-configure-mcp-access).

**Demos**
- 🎛️ [Mission Control walkthrough on LinkedIn](https://lnkd.in/p/gm4yB-9Y) — launch skills and review findings in a canvas dashboard.
- 📺 [VS Code walkthrough on YouTube](https://youtu.be/3UFqWA4cmoE?t=1470) — natural-language investigations, MCP execution, KQL, enrichment, and reporting.

## Start with your scenario

| What are you trying to answer? | Prompt to start with | Workflow / output |
|---|---|---|
| **What needs attention in this shift?** | `Run a threat pulse scan` | A 15-minute scan across incidents, identity, endpoint, email, admin/cloud, and exposure, prioritized with drill-down recommendations. |
| **Is a user account compromised?** | `Investigate user@contoso.com for the last 7 days` | Sign-ins, MFA, risk detections, devices, audit activity, incidents, and an evidence-based verdict with follow-ups. |
| **Did a mailbox takeover or BEC occur?** | `Investigate BEC for user@contoso.com for the last 30 days` | Email delivery/clicks, authentication, forwarding rules, mailbox access, outbound mail, and a UTC evidence timeline. |
| **What happened in a Defender incident?** | `Analyze Defender incident 12345` | Alerts, entities, incident context, affected users/devices, and entity-specific pivots. |
| **Is this IP, domain, URL, or hash malicious?** | `Is 203.0.113.42 malicious?` | Threat intelligence, Sentinel exposure, affected devices, related CVEs, and confidence caveats. |
| **What happened on an endpoint or in an MDE alert?** | `Triage MDE alert <alert-id> on <device>` | Process ancestry, alert evidence, file/network activity, related alerts, logged-on users, vulnerabilities, and device scope. |
| **Is this ransomware or destructive activity?** | `Investigate ransomware incident 12345` | Attributed execution, file impact, remote access, persistence, lateral movement, control outcomes, and affected assets. |
| **Was a session token reused or used from a new location?** | `Trace the authentication chain for user@contoso.com` | Session correlation, interactive MFA origin, token reuse, and geographic anomalies. |
| **Did a Conditional Access policy change or bypass occur?** | `Investigate Conditional Access changes affecting user@contoso.com` | Policy changes correlated with sign-in failures and suspicious policy state. |
| **Where is our vulnerability or configuration exposure?** | `Generate an exposure report for the last 30 days` | Exploitable CVEs, security configuration gaps, critical assets, attack paths, Defender health, and certificate state. |
| **Are apps, service principals, or identities overprivileged?** | `Audit app registration security posture` | Dangerous permissions, ownership, credentials, cross-tenant exposure, role distribution, drift, and attack-chain evidence. |
| **Who accessed sensitive data or changed a label?** | `Who accessed files containing credit card data?` | Sensitive-information-type access, users, files, DLP context, label changes, and Copilot exposure. |
| **Are AI agents too broadly exposed?** | `Audit AI agent security posture` | Agent inventory, access posture, tools/MCP, knowledge sources, external endpoints, credentials, and agent identities. |
| **Are our detections and telemetry healthy?** | `Check investigation readiness for the selected workspace` | Ingestion freshness, rule failures, sensor coverage, data volume, tier/cost signals, and coverage gaps. |
| **Can I investigate the same indicator across tenants?** | `Hunt this indicator across the selected tenants` | Explicit per-tenant collection, one pinned UTC window, isolated evidence, and separate coverage/failure reporting. |

After a workflow finishes, continue naturally rather than restarting:

```text
1. "Investigate Defender incident 12345"
2. "Now investigate the user from that incident"
3. "Check whether the related IP is malicious"
4. "Show the activity on a heatmap"
5. "Save the investigation as a report"
```

Findings are evidence-backed. The skills distinguish **no matching events** from **a source that could not be queried**, and they report unavailable tables, failed authentication, and unsupported guest access instead of treating those states as clean.

## How a scenario runs

```text
Your security question
        │
        ▼
Copilot detects an Agent Skill
        │
        ▼
Tenant + workspace + time window are established
        │
        ├── Sentinel Data Lake MCP ───── workspace KQL + Exposure Graph
        ├── Sentinel Triage MCP ──────── Defender XDR incidents, alerts, entities, Advanced Hunting
        ├── Microsoft Graph MCP ──────── users, devices, roles, risk, authentication context
        ├── Azure MCP / CLI ──────────── ARM, Log Analytics, resource and telemetry operations
        └── Threat-intelligence APIs ─── IP reputation, geolocation, hosting, ports, CVEs
        │
        ▼
Evidence correlation + verified KQL patterns
        │
        ▼
Inline findings, portal links, follow-up prompts, or a report/dashboard
```

The reusable workflow definitions live under [`.github/skills/`](.github/skills/), and verified KQL is indexed in [`queries/`](queries/). Universal routing, schema checks, workspace selection, and evidence rules live in [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

## Onboard the project

### Choose your client

| Use case | Recommended client |
|---|---|
| Interactive triage, ad-hoc investigations, KQL development | **VS Code** with GitHub Copilot Agent mode |
| Scheduled Threat Pulse runs, parallel investigations, Mission Control canvas | **GitHub Copilot app / CLI** |

The steps below cover the standard **single-tenant VS Code** path. For multiple tenants, B2B guests, Defender multitenant management, or immutable case contexts, continue with [Multi-tenant investigations](#multi-tenant-investigations).

### 1. Confirm requirements

#### Required for core investigations

| Requirement | Why it is needed |
|---|---|
| **GitHub Copilot** | Pro+, Business, or Enterprise plan with Agent mode enabled. [Copilot plans](https://github.com/features/copilot) |
| **VS Code 1.99+ recommended** | Agent mode and MCP support. The project can also run in the GitHub Copilot app / CLI. |
| **Microsoft Sentinel + Log Analytics access** | A workspace containing the tables needed by the scenario; workspace reader access is required for KQL. |
| **Microsoft Defender XDR access** | Required for incidents, alerts, Advanced Hunting, endpoint, identity, email, and exposure scenarios that use Triage. |
| **Microsoft Graph MCP access** | Required for Entra identity, device, role, MFA, and Identity Protection enrichment. Tenant admin provisioning is a one-time step. |
| **Python 3.8+** | Report generation, IP enrichment, tenant-context tooling, and repository utilities. |
| **Node.js 18+** | KQL Search MCP and the optional local MCP Apps. |

#### Required only for particular workflows

| Requirement | Used by |
|---|---|
| **GitHub PAT with `public_repo` scope** | KQL Search MCP for schema/query discovery and validation. [Create a token](https://github.com/settings/tokens/new). |
| **Azure CLI** | Azure MCP / ARM access, authenticated tenant checks, and the ingestion report. [Install Azure CLI](https://aka.ms/installazurecli). |
| **`log-analytics` Azure CLI extension** | `sentinel-ingestion-report` query and table-tier collection. |
| **PowerShell 7+** | Parallel ingestion-report collection and optional administration utilities. |
| **Microsoft.Graph PowerShell module** | Detection-authoring workflows and optional rule inventory. |
| **Enrichment API tokens** | Optional higher-rate IP, VPN, abuse, port, service, and CVE enrichment. |

Licensing or ingestion is outside the project: opening MCP access does not enable missing Sentinel connectors, Defender telemetry, Purview events, or optional Advanced Hunting tables.

### 2. Clone and install

```powershell
git clone https://github.com/jvrbn/Investigator.git
cd Investigator

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements.lock
```

On macOS/Linux:

```bash
git clone https://github.com/jvrbn/Investigator.git
cd Investigator

python3 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.lock
```

`requirements.txt` remains available if you need an unhashed install:

```bash
pip install -r requirements.txt
```

### 3. Configure MCP access

Configuration is split across a few local files and authenticated sessions. Keep all live values private:

| File / configuration | Purpose |
|---|---|
| `config.json` | Tenant, workspace, subscription, Azure MCP resource names, output and tenant-profile references. Gitignored. |
| `.env` | Optional IP-enrichment API tokens. Gitignored and loaded by `python-dotenv`. |
| `.vscode/mcp.json` | VS Code MCP connection definitions. Gitignored. |
| `~/.copilot/mcp-config.json` | Copilot app / CLI MCP connections at user scope. |
| Azure CLI session | Supplies Azure MCP / tenant-context authentication for the selected tenant. |

#### 3.1 Add your single-tenant environment

Copy the template:

```powershell
copy config.json.template config.json
copy .env.template .env
```

```bash
cp config.json.template config.json
cp .env.template .env
```

Populate the following fields in `config.json`:

```json
{
  "sentinel_workspace_id": "<LOG_ANALYTICS_WORKSPACE_GUID>",
  "tenant_id": "<ENTRA_TENANT_GUID>",
  "subscription_id": "<AZURE_SUBSCRIPTION_GUID>",
  "azure_mcp": {
    "resource_group": "<RESOURCE_GROUP_CONTAINING_THE_WORKSPACE>",
    "workspace_name": "<LOG_ANALYTICS_WORKSPACE_NAME>",
    "tenant": "<ENTRA_TENANT_GUID>",
    "subscription": "<AZURE_SUBSCRIPTION_GUID>"
  },
  "output_dir": "reports",
  "memory_file": null
}
```

| Setting | Required for | Meaning |
|---|---|---|
| `sentinel_workspace_id` | Sentinel Data Lake KQL | Workspace GUID, not workspace display name. |
| `tenant_id` | Portal links, tenant scoping, Graph/Defender identity | Entra tenant GUID. |
| `subscription_id` | Azure and tenant-context workflows | Subscription containing the primary workspace. |
| `azure_mcp.*` | Azure MCP and direct Log Analytics queries | Tenant, subscription, resource group, and workspace display name. |
| `output_dir` | Reports in legacy single-tenant mode | Defaults to `reports`. Tenant-profile cases route to `reports/tenants/...`. |
| `memory_file` | Optional tenant context | Relative memory filename under the repository memory convention. |

> `config.json` may contain real tenant identifiers and optional tenant-local mappings. It is gitignored and must not be committed.

Add any optional enrichment tokens to `.env`:

```dotenv
IPINFO_TOKEN=
ABUSEIPDB_TOKEN=
VPNAPI_TOKEN=
SHODAN_TOKEN=
```

The providers improve IP reports but are not required to investigate Sentinel or Defender data. See [IP enrichment and rate limits](#ip-enrichment-and-rate-limits).

#### 3.2 Register MCP servers in VS Code

```powershell
copy .vscode\mcp.json.template .vscode\mcp.json
```

```bash
cp .vscode/mcp.json.template .vscode/mcp.json
```

The template preconfigures:

1. Sentinel Data Lake MCP
2. Microsoft Graph MCP
3. Sentinel Triage MCP (Defender XDR)
4. KQL Search MCP
5. Microsoft Learn MCP
6. Three optional local MCP Apps

Install the **Azure MCP Server** VS Code extension if the scenario uses Azure Monitor or resource APIs. The extension registers a stdio MCP server; the Copilot app template can instead launch `@azure/mcp` directly.

For the GitHub Copilot app / CLI, copy [`.copilot/mcp-config.json.template`](.copilot/mcp-config.json.template) to `~/.copilot/mcp-config.json` and merge it with any existing user-level configuration. See [Running in the GitHub Copilot app](#running-in-the-github-copilot-app).

#### 3.3 Authenticate and provision each service

| Connection | Initial setup |
|---|---|
| **Sentinel Data Lake** | Start the MCP server and complete browser sign-in. The tenant must assign Log Analytics/Sentinel read access. |
| **Sentinel Triage / Defender XDR** | Complete browser sign-in with an account that has Defender XDR / SecurityReader access. Triage requires a supported home-tenant session. |
| **Microsoft Graph** | A tenant administrator must complete the one-time [Graph MCP server provisioning](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode) and consent for the client. Users then sign in with delegated permissions. |
| **Azure MCP / CLI** | Run `az login --tenant <tenant-id>` and `az account set --subscription <subscription-id>`. Use the tenant and subscription from `config.json`. |
| **KQL Search** | Supply a GitHub PAT with `public_repo` when VS Code prompts, or set `GITHUB_TOKEN` for the Copilot app template. |
| **Microsoft Learn** | No API key or sign-in is required. |
| **Optional local MCP Apps** | Build with Node.js; each app is documented under [`mcp-apps/`](mcp-apps/). |

Minimum access by workflow is summarized in [MCP servers and permissions](#mcp-servers-and-permissions).

### 4. Verify access before investigating

Restart the MCP servers, open Copilot Chat in **Agent mode**, and run these read-only checks:

| Check | Prompt | What success proves |
|---|---|---|
| Sentinel workspaces | `List my Sentinel workspaces` | The Data Lake MCP session can authenticate and enumerate the connection's workspace scope. |
| Workspace schema | `What columns does the SigninLogs table have?` | Data Lake / KQL Search schema access is available. |
| Defender XDR | `List recent security incidents` | Triage can reach Defender XDR for the current tenant. |
| Microsoft Graph | `Look up my user profile in Graph` | Graph MCP is consented and the delegated session is usable. |
| Microsoft Learn | `Search Microsoft docs for KQL query language` | The Learn MCP endpoint is reachable. |
| Skills | `What investigation skills do you have access to?` | VS Code is loading the repository skills. |

Use the VS Code **MCP: List Servers** command if a connection does not start. Confirm the authenticated tenant as well as the green connection status.

> If multiple Sentinel workspaces are available, the agent must display all available names/IDs and wait for an explicit selection. It must not silently switch workspaces after a query failure.

### 5. Run the first scenario

For an unfamiliar environment, start with a broad, read-only scan:

```text
Run a threat pulse scan
```

Then select the most relevant drill-down:

```text
Investigate the highest-risk user from the scan
Triage the highest-severity open incident
Check the most suspicious IP
Generate a dashboard from the results
```

For a known entity, skip the broad scan and use the entity-specific prompt from [Start with your scenario](#start-with-your-scenario).

## Scenario playbooks

### Daily triage: start broad, then pivot

- **Use:** [Threat Pulse](.github/skills/threat-pulse/SKILL.md)
- **Start:** `Run a threat pulse scan for the last 7 days`
- **Correlates:** Open incidents, human and non-human identity risk, endpoint drift, email threats, admin/cloud operations, and exposure.
- **Next:** Ask Copilot to launch the recommended user, incident, IoC, device, or posture skill.

### Suspected identity compromise: user to session to control

- **Use:** [User investigation](.github/skills/user-investigation/SKILL.md), [authentication tracing](.github/skills/authentication-tracing/SKILL.md), and [Conditional Access investigation](.github/skills/ca-policy-investigation/SKILL.md).
- **Start:** `Investigate user@contoso.com for the last 7 days`
- **Correlates:** MFA, sign-in anomalies, SessionId/token chains, Identity Protection, device state, role/audit activity, incidents, and mailbox signals when applicable.
- **Next:** `Trace the suspicious authentication back to its interactive MFA event`.

### BEC or mailbox takeover: message to account to outbound impact

- **Use:** [BEC investigation](.github/skills/bec-investigation/SKILL.md).
- **Start:** `Investigate BEC for user@contoso.com from this message or incident`
- **Correlates:** Message delivery and clicks, authentication, malicious forwarding/redirect rules, mailbox access, outbound mail, and remediation state.
- **Boundary:** The workflow is read-only; it does not delete rules, revoke sessions, or change a mailbox.

### Incident, endpoint, or ransomware: alert to process to fleet scope

- **Use:** [Incident investigation](.github/skills/incident-investigation/SKILL.md), [computer investigation](.github/skills/computer-investigation/SKILL.md), and [ransomware investigation](.github/skills/ransomware-investigation/SKILL.md).
- **Start:** `Investigate incident 12345` or `Triage MDE alert <alert-id>`
- **Correlates:** Defender alerts/evidence, process ancestry, file and network activity, remote access, logged-on users, vulnerabilities, persistence, and related assets.
- **Next:** `Investigate the user, IP, hash, and device found in that incident`.

### Indicator hunting: reputation to organizational exposure

- **Use:** [IoC investigation](.github/skills/ioc-investigation/SKILL.md).
- **Start:** `Investigate IP 203.0.113.42`, `Investigate domain example.invalid`, or `Investigate file hash <sha256>`
- **Correlates:** Defender Threat Intelligence, Sentinel threat-intel tables, IP enrichment, affected users/devices, network and email exposure, and CVE context.
- **Next:** `Show the associated events on a heatmap` or `Generate an SVG dashboard`.

### Posture review: prioritize systemic control gaps

| Review | Skill |
|---|---|
| Vulnerabilities, attack paths, critical assets | [exposure-investigation](.github/skills/exposure-investigation/SKILL.md) |
| App registration and service principal permissions | [app-registration-posture](.github/skills/app-registration-posture/SKILL.md) |
| Identity inventory, stale accounts, privileged access | [identity-posture](.github/skills/identity-posture/SKILL.md) |
| Email threat protection, DMARC, ZAP, Safe Links | [email-threat-posture](.github/skills/email-threat-posture/SKILL.md) |
| Sensitive-data and label exposure | [data-security-analysis](.github/skills/data-security-analysis/SKILL.md) |
| AI agent configuration and access | [ai-agent-posture](.github/skills/ai-agent-posture/SKILL.md) |
| AI agent runtime activity | [ai-agent-activity](.github/skills/ai-agent-activity/SKILL.md) |

### Detection engineering and telemetry operations

| Need | Skill |
|---|---|
| Author or validate KQL | [kql-query-authoring](.github/skills/kql-query-authoring/SKILL.md) |
| Deploy or manage a custom detection | [detection-authoring](.github/skills/detection-authoring/SKILL.md) |
| Assess ingestion volume and cost | [sentinel-ingestion-report](.github/skills/sentinel-ingestion-report/SKILL.md) |
| Measure telemetry and detection readiness | [telemetry-health](.github/skills/telemetry-health/SKILL.md) |
| Review MITRE ATT&CK coverage | [mitre-coverage-report](.github/skills/mitre-coverage-report/SKILL.md) |
| Audit MCP server usage | [mcp-usage-monitoring](.github/skills/mcp-usage-monitoring/SKILL.md) |
| Turn threat intelligence into tested hunts | [threat-intel-campaign](.github/skills/threat-intel-campaign/SKILL.md) |

## MCP servers and permissions

The project intentionally separates **workspace KQL**, **Defender XDR**, **identity**, and **Azure resource** access. One connection succeeding does not prove that the others are configured.

| Server / data plane | URL or transport | Use it for | Minimum read access to request |
|---|---|---|---|
| **Sentinel Data Lake MCP** | `https://sentinel.microsoft.com/mcp/data-exploration` | `query_lake`, table discovery, Sentinel workspace data, bundled Exposure Graph tools | Log Analytics Reader; Sentinel Reader recommended |
| **Sentinel Triage MCP** | `https://sentinel.microsoft.com/mcp/triage` | Defender XDR incidents, alerts, entities, devices/files/IPs, and Advanced Hunting | Defender / SecurityReader read access and Advanced Hunting access |
| **Microsoft Graph MCP** | `https://mcp.svc.cloud.microsoft/enterprise` | User/device profiles, MFA methods, roles, and Identity Protection data | Delegated `User.Read.All`, `UserAuthenticationMethod.Read.All`, `Device.Read.All`, `IdentityRiskEvent.Read.All` as the scenario requires |
| **Azure MCP Server** | VS Code extension or `@azure/mcp` stdio | ARM, Log Analytics, Activity Log, subscriptions, resource groups, and Azure service inventories | Reader / Log Analytics Reader for read-only scenarios |
| **KQL Search MCP** | `npx -y kql-search-mcp@1.0.5` | Table schemas, KQL examples, ASIM, query validation, and discovery | GitHub PAT with `public_repo` |
| **Microsoft Learn MCP** | `https://learn.microsoft.com/api/mcp` | Official Microsoft documentation and code samples | None |

### Sentinel Data Lake vs. Defender XDR

- **Sentinel Data Lake / workspace KQL** answers questions over a selected Sentinel workspace and supports Data Lake retention where the table is eligible. Use it for Sentinel-native tables and lookbacks longer than 30 days where available.
- **Sentinel Triage / Defender XDR** answers incident-, alert-, device-, and Advanced Hunting questions. Advanced Hunting has a 30-day cap through the Graph-facing tool.
- **Triage does not select a Sentinel workspace.** Workspace selection belongs to the Sentinel Data Lake connection and must be explicit when multiple workspaces exist.
- Some advanced tables exist only in Defender XDR; some legacy Sentinel tables exist only in a workspace-capable route. The skills choose and document the correct route rather than treating the two as interchangeable.

### Microsoft Graph one-time provisioning

The Graph MCP server must be registered in the tenant by an account with the roles required by Microsoft's setup guide, typically Application Administrator or Cloud Application Administrator. This is separate from granting each analyst delegated Graph permissions.

1. Follow the [official Microsoft Graph MCP setup guide](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode).
2. Register and grant the MCP server permission to the VS Code client or Copilot client used by your organization.
3. Have analysts sign in interactively and consent to the delegated scopes needed by their workflows.
4. Verify the session with `Look up my user profile in Graph`.

### Azure MCP / Log Analytics

For direct Azure Monitor and tenant-pinned workflows:

```bash
az login --tenant <tenant-id>
az account set --subscription <subscription-id>
az extension add --name log-analytics
```

The `azure_mcp` values in `config.json` prevent an authenticated Azure CLI account from selecting the wrong tenant or workspace. Reader and Log Analytics Reader are sufficient for the repository's read-only investigation workflows. Do not add write roles merely to make a read-only investigation work.

### Optional local MCP Apps

The repository also includes:

- `sentinel-geomap-server` — geographic attack maps
- `sentinel-heatmap-server` — activity-pattern heatmaps
- `sentinel-incident-comment` — incident comments through an Azure Logic App

Build an app before enabling it in the MCP configuration:

```bash
cd mcp-apps/sentinel-heatmap-server
npm install
npm run build
cd ../..
```

Repeat for another app by changing the directory. The incident-comment app additionally requires the webhook configuration documented in [its README](mcp-apps/sentinel-incident-comment/README.md).

## Running in the GitHub Copilot app

The [GitHub Copilot app](https://github.com/features/ai/github-app) is useful for unattended workflows and parallel investigations:

- Run ready-to-import schedules from [`automations/`](automations/), including daily Threat Pulse and weekly threat-intelligence campaigns.
- Use background agents for long-running hunts and reports.
- Open multiple isolated sessions without sharing a local branch or investigation state.
- Launch **Mission Control** with `Start Mission Control` to use the repository's self-registering canvas dashboard.

![Mission Control Skills tab](docs/images/mission-control-skills.png)

### MCP configuration in the app

The app and CLI read user-scope MCP servers from `~/.copilot/mcp-config.json`, not `.vscode/mcp.json`.

```powershell
copy .copilot\mcp-config.json.template $env:USERPROFILE\.copilot\mcp-config.json
```

```bash
cp .copilot/mcp-config.json.template ~/.copilot/mcp-config.json
```

Then:

1. Merge rather than overwrite any existing user configuration.
2. Set `GITHUB_TOKEN` in the environment for KQL Search.
3. Run `az login --tenant <tenant-id>` for the Azure MCP server.
4. Restart the app or CLI and complete the browser sign-in once so the selected account can refresh authentication.

### Worktree bootstrap caveat

Each app session runs in a fresh git worktree. Gitignored `config.json`, `.env`, and `.vscode/mcp.json` are not copied automatically. Before the first query, copy them from the primary checkout or use a controlled post-checkout/setup script:

```bash
MAIN="/path/to/your/main/checkout"
for f in config.json .env .vscode/mcp.json; do
  if [ ! -f "$f" ] && [ -f "$MAIN/$f" ]; then
    mkdir -p "$(dirname "$f")"
    cp "$MAIN/$f" "$f"
  fi
done
```

Only copy private local configuration into the session; never commit it into the worktree.

## Multi-tenant investigations

Single-tenant root configuration remains the default. Add a `tenants` registry only when you need B2B guest tenants, Defender multitenant management, multiple workspaces, or isolated case routing.

Key rules:

1. Define one profile and one named MCP connection set per tenant.
2. Never share a single named MCP connection across tenants; one MCP session is authenticated to one tenant.
3. Add `x-mcp-client-tenant-id` to the per-tenant server entry. The header selects a tenant but grants no role.
4. Use immutable case contexts to bind tenant, workspace, lookback/UTC window, capability requirements, and evidence location.
5. Run readiness checks; `failed`, `denied`, `unverified`, and `unsupported` are unavailable states, not clean findings.
6. Sentinel Triage / Advanced Hunting through a B2B guest account is unsupported. Keep `connections.triage` null for a guest profile and use supported Data Lake, Graph, CLI, or portal routes instead.

The secure Python context/evidence writers require Python 3.8+ and POSIX descriptor-relative, no-follow filesystem support. They fail closed on unsupported platforms; use a supported POSIX environment for those helpers. This does not change the standard single-tenant Windows investigation workflows.

Create and validate one case:

```bash
python scripts/tenant_context.py profiles
python scripts/tenant_context.py create \
  --profile partner \
  --workspace <registered-workspace-guid> \
  --case partner-001 \
  --lookback-days 7
python scripts/tenant_context.py verify reports/tenants/partner/partner-001/context.json
python scripts/tenant_context.py readiness reports/tenants/partner/partner-001/context.json
```

Render the per-tenant server entries that you must merge into your MCP configuration:

```bash
python scripts/tenant_context.py render-mcp --profile partner
```

Full schema, ledger, and isolation behavior: [Tenant contexts](docs/tenant-contexts.md).
B2B / Defender multitenant management limitations: [B2B guest and multitenant setup](docs/b2b-mto-multi-tenant.md).
Read-only cross-tenant workflow: [Cross-tenant hunt](.github/skills/cross-tenant-hunt/SKILL.md).

## Available skill groups

You do not need to memorize skill names; the prompt-to-skill routing is automatic. The catalog below is useful for discovery and scenario chaining.

| Scenario group | Skills |
|---|---|
| **Start / broad triage** | [threat-pulse](.github/skills/threat-pulse/SKILL.md) |
| **Incidents and indicators** | [incident-investigation](.github/skills/incident-investigation/SKILL.md), [ioc-investigation](.github/skills/ioc-investigation/SKILL.md), [honeypot-investigation](.github/skills/honeypot-investigation/SKILL.md) |
| **Users and authentication** | [user-investigation](.github/skills/user-investigation/SKILL.md), [authentication-tracing](.github/skills/authentication-tracing/SKILL.md), [ca-policy-investigation](.github/skills/ca-policy-investigation/SKILL.md), [scope-drift-detection/user](.github/skills/scope-drift-detection/user/SKILL.md) |
| **Endpoints and destructive activity** | [computer-investigation](.github/skills/computer-investigation/SKILL.md), [ransomware-investigation](.github/skills/ransomware-investigation/SKILL.md), [scope-drift-detection/device](.github/skills/scope-drift-detection/device/SKILL.md) |
| **Email and mailbox** | [bec-investigation](.github/skills/bec-investigation/SKILL.md), [email-threat-posture](.github/skills/email-threat-posture/SKILL.md) |
| **Apps, identities, and data** | [app-registration-posture](.github/skills/app-registration-posture/SKILL.md), [scope-drift-detection/spn](.github/skills/scope-drift-detection/spn/SKILL.md), [identity-posture](.github/skills/identity-posture/SKILL.md), [data-security-analysis](.github/skills/data-security-analysis/SKILL.md) |
| **Exposure and AI agents** | [exposure-investigation](.github/skills/exposure-investigation/SKILL.md), [ai-agent-posture](.github/skills/ai-agent-posture/SKILL.md), [ai-agent-activity](.github/skills/ai-agent-activity/SKILL.md), [local-agent-investigation](.github/skills/local-agent-investigation/SKILL.md) |
| **Detection and operations** | [telemetry-health](.github/skills/telemetry-health/SKILL.md), [sentinel-ingestion-report](.github/skills/sentinel-ingestion-report/SKILL.md), [mitre-coverage-report](.github/skills/mitre-coverage-report/SKILL.md), [mcp-usage-monitoring](.github/skills/mcp-usage-monitoring/SKILL.md), [kql-query-authoring](.github/skills/kql-query-authoring/SKILL.md), [detection-authoring](.github/skills/detection-authoring/SKILL.md), [threat-intel-campaign](.github/skills/threat-intel-campaign/SKILL.md) |
| **Cross-tenant** | [cross-tenant-hunt](.github/skills/cross-tenant-hunt/SKILL.md) |
| **Visualization** | [heatmap-visualization](.github/skills/heatmap-visualization/SKILL.md), [geomap-visualization](.github/skills/geomap-visualization/SKILL.md), [svg-dashboard](.github/skills/svg-dashboard/SKILL.md) |

Ask Copilot for discovery rather than a filename:

```text
What investigation skills do you have access to?
What skill should I use for a suspicious mailbox rule?
Explain the workflow of the user investigation skill.
```

## Query library and extensibility

The [`queries/`](queries/) directory contains scenario-oriented, schema-aware KQL grouped by domain. Query files include searchable metadata for tables, keywords, MITRE techniques, and threat domains.

The discovery manifest connects findings to relevant skills and query files:

```bash
python .github/manifests/build_manifest.py
```

Regenerate it after adding, renaming, or reclassifying a query file or skill. See the query-authoring contract in [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

Ad-hoc investigations can become reusable assets:

```text
Package the verified queries and schema lessons from this investigation into a new skill.
Turn this threat-intelligence article into a tested hunting campaign.
```

## Project structure

```text
Investigator/
├── .github/
│   ├── copilot-instructions.md     # Universal routing, evidence, KQL, and workspace rules
│   ├── skills/                     # Scenario-specific Agent Skills
│   ├── manifests/                  # Query/skill discovery index
│   └── extensions/skills-canvas/   # Mission Control canvas
├── .vscode/mcp.json.template       # VS Code MCP configuration
├── .copilot/mcp-config.json.template # Copilot app / CLI MCP configuration
├── automations/                    # Ready-to-import scheduled workflows
├── docs/                           # Tenant, MCP, and workflow references
├── mcp-apps/                       # Local map, heatmap, and incident-comment servers
├── queries/                        # Verified KQL by security domain
├── reports/                        # Generated reports; tenant cases when profiles are enabled
├── scripts/                        # Reports, tenant contexts, manifests, cleanup, and helpers
├── tests/                          # Offline tests and fixtures
├── enrich_ips.py                   # Standalone / report-time IP enrichment
├── config.json.template            # Environment and optional tenant-profile template
└── .env.template                   # Optional enrichment tokens
```

## Outputs and report safety

Workflows can return:

- Inline evidence summaries with severity and confidence
- Markdown investigation files
- HTML reports
- SVG dashboards
- Heatmaps and geographic maps
- Defender XDR portal links for supported evidence

Tenant-specific reports and evidence can be pinned under `reports/tenants/<profile>/<case>/`. In multi-tenant mode, shared legacy destinations are not safe for evidence: the tenant-context tooling requires an explicit case.

Treat reports as confidential security data:

1. Restrict access to authorized SOC personnel.
2. Do not commit `config.json`, `.env`, private reports, or tenant-specific evidence.
3. Use organizational retention, classification, and audit controls.
4. Review every tenant-memory file before it is used; memory is trusted investigation context.
5. Keep live investigation workflows read-only unless you intentionally select a skill that supports a separately authorized administrative action.

## IP enrichment and rate limits

IP enrichment is optional and normally occurs after data collection, so a report can be enriched again without re-running every investigation query.

| Provider | Typical free capability | Token benefit |
|---|---|---|
| **ipinfo.io** | Geolocation, organization, ASN | Higher limits; paid plans add VPN-related detail |
| **AbuseIPDB** | IP reputation / abuse confidence | Higher report-query limits |
| **vpnapi.io** | VPN/proxy/Tor detection | Higher monthly limits |
| **Shodan** | InternetDB ports, vulnerabilities, and tags | Adds richer host/service data when credits are available |

Check provider limits in the output and report partial enrichment explicitly; a failed third-party lookup is not evidence that an IP is benign.

## Optional persistent tenant context

Tenant context files can record known infrastructure, approved automation fingerprints, false-positive patterns, and validated account classifications. They reduce repeated analyst explanations but must be treated as trusted input.

- Copy and adapt the examples under [`notes/memory/examples/`](notes/memory/examples/).
- Read the [tenant memory guide](notes/memory/README.md).
- Use a tenant-local file for multi-tenant cases; never copy another tenant's baseline.
- Review the diff before accepting memory generated from investigations.

Mission Control exposes memory selection, use, and propose-only compaction actions. The [context-memory-review](.github/skills/context-memory-review/SKILL.md) workflow proposes additions or corrections; it does not silently edit the authoritative file.

## Troubleshooting

| Symptom | Check |
|---|---|
| **MCP server unavailable** | Open **MCP: List Servers**, confirm the server is enabled, sign in again, and check its tenant. A token for another tenant is not a valid fix. |
| **No Sentinel workspaces or access denied** | Verify Log Analytics/Sentinel RBAC and the active Data Lake MCP account. Select the workspace explicitly if more than one is available. |
| **Defender incident tools fail, but Sentinel works** | Triage is a separate connection and permission plane. Verify Defender access and the current home's tenant. Guest/delegated triage is unsupported. |
| **Graph lookup fails** | Confirm one-time tenant provisioning, delegated scopes, consent, and the signed-in user. |
| **Sentinel query times out** | Reduce the time window, filter earlier by timestamp and entity, summarize, or limit output. |
| **Advanced Hunting misses older data** | Advanced Hunting is capped at 30 days through this route. Use the Data Lake-equivalent table for longer ranges where supported. |
| **Table not found** | Confirm the table exists in the selected workspace/route and that the required connector or optional data source is enabled. A missing optional table is a coverage limitation. |
| **Zero results from a populated table** | Check tenant/workspace, event-time column, time range, object ID vs. display name, GUID vs. string type, and query joins before interpreting it as clean. |
| **Report generation fails** | Validate the investigation JSON and required fields, then run the report generator for the correct legacy or tenant-case mode. |
| **IP enrichment failed or incomplete** | Check the optional API token, provider rate limit, and partial/fallback output. |
| **Copilot app cannot find `config.json`** | Bootstrap the gitignored file into the current worktree before launching the workflow. |

## License and acknowledgments

This project is licensed under the [MIT License](LICENSE).

Built with:

- [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/)
- [Microsoft Graph](https://learn.microsoft.com/en-us/graph/)
- [Microsoft Entra ID Protection](https://learn.microsoft.com/en-us/entra/id-protection/)
- [GitHub Copilot](https://github.com/features/copilot) and [Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [KQL Search MCP](https://www.npmjs.com/package/kql-search-mcp)
- [ipinfo.io](https://ipinfo.io/), [AbuseIPDB](https://www.abuseipdb.com/), [vpnapi.io](https://vpnapi.io/), and [Shodan](https://www.shodan.io/)

Special thanks to the Microsoft Security community for shared KQL and detection logic, and to [stefanpems](https://github.com/stefanpems/mcp-add-comment-to-sentinel-incident) for the Sentinel incident-comment MCP pattern.
