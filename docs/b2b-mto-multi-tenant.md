# Multi-tenant access: B2B guests and Defender multitenant management

This guide is for analysts whose user account reaches the other tenants as a **Microsoft
Entra B2B guest**, with those tenants linked through **Microsoft Defender multitenant
management** (a multitenant organization, "MTO"). It explains what each access path can
and cannot do, how to set this repository up for it, and how to report coverage honestly.

Identifiers below are synthetic placeholders. Keep real tenant, subscription and
workspace GUIDs in the git-ignored `config.json`.

> **Verification status.** The repository tooling described here was tested with mocked
> services only; no live tenant, B2B guest account or MTO was available. Statements about
> Microsoft services are conservative summaries of Microsoft documentation that could only
> be checked indirectly. Platform behavior changes: confirm against the current
> [Microsoft Learn](https://learn.microsoft.com/) pages before relying on a statement, and
> run `verify` yourself on each tenant.

## 1. What each access path gives you

| Access path | It gives you | It does **not** give you |
|---|---|---|
| B2B guest account in a target tenant | A directory identity in that tenant that can be assigned roles, and sign-in to it | Any role, consent or workspace access by itself. Sentinel triage (see §4) |
| Azure CLI session for that tenant (`az login --tenant <tenant-id>`) | Tenant-pinned tokens, used by `verify`, `validate --validate-live` and `query` | Proof of which tenant an MCP server session uses |
| `x-mcp-client-tenant-id` header on an MCP server entry | Asks that server to sign you in to that tenant | Roles, consent, triage guest support, or proof that the session really is in that tenant |
| Defender multitenant management portal views | Portal-side overviews and cross-tenant hunting across the tenants you can manage there | Anything this repository's CLI or MCP tooling can consume programmatically |

Consequences that shape the whole design:

- A guest sign-in, a header, a connection *name* and an Azure CLI login are **not**
  authorization. They only select a tenant. The target tenant still has to grant roles.
- One MCP connection is authenticated to one tenant. Do not point two tenants at one
  connection: use a separate named server per tenant (§3).
- Only the Azure CLI probes are verified by code. MCP sessions are **attested** by the
  agent that used them, which is a claim, not proof (see
  [Capability ledger](tenant-contexts.md#capability-ledger-and-readiness)).
- A result from tenant A is never evidence about tenant B. Each tenant and workspace is a
  separate case with its own context, ledger and evidence.

## 2. Prerequisites per target tenant

1. Your guest account has redeemed its invitation in the target tenant, and any
   Conditional Access or cross-tenant access policy there allows it to sign in from the
   place you work. A blocked sign-in shows up as an unverified or denied capability.
2. The tenant administrator granted the roles Microsoft documents for the services you
   will use (Sentinel / Log Analytics read access for the workspace, and the Graph and
   Defender permissions your hunts need). Request read-only roles; this repository never
   needs write access, and it never asks you to elevate.
3. You signed in with the Azure CLI to that tenant: `az login --tenant <tenant-id>`. Repeat
   per tenant. The tooling never logs in, switches accounts or subscriptions for you.
4. For each MCP server you will use, you can complete its interactive sign-in as a member
   or B2B guest of that tenant (§3).

## 3. Repository setup

### 3.1 Register one profile per tenant

Add a profile per tenant under `tenants` in `config.json` (full schema in
[Tenant contexts](tenant-contexts.md#profile-configuration)). Give every tenant its **own**
connection names, and leave `connections.triage` null on a guest tenant:

```json
{
  "tenants": {
    "home": {
      "tenant_id": "11111111-1111-4111-8111-111111111111",
      "connections": {"data_lake": "sentinel-data-home", "graph": "graph-home", "triage": "triage-home"},
      "triage_home_tenant_id": "11111111-1111-4111-8111-111111111111",
      "workspaces": [{"id": "33333333-3333-4333-8333-333333333333", "name": "la-home",
                      "subscription_id": "22222222-2222-4222-8222-222222222222", "resource_group": "rg-home"}]
    },
    "partner": {
      "tenant_id": "44444444-4444-4444-8444-444444444444",
      "connections": {"data_lake": "sentinel-data-partner", "graph": "graph-partner", "triage": null},
      "triage_home_tenant_id": "11111111-1111-4111-8111-111111111111",
      "workspaces": [{"id": "66666666-6666-4666-8666-666666666666", "name": "la-partner",
                      "subscription_id": "55555555-5555-4555-8555-555555555555", "resource_group": "rg-partner"}],
      "sit_mapping": {},
      "label_mapping": {}
    }
  }
}
```

Run `python scripts/tenant_context.py profiles`. Its `warnings` list flags a connection
name that two tenants share. The `triage_home_tenant_id` on a guest profile is optional: it
records your *home* tenant, and makes `readiness` report `triage` as `unsupported` instead
of merely unverified. `sit_mapping`, `label_mapping` and `sit_priority` are tenant-local
Purview GUID tables: fill them from that tenant only and never copy another tenant's.

A tenant that has **no Sentinel workspace** (Defender data only) needs no `workspaces`
entry: create its cases with `--no-workspace` (§5).

### 3.2 Give each tenant its own MCP server entries

```sh
python scripts/tenant_context.py render-mcp --profile partner
```

prints, for that tenant only, one server entry per declared connection, named after the
connection reference and carrying that tenant's `x-mcp-client-tenant-id` header:

```json
{
  "ok": true,
  "profile": "partner",
  "servers": {
    "sentinel-data-partner": {"type": "http", "url": "https://sentinel.microsoft.com/mcp/data-exploration",
                              "headers": {"x-mcp-client-tenant-id": "44444444-4444-4444-8444-444444444444"}},
    "graph-partner": {"type": "http", "url": "https://mcp.svc.cloud.microsoft/enterprise",
                      "headers": {"x-mcp-client-tenant-id": "44444444-4444-4444-8444-444444444444"}}
  },
  "omitted": {"triage": "No connection reference is declared for this profile"}
}
```

(The real output is one compact JSON object with `notes` and `tenant_id` too.)
Triage is omitted unless the profile declares a triage connection **and** a
`triage_home_tenant_id` equal to its own tenant.

The command configures nothing. Merge the entries into `.vscode/mcp.json` or
`.copilot/mcp-config.json` yourself (keep any existing comments and other servers), then
restart each server (VS Code: **MCP: List Servers**) and sign in with the account that is a
member or B2B guest of *that* tenant. If a server still shows the wrong tenant, sign out of
that MCP connection and reconnect. Microsoft documents the header and the troubleshooting
steps:

- [Sentinel MCP troubleshooting](https://learn.microsoft.com/en-us/azure/sentinel/datalake/troubleshoot-sentinel-mcp#troubleshooting)
- [Microsoft Graph MCP server setup](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode)

The older single-tenant procedure in
[MCP multi-tenant configuration plan](mcp-multi-tenant-configuration-plan.md) edits the
three shared entries in place. Do not use it for simultaneous tenants.

### 3.3 Per-tenant case, proofs, then queries

```sh
python scripts/tenant_context.py create --profile partner --workspace 66666666-6666-4666-8666-666666666666 \
    --case partner-001 --lookback-days 7 --capability workspace_arm --capability workspace_query --capability data_lake
python scripts/tenant_context.py verify    reports/tenants/partner/partner-001/context.json
# ...use the tenant's data-lake MCP server for one harmless read, then record what happened:
python scripts/tenant_context.py attest    reports/tenants/partner/partner-001/context.json \
    --capability data_lake --status attested --detail "Listed workspaces on sentinel-data-partner; la-partner present"
python scripts/tenant_context.py readiness reports/tenants/partner/partner-001/context.json
```

Only capabilities that `readiness` lists as `usable` may be used for that case. Everything
else is *unavailable*, never *clean*.

## 4. Triage and guest accounts

Microsoft's [triage documentation](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-triage-tool#limitations)
states that guest and delegated access are not supported and that the triage collection
only works in an account's home tenant. A tenant header does not change that.

- Keep `connections.triage` null on guest profiles. `render-mcp` then emits no triage
  server, `create --capability triage` is refused when a different home tenant is declared,
  and `attest` refuses an `attested` triage claim.
- Use the hunting routes that do work for a guest: workspace tables through the Data Lake
  MCP server, Graph, the Azure CLI `query` command, or the Defender portal.
- Where a native account exists in the target tenant, you may register a separate profile
  for it with its own triage connection and `triage_home_tenant_id` equal to that tenant.
- Report the gap: "triage unsupported for this guest profile; hunt performed through X".

## 5. Defender multitenant management versus this repository

The portal's multitenant views are the fastest way to see what is happening across the
tenants you manage, and cross-tenant hunting there is a portal feature. Advanced hunting
returns a bounded number of rows; check Microsoft's current limits before treating a
result as complete. None of that is available to this repository's code, so:

- Use the portal for **overview and triage across tenants**.
- Use per-tenant cases here for **evidence-grade collection**: pinned tenant, workspace and
  UTC window, a ledger of which proofs held, and evidence files that never mix tenants.
- Portal-only findings are not ingested automatically. Record them in the notes of the
  tenant's own case. Do not paste another tenant's rows into a case.
- `defender_hunting` is attestation-only. Attesting it `--via graph` records a claim; the
  repository contains no Microsoft Graph hunting adapter and has not verified one.

A tenant with Defender data but no Sentinel workspace:

```sh
python scripts/tenant_context.py create --profile partner --no-workspace --case partner-defender-001 \
    --lookback-days 30 --capability defender_hunting
```

Workspace-scoped capabilities (`workspace_arm`, `workspace_query`, `data_lake`) cannot be
required for such a case (`create` refuses them) and show as `unsupported` in `readiness`.

## 6. Hunting across tenants from Mission Control

Select the tenants (and a workspace for each, or Defender-only) in the **Cross-tenant hunt
(read-only)** panel in Mission Control's left rail, or call `POST /api/cross-tenant-hunt`
(see the [cross-tenant-hunt skill](../.github/skills/cross-tenant-hunt/SKILL.md)). Every
target gets its own child case (`<hunt-id>-01`, `-02`, …) sharing one pinned UTC window, so
rows from different tenants cover the same period.

- **Launch here** queues one frozen request per target. Mission Control runs them in a
  single Copilot conversation. Profile selection isolates local routing, files, ledgers and
  findings, but it cannot isolate what the model has already seen in that conversation.
- **Hand-off prompts** plans the targets and returns one prompt per target. It sends
  nothing and creates no files. Open a separate Copilot session per tenant and paste the
  prompt there when you need strict customer separation; the prompt tells that session to
  run `create`, `verify`, `attest` and `readiness` itself. Hand-off carries no correlation
  ID: that session writes its result under the target's case directory and does not
  report back to Mission Control.
- Targets whose requested capabilities are statically unsupported come back as
  `unavailable`; they are never silently dropped or reported clean.
- The panel's readiness view re-reads each case's ledger. It is advisory; the
  authoritative check is `scripts/tenant_context.py readiness`.

## 7. Troubleshooting

| Symptom | Meaning | Action |
|---|---|---|
| `verify`: `Azure CLI token acquisition unavailable` | The Azure CLI is not installed or not on `PATH` | Install it, then `az login --tenant <tenant-id>` and `verify` again |
| `verify`: `Azure CLI token acquisition failed; no login or context switch attempted` | The Azure CLI has no usable session for that tenant | Run `az login --tenant <tenant-id>` yourself, then `verify` again |
| `Azure CLI returned a token for the wrong tenant` | The CLI answered for another tenant | Sign in to the right tenant; never retarget the case |
| `denied` (HTTP 401/403/404) | You authenticated, but the tenant has not granted the read access, or policy blocks it | Ask the tenant admin for the documented read-only role; do not work around it |
| `workspace_arm` unverified: `Live workspace verification requires subscription_id, resource_group, name` | The registered workspace lacks metadata | Add all three to the profile's workspace entry and create a new case |
| `triage`/`defender_hunting --via triage` refused or `unsupported` | Guest or delegated access is unsupported for triage | Use another route (§4) |
| An MCP server answers from the wrong tenant | Cached sign-in or a missing/wrong header | Check the rendered entry, sign out of the MCP connection, restart, sign in again, re-run `attest` |
| `ignored_records` is greater than 0 | Ledger files that failed validation (other tenant or case, expired shape, oversized, tampered) | Inspect them; never copy ledger files between cases |
| A capability shows `expired` | Its record is older than its TTL (24 h default) | Re-run `verify` or `attest` |

## 8. Reporting coverage

For every tenant and workspace searched, state the case, the pinned window and each
capability's status. Keep these outcomes separate: **verified**, **attested** (claim),
**denied**, **expired**, **unverified**, **unsupported**, and **not run**. A scope that
could not be searched is *unavailable*, never *clean*.
