# Tenant profiles and immutable investigation contexts

`scripts/tenant_context.py` supports Python **3.8+** using postponed annotations and
only the standard library. JavaScript UTC timestamps ending in `Z` are accepted
on that baseline too. It does not change
Azure configuration, sign in, switch subscriptions, or configure MCP servers.
Contexts are opt-in: without a `tenants` registry, existing scripts retain their
existing single-tenant behavior. Once a nonempty registry exists it is authoritative,
and the tenant-aware writers refuse to run without a case context
([Legacy writers](#legacy-writers-and-shared-tooling)).
Keep real `config.json` and reports private; never commit live identifiers or tokens.

Working with B2B guest accounts or Defender multitenant management (MTO)? Read
[Multi-tenant access: B2B guests and Defender multitenant management](b2b-mto-multi-tenant.md)
first; it explains what each access path can and cannot do.

## Profile configuration

Without a `tenants` key (or with an empty `tenants` object), the existing root configuration becomes a single profile
named `legacy`. Existing enrichment settings remain supported but are **never copied**
into a context. When `tenants` is nonempty, only that registry is used; malformed
registries fail closed. Missing profile fields are never inherited from root or another tenant.
The existing template intentionally remains a legacy configuration until you opt in.

Example replacement configuration (identifiers below are synthetic placeholders):

```json
{
  "tenants": {
    "example": {
      "tenant_id": "11111111-1111-4111-8111-111111111111",
      "subscription_id": "22222222-2222-4222-8222-222222222222",
      "sentinel_workspace_id": "33333333-3333-4333-8333-333333333333",
      "azure_mcp": {
        "tenant": "11111111-1111-4111-8111-111111111111",
        "subscription": "22222222-2222-4222-8222-222222222222",
        "resource_group": "rg-example",
        "workspace_name": "la-example"
      },
      "memory_file": "example-tenant-context.md",
      "connections": {
        "data_lake": "sentinel-data-example",
        "graph": "graph-example",
        "triage": null
      },
      "workspaces": [
        {
          "id": "33333333-3333-4333-8333-333333333333",
          "name": "la-example",
          "subscription_id": "22222222-2222-4222-8222-222222222222",
          "resource_group": "rg-example"
        }
      ],
      "triage_home_tenant_id": null
    }
  }
}
```

Only `tenant_id` is mandatory in each profile. A case that queries Sentinel needs a
registered workspace; a Defender-only case (`create --no-workspace`) binds none.
`subscription_id`, `sentinel_workspace_id`, `azure_mcp`, `memory_file`,
`connections`, `workspaces`, `triage_home_tenant_id` and the tenant-local tables
`sit_mapping`, `label_mapping` and `sit_priority` are optional. Unknown
profile/workspace/connection fields are rejected, preventing accidental credential
fields from being serialized. Legacy root configuration can still contain unrelated
existing settings.

- Profile and case/run names: lowercase letters, digits, `_`, `-`; start with a
  letter or digit; 1–64 characters. They cannot be paths.
- IDs: nonzero canonical GUIDs (case-insensitive input, normalized lowercase).
- `connections`: only `data_lake`, `graph`, `triage`, each a connection-name
  reference or null. Names start alphanumeric and contain only letters, digits,
  `.`, `_`, `-` (maximum 128 characters). No URLs, auth headers, secrets, or tokens.
  References do not install connections or prove their identity.
- `memory_file`: a simple filename under the existing memory convention, or null.
  It is a reference; this utility does not read or write memory.
- `workspaces`: unique IDs with optional `name`, `subscription_id`,
  `resource_group`. Explicit workspace entries need their own metadata; no
  cross-workspace subscription/resource-group inheritance occurs.
- `sentinel_workspace_id` also registers the default workspace. Its metadata may
  come from this same profile's `azure_mcp`; duplicate default metadata must agree.
  `azure_mcp.tenant`/`subscription` must agree with the corresponding profile IDs.
- For a configured triage reference, offline validation requires an explicitly
  declared `triage_home_tenant_id` equal to `tenant_id`. This declaration is **not**
  proof of the actual MCP identity's home tenant. Guest/delegated triage remains
  unsupported; use a native account in the target tenant. On a guest (B2B) profile
  keep `connections.triage` null. Optionally set `triage_home_tenant_id` to your
  *home* tenant: readiness then reports `triage` as `unsupported` (declared home
  differs) instead of `unverified` (nothing declared), and `render-mcp` emits no
  Triage entry. A case that requires `triage` for such a profile is refused at create.
- `sit_mapping`, `label_mapping`: canonical GUID → short single-line display name
  (maximum 160 characters; a `__comment` key is ignored). `sit_priority`: canonical
  GUID → `High`, `Medium` or `Low` (case-insensitive, normalized). Sensitivity-label
  and custom sensitive-information-type GUIDs belong to one tenant, so they are read
  only from the selected profile and are never merged with the root file or another
  profile. Malformed entries fail closed in a registry profile and are skipped in
  legacy root configuration. Read them with `tenant_context.py mappings <context>`.
- The `profiles` subcommand warns when one connection name is referenced by profiles
  of different tenants: a single MCP connection is authenticated to one tenant, so
  each tenant needs its own named connection (see `render-mcp` below).

## CLI

Run from the repository root; replace synthetic identifiers with your own.
Global flags `--repo-root` and `--config` go **before** the subcommand. Every
subcommand prints exactly one JSON object and exits `0` only when its checks passed
(`1` otherwise; argparse syntax errors use `2`).

```sh
python scripts/tenant_context.py profiles
python scripts/tenant_context.py create --profile example --workspace 33333333-3333-4333-8333-333333333333 --case case-001 --lookback-days 7
python scripts/tenant_context.py create --profile example --workspace 33333333-3333-4333-8333-333333333333 --case query-001 --lookback-days 7 --capability workspace_arm --capability workspace_query
python scripts/tenant_context.py create --profile example --no-workspace --case defender-001 --lookback-days 30 --capability defender_hunting
python scripts/tenant_context.py validate reports/tenants/example/case-001/context.json
python scripts/tenant_context.py validate reports/tenants/example/case-001/context.json --validate-live
python scripts/tenant_context.py verify reports/tenants/example/case-001/context.json
python scripts/tenant_context.py attest reports/tenants/example/case-001/context.json --capability data_lake --status attested --detail "Enumerated workspaces on the example connection; target workspace listed"
python scripts/tenant_context.py readiness reports/tenants/example/case-001/context.json
python scripts/tenant_context.py query reports/tenants/example/case-001/context.json --kql-file hunt.kql --name signins
python scripts/tenant_context.py render-mcp --profile example
python scripts/tenant_context.py mappings reports/tenants/example/case-001/context.json
```

| Subcommand | Purpose |
|---|---|
| `profiles` | Lists profiles with workspaces and connection references (never credentials) plus warnings, such as one connection name shared by two tenants. |
| `create` | Exclusive-creates an immutable context. `--workspace <guid>` or `--no-workspace` is mandatory. Without `--capability` the required set is `tenant_identity` plus `workspace_arm` when a workspace is bound. With `--capability` (repeatable) it is `tenant_identity` plus exactly the names you pass, so list `workspace_arm`/`workspace_query` yourself when you need them. Statically unsupported capabilities are refused. `--hunt-id` / `--window-end` pin a shared hunt window. |
| `validate` | Re-checks an existing context against the registry; never rewrites it. |
| `verify` | Runs tenant-pinned, read-only Azure CLI probes and appends a ledger record per capability. |
| `attest` | Appends a ledger record for an MCP-session capability. This is a **claim**, never proof. |
| `readiness` | Read-only: which capabilities are usable, blocked, expired, unverified or unsupported right now. Exit `1` when a required capability is not usable. |
| `query` | Runs one read-only Log Analytics query over the case window. Needs `workspace_query` among the case's required capabilities and a fresh `verified` record. The rows are written only under the case's `evidence/` directory; stdout carries a summary, never rows. |
| `render-mcp` | Prints per-tenant MCP server entries for you to merge by hand; configures nothing. |
| `mappings` | Prints only this tenant's `sit_mapping`, `label_mapping` and `sit_priority`. |

`--profile` is required when multiple profiles exist; a sole profile is selected
automatically. `--workspace` is always explicit, must be a GUID registered under
that profile, and never accepts `"default"` or a workspace name. `--run` aliases
`--case`; lookback is an integer from 1 through 3650 days. Tool-specific retention
and workspace discovery rules still apply when an investigation executes queries.

Create also accepts `--validate-live`. The context is persisted **before**
validation; failed live validation returns nonzero and leaves the immutable record
for diagnosis. Do not retry create against that run: use `validate` or a new ID.
No query, investigation, or evidence collection is authorized by `create`, `validate`
or `readiness`; `verify` and `query` call only read APIs with a tenant-pinned token.

## Context schema and persistence

The JSON manifest is `reports/tenants/<profile>/<case-or-run>/context.json`.
New contexts use **schema_version 2**; version 1 manifests (no window, hunt or
capabilities) still load and validate, but the capability commands refuse them:
create a new context instead. The fields are:

| Field | Type |
|---|---|
| `schema_version` | integer `2` (`1` accepted for existing manifests) |
| `profile`, `tenant_id` | selected profile slug and tenant GUID |
| `workspace` | object (`id`, `name`, `subscription_id`, `resource_group`), or `null` for a Defender-only case (v2 only) |
| `case_id`, `lookback_days` | run slug and integer 1–3650 |
| `connections` | object: `data_lake`, `graph`, `triage` (name/null) |
| `report_dir` | repository-relative `reports/tenants/<profile>/<case_id>` |
| `created_at` | timezone-aware ISO datetime |
| `memory_file`, `triage_home_tenant_id` | nullable references/declaration |
| `window` | v2: `{start_utc, end_utc}` as `YYYY-MM-DDTHH:MM:SSZ`, exactly `lookback_days` apart, with `end_utc` at most 5 minutes after `created_at` |
| `hunt_id` | v2: shared hunt slug (1–60 characters) or `null`; a hunt case ID must be `<hunt_id>-NN`, NN `01`–`99` |
| `capabilities` | v2: sorted, unique **required** capability names; always includes `tenant_identity` |

Contexts are frozen dataclasses, including nested workspaces and connections.
Create exclusively creates the run directory and manifest; existing runs are
never overwritten or reused. The manifest is owner-readable, not writable
(`0400`); created directories use `0700`. Paths are repository-rooted and
directory-descriptor traversal rejects symlinks, traversal and concurrent symlink
swaps. Legacy `output_dir` cannot override this routing.

Loading checks the exact file location and schema; validation also checks the
persisted record and current selected profile. Changes to a profile's tenant,
selected workspace, connections, memory reference or home-tenant declaration
require a **new run**, not rebinding the old one.

This is application-level immutability, **not tamper-proof storage**. A filesystem
owner can change permissions, alter or delete files; use access controls and
audited/append-only storage where stronger guarantees are required. The safe
directory-descriptor implementation targets POSIX systems supporting `O_NOFOLLOW`
and `dir_fd`; it must not be weakened to follow symlinks on other platforms.

## Collection window and hunts

Every v2 context pins an exact UTC collection window. Queries for the case must filter
with `between (datetime(<start_utc>) .. datetime(<end_utc>))`, never `ago()`, so the
result does not drift when execution is delayed or queued.

A cross-tenant hunt is one request fanned out into one child case per target. The
children share a `hunt_id` and a pinned `window.end_utc` (`create --hunt-id <id> --window-end <end>`),
so results from different tenants are comparable even if the agent runs them minutes
apart. Child case IDs are `<hunt_id>-01`, `-02`, … so two workspaces of one tenant never
share a report directory. Each child still has its own context, ledger and evidence;
nothing is merged across tenants. Mission Control's `POST /api/cross-tenant-hunt` creates
the plan (up to 10 targets, lookback 1–3650 days); see the
[cross-tenant-hunt skill](../.github/skills/cross-tenant-hunt/SKILL.md).

## Capability ledger and readiness

A case can require several capabilities. Each is proven differently, and the ledger
records the outcome so a later step (or Mission Control) can tell what is safe to use.

| Capability | Proof | Scope | Meaning |
|---|---|---|---|
| `tenant_identity` | CLI | tenant | The tenant-pinned Graph organization ID equals the case tenant |
| `workspace_arm` | CLI | workspace | ARM subscription tenant and workspace `customerId` match |
| `workspace_query` | CLI | workspace | The Log Analytics query API answers with a tenant-pinned token |
| `data_lake` | attested | workspace | The Sentinel Data Lake MCP session reaches the case tenant/workspace |
| `graph` | attested | tenant | The Graph MCP session is authenticated to the case tenant |
| `triage` | attested | tenant | The Triage MCP session's home tenant is the case tenant |
| `defender_hunting` | attested | tenant | Defender advanced hunting is available (`--via triage\|graph\|portal`) |

- `verify` runs the CLI probes (`tenant_identity` plus the other CLI capabilities the
  case requires, or those named with `--capability`) and records `verified`, `denied`
  (authenticated but not permitted) or `unverified` (could not be established).
- `attest` records an agent's **claim** about an MCP session this module cannot inspect
  (`attested`, `denied` or `unverified`). It is not proof: a connection name, a header,
  an Azure CLI login or a B2B guest sign-in does not establish which tenant an MCP session
  is authenticated to. An `attested` claim needs a declared connection reference (and
  `--via` for `defender_hunting`) and is refused for statically unsupported capabilities.
- Records are append-only files in the case's private `ledger/` directory
  (`<UTC-stamp>-<capability>.json`, mode `0400`, at most 8 KiB). The newest valid record per
  capability wins. A record expires after `--ttl-hours` (default 24, maximum 168) and then
  reports `expired`. Records for another tenant, profile, case, workspace or capability,
  future-dated, oversized, malformed or with secret-like text are ignored and counted in
  `ignored_records`. A `detail` is plain single-line text of at most 200 characters and is
  refused when it looks like a token or credential.
- `readiness` reads the ledger and reports each capability as `verified`, `attested`,
  `denied`, `unverified`, `expired` or `unsupported`. Only `verified`/`attested` are
  **usable**. `unsupported` comes from declared configuration (no workspace bound, or a
  declared home tenant that differs for Triage). `ok` is true only when every required
  capability is usable. A failed or unusable capability means *unavailable*, never *clean*.

Mission Control shows a JavaScript re-validation of the same records. That view is
**advisory**: `scripts/tenant_context.py readiness` is the authoritative gate.
The ledger is application-level evidence, **not tamper-proof**: anyone who can write
the case directory can add, remove or backdate records.

## Legacy writers and shared tooling

Once a nonempty `tenants` registry exists, the shared legacy output directories
(`temp/`, `reports/user-investigations/`) are never a safe destination for tenant
evidence, so the writers that still produce them require a case.

| Tool | Registry configured | No registry (legacy) |
|---|---|---|
| `enrich_ips.py` | Needs `--context <path>`; results go to `ip_enrichment_<stamp>.json/.txt` in the case directory. `--file` evidence declaring a different `tenant_id` is refused before any lookup. | Unchanged: `temp/ip_enrichment_*` |
| `scripts/generate_report_from_json.py` | Needs `--context <path>`; the input file is never rewritten; the enriched copy and the HTML report are written to the case directory; shared cleanup is skipped. | Unchanged: in-place rewrite, `reports/user-investigations/`, 3-day cleanup |
| `scripts/investigator.py` (`InvestigationConfig`) | Root `tenant_id` and `sentinel_workspace_id` are never used; pass `profile=` to take them from one profile (the workspace only when exactly one is registered). | Reads the root values |
| `scripts/kql_to_ah_url.py` | Never embeds the root `tenant_id`; pass `--tid` explicitly. | Embeds the root `tenant_id` |
| `scripts/cleanup_old_investigations.py` | Unchanged; it only touches its legacy shared locations, never `reports/tenants/**`. | Unchanged |

Usage errors exit `2` and a missing or invalid context prints one error line and writes
nothing. Evidence that declares no tenant is accepted: the explicit context is then the
only binding. The IP-enrichment API tokens remain tenant-agnostic settings. The local-agent
evidence importer (`scripts/import_local_agent_evidence.py`) already requires `--context`.

## Tenant-local mappings

Do not read `sit_mapping`/`label_mapping`/`sit_priority` from the root `config.json` in
registry mode. Use `tenant_context.py mappings <context>` (or the selected profile's own
keys). Entries are never merged across tenants.

## Validation and authenticated proof

Every successful CLI operation emits one JSON object. Validation contains
`ok`, `mode`, `profile`, `context_path` and `sources` (schema v2 also adds
`schema_version`, `hunt_id`, `required_capabilities` and `window`). Source statuses:

- `offline`: `passed`/`failed` structural, path, persisted-record and profile checks.
- `graph_cli`, `workspace_cli`, `workspace_query`: `not_checked`, `verified`,
  `failed` or `not_applicable`, with an explicit `authenticated` boolean. Offline mode
  does **not** authenticate. `workspace_cli` runs only for contexts that require
  `workspace_arm` (always for v1) and `workspace_query` only for v2 contexts that
  require it; a Defender-only case has neither.
- `data_lake`, `graph`, `triage`: always `unverified`; their MCP identities are not
  proven by a separate Azure CLI session. Use `attest` to record a claim and
  `readiness` to see it; neither makes the claim true.

Exit status is `0` only when all checks requested for that mode pass; otherwise
`1` (argument syntax errors use argparse's `2`). `ok: true` in offline mode means
only that offline checks passed. Even authenticated success is **not** proof that
MCP connections are authorized or safe to use.

`--validate-live` (and `verify`, which runs the same probes and records the outcome)
requires an already installed/authenticated Azure CLI, network access and sufficient
read permissions. It performs only:

1. `az account get-access-token` scoped with `--tenant <selected-tenant>` for
   Microsoft Graph. The returned tenant must match.
2. Authenticated `GET https://graph.microsoft.com/v1.0/organization?$select=id`.
   Exactly one organization ID must equal the selected tenant (`tenant_identity`).
3. When `workspace_arm` is required: a similarly tenant-scoped ARM token and
   authenticated subscription GET (`api-version=2022-12-01`). Both subscription ID
   and `tenantId` must match.
4. When `workspace_arm` is required: authenticated ARM workspace GET
   (`api-version=2023-09-01`). The returned resource ID and `properties.customerId`
   must match the selected workspace.
5. When `workspace_query` is required: a tenant-pinned Log Analytics token and the
   trivial read-only query `print probe=1` against the selected workspace GUID.

The workspace's subscription/name/resource group are mandatory for the ARM proof.
Graph organization reads require suitable Graph organization-read permission;
ARM reads require subscription/workspace read access. Wrong tenant, HTTP
401/403, missing metadata/CLI, token acquisition errors, unexpected responses,
or timeouts **fail closed**. No auto-login, account switch, alternate tenant,
workspace fallback, or offline-success fallback occurs. HTTP redirects are not
followed; tokens and raw CLI/HTTP error bodies are never printed or persisted.
These checks use public-cloud Microsoft endpoints only.

`az account get-access-token --tenant <id>` only returns a token when the Azure CLI
already holds a session that can reach that tenant (for a B2B guest this typically means
an earlier `az login --tenant <guest-tenant-id>`). The command never logs in for you. Reaching
the tenant does not grant Graph or Azure RBAC roles; a missing role shows up as
`denied` or `unverified`, which is the correct result.

No live credentials are included in tests; mocked success is not a live tenant
verification. Do not claim authenticated success without an actual successful run.

## Python integration

```python
from pathlib import Path
from scripts.tenant_context import load_context, readiness, validate_context

root = Path.cwd()
context = load_context("reports/tenants/example/case-001/context.json", repo_root=root)
status = validate_context(context, root / "config.json", repo_root=root)
if not status["ok"]:
    raise ValueError("Context validation failed")
gate = readiness(context, repo_root=root)  # read-only; never authenticates or queries
if not gate["ok"]:
    raise ValueError("Required capabilities are not usable: " + ", ".join(gate["blocked"]))
```

Public API: `load_profiles(config_path) -> dict[str, TenantProfile]`,
`select_profile(profiles, profile=None) -> TenantProfile`,
`create_context(config_path, *, profile=None, workspace_id, case_id, lookback_days,
repo_root=..., capabilities=None, hunt_id=None, window_end=None) -> InvestigationContext`
(`workspace_id=None` creates a Defender-only case), `load_context(path, repo_root=...)`,
`context_path(repo_root, context) -> Path`,
`validate_context(context, config_path=..., *, repo_root=..., validate_live=False)
-> dict`, and `open_report_directory(repo_root, context)` yielding a safe integer
directory descriptor. `context.to_dict()` or `dataclasses.asdict(context)` gives
the JSON schema; `context.workspace_id` aliases `context.workspace.id` (or `None`).

Capability and evidence helpers (schema v2 contexts only):
`verify_capabilities(context, *, repo_root, capabilities=None, ttl_hours=24)`,
`attest_capability(context, *, repo_root, capability, status, detail, via=None, ttl_hours=24)`,
`readiness(context, *, repo_root)`, `read_ledger(repo_root, context)`,
`run_query(context, kql_file, name, *, repo_root, max_rows=10000)`,
`render_mcp(profile)` and `tenant_mappings(context, config_path)`.
Writers that must stay tenant-bound use `require_case_context(path, *, repo_root,
config_path=None)` (returns `None` only when no registry is configured; with a registry it
demands a valid context), `check_evidence_tenant(data, context)` and
`write_case_file(repo_root, context, name, content, *, mode=0o600)`, which exclusive-creates
`name` (`[A-Za-z0-9][A-Za-z0-9_.-]{0,127}.json|html|txt`, never `context.json`) in the case
directory through directory descriptors.

Evidence writers should use `write_case_file`, or `open_report_directory` plus relative
safe leaf names with `os.open(..., dir_fd=fd, O_CREAT | O_EXCL | O_NOFOLLOW, mode=0o600)`.
Do not merely concatenate untrusted evidence names onto `report_dir`.

Focused tests: `python -m unittest discover -s tests -p test_tenant_context.py -v` and
`python -m unittest discover -s tests -p test_legacy_writers.py -v` (the second uses
network-blocking stand-ins for `requests` and `python-dotenv` from
`tests/fixtures/offline_stubs/`, so it needs neither package nor network).
The whole Python suite is `python -m unittest discover -s tests -v`; the Mission Control
JavaScript tests are described in the [README](../README.md).

References: [Azure CLI token acquisition](https://learn.microsoft.com/cli/azure/account#az-account-get-access-token),
[Graph organization GET](https://learn.microsoft.com/graph/api/organization-get),
[ARM subscription GET](https://learn.microsoft.com/rest/api/resources/subscriptions/get),
[workspace GET](https://learn.microsoft.com/rest/api/loganalytics/workspaces/get),
[triage limitations](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-triage-tool#limitations).
Microsoft behavior can change; confirm against the current documentation.
