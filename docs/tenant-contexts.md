# Tenant profiles and immutable investigation contexts

`scripts/tenant_context.py` supports Python **3.8+** using postponed annotations and
only the standard library. JavaScript UTC timestamps ending in `Z` are accepted
on that baseline too. It does not change
Azure configuration, sign in, switch subscriptions, or configure MCP servers.
Contexts are opt-in: existing scripts retain their existing single-tenant behavior.
Keep real `config.json` and reports private; never commit live identifiers or tokens.

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

Only `tenant_id` is mandatory in each profile. Supply at least one registered
workspace before creating a context. `subscription_id`, `sentinel_workspace_id`,
`azure_mcp`, `memory_file`, `connections`, `workspaces`, and
`triage_home_tenant_id` are optional. Unknown profile/workspace/connection fields
are rejected, preventing accidental credential fields from being serialized.
Legacy root configuration can still contain unrelated existing settings.

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
  unsupported; use a native account in the target tenant.

## CLI

Run from the repository root; replace synthetic identifiers with your own.
Global flags `--repo-root` and `--config` go **before** the subcommand.

```sh
python scripts/tenant_context.py profiles
python scripts/tenant_context.py create --profile example --workspace 33333333-3333-4333-8333-333333333333 --case case-001 --lookback-days 7
python scripts/tenant_context.py validate reports/tenants/example/case-001/context.json
python scripts/tenant_context.py validate reports/tenants/example/case-001/context.json --validate-live
```

`--profile` is required when multiple profiles exist; a sole profile is selected
automatically. `--workspace` is always explicit, must be a GUID registered under
that profile, and never accepts `"default"` or a workspace name. `--run` aliases
`--case`; lookback is an integer from 1 through 3650 days. Tool-specific retention
and workspace discovery rules still apply when an investigation executes queries.

Create also accepts `--validate-live`. The context is persisted **before**
validation; failed live validation returns nonzero and leaves the immutable record
for diagnosis. Do not retry create against that run: use `validate` or a new ID.
No query, investigation, or evidence collection is authorized by this utility.

## Context schema and persistence

The JSON manifest is `reports/tenants/<profile>/<case-or-run>/context.json`.
Its fields are:

| Field | Type |
|---|---|
| `schema_version` | integer `1` |
| `profile`, `tenant_id` | selected profile slug and tenant GUID |
| `workspace` | object: `id`, `name`, `subscription_id`, `resource_group` |
| `case_id`, `lookback_days` | run slug and positive integer |
| `connections` | object: `data_lake`, `graph`, `triage` (name/null) |
| `report_dir` | repository-relative `reports/tenants/<profile>/<case_id>` |
| `created_at` | timezone-aware ISO datetime |
| `memory_file`, `triage_home_tenant_id` | nullable references/declaration |

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

## Validation and authenticated proof

Every successful CLI operation emits one JSON object. Validation contains
`ok`, `mode`, `profile`, `context_path` and `sources`. Source statuses:

- `offline`: `passed`/`failed` structural, path, persisted-record and profile checks.
- `graph_cli`, `workspace_cli`: `not_checked`, `verified` or `failed`, with an
  explicit `authenticated` boolean. Offline mode does **not** authenticate.
- `data_lake`, `graph`, `triage`: always `unverified`; their MCP identities are not
  proven by a separate Azure CLI session.

Exit status is `0` only when all checks requested for that mode pass; otherwise
`1` (argument syntax errors use argparse's `2`). `ok: true` in offline mode means
only that offline checks passed. Even authenticated success is **not** proof that
MCP connections are authorized or safe to use.

`--validate-live` requires an already installed/authenticated Azure CLI, network
access and sufficient read permissions. It performs only:

1. `az account get-access-token` scoped with `--tenant <selected-tenant>` for
   Microsoft Graph. The returned tenant must match.
2. Authenticated `GET https://graph.microsoft.com/v1.0/organization?$select=id`.
   Exactly one organization ID must equal the selected tenant.
3. A similarly tenant-scoped ARM token and authenticated subscription GET
   (`api-version=2022-12-01`). Both subscription ID and `tenantId` must match.
4. Authenticated ARM workspace GET (`api-version=2023-09-01`). The returned
   resource ID and `properties.customerId` must match the selected workspace.

The workspace's subscription/name/resource group are mandatory for live proof.
Graph organization reads require suitable Graph organization-read permission;
ARM reads require subscription/workspace read access. Wrong tenant, HTTP
401/403, missing metadata/CLI, token acquisition errors, unexpected responses,
or timeouts **fail closed**. No auto-login, account switch, alternate tenant,
workspace fallback, or offline-success fallback occurs. HTTP redirects are not
followed; tokens and raw CLI/HTTP error bodies are never printed or persisted.
These checks use public-cloud Microsoft endpoints only.

No live credentials are included in tests; mocked success is not a live tenant
verification. Do not claim authenticated success without an actual successful run.

## Python integration

```python
from pathlib import Path
from scripts.tenant_context import load_context, validate_context

root = Path.cwd()
context = load_context("reports/tenants/example/case-001/context.json", repo_root=root)
status = validate_context(context, root / "config.json", repo_root=root)
if not status["ok"]:
    raise ValueError("Context validation failed")
```

Public API: `load_profiles(config_path) -> dict[str, TenantProfile]`,
`select_profile(profiles, profile=None) -> TenantProfile`,
`create_context(config_path, *, profile=None, workspace_id, case_id, lookback_days,
repo_root=...) -> InvestigationContext`, `load_context(path, repo_root=...)`,
`context_path(repo_root, context) -> Path`,
`validate_context(context, config_path=..., *, repo_root=..., validate_live=False)
-> dict`, and `open_report_directory(repo_root, context)` yielding a safe integer
directory descriptor. `context.to_dict()` or `dataclasses.asdict(context)` gives
the JSON schema; `context.workspace_id` aliases `context.workspace.id`.

Evidence writers should use `open_report_directory` plus relative safe leaf names
with `os.open(..., dir_fd=fd, O_CREAT | O_EXCL | O_NOFOLLOW, mode=0o600)`.
Do not merely concatenate untrusted evidence names onto `report_dir`.

Focused tests: `python -m unittest discover -s tests -p test_tenant_context.py -v`.

References: [Azure CLI token acquisition](https://learn.microsoft.com/cli/azure/account#az-account-get-access-token),
[Graph organization GET](https://learn.microsoft.com/graph/api/organization-get),
[ARM subscription GET](https://learn.microsoft.com/rest/api/resources/subscriptions/get),
[workspace GET](https://learn.microsoft.com/rest/api/loganalytics/workspaces/get),
[triage limitations](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-triage-tool#limitations).
