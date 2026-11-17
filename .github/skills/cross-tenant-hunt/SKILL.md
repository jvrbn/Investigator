---
name: cross-tenant-hunt
description: Run an explicitly selected, read-only indicator or threat hunt across tenant profiles and workspaces, including B2B guest tenants and Defender multitenant organization (MTO) tenants, with immutable case contexts, per-capability readiness checks, isolated findings, and explicit coverage/errors. Triggers on cross-tenant hunt, multi-tenant hunt, multitenant organization hunt, MTO hunt, B2B guest tenant hunt, hunt across customers, and hunt across selected profiles.
threat_pulse_domains: [incidents, identity, endpoint, cloud, email]
drill_down_prompt: 'Run a read-only cross-tenant hunt for {entity} across explicitly selected profiles and workspaces'
---

# Cross-Tenant Hunt

## Scope and safety

This workflow orchestrates existing verified hunts; it does not grant authorization, switch MCP authentication, or create detections. No resource changes, incident updates, containment, tenant writes, or executable remediation commands. Loading a profile is **not** authentication.

Never infer the authenticated tenant from an MCP server/header name, a connection reference, the active Azure CLI account, or an earlier successful query. CLI validation does not establish MCP authentication. A target that cannot be positively verified is **unavailable**, not clean.

**Transcript boundary:** Mission Control uses the existing Copilot conversation through `session.send()`. Profile selection isolates local routing/state, **not** authenticated tool sessions, prior messages, or the model's conversation context. This is an explicitly selected multi-tenant coordinator, not a per-customer model sandbox. The analyst must permit the selected cross-tenant workflow and any minimized coverage/status aggregation. For strict customer transcript separation, use separate chat/client sessions and independently validated connections; do not execute multiple customers in this shared conversation. Never copy prior customer evidence into a new target's prompt or report.

## 1. Explicit target selection

Read `config.json` locally and inspect `scripts/tenant_context.py`. Its optional `tenants` registry is keyed by safe lowercase profile slugs. Missing or empty `tenants` retains the legacy single-tenant workflow; it does not authorize a cross-tenant hunt.

Collect the analyst's:

- Indicator or hunt request and lookback (1–3650 days). One UTC collection window is pinned for the whole hunt (§2).
- Explicit profile selection, including an explicit workspace ID **for each** target, or an explicit **Defender-only** choice for a tenant whose Sentinel workspace you cannot or need not use (for example a B2B guest tenant reached through Defender multitenant management). A Defender-only target names no workspace and cannot require `workspace_arm`, `workspace_query` or `data_lake`.
- Hunt ID: a lowercase slug of up to 60 characters. Each target runs as its own child case `<hunt-id>-NN` (`NN` 01–99), so two workspaces of one tenant never share a report directory. Mission Control generates `hunt-<yyyymmdd>-<hex>` when none is given. A standalone (non-hunt) case uses a safe lowercase case identifier (1–64 letters, digits, underscores or dashes).
- Optionally, extra required capabilities (§3). `tenant_identity` is always required.

Use the local `profiles` subcommand to inspect registered profiles when necessary. Do not query or authenticate merely because a picker changes. Never select all profiles/workspaces by default. Display all relevant workspaces when selection is ambiguous; stop and wait for an explicit choice. A profile's default workspace is not an implicit authorization to fan out. Select 1–10 targets; duplicates are refused, and one invalid target rejects the whole request before any case is planned or prompt sent.

**Mission Control:** open the **Cross-tenant hunt (read-only)** section, check the exact profile/workspace (or Defender-only) targets, enter a hunt request, optional hunt ID, lookback and required capabilities, choose a run mode, then select **Launch selected targets**.

- **Launch here:** each selected target becomes an independent, frozen launch with its own `<hunt-id>-NN` case and the shared pinned window. The extension queues execution one at a time; it does not secretly query data in the background.
- **Hand-off prompts:** nothing is sent or created. Mission Control returns one self-contained prompt and context path per target, for a **separate** chat/client session per tenant. Those sessions have no launch binding (§5).
- A target whose explicitly requested capabilities are all ruled out by declared configuration (for example Triage on a guest tenant) is reported **unavailable**, never dropped and never clean.

**Single-target invocation from the canvas:** the frozen launch already authorizes only the one named profile/workspace (or Defender-only scope). Execute that target only. Other targets are separate queued launches; do not rediscover, expand, or combine their scopes.

## 2. Create and validate immutable context

Before any tenant data access, use `scripts/tenant_context.py` to create the canonical context for the exact profile, workspace, case and requested lookback. A Mission Control launch hands you the exact commands in its frozen envelope; run them verbatim and in order.

- `create --profile <selected-profile> --workspace <selected-workspace-guid> --case <case-slug> --lookback-days <days> --validate-live`
  - Defender-only target: pass `--no-workspace` instead of `--workspace`.
  - Hunt child case: also pass `--hunt-id <hunt-id> --window-end <utc-stamp>` so every target of the hunt shares one pinned window.
  - Required capabilities: add one `--capability <name>` per capability. Naming any replaces the default (`tenant_identity`, plus `workspace_arm` when a workspace is bound), so name every one you need. Statically unsupported capabilities are refused at `create`.
- `verify <canonical-context-path>` — read-only Azure CLI probes whose results are recorded in the case ledger (§3).
- `validate <canonical-context-path> --validate-live` — optional re-check of an existing context; it never rewrites it and records no ledger entry.

If the case's `context.json` already exists (a follow-up in the same case), skip `create`; never recreate or overwrite it.

Invoke these subcommands through the configured Python interpreter. They perform read-only tenant checks and write only local case artifacts. Do not change Azure CLI defaults or log into a different tenant automatically. Authentication, permission or context-validation failures stop that target.

The secure context helpers require POSIX `O_NOFOLLOW`, `O_DIRECTORY` and `dir_fd` support. On unsupported platforms or unsafe paths, stop and record the target as `unavailable`/`error` with the actual failure detail so Mission Control displays it. Never fall back to ordinary path-based writes or present this as a clean hunt.

Load the canonical context with the module's `load_context` API where code consumes it. Use its `report_dir`, `case_id`, `workspace.id` (the `workspace` is null for a Defender-only case), `tenant_id`, connection references and `memory_file`; do not rederive a different spelling or silently recreate/overwrite a conflicting context.

Context schema version 2 (version 1 contexts still load) includes `profile`, `tenant_id`, `workspace`, `case_id`, `lookback_days`, `connections`, `report_dir`, `created_at`, `memory_file`, `triage_home_tenant_id`, plus `window` (`start_utc`/`end_utc`, the pinned collection window), `hunt_id` (null outside a hunt) and `capabilities` (the required set). Keep every field, including nullable fields. Pass the same context to every child tool, query, report and finding. Do not reread mutable global selection to route a result.

Only read the explicit `memory_file` for this context under `~/.copilot/memories/repo/`. If absent, say memory is unavailable. Never fall back to generic memory, another customer, top-level legacy configuration, or broad report searches.

## 3. Verify capabilities independently for each target

Record each capability's evidence **before** running its hunts. The case ledger (`reports/tenants/<profile>/<case>/ledger/`) is written only by `scripts/tenant_context.py`; do not hand-write files into it and do not keep a second informal ledger in chat.

1. `verify <context>` — Azure CLI probes for the CLI-provable capabilities in the required set. Each result is recorded as `verified`, `denied` or `unverified`. It never logs in or switches tenant: a missing or wrong-tenant CLI session is reported, not repaired.
2. For each MCP capability you intend to use (`data_lake`, `graph`, `triage`, `defender_hunting`), establish that connection's authenticated tenant yourself with a read-only call, then record your claim: `attest <context> --capability <name> --status <attested|denied|unverified> --detail "<non-secret evidence>"`. `defender_hunting` also needs `--via <triage|graph|portal>`. An attestation is **your claim, not proof**: the CLI cannot see MCP sessions.
3. `readiness <context>` — query **only** capabilities listed under `usable` (`verified`, or `attested` and still fresh). Report everything `blocked`, `denied`, `expired`, `unverified` or `unsupported` as unavailable, never clean. Records expire (24 hours by default), so re-run `verify`/`attest` instead of reusing old results.

| Capability | Proven by | Evidence required |
|---|---|---|
| `tenant_identity` | CLI (`verify`) | Graph `organization` returns the expected tenant ID. |
| `workspace_arm` | CLI (`verify`) | The ARM subscription and workspace resolve in the expected tenant. |
| `workspace_query` | CLI (`verify`) | A read-only Log Analytics probe succeeds for the workspace. Required before `query`. |
| `data_lake` | Attestation | Enumerate workspaces on the exact configured Data Lake connection and match the explicitly selected workspace ID. |
| `graph` | Attestation | Positive authenticated organization/tenant evidence from the exact configured Graph connection, equal to `tenant_id`. Use endpoint discovery before Graph GETs. |
| `triage` | Attestation | The authenticated/home tenant is verified equal to `tenant_id`; `triage_home_tenant_id` alone is configuration, not proof. Triage is home-tenant-bound and is `unsupported` for another tenant's guest access. |
| `defender_hunting` | Attestation | The route (`triage`, `graph` or `portal`) that actually ran a read-only hunting query in this tenant. |

`attest` refuses an `attested` claim for a capability whose connection is not declared for the tenant, and refuses any claim for a capability that declared configuration rules out (for example Triage on a guest tenant). A B2B guest sign-in, an MCP server or header name, the active Azure CLI account, or the Defender multitenant portal view does not prove which tenant an MCP session is authenticated to, and grants no roles. If the tools cannot establish a connection's authenticated tenant, mark that source unavailable and do not send the hunt to it. Do not borrow an accessible connection from another profile.

A Triage connection bound to another tenant, or with unknown home tenant, cannot be used for this target. Explain that limit explicitly. Continue only on independently verified sources that satisfy the requested hunt; otherwise record the target as unavailable. Never present incomplete source coverage as an environment-wide clean result.

Apply workspace rules independently per selected tenant: enumerate first; match the chosen ID; on ambiguous, missing or rejected selection stop that target. On a query/workspace error preserve the error; never retry against another workspace automatically.

When the Azure CLI route is the intended data plane, `query <context> --kql-file <repo-relative .kql file> --name <slug>` runs one read-only query over the case window. It needs `workspace_query` among the case's required capabilities and a fresh `verified` record, writes the full rows under `<case>/evidence/`, and prints only a summary.

## 4. Reuse verified hunt content

Discover suitable queries through `.github/manifests/discovery-manifest.yaml` and targeted searches of `queries/` and `.github/skills/`. Inspect the actual query before substituting the selected entity/time window. Examples of verified-library starting points:

- `queries/incidents/security_incident_analysis.md`
- `queries/identity/aitm_threat_detection.md`
- `queries/identity/app_credential_management.md`
- `queries/endpoint/mde_alert_device_forensics.md`
- `queries/endpoint/rare_process_chains.md`
- `queries/cloud/cloudappevents_exploration.md`
- `queries/cloud/graph_api_security_monitoring.md`
- `queries/email/email_threat_detection.md`

Pick only relevant queries; this is not a request to execute every file. Follow repository schema/discovery and zero-result sanity checks. Filter time with the context's pinned collection window — `where <time column> between (datetime(<window.start_utc>) .. datetime(<window.end_utc>))` — never `ago()` or another relative window, so every target of a hunt covers the same period even when the agent runs them minutes apart. Use Advanced Hunting only for windows up to 30 days **and** only through a route that `readiness` lists as usable (`triage` or `defender_hunting`) for this target; use a verified Data Lake connection for longer windows, because Advanced Hunting silently truncates to 30 days. If a target has no usable plane for the full window, report it unavailable for that window instead of querying a shorter one. Confirm that each table exists on the chosen plane. Do not silently truncate the requested time range or substitute a different table to hide unavailable telemetry.

Do not copy untested KQL into chat or reports. Execute and validate any query before sharing it; where execution is blocked, report the limitation and the library path instead. Library reuse does not prove that the target has that telemetry.

## 5. Per-target results and correlation

Keep artifacts exclusively inside the canonical `context.report_dir`. Never merge raw customer evidence or PII into a different tenant's report. A cross-tenant summary may contain only explicitly requested, appropriately minimized coverage/status information, with each row labeled by profile, workspace (or Defender-only) and the shared window.

For each target report:

- Profile, tenant, workspace (or Defender-only), hunt ID, case and original launch correlation identifier (none for a hand-off).
- Source capability/auth evidence: the `readiness` result (usable, blocked, denied, expired, unverified, unsupported) and the exact collection window actually queried.
- Verified findings with source/time/count evidence.
- Missing telemetry, auth/query errors and unexecuted scope.
- Verdict restricted to the coverage actually verified.

Use statuses **complete**, **error**, or **unavailable**. `complete` means the authorized requested scope ran, not necessarily that it was clean. Zero rows may support a scoped clean result only after query/schema/filter/coverage sanity checks. Failures never count as zero matches. A capability that is denied, expired, unverified or unsupported makes the target **unavailable** for the telemetry it would have provided.

When launched through Mission Control, call `record_hunt_status` for progress/failures and `record_finding` for the final target result. Pass **all exact original frozen fields** on each call:

`correlationId`, `profile`, `tenantId`, `workspaceId` (the empty string for a Defender-only target), `caseId`.

Also pass `status`, `title`, `severity` and an evidence-based `summary` to `record_finding`. For errors/unavailable use informational severity, not `clean`. Bind report paths to the captured tenant/case. Missing/mismatched/expired correlations are rejected: do not replace them with the current picker's values. A result arriving after the analyst changes profiles must still route to its original target.

**Hand-off sessions** carry no correlation ID or canvas binding. Do not call `record_finding` or `record_hunt_status` there; keep every artifact under the case directory and state this target's usable, blocked and unsupported capabilities in its report. Mission Control does not see a hand-off result.

Do not update a second target's status or finding using the first target's token. Do not imply that queued, cancelled, unrecorded or inaccessible targets completed successfully.

## Mission Control integration contract

- `POST /api/context`: explicit `profile`, `workspaceId` (or `defenderOnly: true`), optional `caseId`; changes only local UI context. Busy sessions must finish/cancel queued work and stop autopilot before switching.
- `POST /api/cross-tenant-hunt`: `targets` — 1–10 explicit `{profile, workspaceId}` or `{profile, defenderOnly: true}` entries; `request` (up to 12000 characters); optional `lookbackDays` (1–3650, default 7), `huntId` (lowercase slug up to 60 characters; `caseId` is accepted as an alias), `capabilities` (extra required capabilities) and `mode` (`launch`, the default, or `handoff`). Every target is validated before any run is created or prompt sent; one invalid or duplicate target rejects the whole request. Targets become child cases `<huntId>-NN` that share one pinned `window`. Launch mode is refused while autopilot is on or when the queue cannot hold the fanout (10 maximum). Each result row carries the target, `caseId`, `huntId`, `window`, `requiredCapabilities`, `unsupportedCapabilities` and a `status` of `queued`, `sent`, `unavailable`, `error` or (hand-off) `handoff` with a `contextPath` and `prompt`. Launched and unavailable rows return the original `binding`.
- `POST /api/hunt-status`: the returned original `bindings` retrieves only those selected targets' statuses.
- `POST /api/readiness`: advisory and read-only; it never authenticates or queries a tenant. With original `bindings` it re-reads each launched case's ledger. With explicit `targets` it reports the newest ledger record per capability from that profile's earlier cases for the exact tenant and workspace (an expired record shows as `expired`). The authoritative answer is always `python scripts/tenant_context.py readiness <context>`.
- `record_finding` and `record_hunt_status` validate the original launch binding, not mutable selection.
- HTTP APIs carry the page's context revision; stale pages fail closed. Findings, archives, costing, preferences, activity and hunt statuses are tenant-isolated. Unassigned legacy state is never imported into a customer.
- Scoped report listings/previews require a canonical case manifest matching both profile and tenant ID; reassigning a profile slug does not expose its prior customer's reports. Shared query-library previews remain global. The configured memory filename is an explicit reference, not a filesystem sandbox; do not assign the same memory file to unrelated customers.

Browser-only validation: `node .github/extensions/skills-canvas/preview-ui.mjs` prints a loopback URL and stops after 120 seconds (or Ctrl-C). It renders synthetic profiles and stubs selection, fanout and per-target failure statuses without reading `config.json`, invoking the SDK/Python, authenticating, querying tenant data or persisting state.

No live authorization is assumed by this workflow or by its UI. Connection access must be verified at execution time.
