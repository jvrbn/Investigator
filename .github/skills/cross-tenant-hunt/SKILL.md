---
name: cross-tenant-hunt
description: Run an explicitly selected, read-only indicator or threat hunt across tenant profiles and workspaces, with immutable case contexts, per-connection authorization checks, isolated findings, and explicit coverage/errors. Triggers on cross-tenant hunt, multi-tenant hunt, hunt across customers, and hunt across selected profiles.
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

- Indicator or hunt request and lookback.
- Explicit profile selection, including an explicit workspace ID **for each** target.
- Safe lowercase case identifier (1–64 letters, digits, underscores or dashes).

Use the local `profiles` subcommand to inspect registered profiles when necessary. Do not query or authenticate merely because a picker changes. Never select all profiles/workspaces by default. Display all relevant workspaces when selection is ambiguous; stop and wait for an explicit choice. A profile's default workspace is not an implicit authorization to fan out.

**Mission Control:** open the **Cross-tenant hunt (read-only)** section, check the exact profile/workspace pairs, enter a hunt request and lookback, then select **Launch selected targets**. Each selected pair becomes an independent, frozen launch. The extension queues execution one at a time; it does not secretly query data in the background.

**Single-target invocation from the canvas:** the frozen launch already authorizes only the one named profile/workspace. Execute that target only. Other targets are separate queued launches; do not rediscover, expand, or combine their scopes.

## 2. Create and validate immutable context

Before any tenant data access, use `scripts/tenant_context.py` to create the canonical context for the exact profile, workspace, case and requested lookback:

- `create --profile <selected-profile> --workspace <selected-workspace-guid> --case <case-slug> --lookback-days <days> --validate-live`
- `validate <canonical-context-path> --validate-live`

Invoke these subcommands through the configured Python interpreter. They perform read-only tenant checks and write only local case artifacts. Do not change Azure CLI defaults or log into a different tenant automatically. Authentication, permission or context-validation failures stop that target.

The secure context helpers require POSIX `O_NOFOLLOW`, `O_DIRECTORY` and `dir_fd` support. On unsupported platforms or unsafe paths, stop and record the target as `unavailable`/`error` with the actual failure detail so Mission Control displays it. Never fall back to ordinary path-based writes or present this as a clean hunt.

Load the canonical context with the module's `load_context` API where code consumes it. Use its `report_dir`, `case_id`, `workspace.id`, `tenant_id`, connection references and `memory_file`; do not rederive a different spelling or silently recreate/overwrite a conflicting context.

Context schema version 1 includes `profile`, `tenant_id`, `workspace`, `case_id`, `lookback_days`, `connections`, `report_dir`, `created_at`, `memory_file`, and `triage_home_tenant_id`. Keep every field, including nullable fields. Pass the same context to every child tool, query, report and finding. Do not reread mutable global selection to route a result.

Only read the explicit `memory_file` for this context under `~/.copilot/memories/repo/`. If absent, say memory is unavailable. Never fall back to generic memory, another customer, top-level legacy configuration, or broad report searches.

## 3. Verify capabilities independently for each target

Build a capability/authorization ledger **before** running its hunts:

| Source | Required evidence |
|---|---|
| Local context | Profile/workspace matches the frozen request; core validation succeeds. |
| CLI Graph / workspace checks | `--validate-live` verifies the organization tenant, subscription tenant and workspace resource/customer ID. Report precisely which checks passed. |
| Data Lake MCP | Exact configured connection is available, and positive read-only tenant/workspace authorization evidence establishes the target. Enumerate workspaces on this connection and match the explicitly selected ID before querying. |
| Graph MCP | Exact configured connection is available, with positive authenticated organization/tenant evidence equal to `tenant_id`. Use endpoint discovery before Graph GETs. |
| Triage / Advanced Hunting MCP | The authenticated/home tenant is verified equal to `tenant_id`; `triage_home_tenant_id` alone is configuration, not proof. Triage is home-tenant-bound. |

Core validation reports MCP sources as **unverified**. Do not promote them to authenticated based on CLI checks. If the tools cannot establish a connection's authenticated tenant, mark that source unavailable and do not send the hunt to it. Do not borrow an accessible connection from another profile.

A Triage connection bound to another tenant, or with unknown home tenant, cannot be used for this target. Explain that limit explicitly. Continue only on independently verified sources that satisfy the requested hunt; otherwise record the target as unavailable. Never present incomplete source coverage as an environment-wide clean result.

Apply workspace rules independently per selected tenant: enumerate first; match the chosen ID; on ambiguous, missing or rejected selection stop that target. On a query/workspace error preserve the error; never retry against another workspace automatically.

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

Pick only relevant queries; this is not a request to execute every file. Follow repository schema/discovery and zero-result sanity checks. Use Advanced Hunting only for lookbacks up to 30 days **and** a verified matching home tenant; use verified Data Lake connections for longer windows. Confirm that each table exists on the chosen plane. Do not silently truncate the requested time range or substitute a different table to hide unavailable telemetry.

Do not copy untested KQL into chat or reports. Execute and validate any query before sharing it; where execution is blocked, report the limitation and the library path instead. Library reuse does not prove that the target has that telemetry.

## 5. Per-target results and correlation

Keep artifacts exclusively inside the canonical `context.report_dir`. Never merge raw customer evidence or PII into a different tenant's report. A cross-tenant summary may contain only explicitly requested, appropriately minimized coverage/status information, with each row labeled by profile and workspace.

For each target report:

- Profile, tenant, workspace, case and original launch correlation identifier.
- Source capability/auth evidence and exact lookback actually queried.
- Verified findings with source/time/count evidence.
- Missing telemetry, auth/query errors and unexecuted scope.
- Verdict restricted to the coverage actually verified.

Use statuses **complete**, **error**, or **unavailable**. `complete` means the authorized requested scope ran, not necessarily that it was clean. Zero rows may support a scoped clean result only after query/schema/filter/coverage sanity checks. Failures never count as zero matches.

When launched through Mission Control, call `record_hunt_status` for progress/failures and `record_finding` for the final target result. Pass **all exact original frozen fields** on each call:

`correlationId`, `profile`, `tenantId`, `workspaceId`, `caseId`.

Also pass `status`, `title`, `severity` and an evidence-based `summary` to `record_finding`. For errors/unavailable use informational severity, not `clean`. Bind report paths to the captured tenant/case. Missing/mismatched/expired correlations are rejected: do not replace them with the current picker's values. A result arriving after the analyst changes profiles must still route to its original target.

Do not update a second target's status or finding using the first target's token. Do not imply that queued, cancelled, unrecorded or inaccessible targets completed successfully.

## Mission Control integration contract

- `POST /api/context`: explicit `profile`, `workspaceId`, optional `caseId`; changes only local UI context. Busy sessions must finish/cancel queued work and stop autopilot before switching.
- `POST /api/cross-tenant-hunt`: nonempty explicit `targets: [{profile, workspaceId}]`, `request`, `lookbackDays`, optional `caseId`. Returns per-target original bindings and queue/send errors.
- `POST /api/hunt-status`: the returned original `bindings` retrieves only those selected targets' statuses.
- `record_finding` and `record_hunt_status` validate the original launch binding, not mutable selection.
- HTTP APIs carry the page's context revision; stale pages fail closed. Findings, archives, costing, preferences, activity and hunt statuses are tenant-isolated. Unassigned legacy state is never imported into a customer.
- Scoped report listings/previews require a canonical case manifest matching both profile and tenant ID; reassigning a profile slug does not expose its prior customer's reports. Shared query-library previews remain global. The configured memory filename is an explicit reference, not a filesystem sandbox; do not assign the same memory file to unrelated customers.

Browser-only validation: `node .github/extensions/skills-canvas/preview-ui.mjs` prints a loopback URL and stops after 120 seconds (or Ctrl-C). It renders synthetic profiles and stubs selection, fanout and per-target failure statuses without reading `config.json`, invoking the SDK/Python, authenticating, querying tenant data or persisting state.

No live authorization is assumed by this workflow or by its UI. Connection access must be verified at execution time.
