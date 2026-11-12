# MDE Alert-Triggered Device Investigation: Skill and Automation Plan

Status: Reviewed 2026-11-11. Phases A–B (read-only, analyst-guided MVP) are implemented in the repository; Phases C–E remain proposed. No automation, endpoint collection, or response action exists. The new queries were checked offline against the published schemas and have **not** yet been executed against a live tenant (see §11).
Prepared: 2026-11-11.

## 1. Objective and recommended approach

Give a SOC analyst an evidence-backed answer to:

1. What caused the MDE alert, and was the device impacted or merely related?
2. Did execution, persistence, credential access, or network activity actually succeed?
3. How did the activity start, what happened next, and what remains active?
4. Which users, files, destinations, and other devices are affected?
5. What has Defender already blocked or remediated, and what still needs action?
6. What is unknown because evidence is missing, stale, inaccessible, or outside retention?

**Recommendation: add an MDE alert-anchored mode to the existing
[computer-investigation skill](../.github/skills/computer-investigation/SKILL.md),
with a structured handoff from
[incident-investigation](../.github/skills/incident-investigation/SKILL.md).**
Preserve the current standalone device workflow. Do not copy its queries into a
third broad device-investigation skill.

Start with Windows endpoint/server triage, then add platform-specific macOS and
Linux branches. Unsupported Windows artifacts on other platforms must be marked
not applicable, not absent.

The first release is read-only telemetry investigation. Live Response,
investigation-package collection, containment, and remediation remain separate,
explicitly approved activities.

### Existing foundations

- Device investigation already covers identity resolution, alerts, processes,
  files, registry activity, network activity, users, vulnerabilities, and reports.
- Incident investigation already collects incident/alert evidence and routes
  device entities to the device skill.
- The missing layer is an explicit alert-to-device contract, alert-relative time
  windows, process-instance correlation, and an automation-ready evidence ledger.
- Reuse existing endpoint queries and JSON-to-report helpers; extend their
  contracts only where necessary.
- The preceding pulse scan demonstrated why telemetry freshness and field
  completeness must be gates, not assumptions. This plan performs no new hunt.

## 2. What the SOC analyst should receive

P0 is required for initial triage. P1 is a conditional deeper investigation.
These are collection priorities, not incident-severity labels.

| Priority / area | Useful information | Question it answers | Candidate sources |
|---|---|---|---|
| P0: Trigger and case context | Alert/provider IDs, incident IDs, MDE service/detection source, title, severity, category, MITRE techniques, first/last activity, creation/update times, status, owner, evidence role | Why did this device enter the investigation? | Defender alert/incident APIs; AlertInfo + AlertEvidence; SecurityAlert + SecurityIncident |
| P0: Device and business context | MDE DeviceId, Entra ID mapping, name/aliases, OS/build, device role, criticality, owner, onboarding/sensor health, last seen, current response status | Which asset is affected, how important is it, and can it be observed? | DeviceInfo; MDE device inventory; approved asset/CMDB context |
| P0: Detection versus outcome | Observed malicious behavior, attempted/blocked/succeeded/unknown outcome, antivirus/EDR/ASR detections, remediation and AIR/Action center status with timestamps | Was the threat prevented, partially remediated, or still observable? | Alert evidence; relevant DeviceEvents; response-action history |
| P0: Process reconstruction | Seed process, ancestors and descendants, exact command lines, executable paths, hashes, signer context, start times, user, integrity/elevation, remote-session context | What executed, under whose authority, and what launched it? | DeviceProcessEvents; alert process evidence; DeviceFileCertificateInfo where available |
| P0: File and payload provenance | Created/modified/renamed/deleted files, hashes, download/origin information, script/installer/archive relationships, prevalence | What arrived, where did it come from, and where did it go? | DeviceFileEvents; DeviceProcessEvents; AlertEvidence |
| P0: Network activity | Process-attributed destinations, URL/domain, IP, port, protocol, connection outcome, first/last seen, frequency | Did the process communicate externally or with internal targets? | DeviceNetworkEvents; relevant DeviceEvents; approved first-party intelligence |
| P0: User and session context | Account SID/object ID/UPN, local versus domain account, logon type, source device/IP, success/failure, session and privilege context | Was a local, remote, service, or elevated session involved? | DeviceLogonEvents; DeviceProcessEvents; identity logs when needed |
| P0: Related activity and incident context | Other alerts from any Defender product on the same device, hash, IP/URL, or account; other entities in the same incident; payload origin (download, click, email); recurrence on this device; relationship type, pivot, and strength for each link | What else is connected to this alert, and why is it considered related? | AlertInfo + AlertEvidence; incident APIs; DeviceFileEvents origin fields; UrlClickEvents/EmailEvents; DeviceLogonEvents; bounded fleet prevalence |
| P1: Persistence and defense evasion | Run keys, services, tasks, startup entries, WMI evidence, security-control changes, log-clearing evidence; OS-specific equivalents | Is there evidence of continued access or reduced defenses? | DeviceRegistryEvents; DeviceEvents; process/file evidence; approved host collection |
| P1: Credential access and lateral movement | Credential-access evidence, remote execution, RDP/SMB/WinRM/WMI patterns, account reuse on other devices | Did activity extend beyond the alerted process/device? | DeviceEvents; process/network/logon tables; targeted identity pivots |
| P1: Collection, exfiltration, and impact | Archiving/staging, suspicious transfer processes, destructive/encryption behavior, affected paths, sensitive asset context | What may have been collected, lost, or disrupted? | File/process/network events; related alerts; relevant DLP/email/cloud evidence |
| P1: Exposure and fleet scope | Relevant CVEs and configuration weaknesses, same hashes/commands/IOCs on other devices, local/fleet prevalence (related alerts are P0 above) | Is there a plausible entry weakness or a wider campaign? | TVM tables if available; bounded cross-device hunting; related incidents |
| P0: Confidence and evidence coverage | Sources checked, time ranges, row counts, freshness, missing permissions/tables/fields, truncation, competing explanations | How reliable is the assessment, and what must be checked next? | Per-query execution ledger and evidence references |

### Interpretation rules

- Alert severity, analyst confidence, business impact, and response urgency are
  separate dimensions. A High alert is not automatically confirmed compromise.
- Distinguish the execution attempt, observed process creation, successful
  behavior, and remediation outcome. A command line is not proof its intent
  succeeded; an alert being closed is not proof the device is clean.
- Signed software can be abused. An unsigned file, rare process, unusual country,
  vulnerable application, or suspicious IP alone is not proof of compromise.
- Do not infer bytes exfiltrated from connection counts. Do not equate observed
  persistence creation with proof that persistence remains installed now.
- Use "last observed at" for historical telemetry. Do not claim a process is
  currently running without current supporting evidence.
- Separate observed facts, correlation, hypotheses, and analyst decisions.
  Findings must retain evidence references and alternative benign explanations.

## 3. Entry contract and investigation scope

### Supported inputs

- An MDE alert ID, with its provider/API namespace.
- A Defender XDR incident ID containing one or more MDE alerts.
- An incident-to-device handoff containing an alert and verified MDE DeviceId.
- A hostname alone continues to use the existing standalone device mode.

An XDR incident can contain alerts from several products. Verify each alert's
actual service source; do not identify MDE alerts from the title alone. Retain
non-MDE incident context without treating it as endpoint telemetry.

### Required normalized context

| Field group | Required contract |
|---|---|
| Scope | Authorized tenant, workspace when relevant, source provider/API namespace, selected backend, permission context |
| Trigger | Trigger kind and ID, provider incident ID, Sentinel-local incident number if present, alert IDs, source update version/time |
| Device | MDE DeviceId, original device evidence, observed name/aliases, Entra mapping when available, impacted/related role |
| Evidence seeds | Process identity (PID + creation time from the alert API's process evidence; `AlertEvidence` has no process-ID columns), hashes, files, accounts, destinations, evidence timestamps; preserve nulls |
| Time | Alert first/last activity (alert API; `AlertInfo.Timestamp` is a record time, not activity time), detection/creation/update time, fixed collection cutoff, explicit UTC query intervals |
| Policy | Read-only mode, authorized devices/scope, query/row/runtime budgets, report destination, allowed fallback sources |

Keep Graph alert IDs, provider alert IDs, Sentinel SystemAlertId, Defender incident
IDs, and Sentinel incident numbers distinct. Resolve their mappings from evidence;
never assume different identifier namespaces are interchangeable.

Resolve hostnames only for discovery, handling case/FQDN differences. Thereafter,
scope device queries by the verified MDE DeviceId. Account for renames, merged
device identities, re-onboarding, and reimages without combining unrelated
historical device instances.

Manual incident investigations keep existing entity-selection behavior.
Unattended jobs require an explicitly preauthorized device-selection policy and
a finite device cap; ambiguity becomes a blocked job, not an implicit "all devices."

### Proposed time-window defaults

- Freeze collection cutoff once at run start; use explicit UTC start/end values.
- Initial evidence window: 30 minutes before first alert activity through two
  hours after last activity, capped at the collection cutoff.
- Historical context: up to 30 days where the selected source actually supports
  it. Wider Lake history requires verified retention and an approved query budget.
- Take first/last activity from the alert API. If it is unavailable, fall back to
  the min/max evidence record time and label it as record time, not activity time.
- `AlertInfo` and `AlertEvidence` exist only in Advanced Hunting (30 days). For an
  older alert use `SecurityAlert`/`SecurityIncident` and Lake `Device*` tables, and
  mark process-instance seeds unavailable rather than guessing.
- Expand the causal window when an ancestor, download, or precursor predates it;
  record the reason, new bounds, and any retention limit.
- Rerun a bounded affected window when delayed telemetry becomes available.
  Never replace an earlier raw snapshot; create a linked report revision.

These are proposed defaults to validate in a pilot, not guarantees about attacker
timelines. Use half-open intervals consistently; do not add arbitrary extra days.

## 4. Workflow to implement

| Stage | Behavior | Required output / stop condition |
|---|---|---|
| 0. Validate trigger and authorization | Resolve tenant/workspace, provider IDs, MDE source, device evidence, and policy | Stop on tenant/workspace mismatch, ambiguous device, unauthorized scope, or unsupported trigger |
| 1. Check capabilities and coverage | Discover tables/columns, backend retention, permissions, source freshness and null critical fields | Coverage matrix; unsupported sources explicitly excluded before query execution |
| 2. Establish the case | Retrieve original alerts/evidence, incident context, device metadata, existing response history | Preserved trigger snapshot, seed entities, initial timeline |
| 3. Reconstruct the seed process chain | Locate exact process instances; follow bounded ancestry/descendants | Process graph with evidence-backed edges and explicit unresolved relationships |
| 4. Correlate dependent artifacts | Attribute files, connections, registry changes, and logons to seed/related processes and sessions | Unified chronological timeline; behavior outcomes and supporting rows |
| 5. Run relevant forensic branches | Select modules from evidence: malware/execution, script/LOLBin, credential access, persistence, ransomware, lateral movement, network/C2 | Findings per hypothesis; explicit not-run reasons for other modules |
| 6. Related activity and bounded scope | Pivot on strong seeds (same device, hash, IP/URL, account, payload origin, remote logons) across other alerts, the incident, and authorized devices; enrich relevant exposure | Related-activity table (relationship, pivot, strength, source) with explicit scope limits; related devices/users handed off as prompts; no automatic recursive investigation |
| 7. Assess and report | Separate observed facts from hypotheses; compare evidence with existing Defender actions | Triage decision, confidence, remaining risk, next steps, provenance, coverage |
| 8. Review and optional collection | Analyst decides whether telemetry is sufficient or host acquisition/response is needed | Approval request or handoff; no endpoint action from the read-only collector |

Run independent metadata/coverage queries in parallel. Process-dependent joins
must wait for seed resolution. Put time and DeviceId filters early; summarize
high-volume sources before retrieving bounded event details.

### Correlation correctness

- Prefer `(DeviceId, ProcessUniqueId)` and initiating-process unique IDs where
  present. The documented unique IDs correspond to the Process Start Key on
  Windows; discover actual platform/backend availability.
- Fallback to device + PID + process creation time, with an explicit bounded
  tolerance and confidence downgrade if identity cannot be resolved.
- Never join on PID alone: PIDs are reused. Do not present temporal proximity,
  shared IP, or the same filename as a proven parent/child relationship.
- Match an event's initiating-process key to the corresponding process instance.
  Deduplicate source events without losing separate behaviors or evidence roles.
- Preserve original hashes and algorithms. SHA256 is often unpopulated in the
  documented hunting tables; use available SHA1 for correlation rather than
  dropping the event. Artifact-integrity checksums are a separate SHA256 use.
- Correlate session IDs with device, time, and boot context where available;
  session/account identifiers alone do not prove cross-device identity.
- Record graph depth/node limits and unresolved edges. The seed alert and its
  evidence must never disappear because a display limit was reached.

### Coverage and error handling

- Every collection records: source, query/template version, parameters/time
  bounds, execution time, status, rows matched/returned, freshness, truncation,
  and evidence location.
- Distinguish `complete`, `partial`, `no_data`, `not_available`,
  `permission_denied`, `failed`, `blocked`, and `not_run`.
- "No matching activity" is valid only for the stated checked interval and
  observable source. An empty/stale source or null field is a coverage gap.
- Keep backend-specific schemas: native Advanced Hunting tables commonly use
  Timestamp; Lake/Sentinel tables use their discovered time columns. Preserve
  event time separately from ingestion and collection time.
- Native Defender hunting history is generally limited to 30 days; Sentinel
  table retention is separately configured. Portal timeline availability does
  not establish API/Lake query coverage.
- Use bounded same-scope retries for documented throttling/transient failures
  only where policy permits; honor Retry-After. Persist exhausted retries.
- Scope/authentication/workspace failures stop collection. Follow existing
  workspace-failure rules; never silently retry another workspace or bypass
  permissions. Optional unavailable sources identified during preflight produce
  a partial report, not a success-shaped empty result.
- Mark sampled/truncated results visibly. Row caps must not be reported as fleet
  totals; partition only within authorized time/scope and resource limits.

## 5. Automating the investigation

### Keep the skill separate from the event listener

A SKILL.md is an on-demand runbook, not a background trigger or hosted worker.
Build a shared, deterministic collector and report contract that both the manual
skill and an authorized hosted runner can call. If model-assisted analysis is
used, run it in an approved host with the same scope/tool restrictions; do not
assume a Logic App can directly execute Markdown or a user's VS Code session.

Recommended production flow:

1. Sentinel incident-created/updated automation rule receives an authorized case.
2. A Logic App obtains the current incident and verifies relevant MDE alerts.
3. A durable job invokes the shared read-only collection workflow per authorized
   alerted device.
4. Evidence is normalized, correlated, and summarized into JSON plus an analyst
   report in approved restricted storage.
5. The SOC reviews findings and any separate acquisition/response request.

For MDE alerts outside this incident path, a separate authorized Graph alert
poller can use supported update-time filtering, pagination, overlap, and a
checkpoint. Prefer one ingestion path per deployment until deduplication is
tested. Do not assume the standard Sentinel "alert created" trigger receives
every native MDE alert; incident triggers and enhanced alert-trigger capabilities
have different availability.

### First trigger path in this repository

The repository's existing automation primitive is the Copilot-app scheduled
workflow (`automations/*.workflow.md`): interval-based, Autopilot, local,
user-scope MCP servers, gitignored reports. It is not event-driven, and no hosted
runner or Logic App foundation exists here beyond the incident-comment sample.
Start Phase D with a **polling scheduled workflow**: list new MDE alerts above a
severity floor since a local checkpoint, cap devices per run, deduplicate on
(alert ID, DeviceId, evidence revision), run the alert-anchored mode with pinned
workspace and output settings, and write reports under `reports/`. Move to the
Sentinel automation rule + Logic App flow above only if the SOC needs lower
latency than the polling interval.

Both paths need an **unattended mode** for the skills: pinned workspace, preset
output mode, device cap, and block-on-ambiguity. The interactive gates in the
current skills (workspace selection, output-mode prompts) cannot be answered by a
scheduled run. [Section 12 of the mode reference](../.github/skills/computer-investigation/alert-anchored-mode.md#12-unattended-runs-scheduled-workflows)
lists the required parameters.

### Production safeguards

- Pin tenant/workspace in deployment configuration. A mismatch with local
  configuration blocks the job; never select the first reachable workspace.
- Use least-privilege read access. Graph alert and incident retrieval document
  SecurityAlert.Read.All and SecurityIncident.Read.All respectively; hunting,
  Lake, device inventory, and response history need their own verified permissions.
  API permission, license, and resource visibility are separate checks.
- Trigger on new relevant MDE evidence/devices, not every owner, comment, or
  status update. Handle incident merges/reassignment using provider identifiers.
- Deduplicate by authorized scope + provider alert ID + MDE DeviceId + meaningful
  evidence revision. Concurrent deliveries must not create concurrent duplicate
  investigations. Retain links between incident/report revisions.
- Bound devices, process-graph depth, fleet pivots, parallel queries, rows,
  runtime, retry count, and query costs. Overflow is visible and queued for review.
- Revalidate scope on every resumed job. Record partial progress and failures;
  do not endlessly retry expired evidence or ask an unattended user a modal question.
- Store secrets in approved secret management, not skill files or event payloads.
  Keep raw evidence and operational PII out of version control.
- Treat command lines, filenames, URLs, alert descriptions, and retrieved text as
  untrusted evidence, never as agent instructions or executable scripts.
- No automatic external sample upload or third-party enrichment of private
  indicators or sensitive artifacts. Prefer authorized first-party sources.
- Writing a comment/tag, changing an incident, or notifying an external system
  is separate from collection and requires explicit deployment authorization.
  Prevent report publication from retriggering the investigation.

## 6. Telemetry triage versus host forensics and response

| Activity | Default treatment |
|---|---|
| Read authorized alert/device telemetry and existing action history | Automatic within approved scope and budgets |
| Summarize, build timeline, and save reports to approved restricted storage | Automatic; preserve provenance and access controls |
| Collect an investigation package or start Live Response | Explicit analyst/IR approval and audited acquisition scope |
| Acquire volatile memory or disk images | Specialist forensic workflow, legal/operational approval, approved tooling |
| Isolate, kill/quarantine, block indicators, change users, or initiate remediation/AIR | Human-controlled response workflow; not part of this read-only MVP |

MDE telemetry triage is not a full forensic image. A Windows investigation package
can include autoruns, current processes, connections/DNS cache, scheduled tasks,
services, prefetch, security event logs, users/groups, and a collection summary.
Availability varies by OS and collection outcome; review the summary for failures.
It is not a guaranteed complete disk or memory capture.

For approved acquisition, record collector identity, device/action ID, approval,
collection start/end in UTC, source clock uncertainty, collection errors,
artifact SHA256 checksums, storage/access audit, and retention. Keep immutable
originals separate from derived analysis; follow the organization's legal
chain-of-custody process rather than claiming the report alone establishes it.

Balance volatile-evidence preservation against active harm. Do not automatically
reboot, isolate, or delay urgent containment to finish collection; the incident
commander makes that decision.

## 7. Analyst report and structured evidence contract

The first page should contain:

1. One-sentence assessment and immediate decision needed.
2. Original alert severity, analyst assessment, confidence, and business impact.
3. Verified incident/alert/device links and UTC evidence window.
4. A short attack narrative with evidence references, not an unsupported story.
5. Confirmed outcomes versus attempts, existing Defender actions, and last
   observed activity.
6. Top affected users/devices/artifacts and priority next steps.
7. A prominent coverage warning when conclusions are limited.

The full report adds a process tree, unified timeline, evidence tables,
alternative explanations, fleet scope, query appendix, and acquisition handoff.
Retain an explicit initial-access/root-cause field even when the answer is
"not established." Reuse the repository's risk indicators and portal-action policy.

Proposed machine-readable sections:

| Section | Contents |
|---|---|
| run | Schema/collector/template versions, run ID, authorized scope, input fingerprint, timestamps, policy/budgets |
| trigger / device | Original and normalized IDs, service source, evidence roles, device identity mapping, source snapshots |
| coverage / queries | Per-source status/freshness, field completeness, exact intervals, errors, counts, truncation, raw result references |
| evidence / process_graph / timeline | Stable evidence IDs, source table/API, original event identifiers, observed/ingested/collected times, attributed entities and relationship confidence |
| findings | Supporting and contradicting evidence IDs, outcome, assessment, confidence rationale, gaps, alternate explanations |
| actions / recommendations | Observed response actions and status; proposed actions separately marked unexecuted and approval-required |
| artifacts | Restricted storage references, content checksums, acquisition metadata, report revision links |

The existing [report generator](../scripts/report_generator.py) and
[JSON report entry point](../scripts/generate_report_from_json.py) are
user-investigation specific (UPN-centric result types) and have no device or alert
path, so they are not reused. The MVP renders the triage card from the skill
template and exports the JSON ledger itself. Do not force this schema into that
contract; add a versioned specialized report only if a styled output is later
required. An analyst narrative failure must not discard successfully collected
evidence.

## 8. Implementation sequence and repository integration

| Phase | Deliverables | Exit criteria |
|---|---|---|
| A. Contract and coverage | Alert/device input contract, backend capability matrix, evidence schema, approved read-only tool inventory, test fixtures | IDs, source-time semantics, scope, missing-data behavior, and budgets are defined |
| B. Analyst-guided MVP | Alert-context mode in existing skill; trigger/device/coverage checks; process, file, network, logon and response-status collection; inline report + JSON | A supplied MDE alert produces a reproducible evidence-backed device report without actions |
| C. Forensic depth | Persistence/evasion and other evidence-selected modules; bounded fleet pivots; process/timeline joins; report-template integration | Correlation and negative findings pass the edge-case tests below |
| D. Event automation | One approved trigger path, hosted collector, durable execution, deduplication, checkpoint/retry logic, restricted storage, audit | Duplicate/update deliveries are safe; partial failures produce usable results; no unintended writes |
| E. Pilot and release | Approved historical cases, analyst comparison, performance/coverage measurements, documentation and rollback/disable procedure | SOC sign-off and agreed acceptance thresholds; no unreviewed containment path |

Implementation status (2026-11-11): A and B are implemented; C, D and E are not.
B's exit criterion (a reproducible report from a supplied alert) is **not yet
demonstrated** because the queries have not run against a tenant.

Integration points (done unless marked open):

- Extend [computer-investigation](../.github/skills/computer-investigation/SKILL.md)
  with alert triggers, the entry contract, the stage flow, and output expectations.
  Keep the main instructions concise; move detailed query modules and contracts
  into one-level-deep references and scripts only where executable helpers help.
  **Done:** a SKILL.md section plus
  [alert-anchored-mode.md](../.github/skills/computer-investigation/alert-anchored-mode.md).
- Extend [incident-investigation](../.github/skills/incident-investigation/SKILL.md)
  with the structured device handoff; preserve manual selection by default.
  **Done** (Phase 2-B).
- Add a proposed endpoint query library:
  `queries/endpoint/mde_alert_device_forensics.md`. Reuse existing process,
  RDP/logon, persistence, and vulnerability queries instead of duplicating them.
  **Done:** 13 queries, all `cd_ready: false`; existing queries are referenced, not copied.
- Any new query file needs repository metadata, Domains, and a cd-metadata block
  before every query. Mark forensic, parameterized, multi-stage queries as not
  continuous-detection-ready unless they satisfy that contract.
- Update routing in [workspace instructions](../.github/copilot-instructions.md)
  and [README](../README.md); preserve skill discovery metadata and add the
  alert-specific description/drill-down wording. **Done**; the `drill_down_prompt`
  was left unchanged on purpose so threat-pulse behavior does not change.
- Regenerate the discovery manifest with the existing
  [manifest builder](../.github/manifests/build_manifest.py), never by manually
  editing generated entries. Regenerate query TOCs with the existing
  [TOC generator](../scripts/generate_tocs.py) when query files are added/changed.
  **Done** for the slim manifest. The committed full manifest was already stale
  (generated 2026-07-30), so it was not regenerated, to avoid unrelated churn.
- Keep all committed examples tenant-neutral. Verify that operational output
  locations are excluded from version control before collecting real evidence.
  **Verified:** `reports/**` and `temp/*` are gitignored.

Not changed: the report generator, deployment configuration, any automation, and
any response capability.

## 9. Validation and definition of done

Validate using sanitized fixtures first, then read-only replay of approved real
cases. Malware execution or attack simulation is not needed to validate the
collector and requires a separately approved isolated environment if later used.

| Test | Required outcome |
|---|---|
| Known MDE alert with process/file/network evidence | Seed evidence resolves to the correct device/process; narrative references actual source rows |
| Mixed-product, multi-device incident | MDE alerts are verified individually; related versus impacted devices retained; authorized cap enforced |
| Non-MDE alert or ambiguous ID namespace | Explicit unsupported/blocked result; no guessed endpoint lookup |
| Rename, reimage, duplicate hostname, merged device | Correct historical DeviceId preserved; no cross-device blending |
| PID reused at another time | No false process/network/file attribution; fallback uncertainty is visible |
| Empty SHA256, missing unique process key, signer absent | Available SHA1/instance fallback retained; uncertainty is explicit |
| Missing process table, stale telemetry, null exposure field | Coverage gap, never a clean-device verdict |
| Old alert, delayed ingestion, UTC/day boundary | Event-anchored windows stay correct; unavailable history and report revisions are explicit |
| Alert older than the 30-day Advanced Hunting horizon | `AlertInfo`/`AlertEvidence` path reports `not_available`; fallback uses `SecurityAlert` and Lake tables; process-instance seeds are marked unavailable |
| Alert whose `AlertEvidence` has no process identifiers | Seed comes from the alert API process evidence, else a low-confidence hash/name fallback; no tree is built from an unresolved guess |
| Related alert linked only through shared infrastructure or a common signed binary | Relationship is rated weak with the reason; no scope expansion and no automatic investigation of other devices |
| Skill started by a scheduled run | No interactive prompt is required; ambiguity blocks and is reported; pinned workspace and output settings are used |
| Failed or unavailable source in the standalone defaults | Never rendered as an empty array or an "Unknown" default; the coverage status is reported instead |
| Blocked detection and partially successful attack | Blocked/succeeded/unknown behaviors distinguished; closure never substitutes for response evidence |
| Graph/Lake paging, row truncation, throttling, timeout | No silent dropped evidence; totals versus samples clear; bounded retries and partial status retained |
| Duplicate/concurrent trigger, incident merge, comment update | Idempotent collection; evidence-changing updates version results; no comment loop |
| Tenant/workspace/permission mismatch | Collection stops without switching scope or attempting an access workaround |
| Malicious instructions embedded in logs | Text remains inert evidence; no code execution or scope/tool expansion |
| Read-only safety | Tests verify no isolation, package collection, Live Response, remediation, or case-write operation is called |
| Report regeneration | JSON and analyst report agree; every finding/timeline edge has evidence references; raw originals preserved |

Release gates:

- All mandatory fixture tests pass with zero cross-device or cross-tenant
  misattributions and zero unapproved write/endpoint actions.
- All executed queries have provenance, counts, status, and explicit coverage.
- Original standalone device and manual incident behavior remains unchanged.
- The SOC can identify the trigger, activity outcome, affected entities,
  containment/remediation status, uncertainty, and next decision from page one.
- Record pilot runtime, data completeness, analyst agreement, false-positive
  explanations, cost, and evidence-to-report consistency before setting an SLA.
  Suggested triage target: a few minutes when telemetry is available; measure it,
  do not promise it or trade away required evidence to achieve it.

## 10. Official documentation grounding

Reviewed 2026-11-11; backend availability, permissions, licensing, and platform
support must still be verified during implementation.

1. [Investigate devices in Microsoft Defender for Endpoint](https://learn.microsoft.com/defender-endpoint/investigate-machines):
   device context, timeline, health, investigations, and response surfaces.
2. [AlertEvidence schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-alertevidence-table):
   alert-associated entities, evidence roles, source, hashes, and process context;
   join to AlertInfo using AlertId.
3. [DeviceProcessEvents schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table):
   process identity/start times, command lines, session context, unique process
   IDs, and hash limitations.
4. [Take response actions on a device](https://learn.microsoft.com/defender-endpoint/respond-machine-alerts):
   investigation-package contents, collection limitations, Live Response, and
   action history. Collection is an endpoint action, not passive telemetry.
5. [List Graph security alerts](https://learn.microsoft.com/graph/api/security-list-alerts_v2?view=graph-rest-1.0):
   serviceSource/update-time filters and least-privilege read permissions.
6. [List Graph security incidents](https://learn.microsoft.com/graph/api/security-list-incidents?view=graph-rest-1.0):
   incident relationships, supported query options, and read permissions.
7. [Sentinel automation rules](https://learn.microsoft.com/azure/sentinel/automate-incident-handling-with-automation-rules):
   incident-created/updated triggers, automation loops, and alert-trigger limitations.
8. [Advanced hunting quotas and coverage](https://learn.microsoft.com/defender-xdr/advanced-hunting-overview#quotas-and-usage-parameters)
   and [Advanced hunting API limits](https://learn.microsoft.com/defender-xdr/api-advanced-hunting#quotas-and-resource-allocation):
   native Defender retention, result limits, and backend-specific resource limits.
9. [Graph alert resource](https://learn.microsoft.com/graph/api/resources/security-alert?view=graph-rest-1.0):
   first/last activity, provider alert ID, incident ID, and the evidence collection.
10. [Graph process evidence](https://learn.microsoft.com/graph/api/resources/security-processevidence?view=graph-rest-1.0):
    process ID, creation time, parent process, detection status, and MDE device ID.
11. [Graph alert evidence](https://learn.microsoft.com/graph/api/resources/security-alertevidence?view=graph-rest-1.0):
    remediation status, verdict, and evidence roles.
12. [AlertInfo schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-alertinfo-table):
    record `Timestamp` semantics and available columns.

## 11. Review log (2026-11-11)

Reviewed against the goal: give a SOC analyst the essentials for an MDE alert plus
context on related events. Repository claims were checked against the tree; schema
and API claims against the pages listed in section 10.

**Confirmed:** every referenced file and tool exists; the manifest builder and TOC
generator validate cleanly; all section 10 links resolve; the Graph permissions in
section 5 are as documented; `ProcessUniqueId` and `InitiatingProcessUniqueId` exist
on process, network, file, registry, logon, event, and image-load tables and equal
the Windows Process Start Key; `SHA256` is documented as usually unpopulated;
`reports/**` and `temp/*` are gitignored.

| # | Finding | Disposition |
|---|---|---|
| 1 | Related-event context (the stated goal) was scattered across P1 rows and stage 6 and framed as scoping | Added as P0 in section 2; stage 6 reframed; relationship model in mode reference section 8; queries Q10–Q13 |
| 2 | `AlertEvidence` has no PID, creation-time, or unique-ID columns, so "process start times" cannot be seeds from Advanced Hunting | Section 3 seed row; seed chain in mode reference section 4 (alert API process evidence, then Q4, then `ProcessUniqueId`) |
| 3 | First/last activity is not in `AlertInfo`/`AlertEvidence` (`Timestamp` is a record time) | Section 3 time bullets; alert API is the source; labeled fallback |
| 4 | `AlertInfo`/`AlertEvidence` are Advanced Hunting only (30 days) | Section 3 bullet; Q1 and Q10 documented as AH-only; test row added |
| 5 | The report generator is user-investigation specific, so "reuse where compatible" is not viable | Section 7 corrected; the MVP renders from the skill template |
| 6 | Phase D assumed a Logic App and hosted runner; the repository's automation primitive is a scheduled Copilot workflow, and current skill prompts block unattended runs | Section 5 "First trigger path"; unattended parameters in mode reference section 12 |
| 7 | The plan was mostly governance and automation with no analyst page-one example | Triage card in mode reference section 10; Phase B is the shippable slice that meets the goal; D and E deferred |
| 8 | Pre-existing hazards in the standalone skill that "reuse existing queries" would inherit: "Get Machine Alerts" uses `ListAlerts` with a machine filter, which the workspace instructions say is silently ignored (tenant-wide result); the legacy "Required Field Defaults" and "Empty Result Handling" turn failed sources into success-shaped empties; its queries are name-based aggregates over 7-day windows | Not modified (unrelated, pre-existing); the alert-anchored mode avoids each of them explicitly |

**Open risks:**

- The 13 queries were only parsed and schema-checked (Kusto language analyzer against the published schemas; injected defects were caught). Runtime behavior is unverified until the Phase E pilot on approved historical cases: join behavior, field population, `AdditionalFields` shapes, and `DeviceEvents` `ActionType` values (Q9 matches families by substring because the schema page does not list the values).
- Whether the Triage MCP alert response exposes process evidence (PID, creation time, detection and remediation status) must be confirmed on a real alert. If not, the mode falls back to hash/name seeds with an explicit confidence downgrade.
- The process tree links parent and child on either `ProcessUniqueId` or `pid@creation-time`. The second alias assumes the sensor records identical creation times in the process-creation event and in its children's `InitiatingProcessCreationTime`; that is unverified until the pilot, and Q4 reports which alias (`MatchBasis`) seeded the tree.

**Second pass:** an independent review of the query logic (runtime semantics, not syntax) found eight issues, all fixed and re-validated offline: the incident handoff now carries explicit `cases` (alert-to-device pairs); Q4 no longer builds a shared placeholder key, links parent and child on either process alias (each join scoped by `DeviceId`), and ranks hash/name fallback seeds deterministically by distance to an optional alert-evidence time with an explicit truncation flag; Q10 reports every satisfied pivot, matches hosts rather than raw URL strings, enriches from `AlertInfo` independently of the activity range, and flags history cut off by the 30-day horizon; Q11 is split into independently runnable parts (hashes, destinations, command-line fragments) so only applicable parts run and nothing relies on the engine skipping an empty-list fleet scan, each part reports the indicator that actually matched, and the forward day is documented; Q12 selects origins deterministically with a visible count, searches clicks far enough back for the oldest origin, documents its 5-minute skew tolerance, and de-duplicates hosts. A follow-up check of those fixes found two smaller issues, also fixed: URL scheme detection now uses `contains` (`has` matches whole terms, and `://` is punctuation), and Q12's click window now reaches the 5-minute skew allowance at the window end.

**Next:** run Q1–Q13 on three to five approved historical alerts, fix any failures, record first-run evidence per query, then decide on the Phase D polling workflow.
