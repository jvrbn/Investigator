# SOC Investigation Skill Implementation Plan

## Objective

Extend the project from entity and posture investigations into end-to-end
incident workflows. Each workflow should produce an evidence-backed timeline,
distinguish attempted from confirmed activity, identify coverage gaps, and
remain read-only unless a separately authorized child workflow says otherwise.

This plan intentionally reuses existing query libraries and specialized skills.
It does not add parallel copies of working KQL or replace the existing
tenant-context protections.

## Current-state review

| Requested workflow | Current state | Implementation decision |
|---|---|---|
| P1 Cross-tenant campaign investigation | A generic [cross-tenant-hunt skill](../.github/skills/cross-tenant-hunt/SKILL.md) and tenant-isolated Mission Control fanout already exist. | Extend the existing skill; do not create a duplicate campaign skill. Add campaign-oriented inputs, affected-asset normalization, aggregate coverage, and result correlation. |
| P1 Business email compromise investigation | [bec-investigation](../.github/skills/bec-investigation/SKILL.md) exists and composes email, authentication, user, and app-registration workflows. | Harden the workflow, report schema, and regression coverage rather than replace it. |
| P1 Ransomware and lateral-movement investigation | [ransomware-investigation](../.github/skills/ransomware-investigation/SKILL.md) exists and uses the MDE alert, RDP, and SMB query chains. | Add explicit multi-device scope expansion, initial-access/credential paths, and affected-asset accounting. |
| P1 Detection and telemetry health investigation | [telemetry-health](../.github/skills/telemetry-health/SKILL.md) exists and uses ingestion, rule-health, and endpoint-forensics checks. | Add connector-health coverage, ingestion-delay classification, required-source manifests, and skill-readiness summaries. |
| P2 Privileged access abuse investigation | No dedicated incident workflow. Existing role/PIM, user, identity-posture, CA, app, and authentication queries provide most evidence. | Add `privileged-access-investigation` as an orchestrator with a focused abuse timeline. |
| P2 Cloud resource compromise investigation | No dedicated workflow. Key Vault, storage, AzureActivity, Graph, Exposure Graph, and SPN queries already exist. | Add `cloud-resource-investigation`; reuse those query chains and avoid resource-specific forks. |
| P2 Data exfiltration investigation | No cross-channel investigation workflow. Data-security, email, endpoint, Graph, and storage evidence already exist separately. | Add `data-exfiltration-investigation` to join collection, staging, transfer, and impact evidence. |
| P2 Persistence investigation | No unified persistence workflow. Endpoint startup, app credential, OAuth consent, mailbox-rule, role, and automation evidence exist separately. | Add `persistence-investigation` as a source-spanning persistence inventory and timeline. |
| P2 Post-containment verification | No dedicated verification workflow. Disruption, user, device, incident, and remediation data provide most checks. | Add `post-containment-verification` to measure recurrence and verify each control outcome. |

## Shared implementation rules

All phases must preserve these invariants:

1. **Compose verified sources.** Load child `SKILL.md` files and query-library
   definitions before writing or running KQL. New workflows do not duplicate
   existing KQL unless a genuinely missing query is required.
2. **Use immutable tenant contexts.** Tenant, workspace, collection route,
   case/run ID, and UTC collection window are frozen. A query or late Mission
   Control result must not be routed through mutable global selection.
3. **Keep tenant evidence separate.** Raw cross-tenant evidence is never merged
   into another customer's report. A cross-tenant summary contains only the
   approved normalized fields and explicit source/coverage status.
4. **Correlate precisely.** Every timeline join is labeled as exact ID,
   exact entity plus session/process ID, or temporal proximity. Temporal
   correlation is never presented as causation.
5. **Distinguish states.** Use separate values for complete, no scoped matches,
   partial, denied, unsupported, unavailable, stale, error, attempted,
   observed, blocked, prevented, remediated, and unknown.
6. **Apply tenant memory twice.** Before collection and before verdict, skim
   section headers, search only task entities/fingerprints, and read matching
   tenant-local sections. Never borrow another tenant's baseline.
7. **Remain read-only by default.** No tenant, mailbox, identity, device,
   resource, detection-rule, or incident mutation is part of these skills.
   Remediation remains an audited portal handoff.
8. **Report honest query status.** A reference to a library query is not a live
   test. Query failures and zero-result sanity checks remain visible; missing
   telemetry cannot become a clean verdict.

## Phase 0: Shared evidence and timeline contract

Create a small machine-checkable contract used by the investigation skills.

### Deliverables

- `docs/investigation-evidence-contract.md`
  - Required timeline fields: timestamp, source/table, tenant/profile,
    workspace, case, event category, entity, exact event/session/process IDs,
    outcome, correlation basis, confidence, and source reference.
  - Per-entity summary fields: confirmed affected, suspected lead, coverage
    gaps, first/last evidence, and post-response activity.
  - Rules for exact vs temporal correlation and for source-level attribution.
- `scripts/investigation_timeline.py` only if repeated rendering in the skills
  proves error-prone; otherwise keep the contract in the skill/report templates
  and avoid a new runtime dependency.
- Validation fixtures under `tests/fixtures/investigation-timelines/`.

### Acceptance criteria

- A fixture can represent every requested workflow without invented fields.
- A tenant/workspace identifier is mandatory for tenant evidence.
- Attempted, observed, blocked, and remediated outcomes remain distinct.
- A temporal-only event cannot be serialized as an exact causal link.

## Phase 1: P1 workflow hardening

### 1.1 Cross-tenant campaign investigation

Extend [cross-tenant-hunt](../.github/skills/cross-tenant-hunt/SKILL.md) with
two input modes:

- **Indicator mode:** one or more hashes, domains, URLs, IPs, or identities.
- **Campaign mode:** a named hunt with multiple indicators, shared ATT&CK
  techniques/campaign fingerprints, and a single pinned UTC window.

Campaign work is still fanout, not a bulk join:

1. Validate all indicators and 1-10 explicit profile/workspace or Defender-only
   targets before sending any prompt.
2. Build one immutable context per target and one campaign manifest that maps
   selected targets to the same window and indicator set.
3. Reuse `discovery-manifest.yaml` and query-library paths per indicator type.
4. Normalize per-target output to:
   - indicator hits and zero-result status;
   - affected users, devices, mailboxes, apps, and incidents;
   - queried sources and retention actually covered;
   - authentication, table, connector, and capability gaps;
   - response/containment actions already observed.
5. Render a tenant-separated comparison first. Add an aggregate count only if
   every included target reports the same coverage definition.

#### Mission Control

- Add campaign name and indicator-set input to the existing cross-tenant panel.
- Show target-level queued/running/complete/unavailable/error state.
- Reuse original launch bindings for late results.
- Keep raw evidence tenant-scoped; export a minimized cross-tenant summary only
  after the analyst selects the permitted aggregation.

#### Tests

- Duplicate indicators/targets are refused before fanout.
- Two tenants may have the same incident or device IDs without result collision.
- A complete zero-hit tenant is distinct from denied/unavailable telemetry.
- Late results still bind to the original tenant after a UI selection change.

### 1.2 BEC investigation

Harden [bec-investigation](../.github/skills/bec-investigation/SKILL.md) as a
single kill-chain orchestrator over:

- `email_threat_detection.md` for delivery, current disposition, Safe Links,
  forwarding, and outbound mail;
- `user-investigation` and `authentication-tracing` for sign-ins, MFA, sessions,
  and token behavior;
- `OfficeActivity` plus `CloudAppEvents` for mailbox rule and access operations;
- `app-registration-posture` and Graph activity for consent, app credential, and
  programmatic mailbox access;
- incident and IoC skills for involved messages, domains, IPs, and hashes.

Required output:

| Stage | Required evidence |
|---|---|
| Delivery | NetworkMessageId, recipient, delivery/current disposition |
| Interaction | URL click or attachment/device evidence |
| Access | Session, token, risk event, MFA, or explicit gap |
| Persistence | Mailbox rule, permission, consent, or credential change |
| Impact | Observed read/export/send/forward/delete; separate from configuration |
| Response state | ZAP/remediation and subsequent activity |

Gaps to close:

- Add explicit payment-fraud/BEC mailbox content indicators only where
  authorized raw content is actually available.
- Add current mailbox-rule state, not only historical rule-change events.
- Add exact OAuth/Mail API app attribution and a distinction between an app
  permission grant and its subsequent use.
- Add a post-response recurrence check.

### 1.3 Ransomware and lateral-movement investigation

Harden [ransomware-investigation](../.github/skills/ransomware-investigation/SKILL.md)
to represent an incident graph rather than a single-device case:

1. Seed from a Defender alert/incident, device, hash, identity, or remote-access
   event.
2. Use `mde_alert_device_forensics.md` Q1-Q9 for each seed device and exact
   `ProcessUniqueId` attribution.
3. Expand only on concrete identifiers: hashes, exact process instances,
   sessions, account IDs, source/target pairs, incident membership, or proven
   indicators. Do not expand on a filename or IP similarity alone.
4. Use RDP/SMB query chains, endpoint logon data, authentication tracing, and
   app/credential evidence for source-to-target movement.
5. Use persistence, file-impact, shadow-copy/backup command, network, and
   Defender control-outcome evidence to build each device's role.
6. Classify confirmed affected devices separately from suspected leads.

Add a device impact matrix with:

`role`, `seed basis`, `first evidence`, `last evidence`, `process tree`,
`file operations`, `credential use`, `inbound/outbound lateral movement`,
`persistence`, `Defender outcome`, and `post-outcome activity`.

### 1.4 Detection and telemetry health

Harden [telemetry-health](../.github/skills/telemetry-health/SKILL.md) around
an explicit readiness matrix.

Required checks:

- Analytic/custom-detection failures and last successful execution.
- Connector failures and last connector-specific event, where source telemetry
  exposes it. If direct connector health is unavailable, report the limitation
  and use the ingestion anomaly signal as an indirect indicator.
- Ingestion delay/freshness against documented, tenant-local cadence.
- Historical drop-to-zero sources that an inner-join anomaly query can miss.
- Required tables for the selected investigation skill, including AH-only and
  Data Lake-only alternatives.
- Device sensor/telemetry coverage for involved devices.
- Permission, retention, and table-resolution failures.

Do not use the full ingestion report as the only gate. Add a compact required
source map for common workflows and a result type:

`verified_healthy`, `degraded`, `stale`, `denied`, `unavailable`, `unsupported`,
`unverified`, or `not_applicable`.

Add P1 readiness integration to BEC, ransomware, cross-tenant campaign, and
incident entry points so a missing source blocks only the affected conclusion,
not unrelated collection.

## Phase 2: P2 incident orchestrators

These are five new skill files. Each orchestrates existing verified collection
logic and names only the missing query gap to fill.

### 2.1 Privileged access abuse

Proposed skill: `.github/skills/privileged-access-investigation/SKILL.md`

Compose:

- [privileged_account_detection.md](../queries/identity/privileged_account_detection.md)
  for grants, PIM eligibility, baseline differences, and hybrid privilege;
- `identity-posture` and `user-investigation` for current role state and account
  risk;
- `authentication-tracing` for the session immediately before/after elevation;
- `ca-policy-investigation` for control-policy manipulation;
- `app-registration-posture` where app owners or credentials enable privilege;
- Graph role-assignment and PIM inventory calls already documented by the
  workspace instructions.

Missing query work:

- A focused actor/target timeline around role eligibility, activation, permanent
  assignment, role removal, password/MFA reset, and emergency-account activity.
- Tenant-local emergency-account classification; do not infer it from naming
  conventions alone.

Acceptance:

- Every grant says actor, target, role, assignment type, start/expiry, and
  preceding authentication context.
- Permanent/admin-granted privilege, self PIM activation, emergency use, and
  routine documented admin work are distinct outcomes.

### 2.2 Cloud resource compromise

Proposed skill: `.github/skills/cloud-resource-investigation/SKILL.md`

Compose:

- `AzureActivity` control-plane operations;
- [keyvault_storage_access_monitoring.md](../queries/cloud/keyvault_storage_access_monitoring.md);
- [azure_blob_storage_defense_program.md](../queries/cloud/azure_blob_storage_defense_program.md);
- Graph API and service-principal activity;
- Exposure Graph permission paths and Defender for Cloud alerts;
- identity and endpoint evidence where a resource is invoked by or impacts a
  device.

Missing query work:

- A compact resource-centered chain for identity/session, control-plane change,
  diagnostic data-plane access, and subsequent alert/endpoint impact.
- Subscription/resource-group discovery that remains tenant- and
  subscription-qualified.

Acceptance:

- Identify the exact resource ID, subscription, caller identity/type, token or
  managed-identity evidence, operation, and observed result.
- A configuration write, secret read, and data-plane transfer are separate
  events; none alone proves compromise or completed exfiltration.
- Diagnostic-settings blindness is always reported for AzureDiagnostics gaps.

### 2.3 Data exfiltration

Proposed skill: `.github/skills/data-exfiltration-investigation/SKILL.md`

Compose:

- `data-security-analysis` for SIT/label access and DLP;
- `bec-investigation` for mailbox reads, exports, forwarding, and outbound mail;
- endpoint network/file/process evidence for collection and staging;
- `StorageBlobLogs` and Graph/cloud activity for uploads or external sharing;
- IoC, exposure, and incident workflows for destination and affected assets.

Missing query work:

- A cross-stage investigation chain for collection, compression/staging,
  outbound transfer, external sharing, and destination prevalence.
- A channel coverage matrix for email, endpoint, SharePoint/OneDrive, Graph,
  Azure Storage, and optional third-party egress.

Acceptance:

- Report access, staging, transfer attempt, confirmed transfer, and downstream
  access separately.
- A large download is not automatically exfiltration.
- Distinguish content availability from volume/activity evidence.
- Include SIT/label mappings only from the selected tenant.

### 2.4 Persistence investigation

Proposed skill: `.github/skills/persistence-investigation/SKILL.md`

Compose:

- [app_registration_abuse_chains.md](../queries/identity/app_registration_abuse_chains.md)
  and [app_credential_management.md](../queries/identity/app_credential_management.md);
- [startup_folder_persistence.md](../queries/endpoint/startup_folder_persistence.md)
  and MDE process/file/registry forensics;
- privileged role/PIM and ownership changes;
- mailbox forwarding/rules, transport rules, and permissions;
- cloud resource RBAC, SAS, managed identity, automation, and firewall/logging
  changes;
- Defender alerts and exposure evidence.

Missing query work:

- A normalized persistence inventory grouped by identity, endpoint, cloud
  resource, mailbox, and automation plane.
- A "still present / removed / unverified" state with last observed execution.

Acceptance:

- A persistence artifact has creation evidence, actor, scope, last/current
  state when available, and observed execution/use evidence.
- Creation alone is not proof the mechanism executed after the creator was
  removed.
- The workflow never treats all recurring automation as malicious; tenant
  memory and change context must be applied.

### 2.5 Post-containment verification

Proposed skill: `.github/skills/post-containment-verification/SKILL.md`

Compose:

- [device_logon_attack_disruption.md](../queries/endpoint/device_logon_attack_disruption.md)
  pre/post and containment-control queries;
- incident, user, device, BEC, persistence, and ransomware child workflows;
- Identity Protection/remediation state and session/sign-in recurrence;
- Defender automated-investigation/remediation status;
- data-access and outbound recurrence for exfiltration cases.

Require the analyst to identify:

- containment time and source;
- affected entities;
- actions claimed (isolation, token revocation, mailbox purge, rule removal,
  credential rotation, blocking, quarantine);
- verification window and approved telemetry minimum.

Missing query work:

- A parameterized post-action recurrence check per entity type.
- A reusable response-event timeline linking action time to later events without
  assuming every newer event is malicious.

Acceptance:

- Each control has `observed_action`, `expected_effect`, `post-action evidence`,
  and `verification verdict`.
- "No later activity" is valid only after successful coverage checks.
- Active new evidence reopens the appropriate incident skill; the verifier
  does not automatically contain or remediate.

## Phase 3: Query-library additions and metadata

Add only the gaps identified above. Suggested files:

| File | Purpose |
|---|---|
| `queries/identity/privileged_access_abuse.md` | Role/PIM/emergency/MFA/password timeline |
| `queries/cloud/cloud_resource_compromise.md` | Control-plane and data-plane resource timeline |
| `queries/cloud/data_exfiltration_timeline.md` | Collection, staging, transfer, impact chains |
| `queries/incidents/persistence_timeline.md` | Cross-source persistence inventory and use |
| `queries/incidents/post_containment_verification.md` | Per-control recurrence and response verification |
| `queries/cloud/telemetry_readiness.md` | Connector, freshness, table, and rule readiness checks that are not already in ingestion YAML |

Each file must use the existing header format, valid domain tags, cd-metadata
blocks, a PII-free sanity check, and regenerated quick-reference TOCs. Regenerate
only the slim discovery manifest after file/skill metadata changes.

## Phase 4: Integration and reporting

For each new skill:

1. Add frontmatter and a tailored drill-down prompt.
2. Add the skill to `.github/copilot-instructions.md` and README routing.
3. Regenerate `.github/manifests/discovery-manifest.yaml`.
4. Add Threat Pulse and incident shortcut routing only when a concrete query
   evidence pattern triggers it.
5. Add Mission Control follow-up prompts using the actual finding's tenant,
   entity, case, and evidence; never use generic placeholders in recorded data.
6. Ensure findings include metrics, entities, coverage gaps, and original
   launch binding.
7. Add an output template section for attempted vs confirmed activity, exact vs
   temporal correlation, affected assets, and unresolved coverage.

## Verification strategy

### Automated offline checks

- Skill frontmatter parsing and valid domain tags.
- Manifest validation and exact skill discovery.
- Relative-link checks for every child skill and query reference.
- PII scans for committed examples and fixtures.
- `git diff --check` with the repository's CRLF convention preserved.
- Python unit tests for timeline validation and any normalization helper.
- Node tests for Mission Control target/context/result isolation.
- Markdown query-header, TOC, and cd-metadata validation.

### Synthetic workflow tests

- Two tenants with identical incident/device names and separate evidence.
- Campaign with one complete zero-hit, one denied, and one partial target.
- BEC chain with delivery, click, sign-in, rule, and outbound evidence, plus an
  alternate fixture where only a rule exists.
- Ransomware fixture with one confirmed device and two unverified leads.
- Telemetry fixture where a table dropped to zero, a connector is unknown, and a
  rule still has successful historical execution.
- P2 fixtures with attempted-but-blocked action and temporal-only correlation.
- Post-containment fixture with recurrence and a separate clean verified fixture.

### Live pilot checks

For a pilot tenant only:

- Execute every added or changed query through the correct route.
- Validate schema and retention before reporting results.
- Record table absence, permission denial, and query errors as coverage gaps.
- Do not call a query "tested" from offline schema analysis alone.
- No production multi-tenant execution before authenticated target verification
  and the cross-tenant isolation tests pass.

## Delivery order

1. Phase 0 evidence/timeline contract.
2. Telemetry-health readiness manifest and P1 gates, because every later skill
   depends on knowing what evidence is unavailable.
3. Cross-tenant campaign mode and aggregate-summary controls.
4. BEC and ransomware hardening.
5. Privileged-access and cloud-resource orchestrators.
6. Data-exfiltration and persistence orchestrators.
7. Post-containment verification.
8. Final integration, manifest generation, offline tests, and pilot validation.

## Definition of done

The expansion is complete only when:

- Every requested workflow exists either as an extension of the current P1
  skill or as a dedicated P2 skill.
- All P1 workflows use the shared timeline/coverage contract.
- Every P2 workflow reuses existing verified child workflows for at least its
  core entity and event evidence.
- Multi-tenant results remain tenant-separated and original-context bound.
- Every skill can state complete, partial, unavailable, or unsupported evidence
  without converting failure into a clean verdict.
- Mission Control, README, global routing, and the slim discovery manifest know
  about all skills.
- Offline tests pass and the live pilot status is reported honestly.
