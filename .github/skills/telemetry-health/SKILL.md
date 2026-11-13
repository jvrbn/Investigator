---
name: telemetry-health
description: 'Assess SOC investigation readiness: Sentinel analytic-rule failures, ingestion regressions, missing or stale required telemetry, Defender sensor health, and source permissions. Distinguishes confirmed coverage from unverified or unavailable data; reuses ingestion and device-forensics query libraries.'
threat_pulse_domains: [admin, cloud, endpoint, incidents]
drill_down_prompt: 'Assess telemetry and detection health for {entity}: failed analytic rules, ingestion regressions, required-table freshness, and Defender sensor coverage'
---

# Telemetry and Detection Health

## Inputs and boundaries

Read-only, inline by default. Accept a tenant/workspace, investigation skill,
or device plus optional required sources and freshness objectives. Default
comparison is last 24 hours vs available historical ingestion; rule health
uses 7 days. These are inspection windows, not a universal freshness SLA.
Use documented tenant SLAs when present. Without a source-specific SLA,
report age and coverage as observations rather than inventing a failure.

Resolve [tenant contexts](../../../docs/tenant-contexts.md) and authenticate
the selected collection connection. Never interpret a permission failure or
an unsupported delegated Triage connection as absent telemetry.

Before collection and before a verdict, skim tenant-memory headings and
search workspace/source names, devices, connector names, automation actors,
and maintenance windows. Read only matching sections, cite documented
collection schedules/exclusions, and do not assume one tenant's SLA applies
to another tenant.

## Collection plan

1. Build an explicit source checklist from the requested skill's actual
   queries. Record table, collection tool, retention, expected cadence/SLA
   if documented, permission requirement, and validation status. Inventory
   is not ingestion proof, and a table not listed by Usage is not necessarily
   missing: nonbillable telemetry may be excluded.
2. Read the [ingestion skill](../sentinel-ingestion-report/SKILL.md) for its
   tool and authentication requirements. Use these existing query definitions
   directly, substituting only their named parameters:

   | Check | Definition |
   |---|---|
   | Rule execution totals | [Q11](../sentinel-ingestion-report/queries/phase4/Q11-RuleHealthSummary.yaml) |
   | Failed rule detail | [Q11d](../sentinel-ingestion-report/queries/phase4/Q11d-FailingRuleDetail.yaml) |
   | Ingestion change | [Q14](../sentinel-ingestion-report/queries/phase5/Q14-IngestionAnomaly24h.yaml) |
   | Billable table inventory | [Q13](../sentinel-ingestion-report/queries/phase4/Q13-AllTablesWithData.yaml) |
   | Deployed analytic rules | [Q9](../sentinel-ingestion-report/queries/phase3/Q9-AnalyticRuleInventory.yaml) |
   | Custom detections, when authorized | [Q9b](../sentinel-ingestion-report/queries/phase3/Q9b-CustomDetectionRules.yaml) |

   Q9/Q9b are inventory definitions, not KQL; follow their read-only API
   collection instructions. Do not invoke the full cost-report pipeline when
   only these checks are needed.
3. For each required source, verify schema and run a bounded freshness/coverage
   query through the global KQL pre-flight. Do not invent a universal union
   over missing tables. AH is limited to 30 days; use the supported longer
   retention route when needed. Never paste unexecuted KQL as a verified check.
4. For endpoint-dependent investigations, use device-forensics
   [Q2 and Q3](../../../queries/endpoint/mde_alert_device_forensics.md)
   for device identity, sensor health, and event coverage. A quiet event table
   alone is not proof of an offline sensor. Corroborate with DeviceInfo health
   and the documented collection policy. Check optional DeviceCustom tables
   only when evidence warrants escalation.
5. Cross-reference failed rules with their actual required tables and current
   permissions. Use the ingestion drill-down workflow for rule queries and
   dependencies; do not attribute every failure to ingestion.

## Interpretation safeguards

- Q11 treats PartialSuccess as Success. Label that aggregation policy; it
  does not prove complete processing. Inspect underlying status detail
  through schema-validated read-only collection before declaring health.
- Q14 uses inner joins and current-period data. It can miss tables that
  dropped to zero entirely, and it is capped at 20 rows. Independently
  check every required source, including historical-only sources.
- Q13 includes only billable Usage records. Do not call it a complete schema
  or use absence from it to conclude a source is unlicensed.
- No SentinelHealth rows can mean health diagnostics are unavailable.
  Zero failed rules is reassuring only when rule executions were observed.
- An enabled/deployed rule is not proof it ran; zero alerts is not proof it
  ran successfully or that no threats occurred.
- Missing tables, denied permissions, timeouts, and unsupported collection
  paths are separate statuses. Never retry against another tenant/workspace.

## Prioritized readiness dashboard

Render a row for every required source and rule group:

| Field | Required content |
|---|---|
| Scope | Tenant profile, workspace, connection, UTC inspection time |
| Evidence | Source/query definition, last event time, successful executions or failures |
| Status | Verified healthy / Degraded / Unavailable / Unverified / Not applicable |
| Investigation impact | Which requested investigation stage cannot be supported |
| Priority | P1 for observed loss/failure blocking a requested critical investigation; otherwise evidence-based P2/P3 |
| Follow-up | Read-only skill/query prompt with the concrete failing rule/source/device |

Do not label the tenant secure based on telemetry health. Cite matching
maintenance and collection context before assigning priority. Recommend
audited portal navigation for configuration changes, never execute repairs.
Record a Mission Control finding in the original tenant/case context,
including successful checks and coverage gaps even when no failures appear.
