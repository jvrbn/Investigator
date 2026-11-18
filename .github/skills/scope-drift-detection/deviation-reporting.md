# Behavioral Deviation Reporting Contract

Read and apply this contract for user, device, and service-principal scope drift.
It applies to shortcuts, single-entity and fleet/cohort runs, and both inline and
markdown reports.

## Separate Observation From Security Judgment

A measured behavioral deviation does not disappear because its explanation is
legitimate. Report **what changed**, **why it is considered legitimate**, and
**whether there is security concern** as separate judgments.

- Capture candidates from the primary results before benign explanations, score
  adjustments, low-volume filters, or deep-dive tiering. Secondary corroboration
  is required to strengthen a threat conclusion, not to report a measured change.
- Check individual dimensions and available value-set differences as well as the
  composite score. A dimension above 150%, a material volume/failure change, or a
  changed resource, app, account, process chain, or execution context can matter
  even when the composite is at or below 150%. Equal distinct counts can hide
  replacement of the actual values.
- Establish materiality against the entity's observed cadence, absolute counts,
  normalized rates, and baseline coverage. A new value alone is not proof of
  abnormal behavior; check how often comparable changes occurred previously.
- Tiering limits investigation depth, not visibility of already observed changes.
  Keep material candidates from lower tiers and low-volume entities in the report.
  If a query only returns counts or fleet-wide novelty, disclose that it cannot
  exclude entity-local substitutions; use scoped detail queries for selected
  candidates rather than calling the remaining population behaviorally stable.
- Preserve raw measurements and scores alongside any adjusted values, with the
  adjustment's formula and evidence. Do not silently change scoring weights or
  remove activity because it has a benign explanation.

## Required Report Section

Every report must include **Material Deviations (Including Legitimate)** before
the security assessment. Summarize the significant explained and unexplained
changes in the executive summary or opening inline summary, even when overall
security risk is low.

| Entity / dimension | Baseline -> recent | Raw / adjusted score | Disposition | Explanation / evidence / confidence | Security risk / corroboration | Review / reopen trigger |
|--------------------|--------------------|----------------------|-------------|-------------------------------------|-------------------------------|-------------------------|
| <entity and changed behavior> | <UTC windows, values, counts or comparable rates, delta, first/last observed> | <raw and adjusted values, or not scored> | <one disposition below> | <query/event references; evidence supporting or contradicting the explanation; confidence> | <risk assessed separately; secondary evidence checked, absent, unavailable or not run> | <follow-up and concrete condition requiring reassessment> |

Use one of these dispositions:

- **Confirmed legitimate deviation:** A material change with matching evidence
  for its operational purpose or authorization. Cite the applicable tenant-local
  context, verified change record, or corroborated execution/operation history.
- **Explained, not verified:** A plausible operational explanation lacks matching
  evidence. State what is missing; do not upgrade this to confirmed legitimate.
- **Unexplained deviation:** The measured change remains unresolved, including
  candidates not investigated in depth. This alone does not mean malicious.
- **Statistical artifact:** Evidence supports a denominator, window, or observation
  coverage explanation rather than changed behavior. Retain raw and adjusted
  values and the supporting evidence instead of erasing the original candidate.
- **Insufficient evidence:** Baseline, identity resolution, or telemetry coverage
  is inadequate. Do not treat missing data as zero activity or a clean result.

Company-name metadata, familiar tools, system/service accounts, private address
prefixes, absent alerts, or a prior FalsePositive/BenignPositive disposition do not
alone establish legitimacy. A closed alert changes that detection's threat weight,
not whether an independently observed behavioral change occurred.

Group repetitive verified update/rotation artifacts by entity and explanation,
showing counts and representative evidence. Do not hide unrelated material changes
inside a benign group or discard them because they fall outside the top-N deep dives.
If no material deviations were found, say so only for the dimensions actually
checked, and state coverage gaps separately.

## Resurface Previously Accepted Behavior

Retain material deviations judged legitimate in each run where they are observed.
Carry forward the prior decision's source and scope, not an unconditional allowlist.
Reassess when the actor, resource/permission, device, path/parent/command, source
network/geography, volume, cadence, duration, or documented approval scope changes,
or when new alerts or contradictory evidence appear. Expired or unmatched approval
is not confirmation. Do not automatically promote recent behavior into the baseline
or edit tenant-context memory.

## Acceptance Cases

| Case | Required outcome |
|------|------------------|
| An approved resource is new but the composite score is 110 | Retain a confirmed legitimate deviation with the resource delta and approval evidence; no threat escalation from novelty alone. |
| A raw volume spike becomes baseline-consistent after verified uptime normalization | Retain a statistical-artifact row with raw/adjusted values and the normalization evidence. Missing snapshots alone do not prove downtime. |
| A new command runs as a system account and has a familiar company-name field | Keep it unexplained or explained, not verified until its execution context is validated. |
| A previously accepted job now reaches an additional resource or exceeds its approved cadence | Resurface and reassess the changed scope; the old benign disposition does not cover it automatically. |
| Primary telemetry proves a deviation but secondary sources are unavailable | Report the deviation and the corroboration gap; do not suppress it or claim compromise. |
| A baseline is missing, or only aggregate counts were checked | Report insufficient coverage; do not assert normality or absence of entity-local changes. |
