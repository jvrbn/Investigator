---
name: ransomware-investigation
description: 'Investigate suspected ransomware, destructive endpoint activity, encryption alerts, or lateral movement related to a ransomware incident. Reconstructs attributed process activity, file impact, control outcomes, persistence, remote logons, and affected-device scope without executing containment.'
threat_pulse_domains: [endpoint, incidents, identity, exposure]
drill_down_prompt: 'Investigate ransomware and lateral movement for {entity}: process ancestry, file impact, remote access, security-control outcomes, and affected assets'
---

# Ransomware and Lateral-Movement Investigation

## Scope and safety

Accept a Defender incident/alert ID or device. Default to a 30-day contextual
lookback with an alert-relative detailed window. Read-only collection only:
do not isolate devices, remove files, disable users, or deploy detections.
Resolve the selected tenant/workspace through
[tenant contexts](../../../docs/tenant-contexts.md), verify the actual collection
connection, and freeze case and time boundaries. Child skills inherit this
context; never fall back to another tenant when telemetry fails.

Before investigating and before a verdict, skim the selected tenant memory's
headings and search matching devices, accounts, IPs, hashes, process names, and
orchestration fingerprints. Read only matching sections and cite applicable
ground truth. Authorized backup, deployment, and encryption software must be
compared against the documented fingerprint, not dismissed by filename alone.

## Investigation shortcuts

| Trigger | Collection chain |
|---|---|
| Ransomware/MDE alert | Device forensics Q1-Q4, then Q5-Q9 in parallel, Q10-Q13 as applicable |
| Threat Pulse Q6/Q7 endpoint anomaly | Device identification and coverage, then exact process-instance attribution |
| RDP/SMB lateral-movement evidence | Remote-access library baseline, failed-then-success chain, and timeline |
| Threat Pulse Q12 vulnerable device with execution evidence | Device forensics first; exposure report supplies vulnerability context |

## Automated collection sequence

1. Load [incident-investigation](../incident-investigation/SKILL.md) for an
   incident seed or [computer-investigation](../computer-investigation/SKILL.md)
   for a device/alert seed. Preserve alert cluster boundaries: sharing an
   incident does not establish a common attack chain.
2. Read [MDE alert device forensics](../../../queries/endpoint/mde_alert_device_forensics.md).
   Execute Q1-Q3 for evidence, device identity, and telemetry coverage before
   interpreting missing events. These queries are documented as offline
   schema-checked, not live-tested: validate them in the selected tenant.
3. Use Q4 to identify the exact process instance, ancestors, and descendants.
   Attribute by ProcessUniqueId where available; PID-only correlation requires
   process creation time. A matching filename or hash alone is contextual.
4. Collect Q5 network, Q6 file/download, Q7 registry, Q8 logons, and Q9 Defender
   outcomes for the resulting process set. Preserve destructive commands as
   inert evidence; never run them. Describe observed file operations separately
   from inferred encryption, deleted backups, or business outage.
5. Use Q10 related alerts and applicable Q11 prevalence branches to scope spread.
   A device that contacted the same destination is a lead, not automatically
   infected. Do not expand empty indicators into wildcard fleet searches.
6. Follow [RDP](../../../queries/endpoint/rdp_threat_detection.md) Q1/Q2/Q6 or
   [SMB](../../../queries/endpoint/smb_threat_detection.md) Q1/Q2/Q6 where logon
   evidence warrants it. Check source/target identities and times against
   process execution. Network logons can include NLA-RDP: do not label them SMB
   merely because LogonType is Network.
7. Use Q12 payload provenance and Q13 sign-ins for initial-access context.
   Load [exposure-investigation](../exposure-investigation/SKILL.md) only for
   affected devices/CVEs, not as evidence that exploitation occurred.
8. Produce a bounded UTC timeline and per-device impact matrix. Keep separate
   columns for attempted action, observed effect, Defender response, and
   continuing activity after that response.

Use the source files' parameters and timestamp rules. Entity context uses
30-day Advanced Hunting or supported longer-retention Data Lake sources;
the detailed process window remains alert-relative. Respect unavailable
AlertInfo/AlertEvidence and other AH-only sources rather than claiming a
feature-equivalent lake fallback.

## Verdict gates and report

Report:

- Alert clusters, seed identifiers, exact collection window and data coverage.
- Attributed process tree and observed file/security-control activity.
- Source-to-target lateral movement with evidence IDs and confidence.
- Confirmed affected devices vs unverified leads; no invented total.
- Backup/recovery status as Unknown unless retrieved from an authorized source.
- Actions already observed vs proposed audited portal actions.

Rarity, high drift, exploitable CVEs, and backup-related commands alone do not
prove ransomware. High risk requires at least two concrete corroborating
findings. A prevention alert does not prove that earlier actions were undone
or that later execution stopped. Verify outcomes rather than trusting titles.

Every claimed-clean stage must cite a successful scoped collection; inaccessible
or stale data is Unknown. Reapply matching tenant-memory rules before the
verdict. End with tenant-scoped portal links from approved templates, prioritized
read-only follow-up prompts, and an original-context Mission Control finding,
even when the result is clean or incomplete.
