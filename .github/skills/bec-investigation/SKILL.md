---
name: bec-investigation
description: 'Investigate business email compromise (BEC), mailbox takeover, malicious forwarding, payment-fraud email, or an AiTM email-to-account chain. Correlates message delivery and clicks, authentication, mailbox rules, mailbox access, outbound mail, and remediation state using existing verified workflows.'
threat_pulse_domains: [email, identity, incidents, cloud]
drill_down_prompt: 'Investigate business email compromise for {entity}: delivery, clicks, authentication, forwarding, mailbox access, outbound mail, and current exposure'
---

# Business Email Compromise Investigation

## Scope and prerequisites

Read-only investigation, not mailbox remediation. Accept a UPN, NetworkMessageId,
Defender incident ID, or sender/domain. Default to the last 30 days, inline output.
If starting with an incident, retrieve its alerts and resolve the affected mailbox
before broadening the investigation. Do not equate Sentinel incident numbers with
Defender incident IDs.

Resolve the selected tenant and workspace using the
[tenant-context workflow](../../../docs/tenant-contexts.md). All subsequent child
workflows inherit that immutable context, not a different root configuration.
Verify the actual MCP connection's tenant before using it; Azure CLI validation
does not validate MCP authentication. Triage requires a supported home-tenant
session. Discover workspaces on the selected tenant's Data Lake connection and
apply the global explicit-selection rule.

Before collection and again before a verdict, skim headings in the selected
tenant's context-memory file, then search only the mailbox, actors, domains,
IPs, apps, and hashes discovered. Read matching sections only. Cite the section
and matching fingerprint; do not copy ground truth from another tenant.
Missing memory is an explicit limitation, not permission to invent a baseline.

## Investigation shortcuts

| Trigger | Initial collection |
|---|---|
| Threat Pulse Q8 delivered phishing | Email query sections 2.4, 6.2, 7.6, then authentication tracing |
| Threat Pulse Q9 inbox or mailbox changes | Email section 9.3 plus CloudAppEvents through user-investigation |
| Threat Pulse Q3 risky user with inbox manipulation | User-investigation, authentication-tracing, then sections 9.1 and 9.3 |
| A specific message | Email section 12.2, then clicks and affected recipients |

## Automated collection sequence

1. Read the [email query library](../../../queries/email/email_threat_detection.md)
   and child skills before executing their queries. Retain the query's validation
   status; a library reference is not proof of a live test in this tenant.
2. Establish delivery and current disposition with sections 2.4, 6.2, 7.6, and
   10.3. Pivot on NetworkMessageId plus recipient; do not join unrelated mail by
   subject. A delivered message may later have been removed by ZAP.
3. Use [authentication-tracing](../authentication-tracing/SKILL.md) and
   [user-investigation](../user-investigation/SKILL.md) for affected users.
   Correlate recorded sessions and risk events; a click or successful sign-in
   alone does not establish credential theft.
4. Execute section 9.3 for Exchange forwarding, redirect, deletion, and mark-read
   rules. Also collect CloudAppEvents mailbox changes using user-investigation.
   These sources are complementary. Read the full OfficeActivity Parameters and
   ClientIP; distinguish a configured forwarding destination from observed
   delivery. Scope results to the affected mailbox and window.
5. Execute section 9.1 for outbound messages from the affected accounts.
   Use the user-investigation mailbox activity workflow for MailItemsAccessed,
   Send, deletion, and mailbox permission evidence where available. Never infer
   message contents, payment changes, or completed exfiltration from counts.
6. If consent or app access appears in the evidence, load
   [app-registration-posture](../app-registration-posture/SKILL.md) for that app.
   `suspiciousAuthAppApproval` alone is an MFA signal, not OAuth consent evidence.
7. Build a UTC timeline: message delivery, click, interactive authentication,
   token reuse, rule change, mailbox access, outbound send, and remediation.
   Preserve source event IDs and distinguish exact joins from temporal proximity.

Use Advanced Hunting only for windows up to 30 days. For older evidence use the
documented Data Lake equivalents and report unavailable sources separately.
Library EmailEvents queries using TimeGenerated require Timestamp in Advanced
Hunting; OfficeActivity/SigninLogs keep TimeGenerated. AADUserRiskEvents event
time is ActivityDateTime. Verify schema before these adaptations. The
ForwardingInformation column is not assumed to exist: validate it before using
section 9.2, or report that evidence unavailable. Do not silently substitute
unrelated data or share unexecuted KQL with the analyst.

## Verdict and output

Render a compact case summary followed by:

| Stage | Required evidence |
|---|---|
| Initial access | Delivery/current disposition, click, authentication evidence or an explicit gap |
| Account access | User/session identifiers, risk events, and baseline/context comparison |
| Persistence | Rule/consent/permission change, actor, destination, and raw event reference |
| Impact | Observed read/send/forward/delete events; attempted vs confirmed impact |
| Response state | Recorded remediation and subsequent activity, not assumed containment |

Assign High only with at least two concrete corroborating findings. A forwarding
rule alone is suspicious configuration, not confirmed theft. A clean conclusion
requires successful, correctly scoped collection for every claimed-clean stage;
missing/denied/stale telemetry remains Unknown. Recheck tenant memory before
classifying an automation fingerprint as malicious or benign.

End with prioritized evidence-bearing follow-up prompts and tenant-scoped portal
links using the active skill/global URL allowlist. Recommend audited portal
actions only; never execute mailbox or identity changes. When Mission Control
is used, record the result with the original launch context, including clean or
partial results, and never redirect a late result to the currently selected tenant.
