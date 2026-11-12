# MDE Alert-Anchored Device Forensics

**Created:** 2026-11-11  
**Platform:** Microsoft Defender XDR  
**Tables:** AlertInfo, AlertEvidence, DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents, DeviceImageLoadEvents, UrlClickEvents, EmailEvents, EntraIdSignInEvents  
**Keywords:** MDE alert, alert triage, alert-anchored, process tree, ProcessUniqueId, process start key, ancestry, descendants, attribution, payload provenance, FileOriginUrl, related alerts, fleet prevalence, telemetry coverage, detection outcome, persistence, logon session, device investigation  
**MITRE:** T1059, T1204, T1105, T1071, T1547.001, T1562.001, T1021, TA0002, TA0003, TA0005, TA0008, TA0011  
**Domains:** endpoint, incidents  
**Timeframe:** Alert-relative window (default: first activity − 30 min to last activity + 2 h); Advanced Hunting retention ≤ 30 days

---

## Overview

Parameterized, **read-only** drill-down queries for the *MDE alert-anchored mode* of the [computer-investigation skill](../../.github/skills/computer-investigation/SKILL.md). They answer, for one alerted device: what fired, what executed (exact process instances), what it touched, what Defender already did, and what *else* is related.

> **Validation status:** every query below was parsed and schema-checked offline (Kusto language analyzer against the Microsoft Learn Advanced Hunting schemas, 2026-11-11). **None has been executed against a live tenant yet.** Before relying on a result, apply the global sanity checks (zero rows ≠ clean; verify the filter values), and record the first live run per query in the pilot log. Replace every `<PLACEHOLDER>` before running.

### How the queries chain

| Step | Queries | Gate |
|------|---------|------|
| 1. Case + window | **Q1** (alert/evidence), alert API for first/last activity | Confirm `ServiceSource` is Defender for Endpoint per alert; derive `DeviceId`, window, seeds |
| 2. Coverage | **Q2** (device), **Q3** (telemetry freshness) | Empty/stale source = coverage gap, never "clean" |
| 3. Process chain | **Q4** | Produces the `ProcessSet` (ProcessUniqueId values) used below |
| 4. Attributed activity (parallel) | **Q5** network, **Q6** files, **Q7** registry, **Q8** logons, **Q9** security events | Rows are labelled `Attributed`; unattributed rows are context, not proof |
| 5. Related context (parallel) | **Q10** related alerts, **Q11** fleet prevalence (parts a/b/c), **Q12** payload provenance, **Q13** account sign-ins | Correlation ≠ causation; bounded; never auto-recurse. Run only the Q11 parts whose indicators (hashes, destinations, command-line fragments) are non-empty; otherwise Q11 is `not_run` |

### Parameters

| Placeholder | Source |
|-------------|--------|
| `<ALERT_ID_n>` | Defender XDR alert ID (`AlertInfo.AlertId` / Triage MCP alert ID). Not the Sentinel `SystemAlertId` |
| `<DEVICE_ID>` | `AlertEvidence.DeviceId` / alert `mdeDeviceId`. Never a hostname |
| `<WINDOW_START_UTC>` / `<WINDOW_END_UTC>` | Half-open `[start, end)`; default first activity − 30 min and last activity + 2 h, capped at the frozen collection cutoff. Use the alert API's first/last *activity*; `AlertInfo.Timestamp` is when the record was written, not when the activity happened |
| `<SEED_PID_OR_0>` / `<SEED_PROCESS_CREATION_UTC>` | Alert process evidence `processId` / `processCreationDateTime` (not available as `AlertEvidence` columns) |
| `<ALERT_EVIDENCE_TIME_UTC>` | Alert evidence or first-activity time. Only ranks hash/name fallback seed candidates (closest first) in Q4; `datetime(null)` when unknown |
| `<PROCESS_UNIQUE_ID>` / `ProcessSet` | `DeviceProcessEvents.ProcessUniqueId` (Windows Process Start Key) from Q4 |
| `<SEED_SHA1>` | `AlertEvidence.SHA1`. `SHA256` is usually unpopulated in Device tables, so correlate on SHA1 |
| `dynamic([])` | Use for "unknown / none". An empty list matches nothing. Never substitute `[""]` or a wildcard: an empty-string key matches every row that lacks the field. If the engine rejects an empty list, record the query as `failed`; do not widen the filter |

### Data Lake variant

`AlertInfo` and `AlertEvidence` exist only in Advanced Hunting (≤ 30 days): for older alerts use `SecurityAlert` + `SecurityIncident` (Appendix pattern in the workspace instructions) and treat process-instance seeds as unavailable. Device, Email, UrlClick and EntraIdSignIn tables can be queried in the Data Lake by replacing `Timestamp` with `TimeGenerated`; verify the unique-ID columns exist there first.

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Case Snapshot and Evidence Rows](#query-1-case-snapshot-and-evidence-rows) | Investigation | `AlertInfo` |
| 2 | [Device Identity, Onboarding and Sensor Health](#query-2-device-identity-onboarding-and-sensor-health) | Investigation | `DeviceInfo` |
| 3 | [Telemetry Coverage Around the Window](#query-3-telemetry-coverage-around-the-window) | Investigation | `DeviceEvents` + multi |
| 4 | [Seed Process, Ancestors and Descendants](#query-4-seed-process-ancestors-and-descendants) | Investigation | `DeviceProcessEvents` |
| 5 | [Network Activity by Process Set](#query-5-network-activity-by-process-set) | Investigation | `DeviceNetworkEvents` |
| 6 | [File Activity and Download Origin by Process Set](#query-6-file-activity-and-download-origin-by-process-set) | Investigation | `DeviceFileEvents` |
| 7 | [Persistence and Defense-Evasion Registry Changes](#query-7-persistence-and-defense-evasion-registry-changes) | Investigation | `DeviceRegistryEvents` |
| 8 | [Logon and Session Context](#query-8-logon-and-session-context) | Investigation | `DeviceLogonEvents` |
| 9 | [Defender Outcome and Security-Control Events](#query-9-defender-outcome-and-security-control-events) | Investigation | `DeviceEvents` |
| 10 | [Related Activity (Same Device or Shared Evidence)](#query-10-related-activity-same-device-or-shared-evidence) | Investigation | — |
| 11 | [Fleet Prevalence of the Seed Indicators](#query-11-fleet-prevalence-of-the-seed-indicators) | Investigation | `DeviceFileEvents` + `DeviceProcessEvents` |
| 12 | [Payload Provenance (Download Origin, URL Clicks, Email)](#query-12-payload-provenance-download-origin-url-clicks-email) | Investigation | `DeviceFileEvents` + `UrlClickEvents` |
| 13 | [Sign-In Context for the Accounts Involved](#query-13-sign-in-context-for-the-accounts-involved) | Investigation | `EntraIdSignInEvents` |


## Query 1: Case Snapshot and Evidence Rows

**Purpose:** Return alert metadata and every evidence row (entity, role, device, file, process command line, IP/URL, account, registry) for one or more alert IDs. Use it to confirm the alert is an MDE alert (`ServiceSource`), to separate *impacted* from *related* devices (`EvidenceRole`), and to extract seeds (hashes, file names, IPs, accounts, device IDs).

**Tuning Notes:**
- Output is capped at 500 rows. A result of exactly 500 rows is truncated; narrow the alert list.
- `AdditionalFields` is entity-specific JSON; inspect its keys per alert rather than assuming a shape.
- `AlertRecordedAt` / `EvidenceTimestamp` are record times. Take first/last activity from the alert API.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Parameterized case lookup keyed on supplied alert IDs; not a detection."
-->

```kql
// Query 1: Alert + evidence snapshot for supplied alert IDs (Advanced Hunting only)
let AlertIds = dynamic(["<ALERT_ID_1>", "<ALERT_ID_2>"]);
AlertInfo
| where Timestamp > ago(30d)
| where AlertId in (AlertIds)
| summarize arg_max(Timestamp, *) by AlertId
| join kind=inner (
    AlertEvidence
    | where Timestamp > ago(30d)
    | where AlertId in (AlertIds)
    | project AlertId, EvidenceTimestamp = Timestamp, EntityType, EvidenceRole, EvidenceDirection,
        DeviceId, DeviceName, FileName, FolderPath, SHA1, SHA256, ProcessCommandLine,
        RemoteIP, RemoteUrl, LocalIP, AccountName, AccountDomain, AccountSid, AccountObjectId, AccountUpn,
        RegistryKey, RegistryValueName, RegistryValueData, ThreatFamily, AdditionalFields
  ) on AlertId
| project AlertId, Title, Severity, Category, AttackTechniques, ServiceSource, DetectionSource,
    AlertRecordedAt = Timestamp, EvidenceTimestamp, EntityType, EvidenceRole, EvidenceDirection,
    DeviceId, DeviceName, FileName, FolderPath, SHA1, SHA256, ProcessCommandLine,
    RemoteIP, RemoteUrl, LocalIP, AccountName, AccountDomain, AccountSid, AccountObjectId, AccountUpn,
    RegistryKey, RegistryValueName, RegistryValueData, ThreatFamily, AdditionalFields
| order by AlertId asc, EvidenceTimestamp asc
| take 500
```

---

## Query 2: Device Identity, Onboarding and Sensor Health

**Purpose:** Establish which asset this is and whether it can be observed: names seen (rename detection), merged device identities, OS, criticality, onboarding, sensor health, exposure, tags, last record.

**Tuning Notes:**
- Shows the *latest known* state (since 7 days before the window), not necessarily the state at alert time.
- If `MergedToDeviceId` is populated, the device was merged: re-run the case under the merged ID and keep both histories separate.
- `SensorHealthState` other than active, or a `LastRecord` well before the window end, is a coverage warning for every query below.
- Risk score is not in `DeviceInfo`; use the Defender machine API.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Single-device context lookup; not a detection."
-->

```kql
// Query 2: Device identity and health for the verified DeviceId
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
DeviceInfo
| where Timestamp >= WindowStart - 7d
| where DeviceId == DeviceIdParam
| summarize arg_max(Timestamp, *), NamesSeen = make_set(DeviceName, 10), FirstRecord = min(Timestamp), Records = count() by DeviceId
| project DeviceId, DeviceName, NamesSeen, MergedToDeviceId, MergedDeviceIds, LastRecord = Timestamp, FirstRecord, Records,
    OSPlatform, OSVersion, OSBuild, OSArchitecture, DeviceType, DeviceCategory, DeviceRoles, AssetValue, ExposureLevel,
    MachineGroup, OnboardingStatus, SensorHealthState, IsExcluded, ExclusionReason, IsInternetFacing,
    JoinType, IsAzureADJoined, AadDeviceId, LoggedOnUsers, PublicIP, DeviceManualTags, DeviceDynamicTags, RegistryDeviceTag
```

---

## Query 3: Telemetry Coverage Around the Window

**Purpose:** Per-source row counts and first/last event times for the device from 24 h before to 24 h after the evidence window. Distinguishes "nothing happened" from "the sensor or table was silent".

**Tuning Notes:**
- A source with `RowsInWindow = 0` is `no_data` for that source and interval only. If `LastEvent` stops mid-window, treat later absence as unobservable.
- Compare sources: process events present but network events absent is a field/policy gap, not proof of no network activity.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Coverage diagnostic across seven tables; not a detection."
-->

```kql
// Query 3: Is silence real? Per-source coverage for the device around the evidence window
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let Lo = WindowStart - 24h;
let Hi = WindowEnd + 24h;
union
    (DeviceProcessEvents | where Timestamp >= Lo and Timestamp < Hi | where DeviceId == DeviceIdParam
        | summarize Rows = count(), RowsInWindow = countif(Timestamp >= WindowStart and Timestamp < WindowEnd), FirstEvent = min(Timestamp), LastEvent = max(Timestamp)
        | extend SourceTable = "DeviceProcessEvents"),
    (DeviceNetworkEvents | where Timestamp >= Lo and Timestamp < Hi | where DeviceId == DeviceIdParam
        | summarize Rows = count(), RowsInWindow = countif(Timestamp >= WindowStart and Timestamp < WindowEnd), FirstEvent = min(Timestamp), LastEvent = max(Timestamp)
        | extend SourceTable = "DeviceNetworkEvents"),
    (DeviceFileEvents | where Timestamp >= Lo and Timestamp < Hi | where DeviceId == DeviceIdParam
        | summarize Rows = count(), RowsInWindow = countif(Timestamp >= WindowStart and Timestamp < WindowEnd), FirstEvent = min(Timestamp), LastEvent = max(Timestamp)
        | extend SourceTable = "DeviceFileEvents"),
    (DeviceRegistryEvents | where Timestamp >= Lo and Timestamp < Hi | where DeviceId == DeviceIdParam
        | summarize Rows = count(), RowsInWindow = countif(Timestamp >= WindowStart and Timestamp < WindowEnd), FirstEvent = min(Timestamp), LastEvent = max(Timestamp)
        | extend SourceTable = "DeviceRegistryEvents"),
    (DeviceLogonEvents | where Timestamp >= Lo and Timestamp < Hi | where DeviceId == DeviceIdParam
        | summarize Rows = count(), RowsInWindow = countif(Timestamp >= WindowStart and Timestamp < WindowEnd), FirstEvent = min(Timestamp), LastEvent = max(Timestamp)
        | extend SourceTable = "DeviceLogonEvents"),
    (DeviceEvents | where Timestamp >= Lo and Timestamp < Hi | where DeviceId == DeviceIdParam
        | summarize Rows = count(), RowsInWindow = countif(Timestamp >= WindowStart and Timestamp < WindowEnd), FirstEvent = min(Timestamp), LastEvent = max(Timestamp)
        | extend SourceTable = "DeviceEvents"),
    (DeviceImageLoadEvents | where Timestamp >= Lo and Timestamp < Hi | where DeviceId == DeviceIdParam
        | summarize Rows = count(), RowsInWindow = countif(Timestamp >= WindowStart and Timestamp < WindowEnd), FirstEvent = min(Timestamp), LastEvent = max(Timestamp)
        | extend SourceTable = "DeviceImageLoadEvents")
| project SourceTable, RowsInWindow, Rows, FirstEvent, LastEvent
| order by SourceTable asc
```

---

## Query 4: Seed Process, Ancestors and Descendants

**Purpose:** Resolve the exact process instance behind the alert and build a bounded process tree. Each process instance has up to two aliases: its `ProcessUniqueId` (Windows Process Start Key) and `pid@creation-time`. A parent/child edge is accepted when either alias matches, so partially populated telemetry still links. An alias is empty (never a shared placeholder) when its inputs are missing, and PID alone is never used. Output rows carry `TreeRole` (`ancestor_grandparent`, `ancestor_parent`, `seed`, `descendant`), `Depth` and `MatchBasis` (`unique_id`, `pid+creation_time`, `hash_or_name_fallback`).

**Tuning Notes:**
- Seed order of preference: known `ProcessUniqueId` → alert PID + creation time (±2 s) → hash/file-name fallback. Fallback matches are *candidates* (low confidence): the 25 closest to `SeedHintTime` (then earliest, then `ReportId`) are returned, so the same input always yields the same candidates. `FallbackCandidates` is the total matched and `FallbackTruncated` is `true` when more than 25 matched. Pick by command line before trusting the tree.
- Parent and grandparent come from the seed event's own `InitiatingProcess*` fields. To walk further up, re-run with `SeedUniqueIds = [<parent ProcessUniqueId>]` and move `WindowStart` earlier than that process's creation.
- Descendants stop at depth 3. If depth-3 rows exist, children may remain: re-seed from those nodes. A 400-row result is truncated.
- The `ProcessSet` for Q5–Q9 is the distinct `ProcessUniqueId` of `seed` + `descendant` rows (add the direct parent only if it is not a generic shell such as `explorer.exe`/`services.exe`).
- Process creation is *observed execution start*, not proof that the intent succeeded.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Multi-level self-join forensic tree seeded by alert evidence; parameterized per case and not suitable for continuous detection."
-->

```kql
// Query 4: Seed process, ancestors, and descendants (3 levels) keyed on ProcessUniqueId with a pid@creation-time alias
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let SeedUniqueIds = dynamic(["<PROCESS_UNIQUE_ID>"]);     // [] when unknown; re-seed with an ancestor ID to walk upward
let SeedPid = long(<SEED_PID_OR_0>);                       // alert process evidence processId; 0 when unknown
let SeedCreation = datetime(<SEED_PROCESS_CREATION_UTC>);  // alert process evidence processCreationDateTime; datetime(null) when unknown
let SeedSha1s = dynamic(["<SEED_SHA1>"]);                  // fallback only; [] when unknown
let SeedFileNames = dynamic(["<SEED_FILE_NAME>"]);         // fallback only; [] when unknown
let SeedCmdFragments = dynamic([]);                        // optional distinctive command-line fragments for fallback matches
let SeedHintTime = datetime(<ALERT_EVIDENCE_TIME_UTC>);    // alert evidence or first-activity time used to rank fallback candidates; datetime(null) when unknown
let SearchStart = iff(isnotnull(SeedCreation), SeedCreation - 10m, WindowStart);
// Alias "pid@creation-time"; empty (never a shared placeholder) when either input is missing
let PidKey = (pid: long, created: datetime) {
    iff(isnotnull(pid) and pid > 0 and isnotnull(created), strcat(tostring(pid), "@", tostring(created)), "")
};
let Created = materialize(
    DeviceProcessEvents
    | where Timestamp >= SearchStart and Timestamp < WindowEnd
    | where DeviceId == DeviceIdParam
    | where ActionType in ("ProcessCreated", "ProcessCreatedUsingWmiQuery")
    | extend UKey = ProcessUniqueId, PKey = PidKey(ProcessId, ProcessCreationTime),
        ParentUKey = InitiatingProcessUniqueId, ParentPKey = PidKey(InitiatingProcessId, InitiatingProcessCreationTime));
// Children of a parent set, matched on either alias within the same device and de-duplicated per event
let ChildrenOf = (Parents: (DeviceId: string, UKey: string, PKey: string)) {
    union
        (Created | where isnotempty(ParentUKey)
            | join kind=inner (Parents | where isnotempty(UKey) | project DeviceId, ParentUKey = UKey) on DeviceId, ParentUKey),
        (Created | where isnotempty(ParentPKey)
            | join kind=inner (Parents | where isnotempty(PKey) | project DeviceId, ParentPKey = PKey) on DeviceId, ParentPKey)
    | summarize take_any(*) by DeviceId, Timestamp, ReportId
};
let Exact = Created
    | where ProcessUniqueId in (SeedUniqueIds)
        or (SeedPid > 0 and ProcessId == SeedPid and abs(datetime_diff('second', ProcessCreationTime, SeedCreation)) <= 2)
    | extend MatchBasis = iff(ProcessUniqueId in (SeedUniqueIds), "unique_id", "pid+creation_time");
let FallbackAll = Created
    | where toscalar(Exact | count) == 0
    | where SHA1 in~ (SeedSha1s) or FileName in~ (SeedFileNames)
    | where array_length(SeedCmdFragments) == 0 or ProcessCommandLine has_any (SeedCmdFragments);
let FallbackCount = toscalar(FallbackAll | count);
let Seeds = union Exact,
    (FallbackAll
    | extend HintDistanceSec = iff(isnotnull(SeedHintTime), abs(datetime_diff('second', Timestamp, SeedHintTime)), long(0))
    | order by HintDistanceSec asc, Timestamp asc, ReportId asc
    | take 25
    | extend MatchBasis = "hash_or_name_fallback");
let SeedKeys = Seeds | project DeviceId, UKey, PKey;
let D1 = ChildrenOf(SeedKeys) | extend Depth = 1;
let D1Keys = D1 | project DeviceId, UKey, PKey;
let D2 = ChildrenOf(D1Keys) | extend Depth = 2;
let D2Keys = D2 | project DeviceId, UKey, PKey;
let D3 = ChildrenOf(D2Keys) | extend Depth = 3;
let Parents = Seeds
    | project Depth = -1, TreeRole = "ancestor_parent", MatchBasis, Timestamp = InitiatingProcessCreationTime, ReportId,
        ProcessUniqueId = InitiatingProcessUniqueId, ProcessId = InitiatingProcessId, ProcessCreationTime = InitiatingProcessCreationTime,
        FileName = InitiatingProcessFileName, FolderPath = InitiatingProcessFolderPath, SHA1 = InitiatingProcessSHA1,
        ProcessCommandLine = InitiatingProcessCommandLine, AccountDomain = InitiatingProcessAccountDomain,
        AccountName = InitiatingProcessAccountName, AccountSid = InitiatingProcessAccountSid, AccountUpn = InitiatingProcessAccountUpn,
        AccountObjectId = InitiatingProcessAccountObjectId, ProcessIntegrityLevel = InitiatingProcessIntegrityLevel,
        ProcessTokenElevation = InitiatingProcessTokenElevation, LogonId = InitiatingProcessLogonId;
let Grandparents = Seeds
    | project Depth = -2, TreeRole = "ancestor_grandparent", MatchBasis, Timestamp = InitiatingProcessParentCreationTime, ReportId,
        ProcessId = InitiatingProcessParentId, ProcessCreationTime = InitiatingProcessParentCreationTime,
        FileName = InitiatingProcessParentFileName;
union
    Grandparents,
    Parents,
    (Seeds | extend Depth = 0, TreeRole = "seed"),
    (D1 | extend TreeRole = "descendant"),
    (D2 | extend TreeRole = "descendant"),
    (D3 | extend TreeRole = "descendant")
| extend FallbackCandidates = iff(MatchBasis == "hash_or_name_fallback", FallbackCount, long(null)),
    FallbackTruncated = iff(MatchBasis == "hash_or_name_fallback", FallbackCount > 25, bool(null))
| project Depth, TreeRole, MatchBasis, FallbackCandidates, FallbackTruncated, Timestamp, ReportId, ProcessUniqueId, ProcessId, ProcessCreationTime,
    FileName, FolderPath, SHA1, ProcessCommandLine, AccountDomain, AccountName, AccountSid, AccountUpn, AccountObjectId,
    ProcessIntegrityLevel, ProcessTokenElevation, LogonId, IsProcessRemoteSession, ProcessRemoteSessionIP, ProcessRemoteSessionDeviceName
| order by Depth asc, Timestamp asc
| take 400
```

---

## Query 5: Network Activity by Process Set

**Purpose:** Destinations contacted by the process set (`Attributed = true`) versus every other process on the device in the window (`Attributed = false`, context only). Grouped, because network telemetry is high volume.

**Tuning Notes:**
- Pass `ProcessSet = []` to see device-wide destinations with nothing attributed.
- `Events` is a connection-event count, not bytes: never infer data volume or exfiltration from it.
- A destination seen only from unattributed processes is *not* evidence about the seed. Public IPs/URLs from evidence must be defanged in reports.
- Capped at 300 groups; a 300-row result is truncated.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Process-set attribution is supplied per case from Query 4; not a standalone detection."
-->

```kql
// Query 5: Network destinations for the process set (attributed) and the rest of the device (context)
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let ProcessSet = dynamic(["<PROCESS_UNIQUE_ID_1>", "<PROCESS_UNIQUE_ID_2>"]);   // from Query 4; [] = nothing attributed
DeviceNetworkEvents
| where Timestamp >= WindowStart and Timestamp < WindowEnd
| where DeviceId == DeviceIdParam
| extend Attributed = isnotempty(InitiatingProcessUniqueId) and InitiatingProcessUniqueId in (ProcessSet)
| extend ProcessKey = iff(Attributed, InitiatingProcessUniqueId, "")
| summarize Events = count(), LastSeen = max(Timestamp), ActionTypes = make_set(ActionType, 5), Protocols = make_set(Protocol, 3),
    arg_min(Timestamp, ReportId, DeviceName)
    by Attributed, ProcessKey, InitiatingProcessFileName, RemoteIPType, RemoteIP, RemoteUrl, RemotePort
| project Attributed, ProcessKey, InitiatingProcessFileName, RemoteIPType, RemoteIP, RemoteUrl, RemotePort,
    ActionTypes, Protocols, Events, FirstSeen = Timestamp, LastSeen, ReportId, DeviceName
| order by Attributed desc, Events desc
| take 300
```

---

## Query 6: File Activity and Download Origin by Process Set

**Purpose:** Files created, modified, renamed or deleted by the process set, with hashes and download origin (`FileOriginUrl`, referrer, IP). Also surfaces executable/script files written to user-writable locations by *other* processes in the window (`Attributed = false`) so a dropper outside the tree is not missed.

**Tuning Notes:**
- Use `SHA1` for correlation; `SHA256` is usually unpopulated.
- Origin fields are populated only for some downloads (browser/Mark-of-the-Web paths). Empty origin means unknown, not local.
- Capped at 400 rows; a 400-row result is truncated. For suspected mass encryption/impact, switch to the ransomware hunts in `queries/threat-intelligence/`.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Process-set attribution is supplied per case from Query 4; heuristic unattributed branch is noisy by design."
-->

```kql
// Query 6: File events for the process set, plus executable drops in user-writable paths by other processes
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let ProcessSet = dynamic(["<PROCESS_UNIQUE_ID_1>", "<PROCESS_UNIQUE_ID_2>"]);   // from Query 4; [] = nothing attributed
DeviceFileEvents
| where Timestamp >= WindowStart and Timestamp < WindowEnd
| where DeviceId == DeviceIdParam
| where ActionType in ("FileCreated", "FileModified", "FileRenamed", "FileDeleted")
| extend Attributed = isnotempty(InitiatingProcessUniqueId) and InitiatingProcessUniqueId in (ProcessSet)
| extend Extension = tolower(tostring(split(FileName, ".")[-1]))
| extend IsExecutableOrScript = Extension in ("exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "msi", "jar", "iso", "img")
| extend InUserWritablePath = FolderPath has_any ("\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\downloads\\")
| where Attributed or (IsExecutableOrScript and InUserWritablePath)
| project Timestamp, ReportId, DeviceName, Attributed, ActionType, FileName, FolderPath, SHA1, SHA256, FileSize,
    PreviousFileName, PreviousFolderPath, FileOriginUrl, FileOriginReferrerUrl, FileOriginIP,
    InitiatingProcessUniqueId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Attributed desc, Timestamp asc
| take 400
```

---

## Query 7: Persistence and Defense-Evasion Registry Changes

**Purpose:** Registry values set or keys created in autorun, debugger-hijack, logon/boot, service and Defender-configuration locations during the window, with the writing process and an `Attributed` flag.

**Tuning Notes:**
- Observed creation is not proof the persistence still exists: confirm current state with approved host collection or Live Response (separate approval).
- `defender_config` is limited to exclusions and common disable switches. Defender platform updates write other keys under the same path; check the writing process.
- Scheduled-task and service creation are in Query 9 (`DeviceEvents`).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Case-scoped forensic view with Attributed flag; tuned for triage not alerting."
-->

```kql
// Query 7: Persistence / defense-evasion registry writes in the window
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let ProcessSet = dynamic(["<PROCESS_UNIQUE_ID_1>", "<PROCESS_UNIQUE_ID_2>"]);   // from Query 4; [] = nothing attributed
DeviceRegistryEvents
| where Timestamp >= WindowStart and Timestamp < WindowEnd
| where DeviceId == DeviceIdParam
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| extend Attributed = isnotempty(InitiatingProcessUniqueId) and InitiatingProcessUniqueId in (ProcessSet)
| extend PersistenceClass = case(
    RegistryKey has_any ("\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce", "\\CurrentVersion\\RunServices", "\\Policies\\Explorer\\Run"), "autorun",
    RegistryKey has_any ("\\Image File Execution Options\\", "\\SilentProcessExit\\"), "debugger_hijack",
    RegistryKey has_any ("\\Winlogon\\", "\\BootExecute", "\\Active Setup\\Installed Components", "AppInit_DLLs"), "logon_or_boot",
    RegistryKey has "\\Services\\", "service",
    RegistryKey has "Windows Defender" and (RegistryKey has "Exclusions" or RegistryValueName in~ ("DisableAntiSpyware", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableScriptScanning", "TamperProtection")), "defender_config",
    "")
| where Attributed or PersistenceClass != ""
| project Timestamp, ReportId, DeviceName, Attributed, PersistenceClass, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
    PreviousRegistryValueData, InitiatingProcessUniqueId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Attributed desc, Timestamp asc
| take 300
```

---

## Query 8: Logon and Session Context

**Purpose:** Who logged on to the device, how, and from where (logon type, remote IP/device, local-admin status, success/failure) from 24 h before the window through its end. Flags logon sessions that match the seed process's `LogonId` (from Query 4).

**Tuning Notes:**
- `SeedSessionLogonIds`: distinct `LogonId` values from Query 4 `seed`/`descendant` rows, as strings. `LogonId` is unique on a device only between restarts; check boot context before treating a match as the same session.
- Record the success/failure split (`Succeeded`, `Failed`): high volume with zero failures argues against password guessing.
- Account identity here is SID/name; Entra object IDs come from process-event evidence (Query 4 `AccountObjectId`).

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Case-scoped logon summary keyed on a supplied session list; not a detection."
-->

```kql
// Query 8: Logons on the device, grouped, with seed-session flag
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let SeedSessionLogonIds = dynamic(["<LOGON_ID_1>"]);   // LogonId values from Query 4, as strings; [] when unknown
DeviceLogonEvents
| where Timestamp >= WindowStart - 24h and Timestamp < WindowEnd
| where DeviceId == DeviceIdParam
| extend IsSeedSession = tostring(LogonId) in (SeedSessionLogonIds)
| summarize Events = count(), Succeeded = countif(ActionType == "LogonSuccess"), Failed = countif(ActionType == "LogonFailed"),
    SeedSessionRows = countif(IsSeedSession), FailureReasons = make_set(FailureReason, 3), LogonIds = make_set(tostring(LogonId), 5),
    LastSeen = max(Timestamp), arg_min(Timestamp, ReportId, DeviceName)
    by AccountDomain, AccountName, AccountSid, LogonType, RemoteIPType, RemoteIP, RemoteDeviceName, IsLocalAdmin
| project AccountDomain, AccountName, AccountSid, LogonType, RemoteIPType, RemoteIP, RemoteDeviceName, IsLocalAdmin,
    Events, Succeeded, Failed, FailureReasons, SeedSessionRows, LogonIds, FirstSeen = Timestamp, LastSeen, ReportId, DeviceName
| order by SeedSessionRows desc, FirstSeen asc
| take 200
```

---

## Query 9: Defender Outcome and Security-Control Events

**Purpose:** `DeviceEvents` rows that show what Defender detected, blocked or audited (antivirus, ASR, exploit/network protection, SmartScreen, controlled folder access) and defense-evasion or persistence signals (tamper, log clearing, scheduled tasks, services, account changes, PowerShell, remote-thread/named-pipe activity) for the device in the window.

**Tuning Notes:**
- Read `AdditionalFields` verbatim for the detection and remediation details. Do not infer "prevented" from the presence of a detection row, or "clean" from its absence.
- `ActionType` is matched with substrings (`matches regex`) because the full value list is not published in the schema docs; confirm the exact values returned.
- Compare with the alert's evidence status and the MDE action-center/automated-investigation state (API) before stating an outcome.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Broad substring family match over DeviceEvents for case triage; too noisy for continuous detection."
-->

```kql
// Query 9: Detection outcome and security-control events in the window
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let ProcessSet = dynamic(["<PROCESS_UNIQUE_ID_1>", "<PROCESS_UNIQUE_ID_2>"]);   // from Query 4; [] = nothing attributed
DeviceEvents
| where Timestamp >= WindowStart and Timestamp < WindowEnd
| where DeviceId == DeviceIdParam
| extend Family = case(
    ActionType matches regex "Antivirus", "antivirus",
    ActionType matches regex "Asr|ExploitGuard|ControlledFolderAccess|NetworkProtection|SmartScreen", "protection_block_or_audit",
    ActionType matches regex "Tamper|LogCleared", "defense_evasion",
    ActionType matches regex "ScheduledTask|ServiceInstalled", "persistence",
    ActionType matches regex "UserAccount", "account_change",
    ActionType matches regex "PowerShell|CreateRemoteThread|NamedPipe", "execution_or_injection",
    "")
| where Family != ""
| extend Attributed = isnotempty(InitiatingProcessUniqueId) and InitiatingProcessUniqueId in (ProcessSet)
| project Timestamp, ReportId, DeviceName, Attributed, Family, ActionType, FileName, FolderPath, SHA1, ProcessCommandLine,
    RemoteIP, RemoteUrl, AccountName, AdditionalFields,
    InitiatingProcessUniqueId, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Attributed desc, Timestamp asc
| take 300
```

---

## Query 10: Related Activity (Same Device or Shared Evidence)

**Purpose:** Other alerts, from any Defender product, that touch the same device or share a file hash, remote IP, host/domain or account with the seed alert, with the *reason* each is related (`Pivots`, plus a row count per pivot). This is the "what else happened around this?" view: it includes identity, email and cloud-app alerts that share the account.

**Tuning Notes:**
- `SeedAlertIds` decides what counts as "other". Pass **every alert in the incident** to find alerts the platform did *not* correlate into it (adjacent-alert sweep); pass only the focal alert to also see its incident siblings.
- Every satisfied pivot is reported (an alert can be both `same_device` and `same_file_hash`). Related is not the same as in-scope: `same_device` over 14 days is recurrence context; `same_file_hash`/`same_account` across devices suggests spread. State the pivot when reporting.
- `RemoteHosts` takes lowercase host/FQDN values only; evidence URLs are reduced to their host before comparing. This is exact host matching, not subdomain matching.
- Exclude RFC1918 addresses and the device's own public IP from `RemoteIps` first; shared infrastructure (proxies, CGNAT, VPN) creates false links.
- Map alerts to incidents with the SecurityAlert → SecurityIncident pattern or the incident API; `AlertInfo` carries no incident ID. Alert metadata is joined from the last 30 days independently of the activity range; blank `Title` means no `AlertInfo` record was retained.
- Advanced Hunting keeps 30 days. When `HistoryTruncated` is `true` (the 14-day lookback starts before that horizon) the sweep is `partial`; for an older alert use the Data Lake variant.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Pivot lists are supplied per case; relatedness analysis, not a detection."
-->

```kql
// Query 10: Alerts that share the device or an evidence entity with the seed alert(s)
let SeedAlertIds = dynamic(["<ALERT_ID_1>"]);
let DeviceIds = dynamic(["<DEVICE_ID>"]);
let Sha1s = dynamic(["<SEED_SHA1>"]);                    // [] when none
let RemoteIps = dynamic(["<PUBLIC_REMOTE_IP>"]);         // [] when none
let RemoteHosts = dynamic(["<SEED_DOMAIN>"]);            // lowercase host/FQDN only; [] when none
let AccountObjectIds = dynamic(["<ENTRA_OBJECT_ID>"]);   // [] when none
let AlertStart = datetime(<ALERT_FIRST_ACTIVITY_UTC>);
let AlertEnd = datetime(<ALERT_LAST_ACTIVITY_UTC>);
let RelatedFrom = AlertStart - 14d;
let RelatedTo = AlertEnd + 2d;
let Related = AlertEvidence
    | where Timestamp >= RelatedFrom and Timestamp < RelatedTo
    | where AlertId !in (SeedAlertIds)
    | extend RemoteHost = tolower(iff(RemoteUrl contains "://", tostring(parse_url(RemoteUrl).Host), RemoteUrl))
    | extend IsSameDevice = DeviceId in (DeviceIds),
        IsSameHash = isnotempty(SHA1) and SHA1 in~ (Sha1s),
        IsSameIp = isnotempty(RemoteIP) and RemoteIP in (RemoteIps),
        IsSameHost = isnotempty(RemoteHost) and RemoteHost in (RemoteHosts),
        IsSameAccount = isnotempty(AccountObjectId) and AccountObjectId in (AccountObjectIds)
    | where IsSameDevice or IsSameHash or IsSameIp or IsSameHost or IsSameAccount
    | summarize SameDeviceRows = countif(IsSameDevice), SameHashRows = countif(IsSameHash), SameIpRows = countif(IsSameIp),
        SameHostRows = countif(IsSameHost), SameAccountRows = countif(IsSameAccount),
        Devices = make_set(DeviceName, 5), FirstEvidence = min(Timestamp), LastEvidence = max(Timestamp) by AlertId;
Related
| join kind=leftouter (
    AlertInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, *) by AlertId
  ) on AlertId
| extend Pivots = set_difference(pack_array(
        iff(SameDeviceRows > 0, "same_device", ""), iff(SameHashRows > 0, "same_file_hash", ""),
        iff(SameIpRows > 0, "same_remote_ip", ""), iff(SameHostRows > 0, "same_host_or_domain", ""),
        iff(SameAccountRows > 0, "same_account", "")), dynamic([""]))
| extend HistoryTruncated = RelatedFrom < ago(30d)
| project AlertId, Title, Severity, Category, ServiceSource, DetectionSource, AttackTechniques, Pivots,
    SameDeviceRows, SameHashRows, SameIpRows, SameHostRows, SameAccountRows, Devices, FirstEvidence, LastEvidence, HistoryTruncated
| order by FirstEvidence asc
| take 100
```

---

## Query 11: Fleet Prevalence of the Seed Indicators

**Purpose:** Whether the same file hash, destination or distinctive command-line fragment appears on other devices from 14 days before the window end to 1 day after it (to catch spread right after the alert): one device (isolated) versus many (campaign or common software). Three independent parts, one per indicator type.

**Tuning Notes:**
- **Generate only the applicable parts.** Run 11a only when `Sha1s` is non-empty, 11b only when `RemoteIps` or `RemoteHosts` is non-empty, and 11c only when `CmdFragments` is non-empty. If no part applies, record Q11 as `not_run`. Never run a part with all of its lists empty: each part scans a fleet-wide table, and nothing here relies on the engine skipping that scan.
- Bounded to the authorized tenant scope. Counts are for the checked sources only; an indicator absent from the results had no hits in this interval/source. The extra forward day is deliberate context, not part of the 14-day lookback.
- `Match` is the indicator that actually matched (hash, `ip:`/`host:` destination, or command-line fragment). `RemoteHosts` takes lowercase host/FQDN values; evidence URLs are reduced to their host (exact host match, not subdomain match). 11b first narrows rows with a cheap term match, then verifies the exact host, so URL parsing runs only on candidates.
- Command-line fragments must be distinctive; generic terms such as `powershell` return noise. Fragments match as whole terms (`has`), not arbitrary substrings: use full tokens such as `vssadmin` or `-encodedcommand`. Hash matches are on SHA1.
- `Devices` and `Events` are observations, not a verdict. High prevalence of a signed, widely deployed binary is usually benign; do not spawn automatic per-device investigations from this output.

**Part 11a: File hashes** (run only when `Sha1s` is non-empty)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet-wide hash prevalence seeded per case; cost-bounded hunt, not a detection."
-->

```kql
// Query 11a: Fleet prevalence of seed file hashes (run only when Sha1s is non-empty)
let DeviceIdParam = "<DEVICE_ID>";
let WindowEnd = datetime(<WINDOW_END_UTC>);
let From = WindowEnd - 14d;
let To = WindowEnd + 1d;                    // 1 day of forward context to catch spread right after the alert
let Sha1s = dynamic(["<SEED_SHA1>"]);       // must be non-empty for this part
union
    (DeviceProcessEvents
    | where Timestamp >= From and Timestamp < To
    | where SHA1 in~ (Sha1s)
    | summarize Events = count(), Devices = dcount(DeviceId), SeedDeviceRows = countif(DeviceId == DeviceIdParam),
        FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleDevices = make_set(DeviceName, 10)
        by Indicator = "sha1_process_start", Match = SHA1),
    (DeviceFileEvents
    | where Timestamp >= From and Timestamp < To
    | where SHA1 in~ (Sha1s)
    | summarize Events = count(), Devices = dcount(DeviceId), SeedDeviceRows = countif(DeviceId == DeviceIdParam),
        FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleDevices = make_set(DeviceName, 10)
        by Indicator = "sha1_file_event", Match = SHA1)
| order by Devices desc, Events desc
| take 100
```

**Part 11b: Destinations** (run only when `RemoteIps` or `RemoteHosts` is non-empty)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet-wide destination prevalence seeded per case; cost-bounded hunt, not a detection."
-->

```kql
// Query 11b: Fleet prevalence of seed destinations (run only when RemoteIps or RemoteHosts is non-empty)
let DeviceIdParam = "<DEVICE_ID>";
let WindowEnd = datetime(<WINDOW_END_UTC>);
let From = WindowEnd - 14d;
let To = WindowEnd + 1d;                         // 1 day of forward context to catch spread right after the alert
let RemoteIps = dynamic(["<PUBLIC_REMOTE_IP>"]); // [] when none
let RemoteHosts = dynamic(["<SEED_DOMAIN>"]);    // lowercase host/FQDN only; [] when none
DeviceNetworkEvents
| where Timestamp >= From and Timestamp < To
| where RemoteIP in (RemoteIps) or RemoteUrl has_any (RemoteHosts)
| extend RemoteHost = tolower(iff(RemoteUrl contains "://", tostring(parse_url(RemoteUrl).Host), RemoteUrl))
| extend Matches = set_difference(pack_array(
        iff(RemoteIP in (RemoteIps), strcat("ip:", RemoteIP), ""),
        iff(RemoteHost in (RemoteHosts), strcat("host:", RemoteHost), "")), dynamic([""]))
| mv-expand Match = Matches to typeof(string)
| summarize Events = count(), Devices = dcount(DeviceId), SeedDeviceRows = countif(DeviceId == DeviceIdParam),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleDevices = make_set(DeviceName, 10)
    by Match
| order by Devices desc, Events desc
| take 100
```

**Part 11c: Command-line fragments** (run only when `CmdFragments` is non-empty)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet-wide command-line fragment prevalence seeded per case; cost-bounded hunt, not a detection."
-->

```kql
// Query 11c: Fleet prevalence of distinctive command-line fragments (run only when CmdFragments is non-empty)
let DeviceIdParam = "<DEVICE_ID>";
let WindowEnd = datetime(<WINDOW_END_UTC>);
let From = WindowEnd - 14d;
let To = WindowEnd + 1d;                                                // 1 day of forward context to catch spread right after the alert
let CmdFragments = dynamic(["<DISTINCTIVE_COMMAND_LINE_FRAGMENT>"]);    // must be non-empty for this part
DeviceProcessEvents
| where Timestamp >= From and Timestamp < To
| where ProcessCommandLine has_any (CmdFragments)
| mv-apply Fragment = CmdFragments to typeof(string) on (where ProcessCommandLine has Fragment)
| summarize Events = count(), Devices = dcount(DeviceId), SeedDeviceRows = countif(DeviceId == DeviceIdParam),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleDevices = make_set(DeviceName, 10),
    SampleCommandLine = take_any(ProcessCommandLine)
    by Match = Fragment
| order by Devices desc, Events desc
| take 100
```

---

## Query 12: Payload Provenance (Download Origin, URL Clicks, Email)

**Purpose:** How the seed file arrived. Starts from the file-creation event's download origin and referrer, then finds URL clicks (up to 24 h before the file event) and the delivered email behind each click where they point at the same host.

**Tuning Notes:**
- A host match is correlation, not proof that the click or message delivered the file. Report `file_origin` and `click_host_match` rows separately and state the match basis.
- Origins are the earliest 50 matching file-creation events; `OriginCandidates` shows how many matched in total. Hosts are compared in lowercase.
- Clicks are searched from 48 h before the window start so the oldest origin keeps its full 24 h lookback, and up to 5 minutes *after* each file event (through 5 minutes past the window end) to tolerate clock skew. Email is linked by `NetworkMessageId` within 14 days before the window; earlier delivery is not linked.
- Origin fields are populated only for some download paths. Empty means unknown; consider the downloader process and browser history via approved collection.
- Origin and click URLs are untrusted data: defang them in reports and never follow them.
- Capped at 150 rows; email columns are empty when the click has no `NetworkMessageId`.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Three-table provenance correlation keyed on a case file; host-level join, not suitable for alerting."
-->

```kql
// Query 12: Payload provenance — file origin, then URL clicks and email pointing at the same host
let DeviceIdParam = "<DEVICE_ID>";
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let SeedSha1s = dynamic(["<SEED_SHA1>"]);            // [] when none
let SeedFileNames = dynamic(["<SEED_FILE_NAME>"]);   // [] when none
let OriginsAll = DeviceFileEvents
    | where Timestamp >= WindowStart - 24h and Timestamp < WindowEnd
    | where DeviceId == DeviceIdParam
    | where ActionType == "FileCreated"
    | where SHA1 in~ (SeedSha1s) or FileName in~ (SeedFileNames)
    | where isnotempty(FileOriginUrl) or isnotempty(FileOriginReferrerUrl) or isnotempty(FileOriginIP);
let OriginMatchCount = toscalar(OriginsAll | count);
let Origins = materialize(
    OriginsAll
    | order by Timestamp asc, ReportId asc
    | take 50
    | project FileTime = Timestamp, ReportId, DeviceName, FileName, FolderPath, SHA1,
        FileOriginUrl, FileOriginReferrerUrl, FileOriginIP,
        OriginHost = tolower(tostring(parse_url(FileOriginUrl).Host)), ReferrerHost = tolower(tostring(parse_url(FileOriginReferrerUrl).Host)),
        Downloader = InitiatingProcessFileName, DownloaderCommandLine = InitiatingProcessCommandLine);
let Clicks = UrlClickEvents
    | where Timestamp >= WindowStart - 48h and Timestamp < WindowEnd + 5m
    | project ClickTime = Timestamp, ClickUrl = Url, ClickHost = tolower(tostring(parse_url(Url).Host)), ClickUpn = AccountUpn,
        ClickAction = ActionType, ClickedThrough = IsClickedThrough, ClickWorkload = Workload, NetworkMessageId;
let ClickMatches = Origins
    | extend Hosts = set_difference(pack_array(OriginHost, ReferrerHost), dynamic([""]))
    | mv-expand Host = Hosts to typeof(string)
    | join kind=inner (Clicks) on $left.Host == $right.ClickHost
    | where ClickTime between ((FileTime - 24h) .. (FileTime + 5m))
    | join kind=leftouter (
        EmailEvents
        | where Timestamp >= WindowStart - 14d and Timestamp < WindowEnd + 5m
        | summarize arg_max(Timestamp, *) by NetworkMessageId
        | project NetworkMessageId, EmailTime = Timestamp, SenderFromAddress, Subject, RecipientEmailAddress,
            DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods
      ) on NetworkMessageId
    | project Relation = "click_host_match", FileTime, ReportId, DeviceName, FileName, Host,
        ClickTime, ClickUrl, ClickUpn, ClickAction, ClickedThrough, ClickWorkload,
        NetworkMessageId, EmailTime, SenderFromAddress, Subject, RecipientEmailAddress, DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods;
union
    (Origins | extend OriginCandidates = OriginMatchCount
        | project Relation = "file_origin", OriginCandidates, FileTime, ReportId, DeviceName, FileName, FolderPath, SHA1,
            FileOriginUrl, FileOriginReferrerUrl, FileOriginIP, Downloader, DownloaderCommandLine),
    ClickMatches
| order by FileTime asc, Relation asc
| take 150
```

---

## Query 13: Sign-In Context for the Accounts Involved

**Purpose:** Whether the accounts seen on the device (process/logon evidence) signed in from unusual places or failed around the alert: sign-in counts, outcomes, apps, devices, managed/compliant state and risk by IP and country.

**Tuning Notes:**
- Compact triage only. For baselines, MFA, and authentication-chain analysis hand off to the `user-investigation` and `authentication-tracing` skills.
- Interpret an unfamiliar IP against the user's baseline and device compliance before calling it suspicious; managed, compliant devices with no risk detection are a different finding from unmanaged ones.
- `AccountObjectId` comes from Query 4 (process account) or `AlertEvidence`; local-only accounts have none.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Per-case account summary; identity baselining belongs to the user investigation workflow."
-->

```kql
// Query 13: Sign-ins for the accounts involved, around the evidence window
let WindowStart = datetime(<WINDOW_START_UTC>);
let WindowEnd = datetime(<WINDOW_END_UTC>);
let AccountObjectIds = dynamic(["<ENTRA_OBJECT_ID>"]);   // [] when none
let AccountUpns = dynamic(["<UPN>"]);                    // [] when none
EntraIdSignInEvents
| where Timestamp >= WindowStart - 12h and Timestamp < WindowEnd + 2h
| where AccountObjectId in (AccountObjectIds) or AccountUpn in~ (AccountUpns)
| summarize SignIns = count(), Succeeded = countif(ErrorCode == 0), Failed = countif(ErrorCode != 0),
    Managed = countif(IsManaged == 1), Compliant = countif(IsCompliant == 1), MaxRiskDuringSignIn = max(RiskLevelDuringSignIn),
    Apps = make_set(Application, 5), Devices = make_set(DeviceName, 5),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleCorrelationId = take_any(CorrelationId)
    by AccountUpn, IPAddress, Country, City
| order by FirstSeen asc
| take 100
```
