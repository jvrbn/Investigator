# Local agent evidence importer (P1 MVP)

This is a **read-only, offline importer**, not a log collector, endpoint sensor, or
general-purpose parser. Use only evidence you are authorized to access. It never
executes commands, follows URLs, starts MCP servers, or opens files named inside
evidence. There are no live tenant-query results associated with this MVP.

## Tenant binding and safe output

First select a tenant/workspace and create the existing immutable investigation
context through [`scripts/tenant_context.py`](../scripts/tenant_context.py).
The importer requires its canonical, existing
`reports/tenants/<profile>/<case>/context.json`; it does not create contexts,
guess tenants, use the current CLI account, or select another workspace.

The repository root defaults to the directory containing this script's `scripts`
folder, **not the current working directory**. Use `--repo-root isolated-repo`
when the contexts belong to a different authorized repository. Relative
`--context` paths are interpreted under that root; the source path is relative
to the current working directory. Absolute context paths must still be inside
the selected repository. This distinction matters for isolated CLI smoke tests.

From the repository root:

```console
python scripts/import_local_agent_evidence.py evidence.json --context reports/tenants/example/case-1/context.json --authorized
```

`--authorized` is your explicit assertion of permission, **not an authorization
check or proof of provenance**. The core validates context structure and canonical
location. This offline import does not authenticate any tenant or MCP connection.
Normalized exports must contain tenant and workspace IDs exactly matching the
context. Native event subsets have no tenant fields; their binding is explicitly
`operator_asserted`, not independently verified source tenancy.

Output defaults to `local-agent-timeline.json` inside that case directory.
`--output-name another-timeline.json` permits a different **leaf filename only**.
No arbitrary output directory, overwrite, or `context.json` replacement is allowed.
Directory-descriptor traversal rejects symlink components, including source,
context, and output paths; writes use exclusive creation with mode `0600`.
Sources must be regular UTF-8 files, at most 32 MiB and 100,000 events.
These protections use POSIX directory descriptors/`O_NOFOLLOW`; this MVP targets
Linux/macOS and fails rather than weakening them on unsupported platforms.

Keep original exports in access-controlled storage. The report contains their
SHA-256 and byte count, not a copied raw export or its potentially sensitive path.
A hash identifies imported bytes, not their authenticity or original collection
time. Local reports are investigation artifacts, never committed documentation.

Context errors report the core's sanitized validation reason and remind you to
check `--repo-root`/`--context`; filesystem errors distinguish missing source,
existing output, permissions, and refused symlinks without echoing paths or
evidence. Failures exit 2 and never silently switch roots or tenants.

### Runtime requirements

This importer and its tenant-context integration require **Python 3.8+** and
a **POSIX runtime with directory-descriptor operations and `O_NOFOLLOW`** (Linux
or macOS). The platform requirement is narrower than the repository's general
Windows/PowerShell guidance. Native Windows Python, including launches from PowerShell,
is **not supported** for this importer. Use an appropriately authorized Linux
environment (for example, Python inside WSL with the case on its Linux
filesystem); do not assume Windows-mounted filesystem semantics are equivalent.

The importer checks required secure filesystem capabilities before reading
context/evidence and explicitly rejects unsupported platforms with exit code 2.
It never falls back to path-only writes or disables symlink protection.
`--help` remains available without importing evidence. No broad Windows port is
included in this MVP. The focused tests were run on the available Linux Python
interpreter; a separate Python 3.8/macOS compatibility run has not been performed.

## Privacy

**Metadata-only is the default.** Timestamp, event/session/call/agent identifiers,
tool/server names, source record numbers, pairing, and outcomes are retained.
Prompt/response text, tool arguments/results/errors, file paths, commands, URLs,
and other details are withheld as `{"withheld": true}`.

Add `--capture-content` only when explicitly authorized to retain sensitive
content. It prints a warning and includes recursively redacted `details`.
Redaction always remains enabled: common credential keys, bearer/basic auth,
JWTs, some provider tokens, private keys, and common inline secret assignments
are replaced, including inside nested tool arguments/results/errors.

**This is best-effort redaction, NOT guaranteed DLP.** Unknown formats, encoded
values, unlabelled secrets, PII, and unusual credentials may survive. Metadata
itself can identify people, systems, and tools. Inspect and restrict reports
before sharing. Original input files are not changed or sanitized.

## Versioned export contract: `local-agent-evidence/v1`

Choose `--format json` (default) or `--format jsonl` explicitly. There is no
extension-based guessing.

JSON consists of one envelope:

```json
{
  "schema": "local-agent-evidence/v1",
  "tenant_id": "<tenant GUID from selected context>",
  "workspace_id": "<workspace GUID from selected context>",
  "session_id": "session-1",
  "configured_mcp": ["example-server"],
  "events": [
    {
      "type": "prompt",
      "timestamp": "2026-11-13T10:00:00Z",
      "event_id": "event-1",
      "details": {"content": "Inspect the authorized workspace."}
    },
    {
      "type": "tool.start",
      "timestamp": "2026-11-13T10:00:01Z",
      "tool_call_id": "call-1",
      "tool_name": "read_file",
      "mcp_server": "example-server",
      "details": {"arguments": {"path": "/workspace/example.txt"}}
    },
    {
      "type": "tool.complete",
      "timestamp": "2026-11-13T10:00:02Z",
      "tool_call_id": "call-1",
      "outcome": "succeeded",
      "details": {"result": {"content": "Example result"}, "error": null}
    }
  ]
}
```

The placeholders above must be replaced with context IDs; they are not valid
tenant-bound input as written.

JSONL uses the same envelope **without `events` on line 1**, then one event
object per subsequent line. Blank lines are invalid; a final newline is allowed.
`configured_mcp` is optional and is only a supplied configuration snapshot.
An empty/omitted snapshot does not establish that no MCP servers are configured.
All other envelope fields are required; unknown envelope/event fields are rejected
instead of silently dropped. Put provider-specific fields inside `details`.

### Event schema

Each event requires `type`, `timestamp`, and an object-valued `details`.
Timestamps must be RFC3339 datetimes with seconds, an explicit `Z`/numeric offset,
and at most six fractional digits; invalid dates and naive timestamps are rejected.
Offsets beyond 14 hours are rejected. The timeline normalizes to UTC microseconds.

Optional common fields are `session_id` (must match the envelope), `event_id`,
`parent_event_id`, `agent_id`, `tool_call_id`, `tool_name`, `mcp_server`, `outcome`.
Identifiers are 1–256 characters from `A-Z a-z 0-9 _ . : / @ + -`.
No identifiers, timestamps, outcomes, or actions are synthesized from prose.

| `type` | Required additional fields | `details` conventions |
|---|---|---|
| `prompt` | None | `content`: original prompt if available |
| `response` | None | `content`: original response if available |
| `tool.start` | `tool_call_id`, `tool_name` | `arguments`: original JSON arguments |
| `tool.complete` | `tool_call_id`, `outcome` | `result`, `error`: original results/errors |
| `mcp.configured` | `mcp_server` | Configuration snapshot, not runtime usage |
| `process`, `file`, `network` | `outcome` | Nonempty string `action` and `observer`, plus source facts |

`outcome`, when present, must be one of `attempted`, `succeeded`, `failed`,
`blocked`, `audit`, `unknown`. A completion need not assert success: use `unknown`
where the source cannot establish it. Missing optional payloads remain missing;
the importer cannot recover text that was not exported.

For observed OS/network activity, retain original source IDs, PID/process identity,
paths, remote address, event action, and sensor provenance inside `details`.
For example, `{"action":"connect","observer":"authorized-endpoint-export","remote_ip":"192.0.2.10"}`.
Never convert a requested shell command into an observed process or an attempted
file write into a successful file action. `audit` does not mean blocked.

Duplicate JSON keys, nonfinite numbers, duplicate event IDs/tool phases, conflicting
paired metadata, completion-before-start, unknown event types/schema versions,
invalid tenant bindings, and malformed records reject the **entire import**.
There is no partial-success or silent-skip mode.

## Native adapter: `copilot-sdk-events/v1`

The adapter reads **JSONL native Copilot SDK/CLI session event records**, limited
to the following explicitly supported subset:

| Native event | Fields used |
|---|---|
| `user.message` | `data.content` |
| `assistant.message` | `data.content`, `data.messageId` |
| `tool.execution_start` | `data.toolCallId`, `data.toolName`, `data.arguments`, optional MCP names |
| `tool.execution_complete` | `data.toolCallId`, boolean `data.success`, optional `data.result`, `data.error` |

All records require native `id`, `parentId` (identifier or null), `timestamp`,
`type`, and object-valued `data`. Native `agentId` is retained when supplied.
Completion result objects require string `content`, error objects string `message`.
MCP identity prefers `mcpConfigServerName` over `mcpServerName`, preserving the
configured key rather than guessing from a tool-name prefix. Full native records
are retained under `details` **only with content capture**, with redaction.

```console
python scripts/import_local_agent_evidence.py selected-sdk-events.jsonl --format copilot-sdk-events/v1 --session-id exported-session-1 --context reports/tenants/example/case-1/context.json --authorized
```

`--session-id` is required because these individual event envelopes do not carry
the owning session ID. Do not mix sessions in one file.

**Compatibility evidence:** field names and meaning were checked against GitHub's
[generated SDK SessionEvent definitions](https://github.com/github/copilot-sdk/blob/main/nodejs/src/generated/session-events.ts)
on 2026-11-13 (`UserMessageData`, `AssistantMessageData`,
`ToolExecutionStartData`, `ToolExecutionCompleteData`). `v1` versions **this
importer's adapter**, not all upstream SDK releases. Tests exercise synthetic
native-shaped records, pairing, MCP names, arguments, results/errors, and malformed
records; they are not a claim that a real tenant/session export was acquired.

Export just these supported native records with an authorized exporter, retaining
their original fields, and document selection/omission separately. **A full
native session journal containing other event types is rejected**, not silently
filtered. The adapter does not validate the SDK's entire evolving schema and
does not support arbitrary Copilot session storage, VS Code Chat Debug JSON,
Claude/Codex logs, SQLite databases, or undocumented log files. For richer
configuration/process/file/network evidence, use the versioned export contract.

## Reading the result

The `local-agent-timeline/v1` report includes context, source hash/format/binding,
privacy mode, timeline, MCP comparison, and explicit coverage gaps:

- Events sort by normalized UTC timestamp; ties keep source record order.
  `source_record` is a one-based event index (JSONL excludes the header).
- Tool phases pair **only** by matching recorded `(session, agent_id, tool_call_id)`;
  one import contains one session. `paired_source_record` identifies the other phase.
  No nearest-time guessing or auto-generated causal IDs.
- `correlation: recorded_ids` means an ID was supplied, **not proven causality**.
  `parent_event_id` can be a journal ordering link rather than a tool parent.
  Events without recorded correlation IDs are `temporal_only`.
- Missing tool phases are retained and explicitly reported as gaps.
- `mcp.configured` and `configured_mcp` feed configuration; only `tool.start`
  with an explicit MCP server feeds `observed_invocations`. These count invocation
  records, not successful remote executions. Missing configuration may explain
  `observed_not_in_supplied_configuration`; it is not proof of unauthorized access.
- Source-reported outcomes do not establish OS success or policy enforcement.
  Pair with authorized endpoint/network telemetry when needed.
- No filtering to context lookback occurs: original exported events remain intact;
  scope/collection windows and clocks must be checked by the analyst.

Use the [local-agent-investigation skill](../.github/skills/local-agent-investigation/SKILL.md)
to combine this offline view with Defender inventory and optional endpoint evidence.
Do not treat cloud-agent observability as guaranteed local prompt/tool coverage.

## Validation

```console
python -m unittest discover -s tests -p test_local_agent_evidence.py -v
```

No third-party dependencies, background services, live queries, or evidence
commands are needed. Tests keep synthetic case artifacts inside the repository
and clean them afterward.
