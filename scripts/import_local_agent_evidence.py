#!/usr/bin/env python3
"""Import authorized, explicitly supported local-agent evidence; never execute it."""

import argparse
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

try:
    from .tenant_context import ContextError, load_context, open_report_directory
except ImportError:
    from tenant_context import ContextError, load_context, open_report_directory


EXPORT_SCHEMA = "local-agent-evidence/v1"
OUTPUT_SCHEMA = "local-agent-timeline/v1"
NATIVE_FORMAT = "copilot-sdk-events/v1"
MAX_BYTES = 32 * 1024 * 1024
MAX_EVENTS = 100000
TYPES = {
    "prompt", "response", "tool.start", "tool.complete", "mcp.configured",
    "process", "file", "network",
}
NATIVE_TYPES = {
    "user.message": "prompt",
    "assistant.message": "response",
    "tool.execution_start": "tool.start",
    "tool.execution_complete": "tool.complete",
}
OUTCOMES = {"attempted", "succeeded", "failed", "blocked", "audit", "unknown"}
ID = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}\Z")
TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:Z|[+-](?:0\d|1[0-4]):[0-5]\d)\Z"
)
SENSITIVE_KEY = re.compile(
    r"password|passwd|secret|token|authorization|cookie|api[-_]?key|"
    r"private[-_]?key|client[-_]?credential|connection[-_]?string", re.I
)
TEXT_PATTERNS = [
    re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9_./+=-]+", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\b(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"""(?i)(?:password|passwd|secret|token|api[-_]?key|authorization|cookie)"""
        r"""["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
    ),
    re.compile(
        r"""(?i)(?:password|passwd|secret|token|api[-_]?key|authorization|cookie)"""
        r"""["']?\s*[:=]\s*["']?[^"'\s&,;}\]]+"""
    ),
    re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"),
]


class EvidenceError(ValueError):
    """The evidence or requested import is not safe/supported."""


def require_secure_platform():
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if (
        os.name != "posix"
        or not all(hasattr(os, name) for name in required_flags)
        or not {os.open, os.mkdir, os.unlink}.issubset(os.supports_dir_fd)
    ):
        raise EvidenceError(
            "unsupported platform: secure import requires POSIX directory descriptors "
            "and O_NOFOLLOW; Windows is not supported"
        )


def redact(value):
    """Best-effort redaction, including arbitrary nested tool payloads."""
    if isinstance(value, dict):
        return {
            redact(key): "[REDACTED]" if SENSITIVE_KEY.search(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        for pattern in TEXT_PATTERNS:
            value = pattern.sub("[REDACTED]", value)
    return value


def identifier(value, label):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise EvidenceError(f"{label} must be a nonempty identifier (maximum 256 characters)")
    return value


def timestamp(value):
    if not isinstance(value, str) or not TIME.fullmatch(value):
        raise EvidenceError("timestamp must be RFC3339 with explicit timezone and <=6 fractional digits")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if abs(parsed.utcoffset().total_seconds()) > 14 * 3600:
            raise ValueError
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        raise EvidenceError("invalid timestamp") from None


def _object(value, label):
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _keys(value, allowed, label):
    if set(value) - allowed:
        raise EvidenceError(f"{label} contains unsupported fields")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON object key")
        result[key] = value
    return result


def _bad_constant(_value):
    raise EvidenceError("nonfinite JSON numbers are unsupported")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise EvidenceError("nonfinite JSON numbers are unsupported")
    return number


def _json(text):
    try:
        return json.loads(text, object_pairs_hook=_unique_pairs,
                          parse_constant=_bad_constant, parse_float=_finite_float)
    except (json.JSONDecodeError, RecursionError):
        raise EvidenceError("malformed JSON evidence") from None


def read_source(path):
    """Read one regular file without following symlinks in any path component."""
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        source_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source_fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise EvidenceError("evidence must be a regular file <=32 MiB")
            raw = source.read(MAX_BYTES + 1)
            after = os.fstat(source.fileno())
            if len(raw) > MAX_BYTES or (info.st_size, info.st_mtime_ns) != (
                after.st_size, after.st_mtime_ns
            ):
                raise EvidenceError("evidence too large or changed during import")
    finally:
        os.close(fd)
    return raw


def _decode(raw, format_name):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EvidenceError("evidence must be UTF-8") from None
    if format_name == "json":
        return _object(_json(text), "export")
    lines = text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise EvidenceError("JSONL requires one object per nonblank line")
    return [_object(_json(line), "JSONL record") for line in lines]


def _native_event(record, session_id):
    _object(record, "native event")
    if not isinstance(record.get("type"), str):
        raise EvidenceError("native event requires a supported string type")
    kind = NATIVE_TYPES.get(record.get("type"))
    if kind is None:
        raise EvidenceError("unsupported native event type; use the documented four-event subset")
    identifier(record.get("id"), "native id")
    if "parentId" not in record:
        raise EvidenceError("native event requires parentId (identifier or null)")
    if record["parentId"] is not None:
        identifier(record["parentId"], "native parentId")
    data = _object(record.get("data"), "native data")
    event = {
        "type": kind, "timestamp": record.get("timestamp"), "session_id": session_id,
        "event_id": record["id"], "details": record,
    }
    if record["parentId"] is not None:
        event["parent_event_id"] = record["parentId"]
    if "agentId" in record:
        event["agent_id"] = identifier(record["agentId"], "native agentId")
    if kind in {"prompt", "response"}:
        if not isinstance(data.get("content"), str):
            raise EvidenceError("native message requires string data.content")
        if kind == "response":
            identifier(data.get("messageId"), "native messageId")
    else:
        event["tool_call_id"] = identifier(data.get("toolCallId"), "native toolCallId")
        if kind == "tool.start":
            event["tool_name"] = identifier(data.get("toolName"), "native toolName")
            server = data.get("mcpConfigServerName", data.get("mcpServerName"))
            if server is not None:
                event["mcp_server"] = identifier(server, "native MCP server")
        else:
            if type(data.get("success")) is not bool:
                raise EvidenceError("native completion requires boolean data.success")
            event["outcome"] = "succeeded" if data["success"] else "failed"
            for name in ("result", "error"):
                if name in data:
                    obj = _object(data[name], f"native {name}")
                    field = "content" if name == "result" else "message"
                    if not isinstance(obj.get(field), str):
                        raise EvidenceError(f"native {name} requires string {field}")
    return event


def _normalize(record, session_id, index, capture_content):
    _object(record, "event")
    _keys(record, {
        "type", "timestamp", "session_id", "event_id", "parent_event_id",
        "agent_id", "tool_call_id", "tool_name", "mcp_server", "outcome", "details",
    }, "event")
    kind = record.get("type")
    if not isinstance(kind, str) or kind not in TYPES:
        raise EvidenceError("unsupported event type")
    event = {
        "type": kind, "timestamp": timestamp(record.get("timestamp")),
        "session_id": session_id, "source_record": index,
    }
    if "session_id" in record and record["session_id"] != session_id:
        raise EvidenceError("event session_id differs from export session")
    for name in (
        "event_id", "parent_event_id", "agent_id", "tool_call_id", "tool_name", "mcp_server"
    ):
        if name in record:
            event[name] = identifier(record[name], name)
    if kind in {"tool.start", "tool.complete"}:
        identifier(record.get("tool_call_id"), "tool_call_id")
    if kind == "tool.start":
        identifier(record.get("tool_name"), "tool_name")
    if kind == "mcp.configured":
        identifier(record.get("mcp_server"), "mcp_server")
    if kind in {"tool.complete", "process", "file", "network"}:
        if not isinstance(record.get("outcome"), str) or record["outcome"] not in OUTCOMES:
            raise EvidenceError("completion/action requires an explicit supported outcome")
    if "outcome" in record:
        if not isinstance(record["outcome"], str) or record["outcome"] not in OUTCOMES:
            raise EvidenceError("unsupported outcome")
        event["outcome"] = record["outcome"]
    details = _object(record.get("details"), "event details")
    if kind in {"process", "file", "network"}:
        if not isinstance(details.get("action"), str) or not details["action"].strip():
            raise EvidenceError("observed action requires details.action")
        if not isinstance(details.get("observer"), str) or not details["observer"].strip():
            raise EvidenceError("observed action requires details.observer")
    event["details"] = redact(details) if capture_content else {"withheld": True}
    event["correlation"] = "recorded_ids" if any(
        key in event for key in ("event_id", "tool_call_id", "parent_event_id")
    ) else "temporal_only"
    return event


def build_report(raw, *, context, format_name="json", capture_content=False, session_id=None):
    """Validate all records before producing a tenant-bound, sorted report."""
    if len(raw) > MAX_BYTES:
        raise EvidenceError("evidence exceeds 32 MiB")
    if format_name not in {"json", "jsonl", NATIVE_FORMAT}:
        raise EvidenceError("unsupported input format")
    parsed = _decode(raw, format_name)
    native = format_name == NATIVE_FORMAT
    if native:
        session_id = identifier(session_id, "--session-id")
        records = [_native_event(record, session_id) for record in parsed]
        configured = []
    else:
        if format_name == "jsonl":
            header, *records = parsed
            _keys(header, {
                "schema", "tenant_id", "workspace_id", "session_id", "configured_mcp"
            }, "JSONL header")
        else:
            header = parsed
            _keys(header, {
                "schema", "tenant_id", "workspace_id", "session_id", "configured_mcp", "events"
            }, "export")
            records = header.get("events")
        if header.get("schema") != EXPORT_SCHEMA:
            raise EvidenceError("unsupported evidence schema/version")
        if header.get("tenant_id") != context.tenant_id or header.get("workspace_id") != context.workspace_id:
            raise EvidenceError("evidence tenant/workspace differs from immutable context")
        session_id = identifier(header.get("session_id"), "session_id")
        configured = header.get("configured_mcp", [])
        if not isinstance(configured, list):
            raise EvidenceError("configured_mcp must be a list of server identifiers")
        configured = [identifier(item, "configured MCP server") for item in configured]
    if not isinstance(records, list) or not records or len(records) > MAX_EVENTS:
        raise EvidenceError("evidence requires 1..100000 events")
    timeline = [
        _normalize(record, session_id, index, capture_content)
        for index, record in enumerate(records, 1)
    ]
    timeline.sort(key=lambda event: (event["timestamp"], event["source_record"]))
    seen = set()
    calls = {}
    configured = set(configured)
    observed = Counter()
    gaps = [
        "Caller-provided evidence is untrusted; source hashes prove bytes, not authenticity or completeness.",
        "Temporal proximity and parent event order do not establish causal attribution.",
        "Tool start records invocation, not a successful process/file/network action.",
        "Success, blocked, and audit outcomes are source-reported; audit does not prove prevention.",
        "Absent events/configuration are coverage gaps, not proof of no activity.",
        "Secret redaction is best effort, NOT guaranteed DLP; review before sharing.",
    ]
    if native:
        gaps.append(
            "Native subset lacks tenant/workspace/session binding and MCP configuration; "
            "context/session attribution is operator supplied, not independently verified."
        )
    for event in timeline:
        if "event_id" in event:
            if event["event_id"] in seen:
                raise EvidenceError("duplicate event_id")
            seen.add(event["event_id"])
        if event["type"] == "mcp.configured":
            configured.add(event["mcp_server"])
        if event["type"] == "tool.start" and "mcp_server" in event:
            observed[event["mcp_server"]] += 1
        if event["type"] in {"tool.start", "tool.complete"}:
            key = (event.get("agent_id"), event["tool_call_id"])
            pair = calls.setdefault(key, {})
            phase = "start" if event["type"] == "tool.start" else "complete"
            if phase in pair:
                raise EvidenceError("duplicate tool phase for one agent/tool_call_id")
            pair[phase] = event
    for pair in calls.values():
        start, complete = pair.get("start"), pair.get("complete")
        if start is not None and complete is not None:
            if complete["timestamp"] < start["timestamp"]:
                raise EvidenceError("tool completion precedes matching start")
            for name in ("tool_name", "mcp_server"):
                if name in complete and complete[name] != start.get(name):
                    raise EvidenceError("paired tool metadata conflicts")
            start["paired_source_record"] = complete["source_record"]
            complete["paired_source_record"] = start["source_record"]
            complete["tool_name"] = start["tool_name"]
            if "mcp_server" in start:
                complete["mcp_server"] = start["mcp_server"]
        else:
            event = start if start is not None else complete
            gaps.append(f"Unpaired tool phase at source record {event['source_record']}.")
    kinds = {event["type"] for event in timeline}
    for kind in ("prompt", "response", "process", "file", "network"):
        if kind not in kinds:
            gaps.append(f"No {kind} events supplied; coverage unavailable.")
    if not capture_content:
        gaps.append("Content withheld by default: prompts, responses, args, results, errors and action details.")
    return redact({
        "schema": OUTPUT_SCHEMA,
        "context": asdict(context),
        "source": {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw), "format": format_name, "records": len(records),
            "binding": "operator_asserted" if native else "export_identifiers_match_context",
        },
        "privacy": {"capture_content": capture_content, "redaction": "best_effort_not_dlp"},
        "timeline": timeline,
        "mcp": {
            "configured": sorted(configured),
            "observed_invocations": dict(sorted(observed.items())),
            "configured_not_observed": sorted(configured - observed.keys()),
            "observed_not_in_supplied_configuration": sorted(observed.keys() - configured),
            "comparison": "Supplied snapshots only; configured does not mean executed.",
        },
        "coverage_gaps": gaps,
    })


def import_evidence(source_path, context_path, *, repo_root, authorized=False,
                    format_name="json", capture_content=False, session_id=None,
                    output_name="local-agent-timeline.json"):
    require_secure_platform()
    if not authorized:
        raise EvidenceError("explicit authorization required (--authorized)")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.json", output_name) or output_name == "context.json":
        raise EvidenceError("output must be a plain .json filename other than context.json")
    context = load_context(Path(context_path), repo_root=Path(repo_root))
    raw = read_source(source_path)
    report = build_report(
        raw, context=context, format_name=format_name,
        capture_content=capture_content, session_id=session_id,
    )
    payload = (json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
    with open_report_directory(Path(repo_root), context) as directory_fd:
        try:
            fd = os.open(
                output_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=directory_fd,
            )
        except FileExistsError:
            raise EvidenceError("output already exists; choose a different --output-name") from None
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
        except BaseException:
            os.unlink(output_name, dir_fd=directory_fd)
            raise
    return Path(repo_root) / context.report_dir / output_name


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="Repository containing the canonical context (defaults to script repository)")
    parser.add_argument("--authorized", action="store_true", help="Confirm authority to read this export")
    parser.add_argument("--format", choices=("json", "jsonl", NATIVE_FORMAT), default="json")
    parser.add_argument("--session-id", help="Required operator attribution for native subset")
    parser.add_argument("--capture-content", action="store_true", help="Sensitive! Best-effort redaction is NOT DLP")
    parser.add_argument("--output-name", default="local-agent-timeline.json")
    args = parser.parse_args(argv)
    if args.capture_content:
        print("WARNING: content capture may retain secrets/PII. Redaction is NOT guaranteed DLP.", file=sys.stderr)
    try:
        import_evidence(
            args.source, args.context, repo_root=args.repo_root,
            authorized=args.authorized, format_name=args.format,
            capture_content=args.capture_content, session_id=args.session_id,
            output_name=args.output_name,
        )
    except EvidenceError as error:
        print(f"Import rejected: {error}; no report published.", file=sys.stderr)
        return 2
    except ContextError as error:
        # Core ContextError messages are explicitly credential-free.
        print(f"Context rejected: {error}. Check --repo-root and the canonical --context "
              "location; no report published.", file=sys.stderr)
        return 2
    except OSError as error:
        reasons = {
            errno.ENOENT: "source or parent directory does not exist; check the source path",
            errno.EEXIST: "output already exists; choose a different --output-name",
            errno.ELOOP: "symlink refused; use real source/output paths",
            errno.ENOTDIR: "a path component is not a directory or is a symlink",
            errno.EACCES: "permission denied; verify authorized read/write access",
            errno.EPERM: "operation not permitted; verify authorized filesystem access",
            errno.ENOSPC: "insufficient space to write the report",
            errno.ENOTSUP: "filesystem does not support required secure operations",
        }
        reason = reasons.get(error.errno, "secure filesystem operation failed; check file access and filesystem support")
        print(f"Import rejected: {reason}; no report published.", file=sys.stderr)
        return 2
    except RecursionError:
        print("Import rejected: evidence nesting exceeds parser/redaction limits; "
              "reduce nested payload depth; no report published.", file=sys.stderr)
        return 2
    except (ValueError, TypeError):
        # Do not echo arbitrary exception messages that could contain source values.
        print("Import rejected: invalid JSON value or record field type; check the documented "
              "export schema and field types; no report published.", file=sys.stderr)
        return 2
    print("Local evidence timeline written inside the selected tenant case directory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
