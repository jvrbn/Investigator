#!/usr/bin/env python3
"""Tenant-bound, exclusive-create investigation contexts (Python standard library)."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Iterable, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID


REPO_ROOT = Path(__file__).resolve().parents[1]
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
UTC_SECONDS = "%Y-%m-%dT%H:%M:%SZ"
UTC_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
HUNT_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,59}\Z")
CLOCK_SKEW = timedelta(minutes=5)
SCHEMA_VERSIONS = (1, 2)
CURRENT_SCHEMA = 2
TIERS = {"high": "High", "medium": "Medium", "low": "Low"}

# capability -> (how it is proven, whether it is scoped to one workspace).
# "cli" capabilities are proven by this module with a tenant-pinned, read-only
# Azure CLI token. "attested" capabilities live in MCP sessions this module
# cannot inspect; a ledger entry for them is a recorded claim, never proof.
CAPABILITIES = {
    "tenant_identity": ("cli", False),
    "workspace_arm": ("cli", True),
    "workspace_query": ("cli", True),
    "data_lake": ("attested", True),
    "graph": ("attested", False),
    "triage": ("attested", False),
    "defender_hunting": ("attested", False),
}
CONNECTION_FOR = {"data_lake": "data_lake", "graph": "graph", "triage": "triage"}
HUNTING_VIA = ("triage", "graph", "portal")
LEDGER_NAME = re.compile(r"(\d{8}T\d{12}Z)-([a-z_]+)\.json\Z", re.ASCII)
WRITER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.(?:json|html|txt)\Z", re.ASCII)
LEDGER_STATUSES = {
    "cli_probe": ("verified", "denied", "unverified"),
    "agent_attestation": ("attested", "denied", "unverified"),
}
USABLE = ("verified", "attested")
DEFAULT_TTL_HOURS = 24
MAX_TTL_HOURS = 168
SECRET_LIKE = re.compile(
    r"eyJ[A-Za-z0-9_-]{8,}|bearer\s+\S{12,}|(?:secret|password|token|apikey|api_key)\s*[=:]\s*\S",
    re.IGNORECASE,
)
MCP_SERVICES = {
    "data_lake": "https://sentinel.microsoft.com/mcp/data-exploration",
    "graph": "https://mcp.svc.cloud.microsoft/enterprise",
    "triage": "https://sentinel.microsoft.com/mcp/triage",
}
LOG_ANALYTICS = "https://api.loganalytics.io"
MAX_QUERY_BYTES = 65536


class ContextError(ValueError):
    """A safe, non-credential-bearing error for CLI consumers."""


class ProbeDenied(ContextError):
    """The identity authenticated but is not permitted to see the resource."""


def _guid(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ContextError(f"{field} must be a GUID")
    try:
        normalized = str(UUID(value))
    except ValueError:
        raise ContextError(f"{field} must be a GUID") from None
    if value.lower() != normalized or UUID(value).int == 0:
        raise ContextError(f"{field} must be a nonzero canonical GUID")
    return normalized


def _slug(value: object, field: str) -> str:
    if not isinstance(value, str) or not SLUG.fullmatch(value):
        raise ContextError(f"{field} must be a safe lowercase slug (1-64 characters)")
    return value


def _optional_guid(value: object, field: str) -> str | None:
    return None if value is None else _guid(value, field)


def _text(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ContextError(f"{field} must be a nonempty string")
    if any(ord(c) < 32 for c in value) or "/" in value or "\\" in value:
        raise ContextError(f"{field} must be a name, not a path")
    return value


def _object(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        raise ContextError(f"{field} must be an object")
    return value


def _json_read(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8-sig") as stream:
            return _object(json.load(stream), "JSON document")
    except (OSError, ValueError):
        raise ContextError("Unable to read valid JSON configuration/context") from None


@dataclass(frozen=True)
class Connections:
    data_lake: str | None = None
    graph: str | None = None
    triage: str | None = None


@dataclass(frozen=True)
class Workspace:
    id: str
    name: str | None = None
    subscription_id: str | None = None
    resource_group: str | None = None


@dataclass(frozen=True)
class TenantProfile:
    name: str
    tenant_id: str
    subscription_id: str | None
    sentinel_workspace_id: str | None
    workspaces: tuple[Workspace, ...]
    connections: Connections
    memory_file: str | None = None
    triage_home_tenant_id: str | None = None
    # Tenant-local GUID -> name/tier tables (never merged across tenants).
    sit_mapping: tuple[tuple[str, str], ...] = ()
    label_mapping: tuple[tuple[str, str], ...] = ()
    sit_priority: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Window:
    """Exact UTC collection window shared by every query in a case (and hunt)."""

    start_utc: str
    end_utc: str


V1_FIELDS = frozenset({
    "profile", "tenant_id", "workspace", "case_id", "lookback_days", "connections",
    "report_dir", "created_at", "memory_file", "triage_home_tenant_id", "schema_version",
})
V2_FIELDS = V1_FIELDS | {"window", "hunt_id", "capabilities"}


@dataclass(frozen=True)
class InvestigationContext:
    profile: str
    tenant_id: str
    workspace: Workspace | None
    case_id: str
    lookback_days: int
    connections: Connections
    report_dir: str
    created_at: str
    memory_file: str | None = None
    triage_home_tenant_id: str | None = None
    schema_version: int = CURRENT_SCHEMA
    window: Window | None = None
    hunt_id: str | None = None
    capabilities: tuple[str, ...] = ()

    @property
    def workspace_id(self) -> str | None:
        return None if self.workspace is None else self.workspace.id

    def to_dict(self) -> dict:
        data = asdict(self)
        data["capabilities"] = list(self.capabilities)
        return data


def _connections(raw: object) -> Connections:
    values = _object(raw, "connections")
    if set(values) - {"data_lake", "graph", "triage"}:
        raise ContextError("connections may contain only data_lake, graph, triage references")
    for value in values.values():
        if value is not None and (
            not isinstance(value, str) or not REFERENCE.fullmatch(value)
        ):
            raise ContextError("connections must be names only, never URLs or credentials")
    return Connections(**values)


def _workspace(raw: object) -> Workspace:
    values = _object(raw, "workspace")
    if set(values) - {"id", "name", "subscription_id", "resource_group"}:
        raise ContextError("Unknown workspace fields")
    return Workspace(
        id=_guid(values.get("id"), "workspace.id"),
        name=_text(values.get("name"), "workspace.name"),
        subscription_id=_optional_guid(values.get("subscription_id"), "workspace.subscription_id"),
        resource_group=_text(values.get("resource_group"), "workspace.resource_group"),
    )


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not UTC_PATTERN.fullmatch(value):
        raise ContextError(f"{field} must be UTC time formatted YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, UTC_SECONDS).replace(tzinfo=timezone.utc)
    except ValueError:
        raise ContextError(f"{field} must be a valid UTC time") from None


def _utc_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(UTC_SECONDS)


def _add(moment: datetime, delta: timedelta) -> datetime:
    """Saturating add: a crafted year-9999 timestamp must not raise OverflowError."""
    try:
        return moment + delta
    except OverflowError:
        edge = datetime.max if delta > timedelta(0) else datetime.min
        return edge.replace(tzinfo=timezone.utc)


def _lookback(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 3650:
        raise ContextError("lookback_days must be an integer between 1 and 3650")
    return value


def _capabilities(raw: object, *, workspace: bool) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)):
        raise ContextError("capabilities must be an array")
    names = list(raw)
    if any(not isinstance(name, str) or name not in CAPABILITIES for name in names):
        raise ContextError("Unknown capability; expected: " + ", ".join(sorted(CAPABILITIES)))
    if names != sorted(set(names)):
        raise ContextError("capabilities must be unique and sorted")
    if not workspace:
        scoped = [name for name in names if CAPABILITIES[name][1]]
        if scoped:
            raise ContextError("Capabilities require a workspace: " + ", ".join(scoped))
    return tuple(names)


def _mapping(raw: object, field: str, *, tiers: bool = False,
             strict: bool = True) -> tuple[tuple[str, str], ...]:
    """Tenant-local GUID tables. Legacy root files are read leniently, never rejected."""
    if raw is None or (not strict and not isinstance(raw, dict)):
        return ()
    entries: dict[str, str] = {}
    for key, value in _object(raw, field).items():
        if key == "__comment":
            continue
        try:
            guid = _guid(key.lower() if isinstance(key, str) else key, f"{field} key")
            if tiers:
                label = TIERS.get(value.lower()) if isinstance(value, str) else None
                if label is None:
                    raise ContextError(f"{field} values must be High, Medium, or Low")
            elif (not isinstance(value, str) or not value.strip() or len(value) > 160
                    or any(ord(c) < 32 for c in value)):
                raise ContextError(f"{field} values must be short single-line names")
            else:
                label = value
            if guid in entries:
                raise ContextError(f"{field} contains duplicate GUIDs")
        except ContextError:
            if strict:
                raise
            continue
        entries[guid] = label
    return tuple(sorted(entries.items()))


def _profile(name: str, raw: object, *, legacy: bool = False) -> TenantProfile:
    values = _object(raw, "tenant profile")
    allowed = {
        "tenant_id", "subscription_id", "sentinel_workspace_id", "azure_mcp",
        "memory_file", "connections", "workspaces", "triage_home_tenant_id",
        "sit_mapping", "label_mapping", "sit_priority",
    }
    if not legacy and set(values) - allowed:
        raise ContextError("Unknown tenant profile fields; credentials do not belong in profiles")
    tenant = _guid(values.get("tenant_id"), "tenant_id")
    subscription = _optional_guid(values.get("subscription_id"), "subscription_id")
    sentinel = _optional_guid(values.get("sentinel_workspace_id"), "sentinel_workspace_id")
    azure = _object(values.get("azure_mcp", {}), "azure_mcp")
    if set(azure) - {"tenant", "subscription", "resource_group", "workspace_name"}:
        raise ContextError("Unknown azure_mcp fields")
    if azure.get("tenant") is not None and _guid(azure["tenant"], "azure_mcp.tenant") != tenant:
        raise ContextError("azure_mcp.tenant conflicts with profile tenant")
    azure_sub = _optional_guid(azure.get("subscription"), "azure_mcp.subscription")
    if subscription and azure_sub and subscription != azure_sub:
        raise ContextError("azure_mcp.subscription conflicts with profile subscription")
    subscription = subscription or azure_sub
    name_value = _text(azure.get("workspace_name"), "azure_mcp.workspace_name")
    resource_group = _text(azure.get("resource_group"), "azure_mcp.resource_group")
    raw_workspaces = values.get("workspaces", [])
    if not isinstance(raw_workspaces, list):
        raise ContextError("workspaces must be an array")
    workspaces = [_workspace(item) for item in raw_workspaces]
    ids = [item.id for item in workspaces]
    if len(set(ids)) != len(ids):
        raise ContextError("Duplicate workspace IDs")
    if sentinel and sentinel not in ids:
        workspaces.append(Workspace(sentinel, name_value, subscription, resource_group))
    elif sentinel:
        selected = next(item for item in workspaces if item.id == sentinel)
        for field, root_value in (
            ("name", name_value), ("subscription_id", subscription), ("resource_group", resource_group)
        ):
            if root_value and getattr(selected, field) and root_value != getattr(selected, field):
                raise ContextError("Default workspace metadata conflicts with azure_mcp")
        # Enrich only from this same profile, never from legacy root or another tenant.
        workspaces = [
            Workspace(item.id, item.name or name_value, item.subscription_id or subscription,
                      item.resource_group or resource_group) if item.id == sentinel else item
            for item in workspaces
        ]
    memory = _text(values.get("memory_file"), "memory_file")
    if memory and (memory in {".", ".."} or not REFERENCE.fullmatch(memory)):
        raise ContextError("memory_file must be a filename")
    return TenantProfile(
        _slug(name, "profile"), tenant, subscription, sentinel, tuple(workspaces),
        _connections(values.get("connections", {})), memory,
        _optional_guid(values.get("triage_home_tenant_id"), "triage_home_tenant_id"),
        _mapping(values.get("sit_mapping"), "sit_mapping", strict=not legacy),
        _mapping(values.get("label_mapping"), "label_mapping", strict=not legacy),
        _mapping(values.get("sit_priority"), "sit_priority", tiers=True, strict=not legacy),
    )


def load_profiles(config_path: str | Path = REPO_ROOT / "config.json") -> dict[str, TenantProfile]:
    """Load a registry, or a single 'legacy' profile if tenants is absent/empty."""
    config = _json_read(Path(config_path))
    if "tenants" not in config:
        return {"legacy": _profile("legacy", config, legacy=True)}
    registry = _object(config["tenants"], "tenants")
    if not registry:
        return {"legacy": _profile("legacy", config, legacy=True)}
    return {_slug(name, "profile"): _profile(name, value) for name, value in registry.items()}


def select_profile(profiles: dict[str, TenantProfile], profile: str | None = None) -> TenantProfile:
    if profile is None:
        if len(profiles) != 1:
            raise ContextError("Explicit --profile selection is required for multiple tenants")
        return next(iter(profiles.values()))
    if profile not in profiles:
        raise ContextError("Selected profile does not exist")
    return profiles[profile]


def tenant_registry_configured(config_path: str | Path = REPO_ROOT / "config.json") -> bool:
    """True when a nonempty `tenants` registry exists (it is then authoritative).

    A missing config means legacy mode; an unreadable or malformed one fails
    closed so a damaged registry can never silently downgrade to shared output.
    """
    path = Path(config_path)
    if not path.exists():
        return False
    config = _json_read(path)
    return "tenants" in config and bool(_object(config["tenants"], "tenants"))


def profile_warnings(profiles: dict[str, TenantProfile]) -> list[str]:
    """A connection name shared by two tenants would share one authenticated session."""
    owners: dict[str, dict[str, set]] = {}
    for item in profiles.values():
        for reference in {value for value in asdict(item.connections).values() if value}:
            owners.setdefault(reference, {}).setdefault(item.tenant_id, set()).add(item.name)
    return [
        f"Connection '{reference}' is referenced by profiles for different tenants "
        f"({', '.join(sorted(name for names in tenants.values() for name in names))}); "
        "one MCP connection cannot be authenticated to two tenants"
        for reference, tenants in sorted(owners.items()) if len(tenants) > 1
    ]


def static_unsupported(context: InvestigationContext) -> dict[str, str]:
    """Capabilities this context can never provide, from declared configuration only."""
    reasons: dict[str, str] = {}
    home = context.triage_home_tenant_id
    if home is not None and home != context.tenant_id:
        reasons["triage"] = "Triage is home-tenant only; declared home tenant differs from this tenant"
    if context.workspace is None:
        for name, (_, scoped) in CAPABILITIES.items():
            if scoped:
                reasons[name] = "No workspace is bound to this case"
    return reasons


def _report_dir(profile: str, case_id: str) -> str:
    return f"reports/tenants/{_slug(profile, 'profile')}/{_slug(case_id, 'case_id')}"


@contextmanager
def _directory(root: Path, parts: tuple[str, ...], *, create: bool = False,
               exclusive_last: bool = False) -> Iterator[int]:
    """Walk with directory descriptors: reject symlinks, including concurrent swaps."""
    fd = os.open(root.resolve(strict=True), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(parts):
            if part in {"", ".", ".."} or "/" in part or "\\" in part:
                raise ContextError("Unsafe path component")
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    if exclusive_last and index == len(parts) - 1:
                        raise ContextError("Investigation run already exists; choose a new case/run ID") from None
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    except OSError:
        raise ContextError("Unsafe, missing, or inaccessible report path") from None
    finally:
        os.close(fd)


def _check_context(context: InvestigationContext) -> None:
    _slug(context.profile, "profile")
    _guid(context.tenant_id, "tenant_id")
    if type(context.schema_version) is not int or context.schema_version not in SCHEMA_VERSIONS:
        raise ContextError("Unsupported context schema_version")
    if context.workspace is not None:
        _workspace(asdict(context.workspace))
    _connections(asdict(context.connections))
    _lookback(context.lookback_days)
    if context.report_dir != _report_dir(context.profile, context.case_id):
        raise ContextError("Context report_dir does not match profile/case binding")
    try:
        # JavaScript emits Z; Python 3.8's fromisoformat requires an explicit offset.
        created_at = context.created_at
        if isinstance(created_at, str) and created_at.endswith("Z"):
            created_at = created_at[:-1] + "+00:00"
        timestamp = datetime.fromisoformat(created_at)
        if timestamp.utcoffset() is None:
            raise ValueError
    except (TypeError, ValueError):
        raise ContextError("Context created_at must be timezone-aware ISO datetime") from None
    memory = _text(context.memory_file, "memory_file")
    if memory and not REFERENCE.fullmatch(memory):
        raise ContextError("memory_file must be a filename")
    _optional_guid(context.triage_home_tenant_id, "triage_home_tenant_id")
    if context.schema_version == 1:
        if context.workspace is None:
            raise ContextError("schema_version 1 requires a workspace")
        if context.window is not None or context.hunt_id is not None or context.capabilities:
            raise ContextError("schema_version 1 cannot carry window, hunt_id or capabilities")
        return
    if not isinstance(context.window, Window):
        raise ContextError("schema_version 2 requires a window")
    start = _utc(context.window.start_utc, "window.start_utc")
    end = _utc(context.window.end_utc, "window.end_utc")
    if end - start != timedelta(days=context.lookback_days):
        raise ContextError("Context window does not equal lookback_days")
    try:
        created_utc = timestamp.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ContextError("Context created_at must be timezone-aware ISO datetime") from None
    if end > _add(created_utc, CLOCK_SKEW):
        raise ContextError("Context window cannot end after the context was created")
    _capabilities(context.capabilities, workspace=context.workspace is not None)
    if context.hunt_id is not None:
        if not isinstance(context.hunt_id, str) or not HUNT_ID.fullmatch(context.hunt_id):
            raise ContextError("hunt_id must be a safe lowercase slug (1-60 characters)")
        if not re.fullmatch(re.escape(context.hunt_id) + r"-(?:0[1-9]|[1-9]\d)", context.case_id):
            raise ContextError("A hunt child case ID must be <hunt_id>-NN with NN from 01 to 99")


def context_path(repo_root: str | Path, context: InvestigationContext) -> Path:
    _check_context(context)
    return Path(repo_root).resolve() / context.report_dir / "context.json"


@contextmanager
def open_report_directory(repo_root: str | Path, context: InvestigationContext) -> Iterator[int]:
    """Yield a safe dir_fd; consumers should exclusive-create relative leaf names."""
    _check_context(context)
    with _directory(Path(repo_root), tuple(context.report_dir.split("/"))) as fd:
        yield fd


def create_context(
    config_path: str | Path = REPO_ROOT / "config.json", *,
    profile: str | None = None, workspace_id: str | None, case_id: str,
    lookback_days: int, repo_root: str | Path = REPO_ROOT,
    capabilities: Iterable[str] | None = None, hunt_id: str | None = None,
    window_end: str | None = None,
) -> InvestigationContext:
    """Exclusive-create a schema 2 context.

    `workspace_id` is always explicit; pass None for a Defender-only case that
    needs no Sentinel workspace. `window_end` pins the exact UTC end of the
    window so hunt children can share one window; it defaults to now.
    """
    selected = select_profile(load_profiles(config_path), profile)
    lookback = _lookback(lookback_days)
    workspace = None
    if workspace_id is not None:
        workspace_id = _guid(workspace_id, "workspace_id")
        workspace = next((item for item in selected.workspaces if item.id == workspace_id), None)
        if workspace is None:
            raise ContextError("Explicit workspace is not registered in selected profile")
    created = datetime.now(timezone.utc)
    end = created.replace(microsecond=0) if window_end is None else _utc(window_end, "window_end")
    if end > created + CLOCK_SKEW:
        raise ContextError("window_end cannot be in the future")
    try:
        start = end - timedelta(days=lookback)
    except OverflowError:
        raise ContextError("window_end is too early for the requested lookback") from None
    if capabilities is None:
        names = ("tenant_identity",) + (("workspace_arm",) if workspace else ())
    else:
        # The tenant-identity proof is the foundation of every other capability.
        names = tuple(sorted({"tenant_identity", *capabilities}))
    context = InvestigationContext(
        selected.name, selected.tenant_id, workspace, case_id, lookback,
        selected.connections, _report_dir(selected.name, case_id),
        created.isoformat(), selected.memory_file, selected.triage_home_tenant_id,
        window=Window(_utc_text(start), _utc_text(end)),
        hunt_id=hunt_id, capabilities=names,
    )
    _check_context(context)
    unsupported = static_unsupported(context)
    blocked = [name for name in context.capabilities if name in unsupported]
    if blocked:
        raise ContextError("Unsupported capability for this case: " + "; ".join(
            f"{name} ({unsupported[name]})" for name in blocked))
    content = json.dumps(context.to_dict(), indent=2, sort_keys=True) + "\n"
    with _directory(Path(repo_root), tuple(context.report_dir.split("/")),
                    create=True, exclusive_last=True) as directory:
        fd = os.open("context.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o400, dir_fd=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    return context


def context_from_manifest(raw: object) -> InvestigationContext:
    """Strictly parse and validate one manifest, with no filesystem access."""
    try:
        values = dict(_object(raw, "context"))
        version = values.get("schema_version")
        expected = {1: V1_FIELDS, 2: V2_FIELDS}.get(version) if type(version) is int else None
        if expected is None or set(values) != expected:
            raise ContextError("Context fields do not match a supported schema_version")
        values["workspace"] = None if values["workspace"] is None else _workspace(values["workspace"])
        values["connections"] = _connections(values.get("connections"))
        if version == 2:
            window = _object(values["window"], "window")
            if set(window) != {"start_utc", "end_utc"}:
                raise ContextError("Unknown window fields")
            values["window"] = Window(**window)
            if not isinstance(values["capabilities"], list):
                raise ContextError("capabilities must be an array")
            values["capabilities"] = tuple(values["capabilities"])
        context = InvestigationContext(**values)
    except (TypeError, ValueError):
        raise ContextError("Unable to load valid immutable context") from None
    _check_context(context)
    return context


def load_context(path: str | Path, repo_root: str | Path = REPO_ROOT) -> InvestigationContext:
    root = Path(repo_root).resolve(strict=True)
    path = Path(path)
    if not path.is_absolute():
        path = root / path
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise ContextError("Context path must be inside repository") from None
    parts = relative.parts
    if len(parts) != 5 or parts[:2] != ("reports", "tenants") or parts[-1] != "context.json":
        raise ContextError("Context must be reports/tenants/<profile>/<case>/context.json")
    _slug(parts[2], "profile")
    _slug(parts[3], "case_id")
    try:
        with _directory(root, parts[:-1]) as directory:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(fd, encoding="utf-8") as stream:
                raw = _object(json.load(stream), "context")
    except (OSError, TypeError, ValueError):
        raise ContextError("Unable to load valid immutable context") from None
    context = context_from_manifest(raw)
    if relative.as_posix() != context.report_dir + "/context.json":
        raise ContextError("Context file location conflicts with tenant/case binding")
    return context


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _service_message(error: HTTPError) -> str:
    """Best-effort, bounded service message for a rejected query (never headers/bodies)."""
    try:
        message = json.loads(error.read(4096).decode("utf-8", "replace"))["error"]["message"]
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        return ""
    if not isinstance(message, str):
        return ""
    text = " ".join(message.split())[:240]
    return "" if SECRET_LIKE.search(text) or any(ord(c) < 32 for c in text) else text


def _http_error(error: HTTPError, *, with_message: bool = False) -> ContextError:
    if error.code in (401, 403, 404):
        return ProbeDenied(f"Authenticated request denied or resource not visible (HTTP {error.code})")
    message = _service_message(error) if with_message and error.code == 400 else ""
    return ContextError(f"Authenticated request failed (HTTP {error.code})" + (f": {message}" if message else ""))


def _get_json(url: str, token: str) -> dict:
    request = Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        # Never forward a bearer token to a redirect target.
        with build_opener(_NoRedirect()).open(request, timeout=30) as response:
            return _object(json.load(response), "authenticated response")
    except HTTPError as error:
        raise _http_error(error) from None
    except (URLError, OSError, ValueError):
        raise ContextError("Authenticated GET failed or returned invalid JSON") from None


def _post_json(url: str, token: str, body: dict) -> dict:
    request = Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                 "Content-Type": "application/json"},
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=120) as response:
            return _object(json.load(response), "authenticated response")
    except HTTPError as error:
        raise _http_error(error, with_message=True) from None
    except (URLError, OSError, ValueError):
        raise ContextError("Authenticated POST failed or returned invalid JSON") from None


def _cli_token(tenant_id: str, resource: str) -> str:
    try:
        result = subprocess.run(
            ["az", "account", "get-access-token", "--tenant", tenant_id,
             "--resource", resource, "--output", "json", "--only-show-errors"],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise ContextError("Azure CLI token acquisition unavailable") from None
    if result.returncode:
        # stderr can include account details or tokens; never relay it.
        raise ContextError("Azure CLI token acquisition failed; no login or context switch attempted")
    try:
        payload = _object(json.loads(result.stdout), "token response")
        if _guid(payload.get("tenant"), "token tenant") != tenant_id:
            raise ContextError("Azure CLI returned a token for the wrong tenant")
        token = payload.get("accessToken")
        if not isinstance(token, str) or not token or any(c.isspace() for c in token):
            raise ContextError("Azure CLI returned an invalid token")
        return token
    except (TypeError, ValueError):
        raise ContextError("Azure CLI token response invalid or wrong tenant") from None


def _authenticated_graph(context: InvestigationContext) -> None:
    token = _cli_token(context.tenant_id, "https://graph.microsoft.com/")
    organization = _get_json("https://graph.microsoft.com/v1.0/organization?$select=id", token)
    values = organization.get("value")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise ContextError("Organization GET did not return exactly one tenant")
    if _guid(values[0].get("id"), "organization.id") != context.tenant_id:
        raise ContextError("Authenticated organization ID does not match selected tenant")


def _authenticated_workspace(context: InvestigationContext) -> None:
    workspace = context.workspace
    if workspace is None:
        raise ContextError("No workspace is bound to this case")
    if not all((workspace.subscription_id, workspace.resource_group, workspace.name)):
        raise ContextError("Live workspace verification requires subscription_id, resource_group, name")
    token = _cli_token(context.tenant_id, "https://management.azure.com/")
    base = f"https://management.azure.com/subscriptions/{workspace.subscription_id}"
    subscription = _get_json(base + "?api-version=2022-12-01", token)
    if (_guid(subscription.get("subscriptionId"), "subscriptionId") != workspace.subscription_id
            or _guid(subscription.get("tenantId"), "subscription.tenantId") != context.tenant_id):
        raise ContextError("Workspace subscription tenant/identity does not match selected context")
    resource_id = (
        f"/subscriptions/{workspace.subscription_id}/resourceGroups/"
        f"{quote(workspace.resource_group, safe='')}/providers/"
        f"Microsoft.OperationalInsights/workspaces/{quote(workspace.name, safe='')}"
    )
    response = _get_json("https://management.azure.com" + resource_id + "?api-version=2023-09-01", token)
    expected_id = (
        f"/subscriptions/{workspace.subscription_id}/resourceGroups/{workspace.resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{workspace.name}"
    )
    if not isinstance(response.get("id"), str) or response["id"].lower() != expected_id.lower():
        raise ContextError("Authenticated workspace resource ID does not match selected workspace")
    properties = _object(response.get("properties"), "workspace.properties")
    if _guid(properties.get("customerId"), "workspace.customerId") != workspace.id:
        raise ContextError("Authenticated workspace GUID does not match selected workspace")


def _workspace_query_url(context: InvestigationContext) -> str:
    if context.workspace is None:
        raise ContextError("No workspace is bound to this case")
    return f"{LOG_ANALYTICS}/v1/workspaces/{context.workspace.id}/query"


def _query_rows(response: dict) -> tuple[list, list]:
    """Return (columns, rows) of the primary result table of a query response."""
    tables = response.get("tables")
    if not isinstance(tables, list) or not tables or not all(isinstance(t, dict) for t in tables):
        raise ContextError("Query response did not contain result tables")
    table = next((t for t in tables if t.get("name") == "PrimaryResult"), tables[0])
    columns, rows = table.get("columns"), table.get("rows")
    if (not isinstance(columns, list) or not isinstance(rows, list)
            or not all(isinstance(c, dict) and isinstance(c.get("name"), str) for c in columns)
            or not all(isinstance(r, list) for r in rows)):
        raise ContextError("Query response table is malformed")
    return columns, rows


def _authenticated_query(context: InvestigationContext) -> None:
    """Read-only reachability probe for the tenant-pinned Log Analytics query API."""
    token = _cli_token(context.tenant_id, LOG_ANALYTICS)
    _, rows = _query_rows(_post_json(_workspace_query_url(context), token, {"query": "print probe=1"}))
    if rows != [[1]]:
        raise ContextError("Workspace query probe returned an unexpected result")


def _run_probe(name: str, context: InvestigationContext) -> None:
    {"tenant_identity": _authenticated_graph, "workspace_arm": _authenticated_workspace,
     "workspace_query": _authenticated_query}[name](context)


def _live_probes(context: InvestigationContext) -> list:
    """(source key, probe name) run by `validate --validate-live`, in order."""
    probes = [("graph_cli", "tenant_identity")]
    if context.schema_version == 1:
        return probes + [("workspace_cli", "workspace_arm")]
    if "workspace_arm" in context.capabilities:
        probes.append(("workspace_cli", "workspace_arm"))
    if "workspace_query" in context.capabilities:
        probes.append(("workspace_query", "workspace_query"))
    return probes


def validate_context(
    context: InvestigationContext, config_path: str | Path = REPO_ROOT / "config.json", *,
    repo_root: str | Path = REPO_ROOT, validate_live: bool = False,
) -> dict:
    """Offline binding checks plus optional fail-closed, authenticated CLI/HTTP proofs."""
    probes = _live_probes(context)
    applicable = {key for key, _ in probes}
    sources = {"offline": {"status": "pending"}}
    for key in ("graph_cli", "workspace_cli") + (("workspace_query",) if context.schema_version == 2 else ()):
        sources[key] = {"status": "not_checked" if key in applicable else "not_applicable",
                        "authenticated": False}
    sources.update({
        "data_lake": {"status": "unverified", "reason": "MCP identity not authenticated by CLI"},
        "graph": {"status": "unverified", "reason": "MCP identity not authenticated by CLI"},
        "triage": {"status": "unverified", "reason": "MCP identity/home tenant not authenticated by CLI"},
    })
    result = {
        "ok": False, "mode": "authenticated" if validate_live else "offline",
        "profile": context.profile, "sources": sources,
    }
    if context.schema_version == 2:
        result.update(
            schema_version=2, hunt_id=context.hunt_id,
            required_capabilities=list(context.capabilities),
            window=None if context.window is None else asdict(context.window),
        )
    try:
        _check_context(context)
        persisted = load_context(context_path(repo_root, context), repo_root)
        if context != persisted:
            raise ContextError("Context differs from persisted immutable manifest")
        profile = select_profile(load_profiles(config_path), context.profile)
        workspace = None
        if context.workspace is not None:
            workspace = next((item for item in profile.workspaces if item.id == context.workspace.id), None)
        if (
            context.tenant_id != profile.tenant_id or context.workspace != workspace
            or context.connections != profile.connections or context.memory_file != profile.memory_file
            or context.triage_home_tenant_id != profile.triage_home_tenant_id
        ):
            raise ContextError("Profile configuration changed; create a new context, do not rebind this run")
        if ((context.connections.triage or "triage" in context.capabilities)
                and context.triage_home_tenant_id != context.tenant_id):
            raise ContextError("Triage requires a declared home tenant matching the selected tenant")
        sources["offline"] = {"status": "passed", "authenticated": False}
    except ContextError as error:
        sources["offline"] = {"status": "failed", "error": str(error)}
        return result
    if not validate_live:
        result["ok"] = True
        return result
    for key, name in probes:
        try:
            _run_probe(name, context)
            sources[key] = {"status": "verified", "authenticated": True}
        except ContextError as error:
            sources[key] = {"status": "failed", "authenticated": False, "error": str(error)}
            return result
    result["ok"] = True
    return result


LEDGER_SCHEMA = 1
LEDGER_FIELDS = frozenset({
    "schema_version", "kind", "profile", "tenant_id", "workspace_id", "case_id",
    "capability", "status", "method", "checked_at", "expires_at", "detail", "via",
})
MAX_RECORD_BYTES = 8192
PROBE_DETAIL = {
    "tenant_identity": "Graph organization ID matched the selected tenant",
    "workspace_arm": "ARM subscription tenant and workspace customerId matched the selected workspace",
    "workspace_query": "Log Analytics query API answered a probe with a tenant-pinned token",
}


def _require_v2(context: InvestigationContext) -> None:
    if context.schema_version != 2:
        raise ContextError("Capability commands need a schema_version 2 context; create a new context")


def _ttl(hours: object) -> int:
    if type(hours) is not int or not 1 <= hours <= MAX_TTL_HOURS:
        raise ContextError(f"ttl_hours must be an integer between 1 and {MAX_TTL_HOURS}")
    return hours


def _detail(value: object, *, truncate: bool = False) -> str:
    if not isinstance(value, str):
        raise ContextError("detail must be text")
    text = " ".join(value.split())
    if truncate:
        text = text[:200]
    if not text or len(text) > 200 or any(ord(c) < 32 for c in text):
        raise ContextError("detail must be 1-200 characters of plain text")
    if SECRET_LIKE.search(text):
        raise ContextError("detail must not contain tokens or credentials")
    return text


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%f") + "Z"


def _validate_record(raw: object, context: InvestigationContext, now: datetime,
                     name: "re.Match | None" = None) -> dict:
    """Strictly validate one ledger record for exactly this tenant/profile/case."""
    values = _object(raw, "ledger record")
    if set(values) != LEDGER_FIELDS:
        raise ContextError("Ledger record fields do not match the schema")
    if (type(values["schema_version"]) is not int or values["schema_version"] != LEDGER_SCHEMA
            or values["kind"] != "capability_check"):
        raise ContextError("Unsupported ledger record")
    if (values["profile"], values["tenant_id"], values["case_id"]) != (
            context.profile, context.tenant_id, context.case_id):
        raise ContextError("Ledger record belongs to a different tenant, profile, or case")
    capability = values["capability"]
    if not isinstance(capability, str) or capability not in CAPABILITIES:
        raise ContextError("Unknown capability")
    proof, scoped = CAPABILITIES[capability]
    if values["workspace_id"] != (context.workspace_id if scoped else None):
        raise ContextError("Ledger record belongs to a different workspace")
    method, status = values["method"], values["status"]
    if (not isinstance(method, str) or not isinstance(status, str)
            or method not in LEDGER_STATUSES or status not in LEDGER_STATUSES[method]):
        raise ContextError("Invalid ledger method or status")
    if (proof == "cli") != (method == "cli_probe"):
        raise ContextError("Ledger method does not match how this capability is proven")
    checked = _utc(values["checked_at"], "checked_at")
    expires = _utc(values["expires_at"], "expires_at")
    if not checked < expires <= _add(checked, timedelta(hours=MAX_TTL_HOURS)):
        raise ContextError("Ledger expiry is outside the allowed lifetime")
    if checked > _add(now, CLOCK_SKEW):
        raise ContextError("Ledger record is dated in the future")
    if name is not None:
        try:
            written = datetime.strptime(name.group(1), "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
        except ValueError:
            raise ContextError("Ledger file name does not carry a valid UTC stamp") from None
        if name.group(2) != capability or not timedelta(0) <= written - checked < timedelta(seconds=2):
            raise ContextError("Ledger file name does not match its record")
    via = values["via"]
    if capability == "defender_hunting":
        if via is not None and via not in HUNTING_VIA:
            raise ContextError("via must be triage, graph, or portal")
        if status == "attested" and via is None:
            raise ContextError("A defender_hunting attestation must name its route")
    elif via is not None:
        raise ContextError("via applies only to defender_hunting")
    if status == "attested":
        needed = [CONNECTION_FOR[capability]] if capability in CONNECTION_FOR else []
        if via in ("triage", "graph"):
            needed.append(via)
        for reference in needed:
            if getattr(context.connections, reference) is None:
                raise ContextError(f"No {reference} connection is declared for this tenant")
        if "triage" in (capability, via) and "triage" in static_unsupported(context):
            raise ContextError("Triage is not supported for this tenant")
    return dict(values, detail=_detail(values["detail"]))


def _load_record(directory: int, entry: str, context: InvestigationContext, now: datetime) -> "dict | None":
    match = LEDGER_NAME.fullmatch(entry)
    if match is None:
        return None
    try:
        # O_NONBLOCK keeps a planted FIFO from hanging the reader.
        fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=directory)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RECORD_BYTES:
            return None
        with os.fdopen(fd, encoding="utf-8") as stream:
            fd = -1
            raw = json.load(stream)
        return _validate_record(raw, context, now, match)
    except (OSError, ValueError, TypeError, KeyError, ArithmeticError, RecursionError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def read_ledger(repo_root: "str | Path", context: InvestigationContext,
                now: "datetime | None" = None) -> "tuple[dict, int]":
    """Latest valid in-scope record per capability, and how many files were ignored."""
    moment = now or datetime.now(timezone.utc)
    records: dict = {}
    ignored = 0
    with open_report_directory(repo_root, context) as case_fd:
        try:
            directory = os.open("ledger", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=case_fd)
        except FileNotFoundError:
            return records, ignored
        try:
            for entry in sorted(os.listdir(directory)):
                record = _load_record(directory, entry, context, moment)
                if record is None:
                    ignored += 1
                else:
                    records[record["capability"]] = dict(record, file=entry)
        finally:
            os.close(directory)
    return records, ignored


def evaluate_capabilities(context: InvestigationContext, records: dict, now: datetime) -> dict:
    """Effective status of every capability: static limits first, then the newest record."""
    unsupported = static_unsupported(context)
    table = {}
    for name, (proof, _) in CAPABILITIES.items():
        entry = {
            "status": "unverified", "proof": proof, "required": name in context.capabilities,
            "method": None, "checked_at": None, "expires_at": None, "detail": None,
            "via": None, "last_status": None,
        }
        record = records.get(name)
        if name in unsupported:
            entry.update(status="unsupported", detail=unsupported[name])
        elif record is not None:
            expired = now >= _utc(record["expires_at"], "expires_at")
            entry.update(
                status="expired" if expired else record["status"], method=record["method"],
                checked_at=record["checked_at"], expires_at=record["expires_at"],
                detail=record["detail"], via=record["via"],
                last_status=record["status"] if expired else None,
            )
        else:
            reference = CONNECTION_FOR.get(name)
            entry["detail"] = (
                "No connection is declared for this tenant"
                if reference and getattr(context.connections, reference) is None
                else "No check recorded"
            )
        table[name] = entry
    return table


def readiness(context: InvestigationContext, *, repo_root: "str | Path" = REPO_ROOT,
              now: "datetime | None" = None) -> dict:
    """Read-only: can this case rely on each capability right now?"""
    _require_v2(context)
    moment = now or datetime.now(timezone.utc)
    records, ignored = read_ledger(repo_root, context, moment)
    table = evaluate_capabilities(context, records, moment)
    blocked = [name for name in context.capabilities if table[name]["status"] not in USABLE]
    return {
        "ok": not blocked, "profile": context.profile, "tenant_id": context.tenant_id,
        "workspace_id": context.workspace_id, "case_id": context.case_id,
        "hunt_id": context.hunt_id, "window": asdict(context.window),
        "required": list(context.capabilities), "capabilities": table,
        "usable": [name for name, entry in table.items() if entry["status"] in USABLE],
        "blocked": blocked, "ignored_records": ignored,
    }


def _write_unique(repo_root: "str | Path", context: InvestigationContext, subdir: str,
                  suffix: str, content: str, now: datetime) -> str:
    """Exclusive-create `<stamp>-<suffix>` (0400) in a private subdirectory of the case."""
    moment = now
    with open_report_directory(repo_root, context) as case_fd:
        try:
            os.mkdir(subdir, mode=0o700, dir_fd=case_fd)
        except FileExistsError:
            pass
        directory = os.open(subdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=case_fd)
        try:
            for _ in range(100):
                name = f"{_stamp(moment)}-{suffix}"
                try:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o400, dir_fd=directory)
                except FileExistsError:
                    moment += timedelta(microseconds=1)
                    continue
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                return name
        finally:
            os.close(directory)
    raise ContextError("Unable to allocate a unique file name")


def _record_check(context: InvestigationContext, *, repo_root: "str | Path", capability: str,
                  status: str, method: str, detail: str, via: "str | None" = None,
                  ttl_hours: int = DEFAULT_TTL_HOURS, now: "datetime | None" = None) -> str:
    moment = now or datetime.now(timezone.utc)
    checked = moment.replace(microsecond=0)
    record = {
        "schema_version": LEDGER_SCHEMA, "kind": "capability_check",
        "profile": context.profile, "tenant_id": context.tenant_id,
        "workspace_id": context.workspace_id if CAPABILITIES[capability][1] else None,
        "case_id": context.case_id, "capability": capability, "status": status,
        "method": method, "checked_at": _utc_text(checked),
        "expires_at": _utc_text(checked + timedelta(hours=ttl_hours)),
        "detail": detail, "via": via,
    }
    _validate_record(record, context, moment)  # never write what the reader would reject
    return _write_unique(repo_root, context, "ledger", capability + ".json",
                         json.dumps(record, indent=2, sort_keys=True) + "\n", moment)


def verify_capabilities(context: InvestigationContext, *, repo_root: "str | Path" = REPO_ROOT,
                        capabilities: "Iterable[str] | None" = None,
                        ttl_hours: int = DEFAULT_TTL_HOURS, now: "datetime | None" = None) -> dict:
    """Run tenant-pinned, read-only CLI probes and record each outcome in the ledger."""
    _require_v2(context)
    ttl = _ttl(ttl_hours)
    if capabilities:
        names = sorted(set(capabilities))
        for name in names:
            if name not in CAPABILITIES:
                raise ContextError("Unknown capability")
            if CAPABILITIES[name][0] != "cli":
                raise ContextError(f"{name} is attested from its MCP session; use the attest command")
    else:
        names = [name for name, (proof, _) in CAPABILITIES.items()
                 if proof == "cli" and (name == "tenant_identity" or name in context.capabilities)]
    unsupported = static_unsupported(context)
    results: dict = {}
    for name in names:
        if name in unsupported:
            results[name] = {"status": "unsupported", "detail": unsupported[name], "recorded": False}
            continue
        try:
            _run_probe(name, context)
            status, detail = "verified", PROBE_DETAIL[name]
        except ProbeDenied as error:
            status, detail = "denied", _detail(str(error), truncate=True)
        except ContextError as error:
            status, detail = "unverified", _detail(str(error), truncate=True)
        record = _record_check(context, repo_root=repo_root, capability=name, status=status,
                               method="cli_probe", detail=detail, ttl_hours=ttl, now=now)
        results[name] = {"status": status, "detail": detail, "recorded": True, "record": record}
    return {
        "ok": bool(results) and all(item["status"] == "verified" for item in results.values()),
        "profile": context.profile, "tenant_id": context.tenant_id,
        "workspace_id": context.workspace_id, "case_id": context.case_id, "capabilities": results,
    }


def attest_capability(context: InvestigationContext, *, repo_root: "str | Path" = REPO_ROOT,
                      capability: str, status: str, detail: str, via: "str | None" = None,
                      ttl_hours: int = DEFAULT_TTL_HOURS, now: "datetime | None" = None) -> dict:
    """Record the agent's claim about an MCP session this module cannot inspect."""
    _require_v2(context)
    if capability not in CAPABILITIES:
        raise ContextError("Unknown capability")
    if CAPABILITIES[capability][0] != "attested":
        raise ContextError(f"{capability} is proven by the CLI; use the verify command")
    if status not in LEDGER_STATUSES["agent_attestation"]:
        raise ContextError("status must be attested, denied, or unverified")
    unsupported = static_unsupported(context)
    if capability in unsupported:
        raise ContextError(f"{capability} is unsupported for this case: {unsupported[capability]}")
    record = _record_check(
        context, repo_root=repo_root, capability=capability, status=status,
        method="agent_attestation", detail=_detail(detail), via=via, ttl_hours=_ttl(ttl_hours), now=now,
    )
    return {
        "ok": True, "profile": context.profile, "tenant_id": context.tenant_id,
        "case_id": context.case_id, "capability": capability, "status": status,
        "proof": "attested", "record": record,
    }


def _read_kql(path: "str | Path", repo_root: "str | Path") -> str:
    root = Path(repo_root).resolve(strict=True)
    candidate = Path(path)
    message = "KQL file must be an existing .kql file inside the repository"
    try:
        resolved = (candidate if candidate.is_absolute() else root / candidate).resolve(strict=True)
        resolved.relative_to(root)
        if resolved.suffix != ".kql" or not resolved.is_file():
            raise ValueError
    except (OSError, ValueError):
        raise ContextError(message) from None
    if resolved.stat().st_size > MAX_QUERY_BYTES:
        raise ContextError("KQL file is too large")
    try:
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ContextError("KQL file is unreadable or not UTF-8") from None
    if not text.strip():
        raise ContextError("KQL file is empty")
    return text


def run_query(context: InvestigationContext, kql_file: "str | Path", name: str, *,
              repo_root: "str | Path" = REPO_ROOT, max_rows: int = 10000,
              now: "datetime | None" = None) -> dict:
    """Run one read-only query in the case workspace over the case window.

    Requires a fresh CLI-verified workspace_query. The result is written only to
    this case's evidence directory; the return value is a summary, never rows.
    """
    _require_v2(context)
    if context.workspace is None or "workspace_query" not in context.capabilities:
        raise ContextError("workspace_query is not a declared capability of this case")
    _slug(name, "name")
    if type(max_rows) is not int or not 1 <= max_rows <= 100000:
        raise ContextError("max_rows must be an integer between 1 and 100000")
    moment = now or datetime.now(timezone.utc)
    records, _ = read_ledger(repo_root, context, moment)
    status = evaluate_capabilities(context, records, moment)["workspace_query"]["status"]
    if status != "verified":
        raise ContextError(f"workspace_query is {status}; run the verify command first")
    kql = _read_kql(kql_file, repo_root)
    token = _cli_token(context.tenant_id, LOG_ANALYTICS)
    window = context.window
    response = _post_json(_workspace_query_url(context), token,
                          {"query": kql, "timespan": f"{window.start_utc}/{window.end_utc}"})
    columns, rows = _query_rows(response)
    kept = rows[:max_rows]
    digest = hashlib.sha256(kql.encode("utf-8")).hexdigest()
    payload = {
        "schema_version": 1, "kind": "query_result", "profile": context.profile,
        "tenant_id": context.tenant_id, "workspace_id": context.workspace_id,
        "case_id": context.case_id, "hunt_id": context.hunt_id, "name": name,
        "query": kql, "query_sha256": digest, "window": asdict(window),
        "executed_at": _utc_text(moment), "status": "ok", "row_count": len(kept),
        "total_rows": len(rows), "truncated": len(rows) > len(kept),
        "columns": [{"name": c["name"], "type": c.get("type")} for c in columns], "rows": kept,
    }
    written = _write_unique(repo_root, context, "evidence", name + ".json",
                            json.dumps(payload, sort_keys=True) + "\n", moment)
    return {
        "ok": True, "profile": context.profile, "tenant_id": context.tenant_id,
        "workspace_id": context.workspace_id, "case_id": context.case_id, "name": name,
        "evidence_path": f"{context.report_dir}/evidence/{written}", "query_sha256": digest,
        "window": asdict(window), "row_count": len(kept), "total_rows": len(rows),
        "truncated": len(rows) > len(kept), "columns": [c["name"] for c in columns],
    }


def render_mcp(profile: TenantProfile) -> dict:
    """Per-tenant MCP server entries for the operator to merge by hand; changes nothing."""
    servers: dict = {}
    omitted: dict = {}
    for key, url in MCP_SERVICES.items():
        reference = getattr(profile.connections, key)
        if reference is None:
            omitted[key] = "No connection reference is declared for this profile"
        elif key == "triage" and profile.triage_home_tenant_id != profile.tenant_id:
            omitted[key] = ("Triage is home-tenant only: the declared home tenant is missing "
                            "or differs from this tenant")
        elif reference in servers:
            raise ContextError("Connection reference names must be unique within a profile")
        else:
            servers[reference] = {
                "type": "http", "url": url,
                "headers": {"x-mcp-client-tenant-id": profile.tenant_id},
            }
    return {
        "ok": True, "profile": profile.name, "tenant_id": profile.tenant_id,
        "servers": servers, "omitted": omitted,
        "notes": [
            "Merge these entries into the MCP configuration yourself; this command configures nothing.",
            "Restart each server and sign in with an account that is a member or B2B guest of this tenant.",
            "The header selects the tenant; it grants no roles, consent, or Triage guest support.",
        ],
    }


def tenant_mappings(context: InvestigationContext, config_path: "str | Path") -> dict:
    """Only the selected profile's GUID tables; never another tenant's or the root's."""
    profile = select_profile(load_profiles(config_path), context.profile)
    if profile.tenant_id != context.tenant_id:
        raise ContextError("Profile tenant differs from the context tenant")
    return {
        "ok": True, "profile": profile.name, "tenant_id": profile.tenant_id,
        "sit_mapping": dict(profile.sit_mapping), "label_mapping": dict(profile.label_mapping),
        "sit_priority": dict(profile.sit_priority),
    }


def _bound_context(path: "str | Path", repo_root: "str | Path", config: "str | Path") -> InvestigationContext:
    context = load_context(path, repo_root)
    checked = validate_context(context, config, repo_root=repo_root)
    if not checked["ok"]:
        raise ContextError(checked["sources"]["offline"].get("error", "Context validation failed"))
    return context


def require_case_context(context: "str | Path | None", *, repo_root: "str | Path" = REPO_ROOT,
                         config_path: "str | Path | None" = None) -> "InvestigationContext | None":
    """Resolve the tenant case a legacy report writer is bound to.

    None means no registry is configured, so the writer may keep using its legacy
    shared directories. With a registry those directories are never a safe
    destination: a context is mandatory and is validated against the registry.
    """
    config = Path(config_path) if config_path is not None else Path(repo_root) / "config.json"
    if context is None:
        if tenant_registry_configured(config):
            raise ContextError(
                "A tenant registry is configured, so this command needs a tenant case: pass "
                "--context reports/tenants/<profile>/<case>/context.json "
                "(create one with scripts/tenant_context.py create)")
        return None
    return _bound_context(context, repo_root, config)


def check_evidence_tenant(data: object, context: InvestigationContext) -> None:
    """Refuse evidence that declares a tenant other than the case it is written into.

    Evidence without a tenant stamp is accepted: the explicit context is then the
    only binding, so callers should say so.
    """
    declared = data.get("tenant_id") if isinstance(data, dict) else None
    if declared in (None, ""):
        return
    if not isinstance(declared, str) or declared.strip().lower() != context.tenant_id:
        raise ContextError("Evidence declares a different tenant than the supplied case context")


def write_case_file(repo_root: "str | Path", context: InvestigationContext, name: str,
                    content: "str | bytes", *, mode: int = 0o600) -> Path:
    """Exclusive-create one plain .json/.html/.txt file inside the case directory."""
    if not WRITER_NAME.match(name) or name == "context.json":
        raise ContextError("Output must be a plain .json, .html or .txt file name other than context.json")
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    with open_report_directory(repo_root, context) as directory:
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         mode, dir_fd=directory)
        except FileExistsError:
            raise ContextError("Output already exists in the case directory; retry for a new name") from None
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            os.unlink(name, dir_fd=directory)
            raise
    return Path(repo_root).resolve() / context.report_dir / name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--config", type=Path, help="Defaults to <repo-root>/config.json")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("profiles", help="List selectable profiles without credentials")
    create = commands.add_parser("create", help="Exclusive-create an immutable context")
    create.add_argument("--profile")
    target = create.add_mutually_exclusive_group(required=True)
    target.add_argument("--workspace", help="Explicit registered workspace GUID")
    target.add_argument("--no-workspace", action="store_true",
                        help="Defender-only case: bind no Sentinel workspace")
    create.add_argument("--case", "--run", dest="case_id", required=True)
    create.add_argument("--lookback-days", required=True, type=int)
    create.add_argument("--capability", action="append", choices=sorted(CAPABILITIES),
                        help="Required capability (repeatable); tenant_identity is always required. "
                             "Default: tenant_identity plus workspace_arm when a workspace is bound")
    create.add_argument("--hunt-id", help="Shared hunt ID; the case must then be <hunt-id>-NN")
    create.add_argument("--window-end", help="Pinned UTC window end, YYYY-MM-DDTHH:MM:SSZ")
    create.add_argument("--validate-live", action="store_true")
    validate = commands.add_parser("validate", help="Validate an existing context; never rewrite it")
    validate.add_argument("context", type=Path)
    validate.add_argument("--validate-live", action="store_true")
    verify = commands.add_parser("verify", help="Probe CLI-provable capabilities and record the results")
    verify.add_argument("context", type=Path)
    verify.add_argument("--capability", action="append",
                        choices=sorted(n for n, (p, _) in CAPABILITIES.items() if p == "cli"))
    verify.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS)
    attest = commands.add_parser("attest", help="Record an MCP-session capability claim (not proof)")
    attest.add_argument("context", type=Path)
    attest.add_argument("--capability", required=True,
                        choices=sorted(n for n, (p, _) in CAPABILITIES.items() if p == "attested"))
    attest.add_argument("--status", required=True, choices=LEDGER_STATUSES["agent_attestation"])
    attest.add_argument("--detail", required=True)
    attest.add_argument("--via", choices=HUNTING_VIA)
    attest.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS)
    ready = commands.add_parser("readiness", help="Read-only capability readiness for a context")
    ready.add_argument("context", type=Path)
    query = commands.add_parser("query", help="Run one read-only workspace query over the case window")
    query.add_argument("context", type=Path)
    query.add_argument("--kql-file", required=True, type=Path)
    query.add_argument("--name", required=True)
    query.add_argument("--max-rows", type=int, default=10000)
    render = commands.add_parser("render-mcp", help="Print per-tenant MCP entries; configures nothing")
    render.add_argument("--profile")
    mappings = commands.add_parser("mappings", help="Print only this tenant's SIT/label tables")
    mappings.add_argument("context", type=Path)
    args = parser.parse_args(argv)
    config = args.config or args.repo_root / "config.json"
    try:
        if args.command == "profiles":
            profiles = load_profiles(config)
            output = {
                "profiles": [
                    {"profile": p.name, "tenant_id": p.tenant_id,
                     "workspaces": [asdict(workspace) for workspace in p.workspaces],
                     "connections": asdict(p.connections),
                     "triage_home_tenant_id": p.triage_home_tenant_id}
                    for p in profiles.values()
                ],
                "warnings": profile_warnings(profiles),
            }
        elif args.command == "render-mcp":
            output = render_mcp(select_profile(load_profiles(config), args.profile))
        elif args.command in ("verify", "attest", "readiness", "query", "mappings"):
            context = _bound_context(args.context, args.repo_root, config)
            if args.command == "verify":
                output = verify_capabilities(context, repo_root=args.repo_root,
                                             capabilities=args.capability, ttl_hours=args.ttl_hours)
            elif args.command == "attest":
                output = attest_capability(
                    context, repo_root=args.repo_root, capability=args.capability,
                    status=args.status, detail=args.detail, via=args.via, ttl_hours=args.ttl_hours)
            elif args.command == "readiness":
                output = readiness(context, repo_root=args.repo_root)
            elif args.command == "query":
                output = run_query(context, args.kql_file, args.name,
                                   repo_root=args.repo_root, max_rows=args.max_rows)
            else:
                output = tenant_mappings(context, config)
        else:
            if args.command == "create":
                context = create_context(
                    config, profile=args.profile, workspace_id=args.workspace, case_id=args.case_id,
                    lookback_days=args.lookback_days, repo_root=args.repo_root,
                    capabilities=args.capability, hunt_id=args.hunt_id, window_end=args.window_end,
                )
            else:
                context = load_context(args.context, args.repo_root)
            output = validate_context(context, config, repo_root=args.repo_root,
                                      validate_live=args.validate_live)
            output["context_path"] = str(context_path(args.repo_root, context))
        print(json.dumps(output, sort_keys=True))
        return 0 if output.get("ok", True) else 1
    except ContextError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1
    except OSError:
        print(json.dumps({"ok": False, "error": "Unable to access context files; check repository paths and permissions"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
