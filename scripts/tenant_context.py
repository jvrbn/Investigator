#!/usr/bin/env python3
"""Tenant-bound, exclusive-create investigation contexts (Python standard library)."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID


REPO_ROOT = Path(__file__).resolve().parents[1]
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class ContextError(ValueError):
    """A safe, non-credential-bearing error for CLI consumers."""


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


@dataclass(frozen=True)
class InvestigationContext:
    profile: str
    tenant_id: str
    workspace: Workspace
    case_id: str
    lookback_days: int
    connections: Connections
    report_dir: str
    created_at: str
    memory_file: str | None = None
    triage_home_tenant_id: str | None = None
    schema_version: int = 1

    @property
    def workspace_id(self) -> str:
        return self.workspace.id

    def to_dict(self) -> dict:
        return asdict(self)


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


def _profile(name: str, raw: object, *, legacy: bool = False) -> TenantProfile:
    values = _object(raw, "tenant profile")
    allowed = {
        "tenant_id", "subscription_id", "sentinel_workspace_id", "azure_mcp",
        "memory_file", "connections", "workspaces", "triage_home_tenant_id",
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
    _workspace(asdict(context.workspace))
    _connections(asdict(context.connections))
    if context.schema_version != 1 or type(context.schema_version) is not int:
        raise ContextError("Unsupported context schema_version")
    if type(context.lookback_days) is not int or not 1 <= context.lookback_days <= 3650:
        raise ContextError("lookback_days must be an integer between 1 and 3650")
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
    profile: str | None = None, workspace_id: str, case_id: str,
    lookback_days: int, repo_root: str | Path = REPO_ROOT,
) -> InvestigationContext:
    selected = select_profile(load_profiles(config_path), profile)
    workspace_id = _guid(workspace_id, "workspace_id")
    workspace = next((item for item in selected.workspaces if item.id == workspace_id), None)
    if workspace is None:
        raise ContextError("Explicit workspace is not registered in selected profile")
    context = InvestigationContext(
        selected.name, selected.tenant_id, workspace, case_id, lookback_days,
        selected.connections, _report_dir(selected.name, case_id),
        datetime.now(timezone.utc).isoformat(), selected.memory_file,
        selected.triage_home_tenant_id,
    )
    _check_context(context)
    content = json.dumps(asdict(context), indent=2, sort_keys=True) + "\n"
    with _directory(Path(repo_root), tuple(context.report_dir.split("/")),
                    create=True, exclusive_last=True) as directory:
        fd = os.open("context.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o400, dir_fd=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
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
        if set(raw) != set(InvestigationContext.__dataclass_fields__):
            raise ContextError("Context fields do not match schema_version 1")
        raw["workspace"] = _workspace(raw.get("workspace"))
        raw["connections"] = _connections(raw.get("connections"))
        context = InvestigationContext(**raw)
    except (OSError, TypeError, ValueError):
        raise ContextError("Unable to load valid immutable context") from None
    _check_context(context)
    if relative.as_posix() != context.report_dir + "/context.json":
        raise ContextError("Context file location conflicts with tenant/case binding")
    return context


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get_json(url: str, token: str) -> dict:
    request = Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        # Never forward a bearer token to a redirect target.
        with build_opener(_NoRedirect()).open(request, timeout=30) as response:
            return _object(json.load(response), "authenticated response")
    except HTTPError as error:
        raise ContextError(f"Authenticated GET failed (HTTP {error.code})") from None
    except (URLError, OSError, ValueError):
        raise ContextError("Authenticated GET failed or returned invalid JSON") from None


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


def validate_context(
    context: InvestigationContext, config_path: str | Path = REPO_ROOT / "config.json", *,
    repo_root: str | Path = REPO_ROOT, validate_live: bool = False,
) -> dict:
    """Offline binding checks plus optional fail-closed, authenticated CLI/HTTP proofs."""
    result = {
        "ok": False, "mode": "authenticated" if validate_live else "offline",
        "profile": context.profile,
        "sources": {
            "offline": {"status": "pending"},
            "graph_cli": {"status": "not_checked", "authenticated": False},
            "workspace_cli": {"status": "not_checked", "authenticated": False},
            "data_lake": {"status": "unverified", "reason": "MCP identity not authenticated by CLI"},
            "graph": {"status": "unverified", "reason": "MCP identity not authenticated by CLI"},
            "triage": {"status": "unverified", "reason": "MCP identity/home tenant not authenticated by CLI"},
        },
    }
    try:
        _check_context(context)
        persisted = load_context(context_path(repo_root, context), repo_root)
        if context != persisted:
            raise ContextError("Context differs from persisted immutable manifest")
        profile = select_profile(load_profiles(config_path), context.profile)
        workspace = next((item for item in profile.workspaces if item.id == context.workspace.id), None)
        if (
            context.tenant_id != profile.tenant_id or context.workspace != workspace
            or context.connections != profile.connections or context.memory_file != profile.memory_file
            or context.triage_home_tenant_id != profile.triage_home_tenant_id
        ):
            raise ContextError("Profile configuration changed; create a new context, do not rebind this run")
        if context.connections.triage and context.triage_home_tenant_id != context.tenant_id:
            raise ContextError("Triage requires a declared home tenant matching the selected tenant")
        result["sources"]["offline"] = {"status": "passed", "authenticated": False}
    except ContextError as error:
        result["sources"]["offline"] = {"status": "failed", "error": str(error)}
        return result
    if not validate_live:
        result["ok"] = True
        return result
    for name, check in (("graph_cli", _authenticated_graph), ("workspace_cli", _authenticated_workspace)):
        try:
            check(context)
            result["sources"][name] = {"status": "verified", "authenticated": True}
        except ContextError as error:
            result["sources"][name] = {"status": "failed", "authenticated": False, "error": str(error)}
            return result
    result["ok"] = True
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--config", type=Path, help="Defaults to <repo-root>/config.json")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("profiles", help="List selectable profiles without credentials")
    create = commands.add_parser("create", help="Exclusive-create an immutable context")
    create.add_argument("--profile")
    create.add_argument("--workspace", required=True, help="Explicit registered workspace GUID")
    create.add_argument("--case", "--run", dest="case_id", required=True)
    create.add_argument("--lookback-days", required=True, type=int)
    create.add_argument("--validate-live", action="store_true")
    validate = commands.add_parser("validate", help="Validate an existing context; never rewrite it")
    validate.add_argument("context", type=Path)
    validate.add_argument("--validate-live", action="store_true")
    args = parser.parse_args(argv)
    config = args.config or args.repo_root / "config.json"
    try:
        if args.command == "profiles":
            profiles = load_profiles(config)
            output = {"profiles": [
                {"profile": p.name, "tenant_id": p.tenant_id,
                 "workspaces": [asdict(workspace) for workspace in p.workspaces]}
                for p in profiles.values()
            ]}
        else:
            if args.command == "create":
                context = create_context(
                    config, profile=args.profile, workspace_id=args.workspace, case_id=args.case_id,
                    lookback_days=args.lookback_days, repo_root=args.repo_root,
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
