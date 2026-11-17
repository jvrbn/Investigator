import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from dataclasses import FrozenInstanceError, asdict, replace
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from uuid import uuid4

from scripts import tenant_context as tc


TENANT = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
SUB = "33333333-3333-4333-8333-333333333333"
WORKSPACE = "44444444-4444-4444-8444-444444444444"
GUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
GUID_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def profile():
    return {
        "tenant_id": TENANT,
        "subscription_id": SUB,
        "sentinel_workspace_id": WORKSPACE,
        "azure_mcp": {
            "tenant": TENANT, "subscription": SUB,
            "resource_group": "rg-example", "workspace_name": "la-example",
        },
        "memory_file": "example.md",
        "connections": {"graph": "graph-example", "data_lake": "lake-example"},
    }


class ContextTestCase(unittest.TestCase):
    def setUp(self):
        # All scratch data stays under the repository, never system temp directories.
        self.root = Path(__file__).resolve().parents[1] / (".tenant-context-test-" + uuid4().hex)
        self.root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.root)
        self.config = self.root / "config.json"
        self.write_config({"tenants": {"example": profile()}})

    def write_config(self, value):
        self.config.write_text(json.dumps(value), encoding="utf-8")

    def create(self, **kwargs):
        return tc.create_context(
            self.config, repo_root=self.root, workspace_id=WORKSPACE,
            case_id=kwargs.pop("case_id", "case-one"), lookback_days=7, **kwargs,
        )

    def validate(self, context, **kwargs):
        return tc.validate_context(context, self.config, repo_root=self.root, **kwargs)

    def cli(self, *arguments):
        output = io.StringIO()
        with patch("sys.stdout", output):
            code = tc.main(["--repo-root", str(self.root), *arguments])
        return code, json.loads(output.getvalue())

    def _live_responses(self):
        return [
            {"value": [{"id": TENANT}]},
            {"subscriptionId": SUB, "tenantId": TENANT},
            {"id": f"/subscriptions/{SUB}/resourceGroups/rg-example/providers/"
                   "Microsoft.OperationalInsights/workspaces/la-example",
             "properties": {"customerId": WORKSPACE}},
        ]

    def _token_response(self, tenant=TENANT):
        return subprocess.CompletedProcess([], 0, json.dumps({
            "tenant": tenant, "accessToken": "mock-token-never-log",
        }), "")


class TenantContextTests(ContextTestCase):
    def test_explicit_profile_selection_and_no_root_fallback(self):
        self.write_config({"tenants": {"example": profile(), "second": profile()}})
        with self.assertRaises(tc.ContextError):
            self.create()
        self.assertEqual(self.create(profile="second").profile, "second")
        incomplete = profile()
        del incomplete["tenant_id"]
        self.write_config({**profile(), "tenants": {"example": incomplete}})
        with self.assertRaises(tc.ContextError):
            tc.load_profiles(self.config)
        self.write_config({**profile(), "tenants": {}})
        self.assertEqual(list(tc.load_profiles(self.config)), ["legacy"])
        for invalid_registry in (None, [], "invalid"):
            self.write_config({**profile(), "tenants": invalid_registry})
            with self.assertRaises(tc.ContextError):
                tc.load_profiles(self.config)

    def test_legacy_config_supported_without_copying_tokens(self):
        self.write_config({**profile(), "ipinfo_token": "private-secret", "output_dir": "../unsafe"})
        context = self.create()
        self.assertEqual(context.profile, "legacy")
        text = tc.context_path(self.root, context).read_text()
        self.assertNotIn("private-secret", text)
        self.assertNotIn("output_dir", text)
        self.assertTrue(self.validate(context)["ok"])

    def test_workspace_selection_never_crosses_profiles(self):
        config = profile()
        config["workspaces"] = [{"id": OTHER, "name": "another-workspace"}]
        self.write_config({"tenants": {"example": config}})
        context = tc.create_context(self.config, workspace_id=OTHER, case_id="other",
                                    lookback_days=90, repo_root=self.root)
        self.assertIsNone(context.workspace.subscription_id)
        with self.assertRaises(tc.ContextError):
            tc.create_context(self.config, workspace_id=TENANT, case_id="wrong",
                              lookback_days=7, repo_root=self.root)
        with self.assertRaises(TypeError):
            tc.create_context(self.config, case_id="missing", lookback_days=7, repo_root=self.root)

    def test_immutable_snapshot_roundtrip_and_exclusive_run(self):
        context = self.create()
        loaded = tc.load_context(tc.context_path(self.root, context), self.root)
        self.assertEqual(context, loaded)
        with self.assertRaises(FrozenInstanceError):
            context.tenant_id = OTHER
        with self.assertRaises(FrozenInstanceError):
            context.connections.graph = "different"
        with self.assertRaises(tc.ContextError):
            self.create()
        self.assertEqual(context, tc.load_context(tc.context_path(self.root, context), self.root))
        modified = replace(context, lookback_days=30)
        self.assertFalse(self.validate(modified)["ok"])
        self.assertFalse(tc.context_path(self.root, context).stat().st_mode & 0o222)

    def test_configuration_change_cannot_rebind_existing_context(self):
        context = self.create()
        changed = profile()
        changed["tenant_id"] = OTHER
        changed["azure_mcp"]["tenant"] = OTHER
        self.write_config({"tenants": {"example": changed}})
        self.assertFalse(self.validate(context)["ok"])

    def test_javascript_utc_timestamp_roundtrip(self):
        stamp = "2026-01-01T12:00:00.000Z"
        context = self.create()
        path = tc.context_path(self.root, context)
        os.chmod(path, 0o600)
        # A v2 manifest written by JavaScript pins the window to its own clock.
        raw = context.to_dict()
        raw.update(created_at=stamp, window={"start_utc": "2025-12-25T12:00:00Z",
                                             "end_utc": "2026-01-01T12:00:00Z"})
        path.write_text(json.dumps(raw))
        loaded = tc.load_context(path, self.root)
        self.assertEqual(loaded.created_at, stamp)
        self.assertEqual(loaded.window.end_utc, "2026-01-01T12:00:00Z")
        self.assertTrue(self.validate(loaded)["ok"])
        # Existing v1 manifests keep loading and validating unchanged.
        legacy = {key: value for key, value in context.to_dict().items()
                  if key not in ("window", "hunt_id", "capabilities")}
        legacy.update(schema_version=1, created_at=stamp)
        path.write_text(json.dumps(legacy))
        loaded = tc.load_context(path, self.root)
        self.assertEqual((loaded.schema_version, loaded.window, loaded.capabilities), (1, None, ()))
        self.assertTrue(self.validate(loaded)["ok"])
        with self.assertRaises(tc.ContextError):
            tc.readiness(loaded, repo_root=self.root)

    def test_malformed_profiles_and_credentials_are_rejected(self):
        for field, value in (
            ("tenant_id", "not-a-guid"),
            ("connections", {"graph": "Bearer secret"}),
            ("connections", {"graph": {"token": "secret"}}),
            ("connections", {"graph": "https://server.example/"}),
            ("connections", {"token": "secret"}),
            ("accessToken", "secret"),
            ("memory_file", "../memory.md"),
            ("workspaces", [{"id": WORKSPACE}, {"id": WORKSPACE}]),
            ("azure_mcp", {"tenant": OTHER}),
        ):
            with self.subTest(field=field, value=value):
                invalid = profile()
                invalid[field] = value
                self.write_config({"tenants": {"example": invalid}})
                with self.assertRaises(tc.ContextError):
                    tc.load_profiles(self.config)

    def test_path_traversal_and_invalid_lookback_rejected(self):
        for value in ("../escape", "/absolute", "a/b", "a\\b", "..", "BadCase"):
            with self.subTest(value=value), self.assertRaises(tc.ContextError):
                self.create(case_id=value)
        for value in (0, -1, True, 1.5, 3651):
            with self.subTest(value=value), self.assertRaises(tc.ContextError):
                tc.create_context(self.config, workspace_id=WORKSPACE, case_id="invalid",
                                  lookback_days=value, repo_root=self.root)
        with self.assertRaises(tc.ContextError):
            tc.load_context(self.root / "../context.json", self.root)
        self.assertFalse((self.root / "reports").exists())

    def test_symlink_escape_rejected_on_create_and_load(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "reports").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(tc.ContextError):
            self.create()
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / "reports").unlink()
        context = self.create()
        path = tc.context_path(self.root, context)
        os.chmod(path, 0o600)
        original = path.read_text()
        path.unlink()
        target = outside / "context.json"
        target.write_text(original)
        path.symlink_to(target)
        with self.assertRaises(tc.ContextError):
            tc.load_context(path, self.root)

    def test_manifest_location_and_unexpected_fields_rejected(self):
        context = self.create()
        path = tc.context_path(self.root, context)
        os.chmod(path, 0o600)
        raw = context.to_dict()
        raw["case_id"] = "different"
        raw["report_dir"] = "reports/tenants/example/different"
        path.write_text(json.dumps(raw))
        with self.assertRaises(tc.ContextError):
            tc.load_context(path, self.root)
        raw = context.to_dict()
        raw["accessToken"] = "must-not-be-accepted"
        path.write_text(json.dumps(raw))
        with self.assertRaises(tc.ContextError):
            tc.load_context(path, self.root)

    def test_offline_is_not_authenticated_and_mcp_stays_unverified(self):
        context = self.create()
        with patch.object(tc.subprocess, "run") as process:
            result = self.validate(context)
        process.assert_not_called()
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "offline")
        self.assertEqual(result["sources"]["graph_cli"]["status"], "not_checked")
        for source in ("data_lake", "graph", "triage"):
            self.assertEqual(result["sources"][source]["status"], "unverified")

    def test_safe_report_directory_fd(self):
        context = self.create()
        with tc.open_report_directory(self.root, context) as fd:
            file_fd = os.open("evidence.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=fd)
            os.close(file_fd)
        self.assertTrue((tc.context_path(self.root, context).parent / "evidence.json").is_file())

    def test_triage_requires_matching_declared_home_tenant(self):
        config = profile()
        config["connections"]["triage"] = "triage-example"
        self.write_config({"tenants": {"example": config}})
        self.assertFalse(self.validate(self.create())["ok"])
        config["triage_home_tenant_id"] = TENANT
        self.write_config({"tenants": {"example": config}})
        self.assertTrue(self.validate(self.create(case_id="triage"))["ok"])

    def test_live_authentication_gets_verify_tenant_and_workspace(self):
        context = self.create()
        responses = self._live_responses()
        opener = unittest.mock.Mock()
        opener.open.side_effect = [
            io.BytesIO(json.dumps(value).encode()) for value in responses
        ]
        with patch.object(tc.subprocess, "run", return_value=self._token_response()) as process, \
                patch.object(tc, "build_opener", return_value=opener):
            result = self.validate(context, validate_live=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "authenticated")
        for call in process.call_args_list:
            command = call.args[0]
            self.assertEqual(command[:3], ["az", "account", "get-access-token"])
            self.assertEqual(command[command.index("--tenant") + 1], TENANT)
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([request.get_method() for request in requests], ["GET"] * 3)
        self.assertTrue(requests[0].full_url.startswith("https://graph.microsoft.com/"))
        self.assertTrue(all(request.get_header("Authorization") == "Bearer mock-token-never-log"
                            for request in requests))
        self.assertNotIn("mock-token-never-log", json.dumps(result))
        self.assertEqual(result["sources"]["data_lake"]["status"], "unverified")

    def test_wrong_token_tenant_fails_before_network(self):
        context = self.create()
        with patch.object(tc.subprocess, "run", return_value=self._token_response(OTHER)), \
                patch.object(tc, "_get_json") as http:
            result = self.validate(context, validate_live=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["sources"]["graph_cli"]["status"], "failed")
        http.assert_not_called()

    def test_wrong_organization_workspace_and_subscription_fail_closed(self):
        for index, value in (
            (0, {"value": [{"id": OTHER}]}),
            (1, {"subscriptionId": SUB, "tenantId": OTHER}),
            (1, {"subscriptionId": OTHER, "tenantId": TENANT}),
            (2, {"id": "wrong", "properties": {"customerId": WORKSPACE}}),
            (2, {"id": self._live_responses()[2]["id"], "properties": {"customerId": OTHER}}),
        ):
            with self.subTest(index=index, value=value):
                context = self.create(case_id="case-" + uuid4().hex)
                responses = self._live_responses()
                responses[index] = value
                with patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                        patch.object(tc, "_get_json", side_effect=responses):
                    self.assertFalse(self.validate(context, validate_live=True)["ok"])

    def test_token_acquisition_errors_do_not_leak_output_or_fallback(self):
        for response in (
            subprocess.CompletedProcess([], 1, "", "secret-stderr"),
            subprocess.CompletedProcess([], 0, "secret-invalid-json", ""),
            subprocess.CompletedProcess([], 0, '{"accessToken":"secret"}', ""),
        ):
            context = self.create(case_id="case-" + uuid4().hex)
            with patch.object(tc.subprocess, "run", return_value=response), \
                    patch.object(tc, "_get_json") as http:
                result = self.validate(context, validate_live=True)
            self.assertFalse(result["ok"])
            self.assertNotIn("secret", json.dumps(result))
            http.assert_not_called()
        with patch.object(tc.subprocess, "run", side_effect=FileNotFoundError):
            self.assertFalse(self.validate(self.create(case_id="missing-az"), validate_live=True)["ok"])

    def test_http_permissions_network_and_invalid_json_fail_closed(self):
        context = self.create()
        for error in (
            HTTPError("https://example.invalid", 401, "secret error", {}, None),
            HTTPError("https://example.invalid", 403, "secret error", {}, None),
            URLError("secret error"),
        ):
            with patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                    patch.object(tc, "build_opener") as opener:
                opener.return_value.open.side_effect = error
                result = self.validate(context, validate_live=True)
            self.assertFalse(result["ok"])
            self.assertNotIn("secret error", json.dumps(result))
        with patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                patch.object(tc, "build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(b"invalid")
            self.assertFalse(self.validate(context, validate_live=True)["ok"])
        self.assertIsNone(tc._NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere"))

    def test_cli_json_exit_codes_and_live_failure_preserves_context(self):
        output = io.StringIO()
        arguments = ["--repo-root", str(self.root)]
        with patch("sys.stdout", output):
            self.assertEqual(tc.main(arguments + ["profiles"]), 0)
        self.assertEqual(json.loads(output.getvalue())["profiles"][0]["profile"], "example")
        output = io.StringIO()
        with patch("sys.stdout", output), \
                patch.object(tc.subprocess, "run", side_effect=FileNotFoundError):
            code = tc.main(arguments + ["create", "--workspace", WORKSPACE, "--case", "cli",
                                        "--lookback-days", "7", "--validate-live"])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertFalse(result["ok"])
        self.assertTrue(Path(result["context_path"]).is_file())
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(tc.main(arguments + ["validate", result["context_path"]]), 0)
        self.assertEqual(json.loads(output.getvalue())["mode"], "offline")


V2_KEYS = {
    "profile", "tenant_id", "workspace", "case_id", "lookback_days", "connections", "report_dir",
    "created_at", "memory_file", "triage_home_tenant_id", "schema_version", "window", "hunt_id",
    "capabilities",
}
QUERY_RESPONSE = {"tables": [{
    "name": "PrimaryResult",
    "columns": [{"name": "Account", "type": "string"}, {"name": "Count", "type": "long"}],
    "rows": [["a", 1], ["b", 2], ["c", 3]],
}]}
PROBE_RESPONSE = {"tables": [{"name": "PrimaryResult", "columns": [{"name": "probe", "type": "long"}],
                              "rows": [[1]]}]}


class ContractV2Tests(ContextTestCase):
    def rewrite(self, context, **changes):
        path = tc.context_path(self.root, context)
        os.chmod(path, 0o600)
        raw = context.to_dict()
        raw.update(changes)
        path.write_text(json.dumps(raw))
        return path

    def test_manifest_is_v2_with_exact_window_and_default_capabilities(self):
        context = self.create()
        raw = json.loads(tc.context_path(self.root, context).read_text())
        self.assertEqual(set(raw), V2_KEYS)
        self.assertEqual((raw["schema_version"], raw["hunt_id"]), (2, None))
        self.assertEqual(raw["capabilities"], ["tenant_identity", "workspace_arm"])
        start, end = (tc._utc(raw["window"][key], key) for key in ("start_utc", "end_utc"))
        self.assertEqual(end - start, timedelta(days=7))
        self.assertLessEqual(end, datetime.now(timezone.utc))
        self.assertGreater(end, datetime.now(timezone.utc) - timedelta(minutes=1))
        self.assertEqual(tc.load_context(tc.context_path(self.root, context), self.root), context)

    def test_tampered_v2_manifests_are_rejected(self):
        context = self.create()
        start, end = context.window.start_utc, context.window.end_utc
        day = timedelta(days=1)

        def shift(value, delta):
            return tc._utc_text(tc._utc(value, "time") + delta)

        tampered = {
            "short window": {"window": {"start_utc": start, "end_utc": shift(end, -day)}},
            "future window": {"window": {"start_utc": shift(start, day), "end_utc": shift(end, day)}},
            "extra window key": {"window": {"start_utc": start, "end_utc": end, "tz": "UTC"}},
            "offset timestamp": {"window": {"start_utc": start, "end_utc": end.replace("Z", "+00:00")}},
            "unsorted capabilities": {"capabilities": ["workspace_arm", "tenant_identity"]},
            "duplicate capabilities": {"capabilities": ["tenant_identity", "tenant_identity"]},
            "unknown capability": {"capabilities": ["root"]},
            "capabilities not a list": {"capabilities": "tenant_identity"},
            "hunt without numbered case": {"hunt_id": "sweep"},
            "invalid hunt": {"hunt_id": "Bad Hunt"},
            "unknown version": {"schema_version": 3},
            "boolean version": {"schema_version": True},
            "v1 smuggling v2 fields": {"schema_version": 1},
            "created_at below year 1 in UTC": {"created_at": "0001-01-01T00:00:00+05:00"},
            "created_at above year 9999 in UTC": {"created_at": "9999-12-31T23:59:59-05:00"},
        }
        for label, changes in tampered.items():
            with self.subTest(label):
                path = self.rewrite(context, **changes)
                with self.assertRaises(tc.ContextError):
                    tc.load_context(path, self.root)
        raw = context.to_dict()
        del raw["window"]
        path.write_text(json.dumps(raw))
        with self.assertRaises(tc.ContextError):
            tc.load_context(path, self.root)

    def test_hunt_children_share_one_window_and_need_numbered_case_ids(self):
        end = "2026-02-01T00:00:00Z"
        first = self.create(case_id="sweep-01", hunt_id="sweep", window_end=end)
        second = self.create(case_id="sweep-02", hunt_id="sweep", window_end=end)
        self.assertEqual(first.window, tc.Window("2026-01-25T00:00:00Z", end))
        self.assertEqual(first.window, second.window)
        self.assertNotEqual(tc.context_path(self.root, first), tc.context_path(self.root, second))
        for case_id in ("sweep", "sweep-1", "other-01", "sweep-01x"):
            with self.subTest(case_id=case_id), self.assertRaises(tc.ContextError):
                self.create(case_id=case_id, hunt_id="sweep")
        future = tc._utc_text(datetime.now(timezone.utc) + timedelta(hours=1))
        for changes in ({"window_end": future}, {"window_end": "2026-02-01"}, {"hunt_id": "Bad Hunt"},
                        {"window_end": "0001-01-01T00:00:00Z"}):
            with self.subTest(changes=changes), self.assertRaises(tc.ContextError):
                self.create(case_id="sweep-03", **{"hunt_id": "sweep", **changes})

    def test_defender_only_case_binds_no_workspace(self):
        context = tc.create_context(self.config, workspace_id=None, case_id="defender-only",
                                    lookback_days=30, repo_root=self.root)
        self.assertIsNone(context.workspace_id)
        self.assertEqual(context.capabilities, ("tenant_identity",))
        self.assertTrue(self.validate(context)["ok"])
        self.assertEqual(set(tc.static_unsupported(context)), {"workspace_arm", "workspace_query", "data_lake"})
        for capability in ("workspace_arm", "workspace_query", "data_lake"):
            with self.subTest(capability=capability), self.assertRaises(tc.ContextError):
                tc.create_context(self.config, workspace_id=None, lookback_days=7, repo_root=self.root,
                                  case_id="no-" + capability.replace("_", "-"), capabilities=[capability])
        with patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                patch.object(tc, "_get_json", side_effect=self._live_responses()[:1]) as http:
            result = self.validate(context, validate_live=True)
        self.assertTrue(result["ok"])
        self.assertEqual(http.call_count, 1)
        self.assertEqual(result["sources"]["workspace_cli"]["status"], "not_applicable")
        with self.assertRaises(tc.ContextError):
            tc.create_context(self.config, workspace_id=OTHER, case_id="unregistered",
                              lookback_days=7, repo_root=self.root)

    def test_tenant_identity_is_always_required_and_triage_follows_home_tenant(self):
        context = self.create(capabilities=["workspace_query"])
        self.assertEqual(context.capabilities, ("tenant_identity", "workspace_query"))
        config = profile()
        config["triage_home_tenant_id"] = OTHER
        self.write_config({"tenants": {"example": config}})
        self.assertIn("triage", tc.static_unsupported(self.create(case_id="guest")))
        with self.assertRaisesRegex(tc.ContextError, "triage"):
            self.create(case_id="guest-triage", capabilities=["triage"])
        config["triage_home_tenant_id"] = TENANT
        self.write_config({"tenants": {"example": config}})
        self.assertEqual(tc.static_unsupported(self.create(case_id="home")), {})

    def test_declared_workspace_query_is_probed_live_and_fails_closed(self):
        context = self.create(capabilities=["workspace_query"])
        with patch.object(tc.subprocess, "run", return_value=self._token_response()) as process, \
                patch.object(tc, "_get_json", side_effect=self._live_responses()[:1]) as get, \
                patch.object(tc, "_post_json", return_value=PROBE_RESPONSE) as post:
            result = self.validate(context, validate_live=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["sources"]["workspace_query"]["status"], "verified")
        self.assertEqual(result["sources"]["workspace_cli"]["status"], "not_applicable")
        self.assertEqual(get.call_count, 1)
        self.assertEqual(post.call_args.args[0], f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE}/query")
        self.assertEqual(post.call_args.args[2], {"query": "print probe=1"})
        resources = [call.args[0][call.args[0].index("--resource") + 1] for call in process.call_args_list]
        self.assertEqual(resources, ["https://graph.microsoft.com/", "https://api.loganalytics.io"])
        for response in (
            {"tables": [{"name": "PrimaryResult", "columns": [{"name": "probe"}], "rows": [[2]]}]},
            {"tables": []},
            {},
        ):
            with self.subTest(response=response), \
                    patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                    patch.object(tc, "_get_json", side_effect=self._live_responses()[:1]), \
                    patch.object(tc, "_post_json", return_value=response):
                self.assertFalse(self.validate(context, validate_live=True)["ok"])
        with patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                patch.object(tc, "_get_json", side_effect=self._live_responses()[:1]), \
                patch.object(tc, "_post_json", side_effect=tc.ProbeDenied("denied")):
            denied = self.validate(context, validate_live=True)
        self.assertEqual(denied["sources"]["workspace_query"]["status"], "failed")

    def test_post_errors_are_bounded_and_never_leak_credentials(self):
        for code, body, expected in (
            (400, b'{"error":{"message":"Failed to resolve table  Foo"}}', "Failed to resolve table Foo"),
            (400, b'{"error":{"message":"Bearer abcdefghijklmnop"}}', None),
            (400, b"not json", None),
            (500, b'{"error":{"message":"server"}}', None),
        ):
            with self.subTest(code=code, body=body):
                error = HTTPError("https://example.invalid", code, "secret error", {}, io.BytesIO(body))
                with patch.object(tc, "build_opener") as opener:
                    opener.return_value.open.side_effect = error
                    with self.assertRaises(tc.ContextError) as raised:
                        tc._post_json("https://example.invalid", "mock-token", {"query": "print 1"})
                text = str(raised.exception)
                self.assertNotIn("secret error", text)
                self.assertNotIn("abcdefghijklmnop", text)
                self.assertIn(f"(HTTP {code})", text)
                if expected:
                    self.assertTrue(text.endswith(": " + expected), text)
                else:
                    self.assertTrue(text.endswith(f"(HTTP {code})"), text)
        error = HTTPError("https://example.invalid", 403, "secret error", {}, None)
        with patch.object(tc, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(tc.ProbeDenied):
                tc._post_json("https://example.invalid", "mock-token", {})


class CapabilityLedgerTests(ContextTestCase):
    def ledger(self, context):
        return tc.context_path(self.root, context).parent / "ledger"

    def plant(self, context, capability="tenant_identity", *, at=None, name=None, text=None, **fields):
        """Write a ledger file by hand, as an attacker or a buggy tool might."""
        moment = at or datetime.now(timezone.utc)
        checked = moment.replace(microsecond=0)
        record = {
            "schema_version": 1, "kind": "capability_check", "profile": context.profile,
            "tenant_id": context.tenant_id,
            "workspace_id": context.workspace_id if tc.CAPABILITIES.get(capability, ("cli", False))[1] else None,
            "case_id": context.case_id, "capability": capability, "status": "verified",
            "method": "cli_probe", "checked_at": tc._utc_text(checked),
            "expires_at": tc._utc_text(checked + timedelta(hours=24)), "detail": "planted", "via": None,
        }
        record.update(fields)
        directory = self.ledger(context)
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / (name or f"{tc._stamp(moment)}-{capability}.json")
        path.write_text(json.dumps(record) if text is None else text)
        return path

    def entry(self, context, capability, **kwargs):
        return tc.readiness(context, repo_root=self.root, **kwargs)["capabilities"][capability]

    def test_fresh_case_is_unverified_and_not_ready(self):
        context = self.create()
        ready = tc.readiness(context, repo_root=self.root)
        self.assertFalse(ready["ok"])
        self.assertEqual(ready["required"], ["tenant_identity", "workspace_arm"])
        self.assertEqual(ready["blocked"], ["tenant_identity", "workspace_arm"])
        self.assertEqual(ready["usable"], [])
        self.assertEqual(ready["ignored_records"], 0)
        self.assertEqual(ready["window"], asdict(context.window))
        for name, entry in ready["capabilities"].items():
            self.assertEqual(entry["status"], "unverified", name)
            self.assertEqual(entry["required"], name in context.capabilities)
        self.assertEqual(ready["capabilities"]["data_lake"]["proof"], "attested")
        self.assertEqual(ready["capabilities"]["workspace_arm"]["proof"], "cli")
        self.assertEqual(ready["capabilities"]["triage"]["detail"], "No connection is declared for this tenant")
        self.assertFalse(self.ledger(context).exists(), "reading readiness must not create files")

    def test_verify_records_every_probe_outcome_and_latest_record_wins(self):
        context = self.create(capabilities=["workspace_query"])
        context_arm = self.create(case_id="with-arm", capabilities=["workspace_arm", "workspace_query"])

        def probe(name, _context):
            if name == "workspace_arm":
                raise tc.ProbeDenied("Authenticated request denied or resource not visible (HTTP 403)")
            if name == "workspace_query":
                raise tc.ContextError("Azure CLI token acquisition failed; no login or context switch attempted")

        with patch.object(tc, "_run_probe", side_effect=probe) as probes:
            result = tc.verify_capabilities(context_arm, repo_root=self.root)
        self.assertEqual([call.args[0] for call in probes.call_args_list],
                         ["tenant_identity", "workspace_arm", "workspace_query"])
        self.assertFalse(result["ok"])
        self.assertEqual({name: item["status"] for name, item in result["capabilities"].items()},
                         {"tenant_identity": "verified", "workspace_arm": "denied", "workspace_query": "unverified"})
        ready = tc.readiness(context_arm, repo_root=self.root)
        self.assertEqual(ready["usable"], ["tenant_identity"])
        self.assertEqual(ready["blocked"], ["workspace_arm", "workspace_query"])
        self.assertEqual(ready["capabilities"]["workspace_arm"]["method"], "cli_probe")
        # Records are scoped to their case: the sibling case sees none of them.
        self.assertEqual(tc.readiness(context, repo_root=self.root)["usable"], [])
        with patch.object(tc, "_run_probe"):
            self.assertTrue(tc.verify_capabilities(context_arm, repo_root=self.root)["ok"])
        ready = tc.readiness(context_arm, repo_root=self.root)
        self.assertTrue(ready["ok"])
        self.assertEqual(ready["blocked"], [])
        self.assertEqual(len(list(self.ledger(context_arm).iterdir())), 6)

    def test_expired_records_block_and_keep_their_last_status(self):
        context = self.create()
        with patch.object(tc, "_run_probe"):
            tc.verify_capabilities(context, repo_root=self.root, ttl_hours=1)
        soon = datetime.now(timezone.utc) + timedelta(minutes=30)
        self.assertEqual(self.entry(context, "tenant_identity", now=soon)["status"], "verified")
        stale = tc.readiness(context, repo_root=self.root, now=datetime.now(timezone.utc) + timedelta(hours=2))
        entry = stale["capabilities"]["tenant_identity"]
        self.assertEqual((entry["status"], entry["last_status"]), ("expired", "verified"))
        self.assertFalse(stale["ok"])
        self.assertEqual(stale["blocked"], ["tenant_identity", "workspace_arm"])
        for hours in (0, -1, 169, True, 1.5):
            with self.subTest(hours=hours), self.assertRaises(tc.ContextError):
                tc.verify_capabilities(context, repo_root=self.root, ttl_hours=hours)

    def test_forged_misplaced_and_malformed_records_never_count(self):
        context = self.create()
        base = datetime.now(timezone.utc).replace(microsecond=0)
        control = self.plant(context, at=base, detail="control")
        hour = timedelta(hours=1)
        forgeries = {
            "other tenant": dict(tenant_id=OTHER),
            "other profile": dict(profile="second"),
            "other case": dict(case_id="other-case"),
            "workspace on a tenant-wide capability": dict(workspace_id=WORKSPACE),
            "unknown capability": dict(capability="root"),
            "attestation of a cli capability": dict(method="agent_attestation", status="attested"),
            "unknown status": dict(status="great"),
            "wrong kind": dict(kind="note"),
            "wrong schema": dict(schema_version=2),
            "future record": dict(checked_at=tc._utc_text(base + hour), expires_at=tc._utc_text(base + 25 * hour)),
            "inverted expiry": dict(expires_at=tc._utc_text(base - hour)),
            "excessive lifetime": dict(expires_at=tc._utc_text(base + timedelta(days=30))),
            "extra field": dict(token="x"),
            "credential in detail": dict(detail="Bearer abcdefghijklmnop"),
            "control character in detail": dict(detail="a\x1b[31mb"),
            "via on another capability": dict(via="portal"),
            "offset timestamp": dict(checked_at=tc._utc_text(base).replace("Z", "+00:00")),
        }
        count = 0

        def later():
            nonlocal count
            count += 1
            return base + timedelta(microseconds=count)

        for fields in forgeries.values():
            self.plant(context, at=later(), **fields)
        directory = self.ledger(context)
        stamp = tc._stamp
        for name in (
            f"{stamp(later())}-graph.json",
            "latest.json",
            f"{stamp(base - timedelta(minutes=10))}-tenant_identity.json",
            f"{stamp(base + timedelta(seconds=30))}-tenant_identity.json",
        ):
            self.plant(context, name=name)
            count += 1
        for text in ("not json", "[]", "", control.read_text() + " " * (tc.MAX_RECORD_BYTES + 1)):
            self.plant(context, at=later(), text=text)
        elsewhere = self.root / "elsewhere.json"
        elsewhere.write_text(control.read_text())
        (directory / f"{stamp(later())}-tenant_identity.json").symlink_to(elsewhere)
        os.mkfifo(directory / f"{stamp(later())}-tenant_identity.json")
        (directory / f"{stamp(later())}-tenant_identity.json.bak").write_text(control.read_text())
        # Nesting deep enough to exhaust the parser's recursion budget inside the size cap.
        self.plant(context, at=later(), text="[" * 4000 + "]" * 4000)
        # Full-width digits would satisfy a Unicode-aware \d and sort after every real stamp.
        wide = {ord(digit): ord(digit) + 0xFF10 - ord("0") for digit in "0123456789"}
        self.plant(context, name=stamp(later()).translate(wide) + "-tenant_identity.json")
        extras = 5
        ready = tc.readiness(context, repo_root=self.root)
        entry = ready["capabilities"]["tenant_identity"]
        self.assertEqual((entry["status"], entry["detail"]), ("verified", "control"))
        self.assertEqual(ready["ignored_records"], len(forgeries) + 4 + 4 + extras)

    def test_attestations_are_labeled_and_need_declared_connections(self):
        context = self.create(capabilities=["data_lake", "graph", "defender_hunting"])
        for capability, via in (("data_lake", None), ("graph", None), ("defender_hunting", "portal")):
            result = tc.attest_capability(
                context, repo_root=self.root, capability=capability, status="attested",
                detail="MCP session returned tenant-scoped data", via=via)
            self.assertEqual(result["proof"], "attested")
        ready = tc.readiness(context, repo_root=self.root)
        self.assertEqual(ready["usable"], ["data_lake", "graph", "defender_hunting"])
        self.assertEqual(ready["capabilities"]["defender_hunting"]["via"], "portal")
        self.assertEqual(ready["capabilities"]["data_lake"]["method"], "agent_attestation")
        self.assertFalse(ready["ok"], "CLI-proven capabilities are still unverified")
        invalid = (
            dict(capability="defender_hunting", status="attested"),
            dict(capability="defender_hunting", status="attested", via="triage"),
            dict(capability="defender_hunting", status="attested", via="email"),
            dict(capability="triage", status="attested"),
            dict(capability="tenant_identity", status="attested"),
            dict(capability="root", status="attested"),
            dict(capability="graph", status="verified"),
            dict(capability="graph", status="attested", detail="token: abcdefghijkl"),
            dict(capability="graph", status="attested", detail=""),
            dict(capability="graph", status="attested", ttl_hours=169),
            dict(capability="graph", status="attested", via="portal"),
        )
        for fields in invalid:
            with self.subTest(fields=fields), self.assertRaises(tc.ContextError):
                tc.attest_capability(context, repo_root=self.root,
                                     **{"detail": "MCP session answered", **fields})
        denied = tc.attest_capability(context, repo_root=self.root, capability="graph",
                                      status="denied", detail="Guest account lacks access")
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(self.entry(context, "graph")["status"], "denied")
        with patch.object(tc, "_run_probe"):
            with self.assertRaises(tc.ContextError):
                tc.verify_capabilities(context, repo_root=self.root, capabilities=["data_lake"])
            with self.assertRaises(tc.ContextError):
                tc.verify_capabilities(context, repo_root=self.root, capabilities=["root"])

    def test_static_limits_beat_any_record(self):
        config = profile()
        config["triage_home_tenant_id"] = OTHER
        self.write_config({"tenants": {"example": config}})
        context = self.create()
        entry = self.entry(context, "triage")
        self.assertEqual(entry["status"], "unsupported")
        self.assertIn("home tenant", entry["detail"])
        with self.assertRaises(tc.ContextError):
            tc.attest_capability(context, repo_root=self.root, capability="triage",
                                 status="attested", detail="MCP session answered")
        self.plant(context, "triage", method="agent_attestation", status="attested")
        ready = tc.readiness(context, repo_root=self.root)
        self.assertEqual(ready["capabilities"]["triage"]["status"], "unsupported")
        self.assertEqual(ready["ignored_records"], 1)
        self.assertTrue(ready["capabilities"]["triage"]["status"] not in tc.USABLE)

    def test_defender_only_case_reports_workspace_capabilities_unsupported(self):
        context = tc.create_context(self.config, workspace_id=None, case_id="defender-only",
                                    lookback_days=7, repo_root=self.root)
        ready = tc.readiness(context, repo_root=self.root)
        self.assertIsNone(ready["workspace_id"])
        for name in ("workspace_arm", "workspace_query", "data_lake"):
            self.assertEqual(ready["capabilities"][name]["status"], "unsupported")
        with patch.object(tc, "_run_probe") as probe:
            result = tc.verify_capabilities(context, repo_root=self.root)
        self.assertEqual([call.args[0] for call in probe.call_args_list], ["tenant_identity"])
        self.assertTrue(result["ok"])
        with patch.object(tc, "_run_probe") as probe:
            result = tc.verify_capabilities(context, repo_root=self.root, capabilities=["workspace_arm"])
        probe.assert_not_called()
        self.assertEqual(result["capabilities"]["workspace_arm"]["status"], "unsupported")
        self.assertFalse(result["capabilities"]["workspace_arm"]["recorded"])
        self.assertFalse(result["ok"])
        self.assertTrue(tc.readiness(context, repo_root=self.root)["ok"])

    def test_records_are_private_read_only_and_never_overwritten(self):
        context = self.create()
        moment = datetime.now(timezone.utc)
        names = [tc._record_check(context, repo_root=self.root, capability="tenant_identity",
                                  status="verified", method="cli_probe", detail=detail, now=moment)
                 for detail in ("one", "two")]
        self.assertEqual(len(set(names)), 2)
        directory = self.ledger(context)
        self.assertEqual(sorted(path.name for path in directory.iterdir()), sorted(names))
        self.assertEqual({path.stat().st_mode & 0o777 for path in directory.iterdir()}, {0o400})
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.entry(context, "tenant_identity", now=moment)["detail"], "two")
        with self.assertRaises(tc.ContextError):
            tc._record_check(context, repo_root=self.root, capability="tenant_identity", status="verified",
                             method="agent_attestation", detail="wrong method", now=moment)

    def test_symlinked_ledger_directory_is_never_followed(self):
        context = self.create()
        outside = self.root / "outside"
        outside.mkdir()
        self.ledger(context).symlink_to(outside, target_is_directory=True)
        with self.assertRaises(tc.ContextError):
            tc._record_check(context, repo_root=self.root, capability="tenant_identity",
                             status="verified", method="cli_probe", detail="one")
        with self.assertRaises(tc.ContextError):
            tc.readiness(context, repo_root=self.root)
        self.assertEqual(list(outside.iterdir()), [])

    def test_cli_verify_attest_and_readiness_roundtrip(self):
        code, created = self.cli("create", "--workspace", WORKSPACE, "--case", "cli-ledger",
                                 "--lookback-days", "7")
        self.assertEqual(code, 0)
        path = created["context_path"]
        code, ready = self.cli("readiness", path)
        self.assertEqual((code, ready["ok"]), (1, False))
        with patch.object(tc, "_run_probe"):
            code, verified = self.cli("verify", path)
        self.assertEqual((code, verified["ok"]), (0, True))
        code, ready = self.cli("readiness", path)
        self.assertEqual((code, ready["ok"]), (0, True))
        code, attested = self.cli("attest", path, "--capability", "data_lake", "--status", "attested",
                                  "--detail", "MCP session returned tenant-scoped data")
        self.assertEqual((code, attested["proof"]), (0, "attested"))
        code, rejected = self.cli("attest", path, "--capability", "defender_hunting",
                                  "--status", "attested", "--detail", "No route named")
        self.assertEqual((code, rejected["ok"]), (1, False))
        self.assertNotIn("Bearer", json.dumps([created, ready, attested, rejected]))

    def test_ledger_commands_refuse_a_rebound_profile_and_v1_contexts(self):
        context = self.create()
        path = str(tc.context_path(self.root, context))
        changed = profile()
        changed["tenant_id"] = OTHER
        changed["azure_mcp"]["tenant"] = OTHER
        self.write_config({"tenants": {"example": changed}})
        for command in (["verify", path], ["readiness", path],
                        ["attest", path, "--capability", "graph", "--status", "attested", "--detail", "ok"]):
            with self.subTest(command=command[0]), patch.object(tc, "_run_probe") as probe:
                code, result = self.cli(*command)
            self.assertEqual((code, result["ok"]), (1, False))
            probe.assert_not_called()
        self.assertFalse(self.ledger(context).exists())


class WorkspaceQueryTests(ContextTestCase):
    def setUp(self):
        super().setUp()
        self.context = self.create(capabilities=["workspace_arm", "workspace_query"])
        self.kql = "SigninLogs | take 3\n"
        (self.root / "hunt.kql").write_text(self.kql)

    def verified(self, side_effect=None):
        with patch.object(tc, "_run_probe", side_effect=side_effect):
            return tc.verify_capabilities(self.context, repo_root=self.root)

    def run_query(self, path="hunt.kql", name="signins", **kwargs):
        return tc.run_query(self.context, path, name, repo_root=self.root, **kwargs)

    def test_query_requires_a_fresh_cli_verified_workspace_query(self):
        with patch.object(tc, "_post_json") as post, patch.object(tc.subprocess, "run") as process:
            with self.assertRaisesRegex(tc.ContextError, "workspace_query is unverified"):
                self.run_query()
        post.assert_not_called()
        process.assert_not_called()
        self.verified(side_effect=tc.ProbeDenied("Authenticated request denied"))
        with patch.object(tc, "_post_json") as post, self.assertRaisesRegex(tc.ContextError, "is denied"):
            self.run_query()
        post.assert_not_called()
        self.verified()
        with patch.object(tc, "_post_json") as post, self.assertRaisesRegex(tc.ContextError, "is expired"):
            self.run_query(now=datetime.now(timezone.utc) + timedelta(hours=25))
        post.assert_not_called()
        plain = self.create(case_id="plain")
        with self.assertRaisesRegex(tc.ContextError, "not a declared capability"):
            tc.run_query(plain, "hunt.kql", "signins", repo_root=self.root)

    def test_query_runs_over_the_case_window_and_writes_tenant_bound_evidence(self):
        self.verified()
        with patch.object(tc.subprocess, "run", return_value=self._token_response()) as process, \
                patch.object(tc, "_post_json", return_value=QUERY_RESPONSE) as post:
            summary = self.run_query()
        url, token, body = post.call_args.args
        window = self.context.window
        self.assertEqual(url, f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE}/query")
        self.assertEqual(token, "mock-token-never-log")
        self.assertEqual(body, {"query": self.kql, "timespan": f"{window.start_utc}/{window.end_utc}"})
        command = process.call_args.args[0]
        self.assertEqual(command[command.index("--tenant") + 1], TENANT)
        self.assertEqual(command[command.index("--resource") + 1], "https://api.loganalytics.io")
        path = self.root / summary["evidence_path"]
        self.assertEqual(path.parent, tc.context_path(self.root, self.context).parent / "evidence")
        self.assertEqual(path.stat().st_mode & 0o777, 0o400)
        evidence = json.loads(path.read_text())
        self.assertEqual(
            {key: evidence[key] for key in ("kind", "profile", "tenant_id", "workspace_id", "case_id",
                                            "hunt_id", "name", "query", "status")},
            {"kind": "query_result", "profile": "example", "tenant_id": TENANT, "workspace_id": WORKSPACE,
             "case_id": "case-one", "hunt_id": None, "name": "signins", "query": self.kql, "status": "ok"})
        self.assertEqual(evidence["query_sha256"], hashlib.sha256(self.kql.encode()).hexdigest())
        self.assertEqual(evidence["window"], asdict(window))
        self.assertEqual((evidence["row_count"], evidence["total_rows"], evidence["truncated"]), (3, 3, False))
        self.assertEqual(evidence["rows"], QUERY_RESPONSE["tables"][0]["rows"])
        self.assertEqual(evidence["columns"], [{"name": "Account", "type": "string"},
                                               {"name": "Count", "type": "long"}])
        self.assertNotIn("rows", summary)
        self.assertEqual(summary["columns"], ["Account", "Count"])
        self.assertNotIn("mock-token-never-log", json.dumps(summary) + path.read_text())
        with patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                patch.object(tc, "_post_json", return_value=QUERY_RESPONSE):
            again = self.run_query()
        self.assertNotEqual(again["evidence_path"], summary["evidence_path"])
        self.assertTrue(path.is_file())

    def test_query_truncates_to_max_rows_and_rejects_bad_limits(self):
        self.verified()
        with patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                patch.object(tc, "_post_json", return_value=QUERY_RESPONSE):
            summary = self.run_query(max_rows=2)
            for value in (0, 100001, True, "5"):
                with self.subTest(max_rows=value), self.assertRaises(tc.ContextError):
                    self.run_query(max_rows=value)
        self.assertEqual((summary["row_count"], summary["total_rows"], summary["truncated"]), (2, 3, True))
        evidence = json.loads((self.root / summary["evidence_path"]).read_text())
        self.assertEqual(evidence["rows"], [["a", 1], ["b", 2]])

    def test_query_failures_write_no_evidence(self):
        self.verified()
        for failure in (
            {"side_effect": tc.ContextError("Authenticated request failed (HTTP 500)")},
            {"side_effect": tc.ProbeDenied("denied")},
            {"return_value": {}},
            {"return_value": {"tables": [{"name": "PrimaryResult", "columns": [{"name": 1}], "rows": []}]}},
            {"return_value": {"tables": [{"name": "PrimaryResult", "columns": [], "rows": ["x"]}]}},
        ):
            with self.subTest(failure=failure), \
                    patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                    patch.object(tc, "_post_json", **failure):
                with self.assertRaises(tc.ContextError):
                    self.run_query()
        self.assertFalse((tc.context_path(self.root, self.context).parent / "evidence").exists())
        with patch.object(tc.subprocess, "run", return_value=self._token_response(OTHER)), \
                patch.object(tc, "_post_json") as post:
            with self.assertRaises(tc.ContextError):
                self.run_query()
        post.assert_not_called()

    def test_query_files_must_be_small_utf8_kql_files_inside_the_repository(self):
        self.verified()
        outside = self.root.parent / (".tenant-context-outside-" + uuid4().hex + ".kql")
        outside.write_text("print 1")
        self.addCleanup(outside.unlink)
        (self.root / "link.kql").symlink_to(outside)
        (self.root / "notes.txt").write_text("print 1")
        (self.root / "dir.kql").mkdir()
        (self.root / "big.kql").write_text("x" * (tc.MAX_QUERY_BYTES + 1))
        (self.root / "binary.kql").write_bytes(b"\xff\xfe")
        (self.root / "empty.kql").write_text("  \n")
        for path in (outside, "link.kql", "notes.txt", "dir.kql", "big.kql", "binary.kql",
                     "empty.kql", "missing.kql", "../escape.kql"):
            with self.subTest(path=str(path)), patch.object(tc, "_post_json") as post:
                with self.assertRaises(tc.ContextError):
                    self.run_query(path)
            post.assert_not_called()
        for name in ("../x", "Bad Name", "", "a/b"):
            with self.subTest(name=name), self.assertRaises(tc.ContextError):
                self.run_query(name=name)

    def test_cli_query_prints_a_summary_and_never_rows(self):
        self.verified()
        path = str(tc.context_path(self.root, self.context))
        with patch.object(tc.subprocess, "run", return_value=self._token_response()), \
                patch.object(tc, "_post_json", return_value=QUERY_RESPONSE):
            code, result = self.cli("query", path, "--kql-file", "hunt.kql", "--name", "signins",
                                    "--max-rows", "2")
        self.assertEqual((code, result["ok"], result["truncated"]), (0, True, True))
        self.assertNotIn("rows", result)
        code, result = self.cli("query", path, "--kql-file", "missing.kql", "--name", "signins")
        self.assertEqual((code, result["ok"]), (1, False))


class TenantToolingTests(ContextTestCase):
    def second_profile(self, **changes):
        second = profile()
        second.update(tenant_id=OTHER, connections={"graph": "graph-second", "data_lake": "lake-second"})
        second["azure_mcp"]["tenant"] = OTHER
        second.update(changes)
        return second

    def test_render_mcp_is_per_tenant_and_never_includes_credentials(self):
        config = profile()
        config["connections"]["triage"] = "triage-example"
        config["triage_home_tenant_id"] = TENANT
        self.write_config({"tenants": {"example": config}})
        code, result = self.cli("render-mcp", "--profile", "example")
        self.assertEqual(code, 0)
        self.assertEqual(set(result["servers"]), {"graph-example", "lake-example", "triage-example"})
        for server in result["servers"].values():
            self.assertEqual(server["type"], "http")
            self.assertEqual(server["headers"], {"x-mcp-client-tenant-id": TENANT})
        self.assertEqual(result["servers"]["lake-example"]["url"], tc.MCP_SERVICES["data_lake"])
        self.assertEqual(result["omitted"], {})
        self.assertIn("configures nothing", " ".join(result["notes"]))
        self.assertNotIn("Bearer", json.dumps(result))
        config["triage_home_tenant_id"] = OTHER
        self.write_config({"tenants": {"example": config}})
        result = self.cli("render-mcp", "--profile", "example")[1]
        self.assertNotIn("triage-example", result["servers"])
        self.assertIn("home-tenant only", result["omitted"]["triage"])
        del config["connections"]["triage"]
        self.write_config({"tenants": {"example": config}})
        self.assertIn("No connection reference", self.cli("render-mcp", "--profile", "example")[1]["omitted"]["triage"])

    def test_render_mcp_needs_an_explicit_profile_and_unique_names(self):
        self.write_config({"tenants": {"example": profile(), "second": self.second_profile()}})
        code, result = self.cli("render-mcp")
        self.assertEqual((code, result["ok"]), (1, False))
        second = self.cli("render-mcp", "--profile", "second")[1]
        self.assertEqual({server["headers"]["x-mcp-client-tenant-id"] for server in second["servers"].values()}, {OTHER})
        clash = profile()
        clash["connections"] = {"graph": "shared-name", "data_lake": "shared-name"}
        self.write_config({"tenants": {"example": clash}})
        self.assertEqual(self.cli("render-mcp")[0], 1)

    def test_mappings_are_tenant_local_and_validated(self):
        first = profile()
        first.update(sit_mapping={GUID_A.upper(): "Example SIT", "__comment": "note"},
                     label_mapping={GUID_B: "Confidential"}, sit_priority={GUID_A: "high"})
        self.write_config({"tenants": {"example": first, "second": self.second_profile()}})
        context = tc.create_context(self.config, profile="example", workspace_id=WORKSPACE,
                                    case_id="maps", lookback_days=7, repo_root=self.root)
        code, result = self.cli("mappings", str(tc.context_path(self.root, context)))
        self.assertEqual(code, 0)
        self.assertEqual(result["sit_mapping"], {GUID_A: "Example SIT"})
        self.assertEqual(result["label_mapping"], {GUID_B: "Confidential"})
        self.assertEqual(result["sit_priority"], {GUID_A: "High"})
        other = tc.create_context(self.config, profile="second", workspace_id=WORKSPACE,
                                  case_id="maps", lookback_days=7, repo_root=self.root)
        result = self.cli("mappings", str(tc.context_path(self.root, other)))[1]
        self.assertEqual((result["sit_mapping"], result["label_mapping"], result["sit_priority"]), ({}, {}, {}))
        first["sit_mapping"] = {GUID_B: "Changed after the case started"}
        self.write_config({"tenants": {"example": first, "second": self.second_profile()}})
        self.assertEqual(self.cli("mappings", str(tc.context_path(self.root, context)))[1]["sit_mapping"],
                         {GUID_B: "Changed after the case started"})

    def test_invalid_registry_mappings_are_rejected_but_legacy_files_are_read_leniently(self):
        for field, value in (
            ("sit_mapping", {"not-a-guid": "x"}),
            ("sit_priority", {GUID_A: "urgent"}),
            ("label_mapping", {GUID_A: ""}),
            ("label_mapping", {GUID_A: "line\nbreak"}),
            ("sit_mapping", {GUID_A: "a", GUID_A.upper(): "b"}),
            ("sit_mapping", [GUID_A]),
        ):
            with self.subTest(field=field, value=value):
                invalid = profile()
                invalid[field] = value
                self.write_config({"tenants": {"example": invalid}})
                with self.assertRaises(tc.ContextError):
                    tc.load_profiles(self.config)
        legacy = {**profile(), "sit_mapping": {"__comment": "note", GUID_A: "Name", "bad": "x"},
                  "sit_priority": {GUID_A: "urgent", GUID_B: "low"}, "label_mapping": ["not", "a", "table"]}
        self.write_config(legacy)
        loaded = tc.load_profiles(self.config)["legacy"]
        self.assertEqual(loaded.sit_mapping, ((GUID_A, "Name"),))
        self.assertEqual(loaded.sit_priority, ((GUID_B, "Low"),))
        self.assertEqual(loaded.label_mapping, ())

    def test_profiles_warn_when_one_connection_name_spans_tenants(self):
        shared = self.second_profile(connections=profile()["connections"])
        self.write_config({"tenants": {"example": profile(), "second": shared}})
        warnings = tc.profile_warnings(tc.load_profiles(self.config))
        self.assertEqual(len(warnings), 2)
        self.assertTrue(all("different tenants" in warning for warning in warnings))
        code, result = self.cli("profiles")
        self.assertEqual((code, len(result["warnings"])), (0, 2))
        self.assertEqual(result["profiles"][0]["connections"]["graph"], "graph-example")
        self.write_config({"tenants": {"example": profile(), "same-tenant": profile()}})
        self.assertEqual(tc.profile_warnings(tc.load_profiles(self.config)), [])
        self.write_config({"tenants": {"example": profile(), "second": self.second_profile()}})
        self.assertEqual(tc.profile_warnings(tc.load_profiles(self.config)), [])

    def test_registry_detection_fails_closed_on_damage(self):
        self.assertFalse(tc.tenant_registry_configured(self.root / "absent.json"))
        self.assertTrue(tc.tenant_registry_configured(self.config))
        for legacy in (profile(), {**profile(), "tenants": {}}):
            self.write_config(legacy)
            self.assertFalse(tc.tenant_registry_configured(self.config))
        self.config.write_text("{not json")
        with self.assertRaises(tc.ContextError):
            tc.tenant_registry_configured(self.config)
        for damaged in ([], None, "text"):
            self.write_config({"tenants": damaged})
            with self.assertRaises(tc.ContextError):
                tc.tenant_registry_configured(self.config)

    def test_cli_create_supports_no_workspace_hunt_children_and_capabilities(self):
        code, result = self.cli("create", "--no-workspace", "--case", "defender-only", "--lookback-days", "30")
        self.assertEqual((code, result["ok"]), (0, True))
        self.assertEqual(result["required_capabilities"], ["tenant_identity"])
        code, first = self.cli("create", "--workspace", WORKSPACE, "--case", "sweep-01", "--hunt-id", "sweep",
                               "--window-end", "2026-02-01T00:00:00Z", "--lookback-days", "7",
                               "--capability", "workspace_query")
        self.assertEqual(code, 0)
        self.assertEqual(first["required_capabilities"], ["tenant_identity", "workspace_query"])
        self.assertEqual(first["window"], {"start_utc": "2026-01-25T00:00:00Z", "end_utc": "2026-02-01T00:00:00Z"})
        self.assertEqual(first["hunt_id"], "sweep")
        code, second = self.cli("create", "--workspace", WORKSPACE, "--case", "sweep-02", "--hunt-id", "sweep",
                                "--window-end", "2026-02-01T00:00:00Z", "--lookback-days", "7")
        self.assertEqual((code, second["window"]), (0, first["window"]))
        for arguments in (["--capability", "triage"], ["--hunt-id", "other"]):
            code, result = self.cli("create", "--workspace", WORKSPACE, "--case", "sweep-03",
                                    "--lookback-days", "7", *arguments)
            self.assertEqual((code, result["ok"]), (1, False))

    def test_cli_requires_an_explicit_workspace_choice(self):
        for arguments in ([], ["--workspace", WORKSPACE, "--no-workspace"]):
            with self.subTest(arguments=arguments), patch("sys.stderr", io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                tc.main(["--repo-root", str(self.root), "create", "--case", "x",
                         "--lookback-days", "7", *arguments])
            self.assertEqual(raised.exception.code, 2)


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tenant_contract"


def shared_fixture(name):
    return json.loads((FIXTURES / (name + ".json")).read_text(encoding="utf-8"))


def parsed_profile(item):
    """The parsed fields Python and the Mission Control parser must agree on."""
    return {
        "tenant_id": item.tenant_id, "subscription_id": item.subscription_id,
        "sentinel_workspace_id": item.sentinel_workspace_id,
        "workspaces": [asdict(workspace) for workspace in item.workspaces],
        "connections": asdict(item.connections), "memory_file": item.memory_file,
        "triage_home_tenant_id": item.triage_home_tenant_id,
        "sit_mapping": dict(item.sit_mapping), "label_mapping": dict(item.label_mapping),
        "sit_priority": dict(item.sit_priority),
    }


def expand_records(entries):
    """Yield (entry, full record); patch entries edit a copy of an earlier record."""
    built = {}
    for entry in entries:
        if "record" in entry:
            record = copy.deepcopy(entry["record"])
        else:
            record = copy.deepcopy(built[entry["from"]])
            record.update(entry.get("set", {}))
            for key in entry.get("unset", ()):
                record.pop(key, None)
        built[entry["name"]] = record
        yield entry, record


class SharedFixtureTests(ContextTestCase):
    """Pins the contract with the fixtures that the Mission Control tests also consume."""

    def make(self, **kwargs):
        options = {"workspace_id": WORKSPACE, "case_id": "case-one", "lookback_days": 7,
                   "repo_root": self.root}
        return tc.create_context(self.config, **{**options, **kwargs})

    def test_registry_fixture_normalizes_to_the_agreed_shape(self):
        valid = shared_fixture("registry")["valid"]
        self.write_config(valid["config"])
        self.assertTrue(tc.tenant_registry_configured(self.config))
        profiles = tc.load_profiles(self.config)
        self.assertEqual({name: parsed_profile(item) for name, item in profiles.items()}, valid["expected"])

    def test_registry_fixture_rejects_every_invalid_registry(self):
        invalid = shared_fixture("registry")["invalid"]
        self.assertGreaterEqual(len(invalid), 40)
        for case in invalid:
            with self.subTest(case["name"]):
                self.write_config(case["config"])
                with self.assertRaises(tc.ContextError):
                    tc.load_profiles(self.config)

    def test_registry_fixture_legacy_configs_are_not_registries(self):
        for case in shared_fixture("registry")["legacy"]:
            with self.subTest(case["name"]):
                self.write_config(case["config"])
                self.assertFalse(tc.tenant_registry_configured(self.config))

    def test_window_fixture_pins_the_exact_collection_window(self):
        windows = shared_fixture("windows")
        for index, case in enumerate(windows["valid"]):
            with self.subTest(end=case["end"], lookback_days=case["lookback_days"]):
                context = self.make(case_id=f"window-{index}", lookback_days=case["lookback_days"],
                                    window_end=case["end"])
                self.assertEqual(asdict(context.window), {"start_utc": case["start"], "end_utc": case["end"]})
        for end in windows["invalid_ends"]:
            with self.subTest(invalid_end=end), self.assertRaises(tc.ContextError):
                self.make(case_id="bad-end", window_end=end)
        for lookback in windows["invalid_lookbacks"]:
            with self.subTest(invalid_lookback=lookback), self.assertRaises(tc.ContextError):
                self.make(case_id="bad-lookback", lookback_days=lookback)

    def test_hunt_fixture_ids_and_numbered_children(self):
        windows = shared_fixture("windows")
        end = "2024-03-01T12:00:00Z"
        for hunt_id in windows["valid_hunt_ids"]:
            with self.subTest(hunt_id=hunt_id):
                context = self.make(case_id=hunt_id + "-01", hunt_id=hunt_id, window_end=end)
                self.assertEqual((context.hunt_id, context.case_id), (hunt_id, hunt_id + "-01"))
        for hunt_id in windows["invalid_hunt_ids"]:
            with self.subTest(invalid_hunt_id=hunt_id), self.assertRaises(tc.ContextError):
                self.make(case_id="x-01", hunt_id=hunt_id, window_end=end)
        for child in windows["children"]:
            with self.subTest(child=child["case_id"]):
                shutil.rmtree(self.root / "reports", ignore_errors=True)
                context = self.make(case_id=child["case_id"], hunt_id=child["hunt_id"], window_end=end)
                self.assertEqual(context.window.end_utc, end)
        for case_id in windows["invalid_child_case_ids"]:
            with self.subTest(invalid_case_id=case_id), self.assertRaises(tc.ContextError):
                self.make(case_id=case_id, hunt_id="hunt-1", window_end=end)

    def test_ledger_fixture_scenarios(self):
        scenarios = shared_fixture("ledger")["scenarios"]
        for scenario in scenarios:
            with self.subTest(scenario["name"]):
                self.run_ledger_scenario(scenario)

    def run_ledger_scenario(self, scenario):
        context = tc.context_from_manifest(scenario["context"])
        now = tc._utc(scenario["now"], "now")
        directory = self.root / context.report_dir / "ledger"
        directory.mkdir(parents=True, mode=0o700)
        files = []
        for entry, record in expand_records(scenario["records"]):
            files.append(entry["file"])
            (directory / entry["file"]).write_text(json.dumps(record), encoding="utf-8")
            match = tc.LEDGER_NAME.fullmatch(entry["file"])
            try:
                accepted = match is not None and tc._validate_record(record, context, now, match) is not None
            except tc.ContextError:
                accepted = False
            self.assertEqual(accepted, entry["valid"], entry["name"])
        self.assertEqual(len(files), len(set(files)), "fixture file names must be unique")
        ready = tc.readiness(context, repo_root=self.root, now=now)
        expect = scenario["expect"]
        self.assertEqual(ready["ignored_records"], expect["ignored"])
        self.assertEqual(ready["blocked"], expect["blocked"])
        self.assertEqual(ready["ok"], not expect["blocked"])
        self.assertEqual(set(expect["effective"]), set(tc.CAPABILITIES))
        for capability, wanted in expect["effective"].items():
            for key, value in wanted.items():
                self.assertEqual(ready["capabilities"][capability][key], value, f"{capability}.{key}")


if __name__ == "__main__":
    unittest.main()
