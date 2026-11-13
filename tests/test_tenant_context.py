import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from uuid import uuid4

from scripts import tenant_context as tc


TENANT = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
SUB = "33333333-3333-4333-8333-333333333333"
WORKSPACE = "44444444-4444-4444-8444-444444444444"


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


class TenantContextTests(unittest.TestCase):
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
        context = self.create()
        path = tc.context_path(self.root, context)
        raw = context.to_dict()
        raw["created_at"] = "2026-01-01T12:00:00.000Z"
        os.chmod(path, 0o600)
        path.write_text(json.dumps(raw))
        loaded = tc.load_context(path, self.root)
        self.assertEqual(loaded.created_at, raw["created_at"])
        self.assertTrue(self.validate(loaded)["ok"])

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


if __name__ == "__main__":
    unittest.main()
