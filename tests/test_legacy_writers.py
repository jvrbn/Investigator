"""Tenant-bound behavior of the legacy report writers and their shared helpers.

The writers run as real CLIs inside throwaway repositories created under the project
directory, using byte-identical copies of the scripts under test. `requests` and `dotenv` are
always replaced by the offline stubs in tests/fixtures/offline_stubs, which record any network
attempt, so no test can reach an API or load a real token whether or not the real packages are
installed.
"""

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from scripts.tenant_context import (
    ContextError, check_evidence_tenant, create_context, require_case_context, write_case_file,
)


SOURCE = Path(__file__).resolve().parents[1]
STUBS = Path(__file__).resolve().parent / "fixtures" / "offline_stubs"
COPIED = (
    "enrich_ips.py",
    "scripts/tenant_context.py",
    "scripts/generate_report_from_json.py",
    "scripts/investigator.py",
    "scripts/report_generator.py",
    "scripts/cleanup_old_investigations.py",
    "scripts/kql_to_ah_url.py",
)
TENANT_A = "11111111-1111-4111-8111-111111111111"
WORKSPACE_A = "22222222-2222-4222-8222-222222222222"
WORKSPACE_A2 = "55555555-5555-4555-8555-555555555555"
TENANT_B = "33333333-3333-4333-8333-333333333333"
WORKSPACE_B = "44444444-4444-4444-8444-444444444444"
REGISTRY = {
    "alpha": {"tenant_id": TENANT_A, "sentinel_workspace_id": WORKSPACE_A},
    "beta": {"tenant_id": TENANT_B, "sentinel_workspace_id": WORKSPACE_B},
}


class MiniRepo(unittest.TestCase):
    def setUp(self):
        # Keep test material inside the project, never the system temporary directory.
        self.root = Path.cwd() / (".legacy-writers-test-" + uuid4().hex)
        self.root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.root)
        for name in COPIED:
            (self.root / name).parent.mkdir(exist_ok=True)
            shutil.copy2(SOURCE / name, self.root / name)
        self.network_log = self.root / "network.log"

    def write_config(self, registry=True, **extra):
        config = dict(extra)
        if registry:
            config["tenants"] = REGISTRY
        (self.root / "config.json").write_text(json.dumps(config), encoding="utf-8")

    def case(self, profile="alpha", workspace=WORKSPACE_A, case_id="case-1"):
        context = create_context(
            self.root / "config.json", profile=profile, workspace_id=workspace,
            case_id=case_id, lookback_days=7, repo_root=self.root,
        )
        return context, self.root / context.report_dir

    def run_script(self, script, *args):
        environment = {
            **os.environ,
            "PYTHONPATH": str(STUBS),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "WRITER_TEST_NETWORK_LOG": str(self.network_log),
        }
        return subprocess.run(
            [sys.executable, str(self.root / script), *map(str, args)],
            cwd=self.root, env=environment, capture_output=True, text=True,
            encoding="utf-8", timeout=120,
        )

    @staticmethod
    def names(directory):
        return sorted(path.name for path in directory.iterdir())


class GenerateReportTests(MiniRepo):
    SCRIPT = "scripts/generate_report_from_json.py"

    def setUp(self):
        super().setUp()
        self.evidence = self.root / "evidence.json"
        self.write_evidence()

    def write_evidence(self, **extra):
        self.evidence.write_text(json.dumps({
            "upn": "analyst@contoso.example", "user_id": "66666666-6666-4666-8666-666666666666",
            "user_sid": "S-1-5-21-1-2-3-1001", "investigation_date": "2026-11-16",
            "start_date": "2026-11-09", "end_date": "2026-11-16", **extra,
        }), encoding="utf-8")
        self.original = self.evidence.read_bytes()

    def test_registry_requires_a_case_and_writes_nothing(self):
        self.write_config()
        done = self.run_script(self.SCRIPT, self.evidence)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn("--context", done.stdout)
        self.assertFalse((self.root / "temp").exists())
        self.assertFalse((self.root / "reports").exists())
        self.assertEqual(self.evidence.read_bytes(), self.original)

    def test_case_run_stays_inside_its_case_directory(self):
        self.write_config()
        _, case_dir = self.case()
        before = set(case_dir.iterdir())
        done = self.run_script(self.SCRIPT, self.evidence, "--context", case_dir / "context.json")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("Bound to tenant case alpha/case-1", done.stdout)

        (report,) = case_dir.glob("Investigation_Report_Compact_analyst_*.html")
        (enriched,) = case_dir.glob("investigation_enriched_*.json")
        self.assertEqual(set(case_dir.iterdir()) - before, {report, enriched})
        written = {path for path in (self.root / "reports").rglob("*") if path.is_file()}
        self.assertEqual(written, before & written | {report, enriched})
        self.assertFalse((self.root / "temp").exists())
        self.assertFalse((self.root / "reports" / "user-investigations").exists())

        # The supplied evidence is never rewritten; the enriched copy carries the case binding.
        self.assertEqual(self.evidence.read_bytes(), self.original)
        copy = json.loads(enriched.read_text(encoding="utf-8"))
        self.assertEqual((copy["tenant_id"], copy["case_id"]), (TENANT_A, "case-1"))
        self.assertIn("enrichment_metadata", copy)
        for path in (report, enriched):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_evidence_from_another_tenant_is_refused(self):
        self.write_config()
        _, case_dir = self.case()
        self.write_evidence(tenant_id=TENANT_B)
        before = self.names(case_dir)
        done = self.run_script(self.SCRIPT, self.evidence, "--context", case_dir / "context.json")
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn("different tenant", done.stdout)
        self.assertEqual(self.names(case_dir), before)
        self.assertFalse(self.network_log.exists())

    def test_same_case_name_in_two_tenants_never_shares_a_directory(self):
        self.write_config()
        directories = [self.case("alpha", WORKSPACE_A)[1], self.case("beta", WORKSPACE_B)[1]]
        self.assertNotEqual(*directories)
        for case_dir in directories:
            done = self.run_script(self.SCRIPT, self.evidence, "--context", case_dir / "context.json")
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        for case_dir in directories:
            self.assertEqual(len(list(case_dir.glob("Investigation_Report_Compact_*.html"))), 1)
            self.assertEqual(len(list(case_dir.glob("investigation_enriched_*.json"))), 1)

    def test_without_a_registry_the_legacy_locations_still_work(self):
        self.write_config(registry=False)
        shared = self.root / "temp" / "investigation_analyst_20261116_000000.json"
        shared.parent.mkdir()
        shutil.move(self.evidence, shared)
        done = self.run_script(self.SCRIPT, shared.relative_to(self.root))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        reports = self.root / "reports" / "user-investigations"
        self.assertEqual(len(list(reports.glob("Investigation_Report_Compact_analyst_*.html"))), 1)
        self.assertIn("enrichment_metadata", json.loads(shared.read_text(encoding="utf-8")))
        self.assertFalse((self.root / "reports" / "tenants").exists())

    def test_shared_cleanup_never_removes_tenant_case_outputs(self):
        self.write_config()
        _, case_dir = self.case()
        old = time.time() - 30 * 86400
        kept = [case_dir / "investigation_old.json", case_dir / "Investigation_Report_Compact_old.html"]
        legacy = self.root / "temp" / "investigation_legacy.json"
        legacy.parent.mkdir()
        for path in (*kept, legacy):
            path.write_text("{}", encoding="utf-8")
            os.utime(path, (old, old))

        from scripts.cleanup_old_investigations import cleanup_old_investigations
        with contextlib.redirect_stdout(io.StringIO()):
            deleted, _ = cleanup_old_investigations(
                temp_dir=str(self.root / "temp"), reports_dir=str(self.root / "reports"),
                retention_days=3)
        self.assertEqual(deleted, 1)
        self.assertFalse(legacy.exists())
        self.assertTrue(all(path.exists() for path in kept))


class EnrichIpsTests(MiniRepo):
    SCRIPT = "enrich_ips.py"
    IP = "203.0.113.7"

    def test_registry_requires_a_case_before_any_lookup(self):
        self.write_config()
        done = self.run_script(self.SCRIPT, self.IP)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn("--context", done.stdout)
        self.assertFalse((self.root / "temp").exists())
        self.assertFalse(self.network_log.exists())

    def test_case_results_stay_inside_the_case_directory(self):
        self.write_config()
        _, case_dir = self.case()
        before = set(case_dir.iterdir())
        done = self.run_script(self.SCRIPT, self.IP, "--context", case_dir / "context.json")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        (results,) = case_dir.glob("ip_enrichment_*.json")
        (report,) = case_dir.glob("ip_enrichment_*.txt")
        self.assertEqual(set(case_dir.iterdir()) - before, {results, report})
        self.assertEqual([item["ip"] for item in json.loads(results.read_text(encoding="utf-8"))], [self.IP])
        self.assertIn(self.IP, report.read_text(encoding="utf-8"))
        self.assertFalse((self.root / "temp").exists())
        for path in (results, report):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_file_input_must_match_the_case_tenant(self):
        self.write_config()
        _, case_dir = self.case()
        context = case_dir / "context.json"
        mismatched = self.root / "mismatched.json"
        mismatched.write_text(json.dumps({"tenant_id": TENANT_B, "ips": [self.IP]}), encoding="utf-8")
        before = self.names(case_dir)
        done = self.run_script(self.SCRIPT, "--file", mismatched, "--context", context)
        self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
        self.assertIn("different tenant", done.stdout)
        self.assertEqual(self.names(case_dir), before)
        self.assertFalse(self.network_log.exists())

        matching = self.root / "matching.json"
        matching.write_text(json.dumps({"tenant_id": TENANT_A, "ips": [self.IP]}), encoding="utf-8")
        done = self.run_script(self.SCRIPT, "--file", matching, "--context", context)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(len(list(case_dir.glob("ip_enrichment_*.json"))), 1)

    def test_without_a_registry_the_legacy_temp_directory_still_works(self):
        self.write_config(registry=False)
        done = self.run_script(self.SCRIPT, self.IP)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(len(list((self.root / "temp").glob("ip_enrichment_*.json"))), 1)
        self.assertEqual(len(list((self.root / "temp").glob("ip_enrichment_*.txt"))), 1)
        usage = self.run_script(self.SCRIPT)
        self.assertEqual(usage.returncode, 1)
        self.assertIn("Usage:", usage.stdout)


class SharedHelperTests(MiniRepo):
    def test_case_is_mandatory_only_when_a_registry_is_configured(self):
        self.write_config(registry=False)
        self.assertIsNone(require_case_context(None, repo_root=self.root))

        self.write_config()
        with self.assertRaisesRegex(ContextError, "--context"):
            require_case_context(None, repo_root=self.root)
        _, case_dir = self.case()
        bound = require_case_context(case_dir / "context.json", repo_root=self.root)
        self.assertEqual((bound.profile, bound.tenant_id), ("alpha", TENANT_A))

        # Once the registry maps the profile to a different tenant the old case no longer binds.
        registry = {**REGISTRY, "alpha": {**REGISTRY["alpha"], "tenant_id": "99999999-9999-4999-8999-999999999999"}}
        (self.root / "config.json").write_text(json.dumps({"tenants": registry}), encoding="utf-8")
        with self.assertRaises(ContextError):
            require_case_context(case_dir / "context.json", repo_root=self.root)

    def test_evidence_tenant_declaration_must_match_the_case(self):
        self.write_config()
        context, _ = self.case()
        for accepted in ({"tenant_id": TENANT_A.upper()}, {"tenant_id": ""}, {"ips": []}, ["not", "a", "dict"]):
            check_evidence_tenant(accepted, context)
        for declared in (TENANT_B, 7, ["x"], False):
            with self.assertRaises(ContextError):
                check_evidence_tenant({"tenant_id": declared}, context)

    def test_case_files_are_exclusive_plain_names_inside_the_case(self):
        self.write_config()
        context, case_dir = self.case()
        path = write_case_file(self.root, context, "result.json", "{}")
        self.assertEqual(path.resolve(), (case_dir / "result.json").resolve())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaisesRegex(ContextError, "already exists"):
            write_case_file(self.root, context, "result.json", "overwritten")
        self.assertEqual(path.read_text(encoding="utf-8"), "{}")
        before = self.names(case_dir)
        for name in ("../escape.json", "sub/x.json", "context.json", "notes.md", ".hidden.json", ""):
            with self.assertRaises(ContextError, msg=name):
                write_case_file(self.root, context, name, "x")
        self.assertEqual(self.names(case_dir), before)

    def test_a_symlinked_case_directory_is_refused(self):
        self.write_config()
        context, case_dir = self.case("alpha", WORKSPACE_A)
        _, other_dir = self.case("beta", WORKSPACE_B)
        case_dir.rename(case_dir.with_name("moved"))
        case_dir.symlink_to(other_dir, target_is_directory=True)
        with self.assertRaises(ContextError):
            write_case_file(self.root, context, "result.json", "{}")
        self.assertFalse((other_dir / "result.json").exists())


@contextlib.contextmanager
def offline_requests():
    """Import scripts.investigator against a stub `requests` and drop it afterwards."""
    with patch.dict(sys.modules, {"requests": types.ModuleType("requests")}):
        sys.modules.pop("scripts.investigator", None)
        yield


class InvestigationConfigTests(MiniRepo):
    def load(self, config, **kwargs):
        path = self.root / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        with offline_requests():
            from scripts.investigator import InvestigationConfig
            return InvestigationConfig.from_file(str(path), **kwargs)

    def test_unmodelled_keys_do_not_break_loading(self):
        config = self.load({
            "sentinel_workspace_id": WORKSPACE_A, "tenant_id": TENANT_A, "ipinfo_token": "token",
            "subscription_id": "ignored", "azure_mcp": {"tenant": TENANT_A},
        })
        self.assertEqual(
            (config.tenant_id, config.sentinel_workspace_id, config.ipinfo_token),
            (TENANT_A, WORKSPACE_A, "token"))

    def test_registry_is_authoritative_over_root_tenant_values(self):
        config = {"tenant_id": TENANT_B, "sentinel_workspace_id": WORKSPACE_B,
                  "ipinfo_token": "token", "tenants": REGISTRY}
        unselected = self.load(config)
        self.assertEqual((unselected.tenant_id, unselected.sentinel_workspace_id), ("", ""))
        self.assertEqual(unselected.ipinfo_token, "token")
        selected = self.load(config, profile="alpha")
        self.assertEqual((selected.tenant_id, selected.sentinel_workspace_id), (TENANT_A, WORKSPACE_A))

    def test_a_profile_with_several_workspaces_binds_none(self):
        registry = {"alpha": {**REGISTRY["alpha"], "workspaces": [{"id": WORKSPACE_A2}]}}
        selected = self.load({"tenants": registry}, profile="alpha")
        self.assertEqual((selected.tenant_id, selected.sentinel_workspace_id), (TENANT_A, ""))


class PortalLinkTests(MiniRepo):
    def link(self, *args):
        done = self.run_script("scripts/kql_to_ah_url.py", *args, "DeviceInfo | take 1")
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def test_registry_never_borrows_the_root_tenant(self):
        self.write_config(tenant_id=TENANT_B)
        self.assertNotIn("tid=", self.link())
        self.assertTrue(self.link("--tid", TENANT_A).endswith("&tid=" + TENANT_A))

    def test_legacy_config_still_supplies_its_tenant(self):
        self.write_config(registry=False, tenant_id=TENANT_A)
        self.assertTrue(self.link().endswith("&tid=" + TENANT_A))


if __name__ == "__main__":
    unittest.main()
