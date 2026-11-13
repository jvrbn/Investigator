"""Focused synthetic fixtures conforming to documented export/native SDK shapes."""

import copy
from contextlib import redirect_stderr
import hashlib
from io import StringIO
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch
from uuid import uuid4

from scripts.import_local_agent_evidence import (
    EvidenceError, NATIVE_FORMAT, build_report, import_evidence, main, read_source,
)
from scripts.tenant_context import ContextError, create_context


TENANT = "11111111-1111-4111-8111-111111111111"
WORKSPACE = "22222222-2222-4222-8222-222222222222"
OTHER = "33333333-3333-4333-8333-333333333333"


class LocalAgentEvidenceTests(unittest.TestCase):
    def setUp(self):
        # Keep test material inside the project, never the system temporary directory.
        self.root = Path.cwd() / (".local-agent-tests-" + uuid4().hex)
        self.root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.root)
        config = self.root / "config.json"
        config.write_text(json.dumps({
            "tenants": {"example": {"tenant_id": TENANT, "sentinel_workspace_id": WORKSPACE}}
        }), encoding="utf-8")
        self.context = create_context(
            config, profile="example", workspace_id=WORKSPACE,
            case_id="case-1", lookback_days=7, repo_root=self.root,
        )
        self.context_path = self.root / self.context.report_dir / "context.json"
        self.export = {
            "schema": "local-agent-evidence/v1", "tenant_id": TENANT,
            "workspace_id": WORKSPACE, "session_id": "session-1",
            "configured_mcp": ["configured-only", "mcp-one"],
            "events": [
                self.event("tool.complete", "2026-11-13T10:00:02Z",
                           tool_call_id="call-1", outcome="succeeded",
                           details={"result": {"token": "result-secret", "text": "ordinary result"}}),
                self.event("prompt", "2026-11-13T10:00:00Z",
                           details={"content": "Inspect this file; password=hunter2"}),
                self.event("tool.start", "2026-11-13T10:00:01Z",
                           tool_call_id="call-1", tool_name="read_file", mcp_server="mcp-one",
                           details={"arguments": {"nested": [{"api_key": "argument-secret"}]}}),
                self.event("response", "2026-11-13T10:00:03Z",
                           details={"content": "Finished"}),
            ],
        }

    @staticmethod
    def event(kind, timestamp, **kwargs):
        return {"type": kind, "timestamp": timestamp, "details": {}, **kwargs}

    def raw(self, export=None):
        return json.dumps(self.export if export is None else export).encode()

    def report(self, export=None, **kwargs):
        return build_report(self.raw(export), context=self.context, **kwargs)

    def write_source(self, raw=None):
        source = self.root / "evidence.json"
        source.write_bytes(self.raw() if raw is None else raw)
        return source

    def test_orders_pairs_and_distinguishes_configured_from_observed(self):
        report = self.report()
        timeline = report["timeline"]
        self.assertEqual([item["type"] for item in timeline],
                         ["prompt", "tool.start", "tool.complete", "response"])
        self.assertEqual(timeline[1]["paired_source_record"], 1)
        self.assertEqual(timeline[2]["paired_source_record"], 3)
        self.assertEqual(timeline[2]["tool_name"], "read_file")
        self.assertEqual(report["mcp"]["observed_invocations"], {"mcp-one": 1})
        self.assertEqual(report["mcp"]["configured_not_observed"], ["configured-only"])
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(self.raw()).hexdigest())
        self.assertEqual(timeline[0]["correlation"], "temporal_only")

    def test_metadata_default_withholds_all_payloads(self):
        report = self.report()
        serialized = json.dumps(report)
        for value in ("hunter2", "ordinary result", "argument-secret", "Finished"):
            self.assertNotIn(value, serialized)
        self.assertTrue(all(item["details"] == {"withheld": True} for item in report["timeline"]))

    def test_capture_is_opt_in_and_redacts_nested_args_results_errors_and_text(self):
        self.export["events"][0]["details"]["error"] = {
            "headers": {"Authorization": "Bearer abcdefghijklmnop"},
            "message": 'token=error-secret password="multi word secret"',
            "nested_json": '{"api_key": "embedded secret with spaces"}',
        }
        self.export["events"][3]["details"]["content"] = (
            "github_pat_abcdefghijk eyJabc.def.ghi "
            "-----BEGIN PRIVATE KEY-----\nprivate-value\n-----END PRIVATE KEY-----"
        )
        report = self.report(capture_content=True)
        serialized = json.dumps(report)
        for value in (
            "hunter2", "result-secret", "argument-secret", "abcdefghijklmnop",
            "error-secret", "github_pat_abcdefghijk", "eyJabc.def.ghi", "private-value",
            "multi word secret", "embedded secret with spaces",
        ):
            self.assertNotIn(value, serialized)
        self.assertIn("ordinary result", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_jsonl_contract_has_header_then_events(self):
        header = {key: value for key, value in self.export.items() if key != "events"}
        raw = "\n".join(json.dumps(item) for item in [header, *self.export["events"]]).encode()
        report = build_report(raw, context=self.context, format_name="jsonl")
        self.assertEqual(len(report["timeline"]), 4)
        self.assertEqual(report["source"]["records"], 4)

    def test_native_sdk_schema_subset_maps_messages_args_results_errors_and_mcp(self):
        # Native field names verified against github/copilot-sdk's generated session-events.ts.
        records = [
            {"id": "event-1", "parentId": None, "timestamp": "2026-11-13T10:00:00Z",
             "type": "user.message", "data": {"content": "prompt"}},
            {"id": "event-2", "parentId": "event-1", "timestamp": "2026-11-13T10:00:01Z",
             "type": "tool.execution_start", "data": {
                 "toolCallId": "call-1", "toolName": "mcp.tool",
                 "mcpServerName": "friendly-name", "mcpConfigServerName": "server-key",
                 "arguments": {"token": "native-secret", "path": "/workspace/file.txt"},
             }},
            {"id": "event-3", "parentId": "event-2", "timestamp": "2026-11-13T10:00:02Z",
             "type": "tool.execution_complete", "data": {
                 "toolCallId": "call-1", "success": False,
                 "result": {"content": "partial output"},
                 "error": {"message": "token=failed-secret"},
             }},
            {"id": "event-4", "parentId": "event-3", "timestamp": "2026-11-13T10:00:03Z",
             "type": "assistant.message", "data": {"content": "response", "messageId": "message-1"}},
        ]
        raw = "\n".join(map(json.dumps, records)).encode()
        report = build_report(raw, context=self.context, format_name=NATIVE_FORMAT,
                              session_id="operator-supplied", capture_content=True)
        self.assertEqual(report["source"]["binding"], "operator_asserted")
        self.assertEqual(report["mcp"]["observed_invocations"], {"server-key": 1})
        self.assertEqual(report["timeline"][2]["outcome"], "failed")
        self.assertEqual(report["timeline"][1]["parent_event_id"], "event-1")
        self.assertIn("partial output", json.dumps(report))
        self.assertNotIn("native-secret", json.dumps(report))
        self.assertNotIn("failed-secret", json.dumps(report))
        records[0]["type"] = "session.unsupported"
        with self.assertRaises(EvidenceError):
            build_report("\n".join(map(json.dumps, records)).encode(),
                         context=self.context, format_name=NATIVE_FORMAT, session_id="s")

    def test_native_malformed_completion_rejected_not_silently_dropped(self):
        record = {"id": "e", "parentId": None, "timestamp": "2026-11-13T10:00:00Z",
                  "type": "tool.execution_complete",
                  "data": {"toolCallId": "c", "success": "true"}}
        with self.assertRaises(EvidenceError):
            build_report(json.dumps(record).encode(), context=self.context,
                         format_name=NATIVE_FORMAT, session_id="s")
        with self.assertRaises(EvidenceError):
            build_report(json.dumps(record).encode(), context=self.context, format_name=NATIVE_FORMAT)

    def test_observed_actions_preserve_source_outcome_without_inferred_execution(self):
        self.export["events"] = [
            self.event(kind, "2026-11-13T10:00:00Z", outcome=outcome,
                       details={"action": "source-described-action", "observer": "authorized-export"})
            for kind, outcome in (("process", "attempted"), ("file", "blocked"), ("network", "audit"))
        ]
        report = self.report(capture_content=True)
        self.assertEqual([event["outcome"] for event in report["timeline"]],
                         ["attempted", "blocked", "audit"])
        self.assertTrue(all(event["correlation"] == "temporal_only" for event in report["timeline"]))
        self.assertTrue(all("paired_source_record" not in event for event in report["timeline"]))

    def test_offsets_normalize_before_sorting_and_equal_times_keep_input_order(self):
        self.export["events"] = [
            self.event("response", "2026-11-13T11:00:00+02:00"),
            self.event("prompt", "2026-11-13T08:00:00Z"),
            self.event("network", "2026-11-13T09:00:00Z", outcome="unknown",
                       details={"action": "connect", "observer": "export"}),
        ]
        report = self.report()
        self.assertEqual([event["source_record"] for event in report["timeline"]], [2, 1, 3])

    def test_invalid_times_and_wrong_tenant_or_workspace_are_rejected(self):
        for value in ("2026-02-30T00:00:00Z", "2026-11-13", "2026-11-13T00:00:00",
                      "2026-11-13T00:00:00+25:00", 123, None):
            with self.subTest(timestamp=value):
                export = copy.deepcopy(self.export)
                export["events"][0]["timestamp"] = value
                with self.assertRaises(EvidenceError):
                    self.report(export)
        export = copy.deepcopy(self.export)
        export["events"][0]["timestamp"] = "2026-11-13T00:00:00+00:99"
        with self.assertRaises(EvidenceError):
            self.report(export)
        for field in ("tenant_id", "workspace_id"):
            export = copy.deepcopy(self.export)
            export[field] = OTHER
            with self.assertRaises(EvidenceError):
                self.report(export)

    def test_malformed_or_unsupported_exports_fail_closed(self):
        for raw, format_name in (
            (b'{"schema":"one","schema":"two"}', "json"),
            (b'{"events":[NaN]}', "json"),
            (b'{"events":[1e999]}', "json"),
            (b'not-json', "json"), (b'\xff', "json"),
            (b'{}\n\n{}', "jsonl"), (b'[]', "json"),
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(EvidenceError):
                    build_report(raw, context=self.context, format_name=format_name)
        for mutation in (
            lambda export: export.update(schema="local-agent-evidence/v2"),
            lambda export: export.update(events=[]),
            lambda export: export["events"][0].update(type="unknown"),
            lambda export: export["events"][0].update(extra="unsupported"),
            lambda export: export["events"][0].update(details=[]),
            lambda export: export["events"][0].update(session_id="wrong-session"),
        ):
            export = copy.deepcopy(self.export)
            mutation(export)
            with self.assertRaises(EvidenceError):
                self.report(export)

    def test_duplicate_phases_ids_and_completion_before_start_are_rejected(self):
        export = copy.deepcopy(self.export)
        export["events"].append(copy.deepcopy(export["events"][0]))
        with self.assertRaises(EvidenceError):
            self.report(export)
        export = copy.deepcopy(self.export)
        export["events"][0]["timestamp"] = "2026-11-13T09:00:00Z"
        with self.assertRaises(EvidenceError):
            self.report(export)
        export = copy.deepcopy(self.export)
        for event in export["events"][:2]:
            event["event_id"] = "duplicate"
        with self.assertRaises(EvidenceError):
            self.report(export)

    def test_missing_tool_phase_is_an_explicit_coverage_gap(self):
        self.export["events"].pop(0)
        report = self.report()
        self.assertTrue(any("Unpaired tool phase" in gap for gap in report["coverage_gaps"]))

    def test_authorization_and_existing_canonical_context_are_required(self):
        source = self.write_source()
        with self.assertRaises(EvidenceError):
            import_evidence(source, self.context_path, repo_root=self.root)
        with self.assertRaises(ContextError):
            import_evidence(source, self.root / "missing.json", repo_root=self.root, authorized=True)
        copied = self.root / "copied-context.json"
        copied.write_bytes(self.context_path.read_bytes())
        with self.assertRaises(ContextError):
            import_evidence(source, copied, repo_root=self.root, authorized=True)

    def test_unsupported_platform_fails_explicitly_before_accessing_evidence(self):
        with patch("scripts.import_local_agent_evidence.os.name", "nt"):
            with self.assertRaisesRegex(EvidenceError, "unsupported platform.*Windows"):
                import_evidence("unread-source", "unread-context",
                                repo_root="unread-root", authorized=True)
        with patch("scripts.import_local_agent_evidence.os.supports_dir_fd", set()):
            with self.assertRaisesRegex(EvidenceError, "unsupported platform"):
                import_evidence("unread-source", "unread-context",
                                repo_root="unread-root", authorized=True)
            errors = StringIO()
            with redirect_stderr(errors):
                status = main(["unread-source", "--context", "unread-context", "--authorized"])
            self.assertEqual(status, 2)
            self.assertIn("unsupported platform", errors.getvalue())

    def test_exclusive_contained_private_output_and_no_overwrite(self):
        source = self.write_source()
        output = import_evidence(source, self.context_path, repo_root=self.root, authorized=True)
        self.assertEqual(output.parent, self.context_path.parent)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        original = output.read_bytes()
        with self.assertRaises((EvidenceError, OSError, ContextError)):
            import_evidence(source, self.context_path, repo_root=self.root, authorized=True)
        self.assertEqual(output.read_bytes(), original)
        for name in ("../escape.json", "/absolute.json", "sub/file.json", "context.json"):
            with self.assertRaises(EvidenceError):
                import_evidence(source, self.context_path, repo_root=self.root,
                                authorized=True, output_name=name)

    def test_symlink_sources_outputs_and_context_directories_rejected(self):
        source = self.write_source()
        link = self.root / "link.json"
        link.symlink_to(source)
        with self.assertRaises(OSError):
            read_source(link)
        linked_dir = self.root / "linked-dir"
        linked_dir.symlink_to(self.context_path.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            read_source(linked_dir / "context.json")
        outside = self.root / "outside.json"
        outside.write_text("unchanged", encoding="utf-8")
        (self.context_path.parent / "local-agent-timeline.json").symlink_to(outside)
        with self.assertRaises((EvidenceError, OSError, ContextError)):
            import_evidence(source, self.context_path, repo_root=self.root, authorized=True)
        self.assertEqual(outside.read_text(), "unchanged")
        case_dir = self.context_path.parent
        moved = case_dir.with_name("relocated")
        case_dir.rename(moved)
        case_dir.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ContextError):
            import_evidence(source, self.context_path, repo_root=self.root, authorized=True)

    def test_evidence_commands_are_data_never_executed(self):
        marker = self.root / "must-not-exist"
        self.export["events"][2]["details"] = {
            "arguments": {"command": f"touch {marker}"},
            "result": {"command": f"touch {marker}"},
        }
        output = import_evidence(self.write_source(), self.context_path,
                                 repo_root=self.root, authorized=True, capture_content=True)
        self.assertFalse(marker.exists())
        self.assertIn("touch", output.read_text())

    def test_end_to_end_cli_isolated_repo_two_tenants_and_actionable_errors(self):
        config_b = self.root / "tenant-b-config.json"
        config_b.write_text(json.dumps({
            "tenants": {"tenant-b": {"tenant_id": OTHER, "sentinel_workspace_id": OTHER}}
        }), encoding="utf-8")
        tenant_b = create_context(
            config_b, profile="tenant-b", workspace_id=OTHER,
            case_id="case-1", lookback_days=7, repo_root=self.root,
        )
        b_directory = self.root / tenant_b.report_dir
        b_original = (b_directory / "context.json").read_bytes()
        source = self.write_source()
        command = [
            sys.executable, str(Path(__file__).resolve().parents[1] /
                                "scripts/import_local_agent_evidence.py"),
            str(source), "--repo-root", str(self.root),
            "--context", self.context.report_dir + "/context.json",
            "--format", "json", "--authorized",
        ]
        for name, flags in (("default.json", []), ("capture.json", ["--capture-content"])):
            result = subprocess.run(command + ["--output-name", name] + flags,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads((self.context_path.parent / name).read_text())
            self.assertEqual([event["type"] for event in output["timeline"]],
                             ["prompt", "tool.start", "tool.complete", "response"])
            self.assertEqual(output["timeline"][1]["paired_source_record"], 1)
            self.assertEqual(output["mcp"]["observed_invocations"], {"mcp-one": 1})
            self.assertEqual(output["mcp"]["configured_not_observed"], ["configured-only"])
            self.assertNotIn("argument-secret", json.dumps(output))
            self.assertNotIn("result-secret", json.dumps(output))
            self.assertEqual("ordinary result" in json.dumps(output), bool(flags))
        self.assertEqual(sorted(path.name for path in b_directory.iterdir()), ["context.json"])
        self.assertEqual((b_directory / "context.json").read_bytes(), b_original)
        result = subprocess.run(command + ["--output-name", "default.json"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output already exists", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        wrong_root = self.root / "wrong-root"
        wrong_root.mkdir()
        result = subprocess.run([
            sys.executable, command[1], str(source), "--repo-root", str(wrong_root),
            "--context", str(self.context_path), "--authorized",
        ], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Context rejected:", result.stderr)
        self.assertIn("inside repository", result.stderr)
        self.assertIn("--repo-root", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
