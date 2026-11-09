"""Offline synthetic tests for the redacted receipt parser."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "summarize-dsh-agent.py"
MODULE = runpy.run_path(str(SCRIPT))
AGENT = MODULE["AGENT"]
PREFLIGHT = MODULE["PREFLIGHT"]
CLEAN = dict.fromkeys(MODULE["CLEANUP"], 0)


class Receipt(unittest.TestCase):
    def setUp(self):
        scratch = SCRIPT.parents[1] / ".build"
        scratch.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix="receipt-check-", dir=scratch)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for role in ("app", "test"):
            with zipfile.ZipFile(self.root / role, "w") as out:
                out.writestr("AndroidManifest.xml", role)
                out.writestr("classes.dex", b"fixture")
        self.rows = [{"test": name, "status": status}
                     for name in [*sorted(PREFLIGHT), *AGENT] for status in ("started", "passed")]
        self.summary = {"status": "passed", "mode": "real", "passed": len(PREFLIGHT) + 4,
                        "confirmed_receipts": 1, "removed_forwards": 1}

    def receipt(self, rows, cleanup=CLEAN):
        (self.root / "run").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        output = self.root / "receipt"
        output.unlink(missing_ok=True)
        args = [sys.executable, str(SCRIPT), "--controller", self.root / "run",
                "--app-apk", self.root / "app", "--test-apk", self.root / "test", "--output", output]
        if cleanup is not None:
            (self.root / "cleanup").write_text(json.dumps(cleanup), encoding="utf-8")
            args += ["--cleanup", self.root / "cleanup"]
        result = subprocess.run(args, capture_output=True, check=False)
        data = json.loads(output.read_bytes()) if output.exists() else None
        return result.returncode, data

    def test_all_four_and_cleanup(self):
        rc, result = self.receipt(self.rows + [self.summary])
        self.assertEqual((rc, result["status"]), (0, "passed"))
        self.assertEqual(result["real_controller"]["agent_cases"], dict.fromkeys(AGENT, "passed"))
        self.assertEqual(result["real_controller"]["preflight"]["passed"], len(PREFLIGHT))
        self.assertNotEqual(*result["supplied_apk_sha256"].values())

    def test_cleanup_is_independent(self):
        for cleanup, expected in [(None, "incomplete"), ({**CLEAN, "owned_adb_forwards_remaining": 1}, "failed")]:
            rc, result = self.receipt(self.rows + [self.summary], cleanup)
            self.assertEqual((rc, result["status"]), (1, expected))
            self.assertEqual(result["real_controller"]["status"], "passed")
        self.assertEqual(self.receipt(self.rows + [self.summary], {**CLEAN, "temporary_imports_remaining": False}), (2, None))

    def test_truncated_and_failed(self):
        rc, result = self.receipt(self.rows[:-1])
        self.assertEqual((rc, result["status"], result["real_controller"]["agent"]["passed"]), (1, "incomplete", 3))
        self.assertIsNone(result["real_controller"]["confirmed_receipts"])
        failed = [*self.rows[:-1], {"test": AGENT[-1], "status": "failed"}, {"status": "failed", "stage": "device_case_failed"}]
        rc, result = self.receipt(failed)
        self.assertEqual((rc, result["status"], result["real_controller"]["agent"]["failed"]), (1, "failed", 1))

    def test_reject_forged_success_or_unlisted_content(self):
        for rows in ([self.summary], self.rows + [{**self.summary, "mode": "synthetic"}],
                     self.rows + [{**self.summary, "confirmed_receipts": True}],
                     self.rows + [self.summary, self.summary], [self.rows[0], self.rows[0]],
                     [{"status": "failed", "stage": "untrusted payload"}],
                     [{"test": AGENT[0], "status": "started", "stdout": "untrusted payload"}]):
            self.assertEqual(self.receipt(rows), (2, None))

    def test_controller_diagnostics(self):
        start = {"test": AGENT[0], "status": "started"}
        diag = {"test": AGENT[0], "status": "agent_diagnostic", "stage": "prepare",
                "safe_reason": "assertion", "error_kind": "none", "event_count": 0,
                "tool_count": 0, "http_status": 0, "rpc_code": 0}
        self.assertEqual(self.receipt([start, diag, {"test": AGENT[0], "status": "passed"}]), (2, None))
        self.assertEqual(self.receipt([start, {**diag, "error_kind": "untrusted payload"}]), (2, None))
        self.assertEqual(self.receipt([start, diag, {"test": AGENT[0], "status": "failed"}])[0], 1)


if __name__ == "__main__":
    unittest.main()
