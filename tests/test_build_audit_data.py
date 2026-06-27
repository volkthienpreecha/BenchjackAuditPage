import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_audit_data


README = """# FrontierSWE

- **Upstream repo:** <https://github.com/Proximal-Labs/frontier-swe>
- **Upstream commit:** [`d2ba265`](https://github.com/Proximal-Labs/frontier-swe/commit/d2ba265a79b1b5a7ba34763802cb43720a183f67) (2026-04-16)
- **Audited on:** 2026-04-16
- **Backend:** `claude`
- **Mode:** `audit`
- **Auditor:** BenchJack maintainers

## Summary

FrontierSWE is 17 coding tasks. Every task runs the agent phase and verifier phase inside the same container.

## Findings

| Class | Name | Prevalence | Severity |
|-------|------|------------|----------|
| V1 | No Isolation Between Agent and Evaluator | all 17 tasks | high |
| V2 | Answers Shipped With the Test | many tasks | high |
| V3 | RCE on Untrusted Input | majority of tasks | high |
| V4 | LLM Judge Without Sanitization | - | n/a |
| V5 | Weak String Matching | most tasks | medium |
| V6 | Evaluation Logic Gaps | multiple tasks | medium |
| V7 | Trusting Output of Untrusted Code | majority of tasks | high |
| V8 | Unnecessary Permissions | root agent, GPU exposure | medium |

Per-task detail in [`task_results.json`](task_results.json).

## Reproduction

```bash
benchjack https://github.com/Proximal-Labs/frontier-swe --no-ui
```

## Artifacts

- [`recon.md`](recon.md)
- [`task_results.json`](task_results.json)

## Disclosure

- [x] Not applicable
"""


class BuildAuditDataTests(unittest.TestCase):
    def make_source(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        audit = root / "audits" / "FrontierSWE"
        (audit / "poc").mkdir(parents=True)
        (audit / "README.md").write_text(README, encoding="utf-8")
        (audit / "recon.md").write_text("# Recon\n", encoding="utf-8")
        (audit / "vuln_scan.md").write_text("# Scan\n", encoding="utf-8")
        (audit / "poc.md").write_text("# PoC\n", encoding="utf-8")
        (audit / "poc" / "run.sh").write_text("echo run\n", encoding="utf-8")
        return temp, root

    def test_builds_snapshot_from_audit_readme(self):
        temp, root = self.make_source()
        self.addCleanup(temp.cleanup)

        snapshot = build_audit_data.build_snapshot(root)

        self.assertEqual(snapshot["summary"]["record_count"], 1)
        self.assertEqual(snapshot["summary"]["task_count"], 17)
        record = snapshot["records"][0]
        self.assertEqual(record["name"], "FrontierSWE")
        self.assertEqual(record["backend"], "claude")
        self.assertEqual(record["upstream_repo"], "https://github.com/Proximal-Labs/frontier-swe")
        self.assertEqual(record["task_count"], 17)
        self.assertIsNone(record["exploit_score"])
        self.assertEqual(record["findings"]["V1"]["severity"], "high")
        self.assertEqual(record["findings"]["V4"]["severity"], "na")

    def test_suppresses_missing_artifact_links(self):
        temp, root = self.make_source()
        self.addCleanup(temp.cleanup)

        record = build_audit_data.build_snapshot(root)["records"][0]
        paths = {artifact["path"] for artifact in record["artifacts"]}

        self.assertIn("recon.md", paths)
        self.assertIn("poc/run.sh", paths)
        self.assertNotIn("task_results.json", paths)
        self.assertIn("task_results.json", record["missing_artifact_references"])

    def test_cli_writes_json(self):
        temp, root = self.make_source()
        self.addCleanup(temp.cleanup)
        out = root / "data" / "audits.json"

        exit_code = build_audit_data.main_with_args(["--source", str(root), "--out", str(out)])

        self.assertEqual(exit_code, 0)
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["records"][0]["name"], "FrontierSWE")


if __name__ == "__main__":
    unittest.main()

