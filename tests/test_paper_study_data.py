import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAPER_DATA = ROOT / "data" / "paper-study.json"


class PaperStudyDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(PAPER_DATA.read_text(encoding="utf-8"))
        cls.records = {record["name"]: record for record in cls.payload["records"]}

    def test_has_exact_ten_benchmark_study(self):
        self.assertEqual(self.payload["summary"]["record_count"], 10)
        self.assertEqual(len(self.payload["records"]), 10)
        self.assertEqual(sum(record["task_count"] for record in self.payload["records"]), 8614)
        self.assertEqual(self.payload["summary"]["table_task_count"], 8614)
        self.assertEqual(self.payload["summary"]["flaw_count"], 219)

    def test_records_exact_appendix_outcomes(self):
        expected = {
            "SWE-bench Verified": (500, 500, 100),
            "SWE-bench Pro": (731, 731, 100),
            "FrontierSWE": (17, 17, 100),
            "MLE-Bench": (74, 75, 98.7),
            "SkillsBench": (79, 88, 89.8),
            "Terminal-Bench": (241, 241, 100),
            "OSWorld": (369, 369, 100),
            "WebArena": (812, 812, 100),
            "NetArena": (5000, 5030, 99.4),
            "AgentBench": (300, 903, 33.2),
        }

        for name, (exploited, denominator, score) in expected.items():
            with self.subTest(name=name):
                record = self.records[name]
                self.assertEqual(record["exploited_count"], exploited)
                self.assertEqual(record["outcome_denominator"], denominator)
                self.assertEqual(record["exploit_score"], score)

    def test_terminal_bench_denominator_mismatch_is_explicit(self):
        terminal = self.records["Terminal-Bench"]

        self.assertEqual(terminal["task_count"], 89)
        self.assertEqual(terminal["outcome_denominator"], 241)
        self.assertTrue(any("89 tasks" in note and "241 tasks" in note for note in terminal["data_notes"]))
        self.assertTrue(any("Terminal-Bench" in note and "241 tasks" in note for note in self.payload["notes"]))

    def test_chart_only_values_are_not_promoted_to_data(self):
        self.assertEqual(
            self.payload["summary"]["chart_value_policy"],
            "exact values only; chart-only values are not digitized",
        )
        self.assertNotIn("figure6_severity_stacks", self.payload)
        self.assertNotIn("figure8_rounds", self.payload)

    def test_paper_matrix_uses_major_flaw_status(self):
        frontierswe = self.records["FrontierSWE"]

        self.assertEqual(frontierswe["findings"]["V1"]["severity"], "major")
        self.assertEqual(frontierswe["findings"]["V7"]["severity"], "major")
        self.assertEqual(frontierswe["findings"]["V4"]["severity"], "na")


if __name__ == "__main__":
    unittest.main()
