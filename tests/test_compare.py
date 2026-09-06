import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.models import Finding
from edr_auditor.compare import compare_reports, _finding_key

# Only the persistence module contributes to the totals used in assertions.
CFG = {"score": {"min_severity": "low", "weights": {
    "persistence": 100, "services": 0, "sockets": 0, "patches": 0, "hardening": 0,
}}}


def _finding(module, title, severity="low"):
    return Finding(module=module, severity=severity, title=title, description="d",
                   remediation="r", evidence="e")


def _doc(*fs):
    return {
        "host": "fixture",
        "generated_at": "2026-01-01T00:00:00Z",
        "modules": {
            "persistence": {"findings": [
                f.as_dict() if hasattr(f, "as_dict") else f for f in fs
            ]},
        },
    }


class TestFindingKey(unittest.TestCase):
    def test_key_stable_across_dict_and_object(self):
        f = _finding("persistence", "Suspicious cron job", "high")
        d = f.as_dict()
        self.assertEqual(_finding_key(d),
                         (d["module"] if "module" in d else "",
                          d["title"],
                          d.get("source", "")))


class TestCompareReport(unittest.TestCase):
    def setUp(self):
        self.f = _finding("persistence", "Suspicious cron job", "high")   # penalty 25 -> 75
        self.g = _finding("persistence", "Evil service", "critical")        # penalty 40 -> 35 with f

    def test_identical_unchanged(self):
        doc = _doc(self.f)
        delta = compare_reports(doc, dict(doc), CFG)
        self.assertEqual(delta["score"]["delta"], 0.0)
        self.assertEqual(delta["summary"]["new"], 0)
        self.assertEqual(delta["summary"]["removed"], 0)
        self.assertEqual(delta["summary"]["changed"], 0)

    def test_new_finding_detected(self):
        before = _doc(self.f)          # 75.0
        after = _doc(self.f, self.g)   # 35.0
        delta = compare_reports(before, after, CFG)
        self.assertAlmostEqual(delta["score"]["before"], 75.0)
        self.assertAlmostEqual(delta["score"]["after"], 35.0)
        self.assertAlmostEqual(delta["score"]["delta"], -40.0)
        self.assertEqual(delta["summary"]["new"], 1)
        self.assertIn(self.g.title, [f["title"] for f in delta["findings"]["new"]])

    def test_removed_finding_detected(self):
        before = _doc(self.f, self.g)  # 35.0
        after = _doc(self.f)           # 75.0
        delta = compare_reports(before, after, CFG)
        self.assertAlmostEqual(delta["score"]["delta"], 40.0)
        self.assertEqual(delta["summary"]["removed"], 1)
        self.assertIn(self.g.title, [f["title"] for f in delta["findings"]["removed"]])

    def test_severity_change_detected(self):
        f2 = dict(self.f.as_dict())
        f2["severity"] = "critical"   # 75 -> 60
        before = _doc(self.f)
        after = _doc(f2)
        delta = compare_reports(before, after, CFG)
        self.assertAlmostEqual(delta["score"]["delta"], -15.0)
        self.assertEqual(delta["summary"]["changed"], 1)
        self.assertIn(self.f.title,
                      [c["before"]["title"] for c in delta["findings"]["severity_changed"]])

    def test_with_only_new_module(self):
        other = _finding("hardening", "No host firewall detected", "high")
        before = _doc()
        after = _doc(self.f, other)
        delta = compare_reports(before, after, CFG)
        self.assertIn("hardening", delta["modules"])
        self.assertEqual(delta["summary"]["new"], 2)


if __name__ == "__main__":
    unittest.main()