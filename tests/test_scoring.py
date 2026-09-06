import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.models import Finding, SEVERITY_POINTS
from edr_auditor.scoring import score_report, score_findings, normalize_weights

DEFAULT_WEIGHTS = {"persistence": 30, "services": 15, "sockets": 15,
                   "patches": 20, "hardening": 20}


def _finding(module, severity):
    return Finding(module=module, severity=severity, title="t", description="d",
                   remediation="r", evidence="e")


def _report(rows_by_module):
    rows = {}
    for name, fs in rows_by_module.items():
        rows[name] = [f if isinstance(f, dict) else f.as_dict() for f in fs]
    return {"modules": {name: {"findings": fs} for name, fs in rows.items()}}


def _cfg(min_severity="low", weights=None):
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)
    return {"score": {"min_severity": min_severity, "weights": w}}


class TestSeverityPoints(unittest.TestCase):
    def test_points_map(self):
        self.assertEqual(SEVERITY_POINTS["critical"], 40)
        self.assertEqual(SEVERITY_POINTS["high"], 25)
        self.assertEqual(SEVERITY_POINTS["medium"], 12)
        self.assertEqual(SEVERITY_POINTS["low"], 5)
        self.assertEqual(SEVERITY_POINTS["info"], 1)


class TestScoreReport(unittest.TestCase):
    def test_clean_host_100(self):
        score = score_report(_report({}), _cfg())
        self.assertEqual(score["total"], 100.0)
        self.assertEqual(score["severity"], "info")

    def test_single_critical_drops_to_60(self):
        score = score_report(_report({"persistence": [_finding("persistence", "critical")]}),
                             _cfg())
        self.assertAlmostEqual(score["total"], 88.0, places=6)
        self.assertEqual(score["modules"]["persistence"]["score"], 60.0)

    def test_weights_normalised(self):
        rows = {"persistence": [_finding("persistence", "critical")],
                "hardening": [_finding("hardening", "critical")]}
        score = score_report(_report(rows), _cfg())
        self.assertAlmostEqual(score["total"], 80.0, places=6)

    def test_penalty_accumulates(self):
        rows = {"persistence": [_finding("persistence", "critical"),
                                _finding("persistence", "high")]}
        score = score_report(_report(rows), _cfg())
        # module score 100 - (40 + 25) = 35
        self.assertAlmostEqual(score["total"], 80.5, places=6)
        self.assertAlmostEqual(score["modules"]["persistence"]["score"], 35.0, places=6)

    def test_low_excluded_below_threshold(self):
        rows = {"patches": [_finding("patches", "low")]}
        score = score_report(_report(rows), _cfg(min_severity="medium"))
        self.assertEqual(score["modules"]["patches"]["score"], 100.0)
        self.assertEqual(score["modules"]["patches"]["findings_in_scope"], 0)
        self.assertEqual(score["modules"]["patches"]["findings_total"], 1)

    def test_low_included_at_default_threshold(self):
        rows = {"patches": [_finding("patches", "low")]}
        score = score_report(_report(rows), _cfg())
        self.assertAlmostEqual(score["total"], 99.0, places=6)
        self.assertAlmostEqual(score["modules"]["patches"]["score"], 95.0, places=6)

    def test_no_negative_scores(self):
        rows = {"persistence": [_finding("persistence", "critical")] * 4}
        score = score_report(_report(rows), _cfg())
        self.assertEqual(score["modules"]["persistence"]["score"], 0.0)
        self.assertAlmostEqual(score["total"], 70.0, places=6)

    def test_weighted_average_mixes_modules(self):
        # persistence critical (30/100 weight) -> 60, patches clean -> 100
        rows = {"persistence": [_finding("persistence", "critical")],
                "patches": []}
        score = score_report(_report(rows), _cfg())
        expected = (60.0 * 30 + 100.0 * (15 + 15 + 20 + 20)) / 100.0
        self.assertAlmostEqual(score["total"], expected, places=6)


class TestSeverityThresholds(unittest.TestCase):
    def test_info_below_every_threshold(self):
        rows = {"services": [_finding("services", "info")]}
        for sev in ("low", "medium", "high", "critical"):
            score = score_report(_report(rows), _cfg(min_severity=sev))
            self.assertEqual(score["modules"]["services"]["findings_in_scope"], 0,
                             "info must not be in scope at min_severity=%s" % sev)

    def test_critical_always_in_scope(self):
        rows = {"services": [_finding("services", "critical")]}
        score = score_report(_report(rows), _cfg(min_severity="critical"))
        self.assertEqual(score["modules"]["services"]["findings_in_scope"], 1)


class TestScoreFindings(unittest.TestCase):
    def test_convenience_helper(self):
        score = score_findings({"hardening": [_finding("hardening", "high")]}, _cfg())
        self.assertAlmostEqual(score["total"], 95.0, places=6)


class TestWeights(unittest.TestCase):
    def test_defaults_filled(self):
        weights = normalize_weights({})
        self.assertIn("persistence", weights)
        self.assertIn("hardening", weights)
        self.assertEqual(weights["persistence"], 10)

    def test_partial_merged(self):
        weights = normalize_weights({"score": {"weights": {"patches": 50}}})
        self.assertEqual(weights["patches"], 50)
        self.assertEqual(weights["persistence"], 10)  # unset modules fall back to the default


if __name__ == "__main__":
    unittest.main()