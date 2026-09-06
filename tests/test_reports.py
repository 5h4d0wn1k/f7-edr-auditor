import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.models import Finding, SEVERITIES
from edr_auditor.report import (
    build_report, render_html, render_json, write_reports, sanitize_hostname,
)

CFG = {"report": {"dir": "/tmp/edr_test_reports"},
       "score": {"min_severity": "low",
                 "weights": {"persistence": 30, "services": 15, "sockets": 15,
                             "patches": 20, "hardening": 20}},
       "scan_scope": {"patches": {"enabled": True}}}


def _finding(module, title, severity="high", evidence="<evil&co>"):
    return Finding(module=module, severity=severity, title=title, description="d",
                   evidence=evidence, remediation="remediate it")


class TestSanitizeHostname(unittest.TestCase):
    def test_replaces_unsafe_characters(self):
        self.assertEqual(sanitize_hostname("h/ost:1*?"), "h-ost-1-")

    def test_empty_falls_back(self):
        self.assertTrue(sanitize_hostname("") or sanitize_hostname(None))


class TestRenderJson(unittest.TestCase):
    def test_round_trips(self):
        report = build_report({"host": "test-host"}, {}, CFG, "fixture")
        blob = render_json(report)
        parsed = json.loads(blob)
        self.assertEqual(parsed["tool"], "f7-edr-auditor")
        self.assertEqual(parsed["host"], "test-host")
        self.assertIn("modules", parsed)

    def test_score_included_by_build(self):
        report = build_report({}, {}, CFG, "fixture")
        self.assertIn("score", report)


class TestRenderHtml(unittest.TestCase):
    def test_escapes_untrusted_strings(self):
        f = _finding("patches", "Outdated <package>", evidence='ev & "quoted"')
        report = {"tool": "f7", "host": "x", "mode": "fixture",
                  "platform": "synthetic", "distro": "",
                  "generated_at": "2026-01-01T00:00:00Z",
                  "score": {"total": 10.5},
                  "modules": {"patches": {"score": 10.5, "findings": [f.as_dict()]}}}
        html_text = render_html(report).decode("utf-8")
        self.assertIn("Outdated &lt;package&gt;", html_text)
        self.assertNotIn("Outdated <package>", html_text)
        self.assertIn("ev &amp; &quot;quoted&quot;", html_text)
        self.assertNotIn("'<evil&co>'", html_text)

    def test_escapes_evidence(self):
        f = _finding("sockets", "Wildcard listener", evidence="0.0.0.0:31337 <i>x</i>")
        report = dict(_empty_report())
        report["modules"] = {"sockets": {"score": 50.0,
                                         "findings": [f.as_dict()]}}
        html_text = render_html(report).decode("utf-8")
        self.assertIn("&lt;i&gt;x&lt;/i&gt;", html_text)
        self.assertNotIn("<i>x</i>", html_text)


def _empty_report():
    return {"tool": "f7", "host": "x", "mode": "fixture", "platform": "synthetic",
            "distro": "", "generated_at": "2026-01-01T00:00:00Z",
            "score": {"total": 100.0}, "modules": {}}


class TestWriteReports(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.join("/tmp", "edr_test_write_%d_%d" % (os.getpid(), id(self)))
        os.makedirs(self.dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_writes_json_and_html(self):
        report = dict(_empty_report())
        json_path, html_path = write_reports(report, "both", self.dir)
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(html_path))
        base = os.path.basename(json_path)
        self.assertTrue(base.startswith("audit-"))
        self.assertTrue(base.endswith(".json"))

    def test_writes_only_json_when_requested(self):
        report = dict(_empty_report())
        paths = write_reports(report, "json", self.dir)
        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0].endswith(".json"))


class TestSeverityModel(unittest.TestCase):
    def test_all_severities_ranked(self):
        self.assertEqual(list(SEVERITIES),
                         ["critical", "high", "medium", "low", "info"])


if __name__ == "__main__":
    unittest.main()