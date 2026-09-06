import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.modules.patches import (
    audit_patches, _parse_packages, _parse_watch, _version_tuple,
)

CFG = {"scan_scope": {
    "patches": {
        "enabled": True,
        "watch": ["openssh-server>=9.0p1", "openssl>=3.1.0"],
    }
}}


def _ctx(packages=None, mode="fixture"):
    return {"mode": mode, "distro": "debian", "packages": packages or ""}


class TestParsePackages(unittest.TestCase):
    def test_tab_separated(self):
        self.assertEqual(_parse_packages("openssh-server\t8.9p1-3\nopenssl\t3.0.0\n"),
                         {"openssh-server": "8.9p1-3", "openssl": "3.0.0"})

    def test_dpkg_status_lines(self):
        text = ("ii  openssh-server 1:8.9p1-3  amd64\n"
                "un  openssh-client <none> <none>\n"
                "ii  openssl 3.0.0-2 amd64\n")
        self.assertEqual(_parse_packages(text),
                         {"openssh-server": "1:8.9p1-3", "openssl": "3.0.0-2"})

    def test_plain_whitespace(self):
        self.assertEqual(_parse_packages("curl 7.88.1\ncoreutils 9.1\n"),
                         {"curl": "7.88.1", "coreutils": "9.1"})

    def test_empty(self):
        self.assertEqual(_parse_packages(""), {})


class TestVersionCompare(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(_version_tuple("8.9p1"), _version_tuple("9.0p1"))
        self.assertLess(_version_tuple("9.0p0"), _version_tuple("9.0p1"))
        self.assertEqual(_version_tuple("9.0p1"), _version_tuple("9.0p1"))

    def test_non_numeric_is_zero(self):
        self.assertEqual(_version_tuple("abc"), (0,))


class TestWatchParse(unittest.TestCase):
    def test_parses_rule_strings(self):
        rules = _parse_watch(["openssh-server>=9.0p1", "openssl < 3.2"])
        self.assertEqual(rules[0]["name"], "openssh-server")
        self.assertEqual(rules[0]["op"], ">=")
        self.assertEqual(rules[0]["version"], "9.0p1")
        self.assertEqual(rules[1]["name"], "openssl")
        self.assertEqual(rules[1]["op"], "<")
        self.assertEqual(rules[1]["version"], "3.2")

    def test_invalid_rule_skipped(self):
        self.assertEqual(_parse_watch(["nonsense"]), [])


class TestPatchAudit(unittest.TestCase):
    def test_outdated_high(self):
        ctx = _ctx(packages="openssh-server\t8.9p1-3\n")
        findings = audit_patches(ctx, CFG)
        outdated = [f for f in findings if "Outdated package" in f.title]
        self.assertEqual(len(outdated), 1)
        self.assertEqual(outdated[0].evidence, "8.9p1-3 >=9.0p1")
        self.assertEqual(outdated[0].severity, "high")

    def test_current_no_finding(self):
        ctx = _ctx(packages="openssh-server\t9.6p1-3\nopenssl\t3.3.2\n")
        findings = audit_patches(ctx, CFG)
        self.assertNotIn("Outdated package", [f.title for f in findings])

    def test_missing_package_ignored(self):
        ctx = _ctx(packages="python3\t3.11.2\n")
        findings = audit_patches(ctx, CFG)
        self.assertNotIn("Outdated package", [f.title for f in findings])

    def test_package_database_gap(self):
        findings = audit_patches(_ctx(""), CFG)
        self.assertTrue(any("Package database unavailable" in f.title
                            for f in findings))


if __name__ == "__main__":
    unittest.main()