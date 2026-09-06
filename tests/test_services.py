import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.modules.services import (
    audit_services, _parse_unit_files, _windows_enabled_services,
)
from edr_auditor.hive import HiveBuilder, REG_SZ, REG_DWORD

CFG = {"scan_scope": {"services": {"baseline": ["evil-watcher.service"]}}}

UNIT_TEXT = (
    "UNIT FILE                               STATE\n"
    "evil-watcher.service                    enabled\n"
    "zzz-nefarious.service                   enabled\n"
    "unused.timer                            disabled\n"
)


def _ctx(unit_text=None, hives=None, mode="fixture"):
    return {
        "mode": mode,
        "systemctl_units": unit_text or "",
        "hives": hives or {},
    }


def _titles(findings):
    return [f.title for f in findings]


class TestParseUnitFiles(unittest.TestCase):
    def test_enabled_only(self):
        self.assertEqual(_parse_unit_files(UNIT_TEXT),
                         ["evil-watcher.service", "zzz-nefarious.service"])

    def test_empty(self):
        self.assertEqual(_parse_unit_files(""), [])


class TestParseWindowsServices(unittest.TestCase):
    def test_start2_enabled_automatic(self):
        workdir = "/tmp/edr_test_svc_%d" % os.getpid()
        os.makedirs(workdir, exist_ok=True)
        path = os.path.join(workdir, "SYSTEM")
        b = HiveBuilder()
        b.add_key("ControlSet001\\Services\\evil")
        b.add_value("ControlSet001\\Services\\evil", "Start", REG_DWORD, 2)
        b.add_value("ControlSet001\\Services\\evil", "DisplayName",
                    REG_SZ, "Evil service")
        b.write(path)
        from edr_auditor.hive import HiveRegistry
        services = _windows_enabled_services({"SYSTEM": HiveRegistry(path)})
        self.assertEqual([s["name"] for s in services], ["evil"])
        self.assertEqual(services[0]["display"], "Evil service")
        self.assertEqual(services[0]["hive"], "SYSTEM")

    def test_start1_ignored(self):
        workdir = "/tmp/edr_test_svc1_%d" % os.getpid()
        os.makedirs(workdir, exist_ok=True)
        path = os.path.join(workdir, "SYSTEM")
        b = HiveBuilder()
        b.add_key("ControlSet001\\Services\\ok")
        b.add_value("ControlSet001\\Services\\ok", "Start", REG_DWORD, 1)
        b.write(path)
        from edr_auditor.hive import HiveRegistry
        services = _windows_enabled_services({"SYSTEM": HiveRegistry(path)})
        self.assertEqual(services, [])


class TestServicesAudit(unittest.TestCase):
    def test_outside_baseline_medium(self):
        findings = audit_services(_ctx(UNIT_TEXT), CFG)
        match = [f for f in findings if "outside baseline" in f.title]
        names = " ".join(m.title for m in match)
        self.assertIn("zzz-nefarious", names)
        self.assertNotIn("evil-watcher", names)
        self.assertEqual(len(match), 1)

    def test_baseline_removed_low(self):
        # zero enabled units would mean no services; use one enabled unit so
        # the baseline diff reports the removed baseline entry.
        text = ("evil-watcher.service       disabled\n"
                "cron.service                enabled\n")
        findings = audit_services(_ctx(text), CFG)
        match = [f for f in findings if "no longer enabled" in f.title]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].severity, "low")
        self.assertIn("evil-watcher", match[0].title)

    def test_empty_listing_no_crash(self):
        findings = audit_services(_ctx(""), CFG)
        self.assertIsInstance(findings, list)


class TestHiveServicesDiff(unittest.TestCase):
    def test_auto_start_outside_baseline(self):
        workdir = "/tmp/edr_test_svcx_%d" % os.getpid()
        os.makedirs(workdir, exist_ok=True)
        path = os.path.join(workdir, "SYSTEM")
        b = HiveBuilder()
        b.add_key("ControlSet001\\Services\\evil")
        b.add_value("ControlSet001\\Services\\evil", "Start", REG_DWORD, 2)
        b.write(path)
        from edr_auditor.hive import HiveRegistry
        ctx = _ctx(hives={"SYSTEM": HiveRegistry(path)})
        findings = audit_services(ctx, CFG)
        match = [f for f in findings if "auto-start outside baseline" in f.title]
        self.assertEqual(len(match), 1)

    def test_baseline_allowlisted(self):
        workdir = "/tmp/edr_test_svcy_%d" % os.getpid()
        os.makedirs(workdir, exist_ok=True)
        path = os.path.join(workdir, "SYSTEM")
        b = HiveBuilder()
        b.add_key("ControlSet001\\Services\\evil-watcher.service")
        b.add_value("ControlSet001\\Services\\evil-watcher.service",
                    "Start", REG_DWORD, 2)
        b.write(path)
        from edr_auditor.hive import HiveRegistry
        ctx = _ctx(hives={"SYSTEM": HiveRegistry(path)})
        findings = audit_services(ctx, CFG)
        self.assertNotIn("auto-start outside baseline",
                         " ".join(_titles(findings)))


if __name__ == "__main__":
    unittest.main()