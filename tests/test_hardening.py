import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.modules.hardening import audit_hardening

CFG = {"scan_scope": {"hardening": {
    "permission_files": [],
    "expiry_limits": {"password_max_age": 90, "min_password_len": 12},
    "password_quality": {"enabled": True},
    "firewall": {"check": True},
}}}


def _ctx(sshd_config=None, login_defs=None, common_password=None, shadow=None,
         perms=None, firewall=None, mode="local"):
    return {
        "mode": mode,
        "sshd_config": sshd_config or "",
        "login_defs": login_defs,
        "common_password": common_password,
        "shadow": shadow,
        "file_perms": perms or {},
        "firewall": firewall or {"ufw": "", "nft": "", "iptables": ""},
        "hives": {},
    }


def _titles(findings):
    return [f.title for f in findings]


class TestSshdHardening(unittest.TestCase):
    def test_root_login_high(self):
        ctx = _ctx(sshd_config="PermitRootLogin yes\nPort 22\n")
        match = [f for f in audit_hardening(ctx, CFG) if "root login" in f.title.lower()]
        self.assertEqual(match[0].severity, "high")

    def test_root_login_explicit_no_not_flagged(self):
        ctx = _ctx(sshd_config="PermitRootLogin no\n")
        self.assertNotIn("SSH root login permitted", _titles(audit_hardening(ctx, CFG)))

    def test_password_auth_medium(self):
        ctx = _ctx(sshd_config="PasswordAuthentication yes\n")
        match = [f for f in audit_hardening(ctx, CFG)
                 if "SSH password authentication enabled" in f.title]
        self.assertEqual(match[0].severity, "medium")


class TestLoginDefs(unittest.TestCase):
    def test_weak_max_age(self):
        ctx = _ctx(login_defs="PASS_MAX_DAYS 180\nPASS_MIN_LEN 4\n")
        findings = audit_hardening(ctx, CFG)
        titles = _titles(findings)
        self.assertIn("Password expiry not enforced", titles)
        self.assertIn("Minimum password length weak", titles)

    def test_shadow_unreadable_info(self):
        findings = audit_hardening(_ctx(), CFG)
        self.assertIn("shadow file not readable", _titles(findings))

    def test_empty_ctx_no_crash(self):
        self.assertIsInstance(audit_hardening(_ctx(), {}), list)


class TestPasswordQuality(unittest.TestCase):
    def test_weak_quality_medium(self):
        ctx = _ctx(common_password="password requisite pam_pwquality.so retry=3 minlen=6")
        match = [f for f in audit_hardening(ctx, CFG)
                 if "password quality policy" in f.title.lower()]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].severity, "medium")

    def test_strong_quality_ok(self):
        ctx = _ctx(common_password="password requisite pam_pwquality.so minlen=12")
        self.assertNotIn("Weak password quality policy",
                         _titles(audit_hardening(ctx, CFG)))


class TestBlankPassword(unittest.TestCase):
    def test_blank_password_critical(self):
        shadow = "root:x:1:...\nvictim::0:99999:7:::\nother:x:1:...\n"
        ctx = _ctx(shadow=shadow)
        match = [f for f in audit_hardening(ctx, CFG) if "blank password" in f.title.lower()]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].severity, "critical")
        self.assertIn("victim", match[0].title)

    def test_no_blank_passwords(self):
        shadow = "root:x:1:...\nvictim:!:0:99999:7:::\n"
        ctx = _ctx(shadow=shadow)
        self.assertNotIn("blank password", "\n".join(_titles(audit_hardening(ctx, CFG))).lower())


class TestFirewall(unittest.TestCase):
    def test_no_firewall_high(self):
        ctx = _ctx(firewall={"ufw": "Status: inactive\n", "nft": "", "iptables": ""})
        match = [f for f in audit_hardening(ctx, CFG)
                 if "No host firewall detected" in f.title]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].severity, "high")

    def test_active_firewall_info(self):
        ctx = _ctx(firewall={"ufw": "Status: active\n", "nft": "", "iptables": ""})
        self.assertIn("Host firewall active", _titles(audit_hardening(ctx, CFG)))


class TestWorldWritablePermissions(unittest.TestCase):
    def test_world_writable_high(self):
        ctx = _ctx(perms={"/etc/ssh/sshd_config.d/extras.conf": (0o666, "root")})
        match = [f for f in audit_hardening(ctx, CFG)
                 if "World-writable" in f.title]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].severity, "high")

    def test_group_writable_low(self):
        ctx = _ctx(perms={"/etc/ssh/sshd_config.d/x.conf": (0o660, "root")})
        match = [f for f in audit_hardening(ctx, CFG)
                 if "Group-writable" in f.title]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].severity, "low")

    def test_safe_permissions_no_finding(self):
        ctx = _ctx(perms={"/etc/ssh/sshd_config.d/extras.conf": (0o600, "root")})
        titles = "\n".join(_titles(audit_hardening(ctx, CFG)))
        self.assertNotIn("writable configuration", titles)

    def test_perms_skipped_in_hive_mode(self):
        ctx = _ctx(perms={"/etc/x": (0o666, "root")}, mode="hive")
        self.assertNotIn("World-writable", _titles(audit_hardening(ctx, CFG)))


if __name__ == "__main__":
    unittest.main()