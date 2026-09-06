import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from edr_auditor.modules.sockets import audit_sockets, _parse_ss

CFG = {"scan_scope": {
    "sockets": {"risky_ports": [31337], "critical_watch": [22]},
    "services": {"baseline": []},
}}

SS_SAMPLE = (
    "Netid State Recv-Q Send-Q  Local Address:Port    Peer Address:Port  Process\n"
    'tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*       users:(("sshd",pid=414))\n'
    'tcp   LISTEN 0      4096        127.0.0.1:631       0.0.0.0:*       users:(("cupsd",pid=333))\n'
    'tcp   LISTEN 0      128        0.0.0.0:31337      0.0.0.0:*       users:(("evil-svc",pid=777))\n'
    'udp   UNCONN 0      1          0.0.0.0:68         0.0.0.0:*       users:(("dhclient",pid=55))\n'
    'tcp   ESTAB  0      0           192.0.2.5:22        192.0.2.6:3333  users:(("sshd",pid=414))\n'
)


def _ctx(ss_text=None, mode="local"):
    return {
        "mode": mode,
        "ss_output": ss_text or "",
        "hives": {},
        "systemd_units": "",
    }


class TestParseSS(unittest.TestCase):
    def test_parses_listening_entries(self):
        rows = list(_parse_ss(SS_SAMPLE))
        self.assertEqual(len(rows), 4)
        listen = [r for r in rows if r["state"] == "LISTEN"]
        self.assertEqual(len(listen), 3)
        self.assertEqual(listen[0]["process"], "sshd")
        self.assertEqual(listen[0]["addr"], "0.0.0.0")
        self.assertEqual(listen[0]["port"], 22)

    def test_skips_garbage(self):
        self.assertEqual(list(_parse_ss("* kernel\nfoo bar\n")), [])


class TestSocketAudit(unittest.TestCase):
    def test_wildcard_listen_low(self):
        findings = audit_sockets(_ctx(SS_SAMPLE), CFG)
        match = [f for f in findings if f.title == "Listener on all interfaces: 68"]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].severity, "low")

    def test_risky_port_medium(self):
        findings = audit_sockets(_ctx(SS_SAMPLE), CFG)
        risky = [f for f in findings if f.title.startswith("Service exposed on all interfaces:")]
        self.assertEqual(len(risky), 1)
        self.assertEqual(risky[0].severity, "medium")
        self.assertIn("31337", risky[0].evidence)

    def test_critical_watch_high(self):
        findings = audit_sockets(_ctx(SS_SAMPLE), CFG)
        crit = [f for f in findings if f.title.startswith("Critically watched port")]
        # two high findings for the sshd listener: "open on all interfaces"
        # (critical_watch + wildcard) and "Critically watched port exposed".
        self.assertEqual(len(crit), 2)
        for f in crit:
            self.assertEqual(f.severity, "high")

    def test_every_listener_gets_overview(self):
        findings = audit_sockets(_ctx(SS_SAMPLE), CFG)
        overview = [f for f in findings if f.title.startswith("Listening service:")]
        self.assertEqual(len(overview), 4)

    def test_estab_not_listened(self):
        findings = audit_sockets(_ctx(SS_SAMPLE), CFG)
        self.assertFalse(any("ESTAB" in f.title for f in findings))

    def test_unknown_process_medium(self):
        # loopback listener with an un-attributable process.
        text = ('tcp   LISTEN 0  128  127.0.0.1:4444  0.0.0.0:*  users:((secretholder))\n')
        findings = audit_sockets(_ctx(text), CFG)
        unknown = [f for f in findings if "no attributable process" in f.title]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0].severity, "medium")

    def test_empty_hive_mode_no_echo(self):
        findings = audit_sockets(_ctx("", mode="hive"), CFG)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()