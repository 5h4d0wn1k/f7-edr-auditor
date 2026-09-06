"""Collection pipeline: turns OS data (live) or a fixture sandbox (self-test)
into the context dict that audit modules consume.

The context keys used by modules:
  mode, host, platform, distro
  autostart_files, crontab_files, systemd_files, systemd_enabled
  systemctl_units, ss_output, packages
  sshd_config, file_perms, login_defs, common_password, shadow, firewall
  hives (label -> HiveRegistry)
"""

import glob
import json
import os
import platform
import shutil
import socket
import subprocess

from edr_auditor import __version__
from edr_auditor.hive import HiveRegistry, HiveError
from edr_auditor.config import get, resolve_path

COMMAND_TIMEOUT = 6


def _run(cmd):
    """Run a local command, returning stdout text or None (best effort)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=COMMAND_TIMEOUT, check=False)
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return None


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (OSError, IsADirectoryError):
        return None


def _read_dir_files(directory, suffixes=(".desktop",)):
    """Read every direct file in ``directory`` whose suffix matches."""
    out = {}
    if not os.path.isdir(directory):
        return out
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in names:
        path = os.path.join(directory, name)
        if os.path.isfile(path) and any(name.endswith(suf) for suf in suffixes):
            content = _read_text(path)
            if content is not None:
                out[f"{directory}/{name}"] = content
    return out


def _collect_wants_enabled(directory):
    """Units enabled via `*.wants`/`.wants` symlink directories."""
    enabled = set()
    if not os.path.isdir(directory):
        return enabled
    for entry in sorted(os.listdir(directory)):
        path = os.path.join(directory, entry)
        if not os.path.isdir(path) or not (entry.endswith(".wants") or entry == "wants"):
            continue
        try:
            for name in sorted(os.listdir(path)):
                enabled.add(name)
        except OSError:
            continue
    return enabled


# ---------------------------------------------------------------------------
# Live collection (Linux; guarded by the CLI)
# ---------------------------------------------------------------------------

def _distro_label():
    os_release = _read_text("/etc/os-release") or ""
    for line in os_release.splitlines():
        if line.startswith("ID="):
            return line.split("=", 1)[1].strip().strip('"')
    return "linux"


def _live_command_sources():
    tools = {}
    ss = _run(["ss", "-tulnap"])
    if ss is None:
        ss = _run(["netstat", "-tulnp"])
    tools["ss_output"] = ss or ""

    packages = None
    for cmd in (["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"],
                ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"],
                ["apk", "info", "-a"],
                ["pacman", "-Q"]):
        if shutil.which(cmd[0]):
            packages = _run(cmd)
            if packages:
                break
    tools["packages"] = packages

    ufw = _run(["ufw", "status"]) if shutil.which("ufw") else None
    nft = _run(["nft", "list", "ruleset"]) if shutil.which("nft") else None
    iptables = _run(["iptables", "-L", "-n"]) if shutil.which("iptables") else None
    tools["firewall"] = {"ufw": ufw or "", "nft": nft or "", "iptables": iptables or ""}

    return tools


def _live_home_dirs():
    home = os.path.expanduser("~")
    return {
        "autostart": [f"{home}/.config/autostart", "/etc/xdg/autostart"],
        "crontab": ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"],
        "systemd_user": [],
    }


def _file_perms_live(paths):
    out = {}
    for path in paths:
        try:
            st = os.stat(path)
            out[path] = (st.st_mode & 0o7777, st.st_uid)
        except OSError:
            continue
    return out


def collect_local():
    """Gather context from the real Linux host (run as yourself; read-only)."""
    ctx = {
        "mode": "local",
        "host": socket.gethostname() or "localhost",
        "platform": f"{platform.system()} {platform.release()}",
        "distro": _distro_label(),
        "hives": {},
    }

    home = os.path.expanduser("~")
    autostart = {}
    for d in (f"{home}/.config/autostart", "/etc/xdg/autostart"):
        autostart.update(_read_dir_files(d, suffixes=(".desktop",)))
    ctx["autostart_files"] = autostart

    crontab = {}
    for d in ("/etc/cron.d", "/var/spool/cron/crontabs"):
        crontab.update(_read_dir_files(d, suffixes=("",)))
    for path in ("/etc/crontab",):
        content = _read_text(path)
        if content is not None:
            crontab[path] = content
    ctx["crontab_files"] = crontab

    systemd_files = {}
    systemd_dirs = [f"{home}/.config/systemd/user", "/etc/systemd/system",
                    "/etc/systemd/user", f"{home}/.config/systemd/user"]
    # de-dup while preserving order
    seen = set()
    for d in systemd_dirs:
        if d in seen:
            continue
        seen.add(d)
        for path, content in _read_dir_files(d, suffixes=(".service", ".timer", ".socket")).items():
            if "/.wants/" in path or path.endswith(".wants"):
                continue
            systemd_files[path] = content
    ctx["systemd_files"] = systemd_files
    ctx["systemd_enabled"] = set()
    for d in seen:
        ctx["systemd_enabled"] |= _collect_wants_enabled(d)

    cmd_sources = _live_command_sources()
    ctx["ss_output"] = cmd_sources["ss_output"]
    ctx["packages"] = cmd_sources["packages"]
    ctx["firewall"] = cmd_sources["firewall"]

    sshd = _read_text("/etc/ssh/sshd_config")
    sshd_d = {}
    for path in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
        content = _read_text(path)
        if content is not None:
            sshd_d[path] = content
    if sshd is None and not sshd_d:
        # try ppc-style location
        sshd = _read_text("/etc/sshd/sshd_config")
    merged = ""
    if sshd:
        merged = sshd + "\n"
    merged += "\n".join(sshd_d.values())
    ctx["sshd_config"] = merged
    perms_paths = []
    if sshd:
        perms_paths.append("/etc/ssh/sshd_config")
    perms_paths.extend(list(sshd_d.keys()))
    if not perms_paths and sshd:
        perms_paths.append("/etc/sshd/sshd_config")
    ctx["file_perms"] = _file_perms_live(perms_paths)

    ctx["login_defs"] = _read_text("/etc/login.defs")
    pam = _read_text("/etc/pam.d/common-password")
    if pam is None:
        pam = _read_text("/etc/pam.d/system-auth")
    if pam is None:
        pam = _read_text("/etc/pam.d/password-auth")
    ctx["common_password"] = pam
    ctx["shadow"] = _read_text("/etc/shadow")

    # systemctl unit-file listing
    ctx["systemctl_units"] = _run(["systemctl", "list-unit-files", "--no-pager"]) or ""

    return ctx


# ---------------------------------------------------------------------------
# Fixture collection (self-test / demo; never touches the real host)
# ---------------------------------------------------------------------------

def collect_fixture(fixture_root):
    root = os.path.abspath(str(fixture_root))

    def rel(*parts):
        return os.path.join(root, *parts)

    ctx = {
        "mode": "fixture",
        "host": "fixture-synthetic",
        "platform": "synthetic-fixture",
        "distro": "fixture-debian",
    }

    ctx["autostart_files"] = _read_dir_files(rel("data", "autostart"), suffixes=(".desktop",))
    ctx["crontab_files"] = _read_dir_files(rel("data", "crontab"), suffixes=(".cron",))
    ctx["systemd_files"] = {}
    for path, content in _read_dir_files(rel("data", "systemd", "user"),
                                         suffixes=(".service", ".timer", ".socket")).items():
        if "/.wants/" in path:
            continue
        ctx["systemd_files"][path] = content
    ctx["systemd_files"].update(_read_dir_files(rel("data", "systemd", "system"),
                                                suffixes=(".service", ".timer", ".socket")))
    ctx["systemd_enabled"] = set()
    for d in (rel("data", "systemd", "user"), rel("data", "systemd", "system")):
        ctx["systemd_enabled"] |= _collect_wants_enabled(d)

    ctx["ss_output"] = _read_text(rel("data", "socket", "ss.txt")) or ""
    ctx["packages"] = _read_text(rel("data", "packages", "pkgs.txt")) or None

    sshd = _read_text(rel("data", "ssh", "sshd_config"))
    sshd_d = _read_dir_files(rel("data", "ssh", "sshd_config.d"), suffixes=(".conf",))
    merged = (sshd + "\n" if sshd else "") + "\n".join(sshd_d.values())
    ctx["sshd_config"] = merged

    ctx["file_perms"] = {}
    perms_raw = _read_text(rel("data", "permissions.json"))
    if perms_raw:
        try:
            ctx["file_perms"] = {k: tuple(v) for k, v in json.loads(perms_raw).items()}
        except (ValueError, TypeError):
            ctx["file_perms"] = {}

    ctx["login_defs"] = _read_text(rel("data", "policy", "login.defs"))
    ctx["common_password"] = _read_text(rel("data", "policy", "common-password"))
    ctx["shadow"] = _read_text(rel("data", "policy", "shadow"))

    ctx["firewall"] = {
        "ufw": _read_text(rel("data", "firewall", "ufw.txt")) or "",
        "nft": _read_text(rel("data", "firewall", "nft.txt")) or "",
        "iptables": _read_text(rel("data", "firewall", "iptables.txt")) or "",
    }

    ctx["systemctl_units"] = _read_text(rel("data", "systemctl", "units.txt")) or ""

    ctx["hives"] = {}
    hive_dir = rel("hives")
    if os.path.isdir(hive_dir):
        for name in sorted(os.listdir(hive_dir)):
            label = os.path.splitext(name)[0]
            try:
                ctx["hives"][label] = HiveRegistry(os.path.join(hive_dir, name))
            except HiveError:
                continue

    return ctx


# ---------------------------------------------------------------------------
# Hive collection (passive Windows)
# ---------------------------------------------------------------------------

def collect_hive(cfg, config_dir=None):
    ctx = {
        "mode": "hive",
        "host": socket.gethostname() or "localhost",
        "platform": "windows-hive-passive",
        "distro": "",
        "hives": {},
    }
    hives_cfg = get(cfg, "scan_scope", "hives", default={}) or {}
    for label, path in sorted(hives_cfg.items()):
        resolved = resolve_path(cfg, path)
        if not os.path.isabs(resolved) and config_dir:
            resolved = os.path.join(config_dir, resolved)
        if not os.path.isfile(resolved):
            continue
        try:
            ctx["hives"][label] = HiveRegistry(resolved)
        except HiveError as exc:
            print(f"[!] skipped hive {label} ({resolved}): {exc}")
    return ctx


def collect(mode, cfg, fixture_root=None, config_dir=None):
    """Dispatch to the right collector. Returns a context dict."""
    if mode == "local":
        return collect_local()
    if mode == "fixture":
        return collect_fixture(fixture_root)
    return collect_hive(cfg, config_dir=config_dir)