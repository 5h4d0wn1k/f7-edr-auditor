"""Patches module: installed package / update status (Linux).

Reads a package listing from the distro-appropriate tool
(``dpkg-query``, ``rpm -qa``, ``apk`` or ``pacman``) and compares installed
versions against the security watchlist in ``scan_scope.patches.watch``
(entries like ``"openssh-server>=9.0p1"``). The live run uses the package
manager; passive/fixture runs read the captured listing.
"""

import re

from edr_auditor.models import Finding
from edr_auditor.config import get


def _version_tuple(version):
    """A conservative, numeric-only version comparator.

    ``1:8.9p1`` -> ``(1, 8, 9, 1)``. Loses fine-grained distro semantics
    (epoch, p1 suffixes) but is deterministic and good enough for watch rules.
    """
    if version is None:
        return ()
    digits = re.findall(r"\d+", str(version))
    return tuple(int(d) for d in digits) or (0,)


def _parse_packages(text):
    """Parse a package listing text into {name: version}.

    Tolerates ``dpkg-query`` (``ii  name  version  arch``), ``rpm -qa``
    (``name-version-arch``), and plain ``name\\tversion`` / ``name version``
    lines so the same module works across distro tools.
    """
    packages = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if "\t" in line:
            name, _, version = line.partition("\t")
        else:
            parts = line.split()
            if len(parts) < 2:
                continue
            if re.match(r"^[a-z][a-z]$", parts[0]):
                # dpkg status line: "ii  openssh-server  1:8.9p1-3  amd64".
                # Keep only currently-installed states (ii/hi/iU/...).
                if parts[0].startswith("i") and len(parts) >= 3:
                    name, version = parts[1], parts[2]
                else:
                    continue
            else:
                name, version = parts[0], parts[1]
        packages.setdefault(name.strip(), version.strip())
    return packages


def _parse_watch(entries):
    """Parse watchlist entries like 'openssh-server>=9.0p1'."""
    rules = []
    for entry in entries or []:
        entry = str(entry).strip()
        m = re.match(r"^(.+?)(>=|<=|>|<|==)(.+)$", entry)
        if not m:
            continue
        name, op, ver = m.group(1).strip(), m.group(2), m.group(3).strip()
        rules.append({"name": name, "op": op, "version": ver, "raw": entry})
    return rules


def _violates(installed, rule):
    return _version_tuple(installed) < _version_tuple(rule["version"])


def audit_patches(ctx, cfg):
    findings = []
    packages = _parse_packages(ctx.get("packages"))
    distro = ctx.get("distro") or "unknown"

    if packages:
        findings.append(Finding(
            module="patches",
            severity="info",
            title=f"Installed packages: {len(packages)}",
            description=f"Package database reports {len(packages)} installed packages "
                        f"(distro: {distro}).",
            remediation="Keep the system patched; schedule regular updates "
                        "(unattended-upgrades / dnf-automatic / pacman hook).",
            evidence=f"count={len(packages)}",
            source="package-list",
            tags=("overview",),
        ))
    else:
        findings.append(Finding(
            module="patches",
            severity="info",
            title="Package database unavailable",
            description="No package listing could be read; the patches module cannot "
                        "verify versions.",
            remediation="Run the audit on Linux with dpkg/rpm/apk/pacman available.",
            evidence="",
            source="package-list",
            tags=("coverage-gap",),
        ))

    rules = _parse_watch(get(cfg, "scan_scope", "patches", "watch", default=[]))
    for rule in rules:
        installed = packages.get(rule["name"])
        if installed is None:
            continue
        if _violates(installed, rule):
            findings.append(Finding(
                module="patches",
                severity="high",
                title=f"Outdated package: {rule['name']}",
                description=f"{rule['name']} is {installed}, below the watch minimum "
                            f"{rule['op']}{rule['version']}.",
                remediation=f"Upgrade {rule['name']} (e.g. apt-get install --only-upgrade "
                            f"{rule['name']}) and re-run the audit.",
                evidence=f"{installed} {rule['op']}{rule['version']}",
                source=rule["raw"],
                tags=("patch", "watchlist"),
            ))

    return findings