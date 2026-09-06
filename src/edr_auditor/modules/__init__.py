"""Audit module registry."""

from edr_auditor.modules.persistence import audit_persistence
from edr_auditor.modules.services import audit_services
from edr_auditor.modules.sockets import audit_sockets
from edr_auditor.modules.patches import audit_patches
from edr_auditor.modules.hardening import audit_hardening
from edr_auditor.models import Finding

MODULES = {
    "persistence": {
        "audit": audit_persistence,
        "checks": "Autoruns & startup persistence: Linux autostart, crontab, "
                  "systemd units; Windows Run/RunOnce registry-hive keys.",
        "modes": "local, fixture, hive",
        "weight_default": 30,
    },
    "services": {
        "audit": audit_services,
        "checks": "Enabled services: comparison against baseline allowlist "
                  "(systemctl; Windows hive ControlSet001\\Services Start=2).",
        "modes": "local, fixture, hive",
        "weight_default": 15,
    },
    "sockets": {
        "audit": audit_sockets,
        "checks": "Listening TCP/UDP sockets + owning process; wildcard / risky "
                  "port exposure.",
        "modes": "local, fixture",
        "weight_default": 15,
    },
    "patches": {
        "audit": audit_patches,
        "checks": "Installed package/update status vs a watchlist "
                  "(dpkg/rpm/apk/pacman listings).",
        "modes": "local, fixture",
        "weight_default": 20,
    },
    "hardening": {
        "audit": audit_hardening,
        "checks": "Config hardening: SSH config + file perms, password policy "
                  "(login.defs/PAM/shadow), host firewall status.",
        "modes": "local, fixture",
        "weight_default": 20,
    },
}

# Modules that need live data and get an explicit "skip" note in hive mode.
_LIVE_ONLY = ("sockets", "patches", "hardening")


def run_all(ctx, cfg):
    """Run every audit module against the collected context.

    Returns {module_name: [Finding, ...]}. In hive (passive) mode, live-only
    modules emit an informational note pointing the operator at
    ``edr audit --host local``.
    """
    results = {}
    for name, spec in MODULES.items():
        findings = list(spec["audit"](ctx, cfg))
        if ctx.get("mode") == "hive":
            if not ctx.get("hives") and name in ("persistence", "services"):
                findings.insert(0, _no_hives_note(name))
            elif name in _LIVE_ONLY and not findings:
                findings.append(_live_only_note(name))
        # Always keep a deterministic order.
        findings.sort(key=lambda f: (f.severity, f.title))
        results[name] = findings
    return results


def _no_hives_note(name):
    return Finding(
        module=name,
        severity="info",
        title="No registry hives configured",
        description="No hive files were found at scan_scope.hives; this module had "
                    "nothing passive to parse.",
        remediation="Add copies of your own NTUSER.DAT / SOFTWARE / SYSTEM to "
                    "scan_scope.hives, or run 'edr audit --host local'.",
        evidence="",
        source="config",
        tags=("coverage-gap",),
    )


def _live_only_note(name):
    return Finding(
        module=name,
        severity="info",
        title="Live data required",
        description="This module needs live endpoint data and cannot run from "
                    "registry hives alone.",
        remediation="Run 'edr audit --host local' on a Linux endpoint for a live check. "
                    "See README → Platform Support.",
        evidence="",
        source="hive-mode",
        tags=("coverage-gap",),
    )