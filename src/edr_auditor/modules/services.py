"""Services module: enabled services (and baseline comparison).

Linux live/fixture source: ``systemctl list-unit-files`` text.
Windows passive source: SERVICES hive (ControlSet001\\Services with Start == 2).
Baseline services come from config ``scan_scope.services.baseline`` — a
"known-good" allowlist. Services enabled outside the baseline lower the score.
"""

from edr_auditor.models import Finding
from edr_auditor.config import get

ENABLED_STATES = {"enabled", "enabled-runtime", "linked"}


def _parse_unit_files(text):
    """Parse `systemctl list-unit-files` output -> list of enabled unit names."""
    enabled = []
    for line in (text or "").splitlines():
        tokens = line.split()
        if len(tokens) >= 2 and "." in tokens[0]:
            if tokens[1] in ENABLED_STATES:
                enabled.append(tokens[0])
    return enabled


def _windows_enabled_services(hives):
    enabled = []
    for hlabel, hive in (hives or {}).items():
        svc_node = hive.open_key("ControlSet001\\Services")
        if svc_node is None:
            continue
        for sub in svc_node.subkeys():
            start = sub.get_value("Start")
            if start is None:
                continue
            data = start.data
            if isinstance(data, int) and data == 2:  # SERVICE_AUTO_START
                display = sub.get_value("DisplayName")
                image = sub.get_value("ImagePath")
                enabled.append({
                    "name": sub.name,
                    "display": str(display.data) if display else "",
                    "image": str(image.data) if image else "",
                    "hive": hlabel,
                })
    return enabled


def audit_services(ctx, cfg):
    findings = []
    baseline = list(get(cfg, "scan_scope", "services", "baseline", default=[]))

    linux_enabled = _parse_unit_files(ctx.get("systemctl_units") or "")
    if linux_enabled:
        findings.append(Finding(
            module="services",
            severity="info",
            title=f"Enabled services: {len(linux_enabled)}",
            description="Services currently flagged as enabled by systemd: "
                        + ", ".join(sorted(linux_enabled)),
            remediation="Review the list; keep the attack surface minimal "
                        "(disable unused units).",
            evidence=", ".join(sorted(linux_enabled)),
            source="systemctl-list-unit-files",
            tags=("systemd", "overview"),
        ))

    # Enabled services beyond / missing from the baseline.
    if baseline and linux_enabled:
        added = sorted(set(linux_enabled) - set(baseline))
        removed = sorted(set(baseline) - set(linux_enabled))
        for unit in added:
            findings.append(Finding(
                module="services",
                severity="medium",
                title=f"Service enabled outside baseline: {unit}",
                description=f"Unit {unit} is enabled but is not in the baseline allowlist.",
                remediation="Disable the service if it was not intentionally enabled, or "
                            "document it and add it to scan_scope.services.baseline.",
                evidence=unit,
                source="systemctl-list-unit-files",
                tags=("systemd", "baseline"),
            ))
        for unit in removed:
            findings.append(Finding(
                module="services",
                severity="low",
                title=f"Baseline service no longer enabled: {unit}",
                description=f"Unit {unit} is listed in the baseline but is not currently enabled.",
                remediation="Re-enable the service if it should be running, or update the baseline.",
                evidence=unit,
                source="systemctl-list-unit-files",
                tags=("systemd", "baseline"),
            ))

    # Windows hive services (passive).
    win_enabled = _windows_enabled_services(ctx.get("hives"))
    if win_enabled:
        win_names = {s["name"] for s in win_enabled}
        if baseline:
            added = sorted(win_names - set(baseline))
        else:
            added = sorted(win_names)
        for svc in sorted(win_enabled, key=lambda s: s["name"]):
            if svc["name"] not in added:
                continue
            label = svc["display"] or svc["name"]
            findings.append(Finding(
                module="services",
                severity="medium",
                title=f"Windows service auto-start outside baseline: {svc['name']}",
                description=f"Service {label} (ImagePath: {svc['image'] or 'n/a'}) is set to "
                            f"Start=2 (auto) in hive {svc['hive']} and is not allowlisted.",
                remediation="Verify the service is legitimate; set Start to demand/manual or "
                            "disable it via services.msc (or sc config ... start= demand).",
                evidence=svc["image"],
                source=f"{svc['hive']}:ControlSet001\\Services\\{svc['name']}",
                tags=("windows-hive", "services"),
            ))

    return findings