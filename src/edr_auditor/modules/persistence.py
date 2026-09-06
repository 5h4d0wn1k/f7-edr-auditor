"""Persistence module: autoruns / startup persistence.

Linux live/fixture sources:
  * ~/.config/autostart + /etc/xdg/autostart  (*.desktop entries)
  * user + system crontab files
  * systemd user/system unit files (+ enabled state via *.wants symlinks)

Windows passive source (registry hive files):
  * Run / RunOnce values under SOFTWARE (incl. Wow6432Node) and NTUSER.DAT
"""

from edr_auditor.models import Finding
from edr_auditor.modules._common import classify_command

RUN_KEY_PATHS = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
]

_CRON_KEYWORDS = ("@reboot", "@daily", "@hourly", "@weekly", "@monthly",
                  "@yearly", "@annually", "@midnight", "@everyminute")


def _parse_desktop_exec(content):
    """Extract the Exec= of a .desktop [Desktop Entry]; None if hidden/absent."""
    if not content:
        return None
    in_entry = False
    exec_cmd = None
    hidden = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_entry = line[1:-1].strip() == "Desktop Entry"
            continue
        if not in_entry:
            continue
        low = line.lower()
        if low.startswith("hidden="):
            hidden = line.split("=", 1)[1].strip().lower() in ("true", "1", "yes")
        elif low.startswith("exec="):
            exec_cmd = line.split("=", 1)[1].strip()
    if hidden:
        return None
    return exec_cmd


def _is_time_field(field):
    return bool(field) and all(ch in "0123456789*?,-/" for ch in field)


def _cron_jobs(content):
    """Yield (raw_line, command) tuples for real cron job lines."""
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(_CRON_KEYWORDS):
            command = line.split(None, 1)[1] if " " in line else ""
            yield line, command
            continue
        tokens = line.split(None, 5)
        if len(tokens) >= 6 and all(_is_time_field(t) for t in tokens[:5]):
            yield line, tokens[5]
            continue
        # Environments like MAILTO/PATH/SHELL are not job lines.
        if len(tokens) >= 2 and "=" in tokens[0]:
            continue


def _unit_exec_start(content):
    """Return the ExecStart of the [Service] section, or None."""
    exec_start = None
    in_service = False
    for line in content.splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith("["):
            in_service = low == "[service]" or low == "[timer]"
            continue
        if in_service and low.startswith("execstart="):
            exec_start = line.split("=", 1)[1].strip()
    return exec_start


def _linux_persistence_findings(ctx):
    findings = []

    for label, content in (ctx.get("autostart_files") or {}).items():
        exec_cmd = _parse_desktop_exec(content)
        if exec_cmd is None:
            continue
        findings.append(Finding(
            module="persistence",
            severity="low",
            title=f"Autostart entry: {label}",
            description=f"A desktop auto-start entry is configured and will run: {exec_cmd}.",
            remediation="Review whether this startup entry is expected. Remove or disable "
                        "unwanted entries (e.g. mv to a backup, or set Hidden=true only "
                        "after investigation).",
            evidence=exec_cmd,
            source=label,
            tags=("autorun", "linux-desktop"),
        ))
        cls = classify_command(exec_cmd)
        if cls:
            severity, reasons = cls
            findings.append(Finding(
                module="persistence",
                severity=severity,
                title="Suspicious autostart command",
                description=f'The autostart "{label}" runs: {exec_cmd} (signals: {"; ".join(reasons)}).',
                remediation="Remove the autostart entry and inspect the script/binary it launches.",
                evidence=exec_cmd,
                source=label,
                tags=("autorun", "suspicious"),
            ))

    for label, content in (ctx.get("crontab_files") or {}).items():
        for raw_line, command in _cron_jobs(content):
            findings.append(Finding(
                module="persistence",
                severity="low",
                title=f"Cron job scheduled: {label}",
                description=f"Found scheduled job in {label}: {raw_line}",
                remediation="Remove the cron entry if it is not expected or approved.",
                evidence=raw_line,
                source=label,
                tags=("cron", "schedule"),
            ))
            cls = classify_command(command)
            if cls:
                severity, reasons = cls
                findings.append(Finding(
                    module="persistence",
                    severity=severity,
                    title="Suspicious cron job",
                    description=f"Cron job in {label} runs: {command} "
                                f'(signals: {"; ".join(reasons)}).',
                    remediation="Delete the cron entry and determine how it was installed "
                                "(check crontab ownership, systemd timers, /etc/cron.d).",
                    evidence=raw_line,
                    source=label,
                    tags=("cron", "suspicious"),
                ))

    enabled = set(ctx.get("systemd_enabled") or [])
    for label, content in (ctx.get("systemd_files") or {}).items():
        exec_start = _unit_exec_start(content)
        if exec_start is None:
            continue
        unit_name = label.rsplit("/", 1)[-1]
        is_enabled = unit_name in enabled
        state = " (enabled)" if is_enabled else ""
        findings.append(Finding(
            module="persistence",
            severity="low",
            title=f"Systemd unit present: {label}",
            description=f"Unit{state} is installed with ExecStart: {exec_start}.",
            remediation="Remove or disable the unit if unexpected "
                        "('systemctl --user disable/stop' or 'systemctl disable/stop').",
            evidence=exec_start,
            source=label,
            tags=("systemd", "unit"),
        ))
        cls = classify_command(exec_start)
        if cls:
            severity, reasons = cls
            if is_enabled and severity == "medium":
                severity = "high"
            findings.append(Finding(
                module="persistence",
                severity=severity,
                title="Suspicious systemd unit",
                description=f"Unit {label}{state} launches: {exec_start} "
                            f'(signals: {"; ".join(reasons)}).',
                remediation="Disable and remove the unit; investigate the binary it launches.",
                evidence=exec_start,
                source=label,
                tags=("systemd", "suspicious"),
            ))

    return findings


def _hive_persistence_findings(ctx):
    findings = []
    for hlabel, hive in (ctx.get("hives") or {}).items():
        seen = set()
        for run_key in RUN_KEY_PATHS:
            node = hive.open_key(run_key)
            if node is None:
                continue
            for value in node.values():
                val_text = str(value.data)
                ident = (run_key, value.name)
                if ident in seen:
                    continue
                seen.add(ident)
                if run_key.lower().endswith("\\runonce") or "runonce" in run_key.lower():
                    reminders = "RunOnce entries only run once and are often used by installer/patchers — validate before removal."
                    sev = "low"
                    title = f"Registry RunOnce entry: {hlabel}:{run_key}\\{value.name}"
                else:
                    reminders = "Removing unexpected Run/RunOnce values breaks persistence; verify the entry belongs to installed software."
                    sev = "low"
                    title = f"Registry Run key entry: {hlabel}:{run_key}\\{value.name}"
                findings.append(Finding(
                    module="persistence",
                    severity=sev,
                    title=title,
                    description=f"An autorun value in hive {hlabel} will execute: {val_text}",
                    remediation=reminders,
                    evidence=val_text,
                    source=f"{hlabel}:{run_key}",
                    tags=("windows-hive", "runkey"),
                ))
                cls = classify_command(val_text)
                if cls:
                    severity, reasons = cls
                    findings.append(Finding(
                        module="persistence",
                        severity=severity,
                        title="Suspicious registry autostart",
                        description=f"Value {value.name} in {hlabel}:{run_key} runs: {val_text} "
                                    f'(signals: {"; ".join(reasons)}).',
                        remediation="Remove the value, then trace and remove whatever created it.",
                        evidence=val_text,
                        source=f"{hlabel}:{run_key}",
                        tags=("windows-hive", "suspicious"),
                    ))
    return findings


def audit_persistence(ctx, cfg):
    return _linux_persistence_findings(ctx) + _hive_persistence_findings(ctx)