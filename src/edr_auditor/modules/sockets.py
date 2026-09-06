"""Sockets module: listening sockets + their processes.

Data comes from ``ss -tulnap`` (live Linux) or a captured fixture equivalent.
The module flags listeners where a network service is exposed, especially on
all interfaces (0.0.0.0 / ::), on risky ports, or where the owning process
could not be attributed (usually: run ``edr audit --host local`` as root).
"""

import re

from edr_auditor.models import Finding
from edr_auditor.config import get

_PROCESS_RE = re.compile(r'"([^"]+)",pid=')
_WILDCARD = ("0.0.0.0", "::", "0", "*", "0.0.0.0.0", "::ffff:0.0.0.0")


def _parse_ss(text):
    """Parse `ss -tulnap` output into listener rows."""
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        netid = parts[0]
        if not netid.startswith(("tcp", "udp", "raw")):
            continue
        state = parts[1]
        if state not in ("LISTEN", "UNCONN"):  # ESTAB rows are not listeners
            continue
        local, peer, proc_field = parts[4], parts[5], " ".join(parts[6:])
        if ":" not in local:
            continue
        addr, _, port = local.rpartition(":")
        m = re.search(r"^\[(.+)\]$", addr)
        if m:
            addr = m.group(1)
        if not port.isdigit():
            continue
        pm = _PROCESS_RE.search(proc_field)
        try:
            port = int(port)
        except ValueError:
            continue
        rows.append({
            "netid": netid,
            "state": state,
            "addr": addr,
            "port": port,
            "process": pm.group(1) if pm else None,
            "proc_field": proc_field,
        })
    return rows


def _is_wildcard(addr):
    return addr in _WILDCARD or addr in ("*", "[]", "")


def audit_sockets(ctx, cfg):
    findings = []
    rows = _parse_ss(ctx.get("ss_output") or "")
    if not rows and ctx.get("mode") != "hive":
        findings.append(Finding(
            module="sockets",
            severity="info",
            title="No listening-socket data captured",
            description="ss/netstat output was empty or unavailable; listening sockets "
                        "were not evaluated.",
            remediation="Re-run as root (or install iproute2) so all listeners are visible.",
            evidence="",
            source="ss/netstat",
            tags=("coverage-gap",),
        ))

    risky_ports = set(int(p) for p in get(cfg, "scan_scope", "sockets", "risky_ports", default=[]))
    critical_watch = set(int(p) for p in get(cfg, "scan_scope", "sockets", "critical_watch", default=[]))

    for row in rows:
        addr, port = row["addr"], row["port"]
        proc = row["process"] or "unknown"
        wildcard = _is_wildcard(addr)

        findings.append(Finding(
            module="sockets",
            severity="info",
            title=f"Listening service: {row['netid']}:{addr}:{port}",
            description=f"A {row['netid'].upper()} listener is bound to {addr}:{port}"
                        f" (process: {proc}).",
            remediation="Verify the service is needed and exposed only where intended.",
            evidence=f"{proc} pid-field: {row['proc_field']}",
            source="ss-output",
            tags=("listener",),
        ))

        if port in critical_watch and wildcard:
            findings.append(Finding(
                module="sockets",
                severity="high",
                title=f"Critically watched port open on all interfaces: {port}",
                description=f"Port {port} (process {proc}) is listening on every interface "
                            "and is on the critical_watch list.",
                remediation="Bind the service to loopback or an internal IP and block the "
                            "port in host firewall.",
                evidence=f"{addr}:{port}",
                source="ss-output",
                tags=("exposure", "watchlist"),
            ))

        if wildcard:
            if port in risky_ports:
                severity = "medium"
                title = f"Service exposed on all interfaces: {port}"
            elif port in critical_watch:
                severity = "high"
                title = f"Critically watched port exposed: {port}"
            else:
                severity = "low"
                title = f"Listener on all interfaces: {port}"
            findings.append(Finding(
                module="sockets",
                severity=severity,
                title=title,
                description=f"{row['netid'].upper()} {addr}:{port} ({proc}) accepts traffic "
                            "on all interfaces.",
                remediation="Restrict the listener to loopback/internal interfaces and "
                            "enforce host firewall rules.",
                evidence=f"{addr}:{port} process={proc}",
                source="ss-output",
                tags=("exposure",),
            ))
        elif proc == "unknown" and row["state"] == "LISTEN":
            findings.append(Finding(
                module="sockets",
                severity="medium",
                title=f"Listener with no attributable process: {port}",
                description=f"A listener on {addr}:{port} could not be attributed to a "
                            "process (permissions).",
                remediation="Re-run the audit as root to see process ownership, then verify "
                            "the owning binary is expected.",
                evidence=f"{addr}:{port}",
                source="ss-output",
                tags=("owner-gap",),
            ))

    return findings