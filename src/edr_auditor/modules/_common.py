"""Shared helpers for audit modules (stdlib only)."""

import re

# Patterns used to eyeball commands / autoruns for abuse-ish signals. These are
# heuristic and belong to a *defensive* posture: they only ever run against
# machines you own, and every match carries remediation text.
_URL = re.compile(r"https?://")
_TEMP_PATH = re.compile(r"(/tmp/|/var/tmp/|/dev/shm/|\\Windows\\Temp|\\AppData\\Local\\Temp)")
_DOWNLOADER = re.compile(r"\b(curl|wget|aria2c|nc\b|ncat|socat|lwp-download|powershell|wget64)\b", re.I)
_EXEC_CHAIN = re.compile(r"[|;]\s*(sh|bash|zsh|/bin/sh|/bin/bash)\b", re.I)
_SCRIPT_HELPER = re.compile(r"\b(base64|wscript|cscript|rundll32|mshta|regsvr32|psexec|certutil|bitsadmin|powershell)\b", re.I)
_SHELL_WORD = re.compile(r"\bsh\b|\bbash\b|\bzsh\b", re.I)


def classify_command(cmd):
    """Heuristic triage of an autostart/command line.

    Returns ``None`` when nothing stands out, or ``(severity, reasons)`` with
    severity in {"medium", "high"}.
    """
    if not cmd:
        return None
    low = cmd.lower()
    reasons = []

    if _TEMP_PATH.search(low):
        reasons.append("executes from a temp/shared path")
    if _URL.search(low):
        reasons.append("references a network URL")
    if _SCRIPT_HELPER.search(low):
        reasons.append("uses a scripting helper / LOLBin")
    downloads_and_shell = bool(
        _DOWNLOADER.search(low) and (_EXEC_CHAIN.search(low) or _TEMP_PATH.search(low))
    )
    if downloads_and_shell:
        reasons.append("download-then-execute chain")

    if not reasons:
        return None
    severity = "high" if downloads_and_shell else "medium"
    return severity, reasons