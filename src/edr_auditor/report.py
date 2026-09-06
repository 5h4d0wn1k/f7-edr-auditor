"""Report building + JSON/HTML writers (pure stdlib)."""

import html
import json
import os
import re
import time
from datetime import datetime, timezone

from edr_auditor import __version__
from edr_auditor.models import SEVERITIES
from edr_auditor.scoring import score_report

_SEV_COLOURS = {
    "critical": "#b00020",
    "high": "#d93025",
    "medium": "#f29900",
    "low": "#1a73e8",
    "info": "#5f6368",
}


def sanitize_hostname(host):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", host or "unknown")


def timestamp_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def build_report(ctx, findings_by_module, cfg, mode):
    """Assemble the structured report dict (used for JSON, HTML and compare)."""
    module_meta = []
    weights = _weights(cfg)
    min_sev = _min_severity(cfg)
    report = {
        "tool": "f7-edr-auditor",
        "version": __version__,
        "generated_at": timestamp_iso(),
        "host": ctx.get("host", "unknown"),
        "platform": ctx.get("platform", ""),
        "distro": ctx.get("distro", ""),
        "mode": mode,
        "config": {
            "score": {
                "min_severity": min_sev,
                "weights": dict(weights),
            }
        },
        "modules": {},
    }
    for name in ("persistence", "services", "sockets", "patches", "hardening"):
        findings = sorted(
            findings_by_module.get(name, []),
            key=lambda f: (SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 0,
                           f.title.lower()),
        )
        report["modules"][name] = {
            "weight": weights.get(name, 0),
            "findings": [f.as_dict() for f in findings],
        }
    report["score"] = score_report(report, cfg)
    return report


def _weights(cfg):
    return dict(cfg.get("score", {}).get("weights", {}) or {})


def _min_severity(cfg):
    value = cfg.get("score", {}).get("min_severity", "low")
    return value if value in SEVERITIES else "low"


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_reports(report, out_format, report_dir):
    """Write JSON/HTML report(s) under report_dir. Returns list of paths."""
    out_format = out_format or "both"
    if out_format not in ("json", "html", "both"):
        raise ValueError(f"unknown out format: {out_format}")

    os.makedirs(report_dir, exist_ok=True)
    if out_format in ("json", "both"):
        json_bytes = render_json(report)
        json_path = os.path.join(report_dir, "audit-%s.%s" % (
            _stamp(report), "json"))
        _atomic_write(json_path, json_bytes)
    else:
        json_path = None
    if out_format in ("html", "both"):
        html_bytes = render_html(report)
        html_path = os.path.join(report_dir, "audit-%s.%s" % (
            _stamp(report), "html"))
        _atomic_write(html_path, html_bytes)
    else:
        html_path = None
    return [p for p in (json_path, html_path) if p]


def _stamp(report):
    host = sanitize_hostname(report.get("host") or "unknown")
    when = time.strftime("%Y%m%d-%H%M%S")
    return f"{host}-{report.get('mode', 'audit')}-{when}"


def _atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def render_json(report):
    return json.dumps(report, indent=2, sort_keys=True).encode("utf-8")


def render_html(report):
    e = html.escape
    score = report.get("score") or {}
    parts = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(f"<title>{e(report.get('tool', ''))} — audit report</title>")
    parts.append(_STYLE)
    parts.append("</head><body>")
    parts.append(f'<div class="banner">BLUE-TEAM TOOL — run only against machines you own.</div>')
    parts.append(f"<h1>{e(report.get('tool', ''))} v{e(report.get('version', ''))}</h1>")
    parts.append(f"<p>Generated {e(str(report.get('generated_at', '')))} · "
                 f"host <code>{e(str(report.get('host', '')))}</code> · "
                 f"mode <code>{e(str(report.get('mode', '')))}</code> · "
                 f"platform <code>{e(str(report.get('platform', '')))}</code></p>")

    parts.append('<div class="scorebox">')
    parts.append(f'<div class="score">');
    parts.append(f'<span class="scorenum">{e(str(score.get("total", "-")))}</span>')
    parts.append(f'<span class="scorelabel">hardening score / 100</span>')
    parts.append("</div>")
    parts.append(f'<div class="scoremeta">overall posture: '
                 f'<b style="color:{_SEV_COLOURS.get(score.get("severity", "info"), "#333")}">'
                 f'{e(str(score.get("severity", "info")))}</b>'
                 f" · {e(str(score.get('in_scope_findings', 0)))} in-scope findings "
                 f"(min severity {e(str(score.get('min_severity', 'low')))})</div>")
    parts.append("</div>")

    for name, mod in report.get("modules", {}).items():
        parts.append(f"<h2>{e(name)} "
                     f'<span class="modmeta">weight {int(mod.get("weight", 0))}</span></h2>')
        parts.append('<table><thead><tr>'
                     '<th>Severity</th><th>Finding</th><th>Detail</th><th>Evidence</th>'
                     '<th>Remediation</th></tr></thead><tbody>')
        findings = mod.get("findings") or []
        if not findings:
            parts.append('<tr><td colspan="5" class="ok">No findings.</td></tr>')
        for f in findings:
            sev = f.get("severity", "info")
            colour = _SEV_COLOURS.get(sev, "#333")
            parts.append("<tr>")
            parts.append(f'<td><span class="sev" style="background:{colour}">{e(sev)}</span></td>')
            parts.append(f"<td><b>{e(str(f.get('title', '')))}</b>"
                         f'<div class="src">{e(str(f.get("source", "")))}</div></td>')
            parts.append(f"<td>{e(str(f.get('description', '')))}</td>")
            parts.append(f"<td><code>{e(str(f.get('evidence', '')))}</code></td>")
            parts.append(f"<td>{e(str(f.get('remediation', '')))}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")

    parts.append("<p class='foot'>f7-edr-auditor — blue-team endpoint hardening "
                 "auditor. Authorized/machine-you-own use only. See README "
                 "“IMPORTANT: Read before use”.</p>")
    parts.append("</body></html>")
    return "\n".join(parts).encode("utf-8")


_STYLE = """
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
         margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #202124; }
  .banner { background: #1a73e8; color: #fff; padding: .5rem 1rem;
            border-radius: 4px; margin-bottom: 1rem; }
  h1 { margin-bottom: .2rem; }
  h2 { border-bottom: 2px solid #dadce0; padding-bottom: .2rem; margin-top: 2rem; }
  .modmeta { color: #5f6368; font-weight: normal; font-size: .85rem; }
  .scorebox { background: #f8f9fa; border: 1px solid #dadce0; border-radius: 8px;
              padding: 1rem 1.25rem; margin: 1rem 0; display: flex;
              align-items: baseline; gap: 1.5rem; }
  .scorenum { font-size: 2.6rem; font-weight: 700; }
  .scorelabel { color: #5f6368; margin-left: .5rem; }
  .scoremeta { color: #3c4043; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0 2rem; }
  th, td { border: 1px solid #dadce0; padding: .45rem .6rem; text-align: left;
           vertical-align: top; font-size: .9rem; }
  th { background: #f1f3f4; }
  .sev { color: #fff; padding: .12rem .45rem; border-radius: 3px;
         font-size: .75rem; text-transform: uppercase; white-space: nowrap; }
  .src { color: #5f6368; font-size: .75rem; margin-top: .25rem; }
  .ok { color: #188038; }
  code { background: #f1f3f4; padding: .1rem .3rem; border-radius: 3px;
         word-break: break-all; }
  .foot { color: #5f6368; font-size: .8rem; margin-top: 3rem; }
</style>
"""