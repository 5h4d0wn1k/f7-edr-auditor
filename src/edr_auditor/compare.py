"""Compare two audit runs: delta report between before/after JSON."""

import html
import json
import os
import time

from edr_auditor.models import SEVERITIES, severity_rank
from edr_auditor.scoring import score_report
from edr_auditor.report import sanitize_hostname, _atomic_write


def _finding_key(f):
    return (f.get("module", ""), f.get("title", ""), f.get("source", ""))


def compare_reports(before, after, cfg):
    """Diff ``after`` against ``before``. Returns a structured delta dict."""
    before_score = score_report(before, cfg)
    after_score = score_report(after, cfg)

    b_map = {_finding_key(f): f
             for mod in (before.get("modules") or {}).values()
             for f in mod.get("findings", [])}
    a_map = {_finding_key(f): f
             for mod in (after.get("modules") or {}).values()
             for f in mod.get("findings", [])}

    new = [f for k, f in sorted(a_map.items()) if k not in b_map]
    removed = [f for k, f in sorted(b_map.items()) if k not in a_map]
    changed = []
    for key in sorted(set(b_map) & set(a_map)):
        fb, fa = b_map[key], a_map[key]
        if fb.get("severity") != fa.get("severity"):
            changed.append({"before": fb, "after": fa})

    delta = round(after_score["total"] - before_score["total"], 1)
    module_delta = {}
    for name in before_score["modules"]:
        sb = before_score["modules"].get(name, {})
        sa = after_score["modules"].get(name, {})
        module_delta[name] = {
            "before_score": sb.get("score"),
            "after_score": sa.get("score"),
            "delta": round((sa.get("score") or 0) - (sb.get("score") or 0), 1),
            "before_findings": sb.get("findings_total", 0),
            "after_findings": sa.get("findings_total", 0),
        }

    return {
        "tool": "f7-edr-auditor",
        "generated_at": after.get("generated_at"),
        "before": {"host": before.get("host"), "generated_at": before.get("generated_at"),
                   "file": os.path.basename(str(before.get("_file", "")))},
        "after": {"host": after.get("host"), "generated_at": after.get("generated_at"),
                  "file": os.path.basename(str(after.get("_file", "")))},
        "score": {
            "before": before_score["total"],
            "after": after_score["total"],
            "delta": delta,
            "severity_before": before_score["severity"],
            "severity_after": after_score["severity"],
        },
        "modules": module_delta,
        "findings": {
            "new": new,
            "removed": removed,
            "severity_changed": changed,
        },
        "summary": {
            "new": len(new),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def write_compare_reports(delta, out_format, report_dir):
    out_format = out_format or "both"
    os.makedirs(report_dir, exist_ok=True)
    stamp = "%s-%s" % (sanitize_hostname((delta.get("after") or {}).get("host") or "unknown"),
                       time.strftime("%Y%m%d-%H%M%S"))
    paths = []
    if out_format in ("json", "both"):
        path = os.path.join(report_dir, f"compare-{stamp}.json")
        _atomic_write(path, json.dumps(delta, indent=2, sort_keys=True).encode("utf-8"))
        paths.append(path)
    if out_format in ("html", "both"):
        path = os.path.join(report_dir, f"compare-{stamp}.html")
        _atomic_write(path, render_compare_html(delta).encode("utf-8"))
        paths.append(path)
    return paths


def render_compare_html(delta):
    e = html.escape
    score = delta["score"]
    parts = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
             "<title>f7-edr-auditor — compare report</title>", _STYLE,
             "</head><body>"]
    parts.append('<div class="banner">BLUE-TEAM TOOL — run only against machines you own.</div>')
    parts.append("<h1>Audit delta report</h1>")
    parts.append(f"<p>before: <code>{e(str(delta['before']['file']))}</code> "
                 f"({e(str(delta['before']['generated_at']))}) → "
                 f"after: <code>{e(str(delta['after']['file']))}</code> "
                 f"({e(str(delta['after']['generated_at']))})</p>")

    d = score["delta"]
    colour = "#188038" if d > 0 else ("#b00020" if d < 0 else "#5f6368")
    parts.append('<div class="scorebox">')
    parts.append('<div class="score">')
    parts.append(f'<span class="scorenum">{e(str(score["before"]))} → {e(str(score["after"]))}</span>')
    parts.append(f'<span class="scorelabel">delta <b style="color:{colour}">{e(str(d))}</b></span>')
    parts.append("</div></div>")

    parts.append("<h2>Module deltas</h2><table><thead><tr><th>Module</th>"
                 "<th>Before</th><th>After</th><th>Δ</th><th>Findings</th></tr></thead><tbody>")
    for name, m in delta["modules"].items():
        dscore = m["delta"]
        c = "#188038" if dscore > 0 else ("#b00020" if dscore < 0 else "#5f6368")
        parts.append(f"<tr><td>{e(name)}</td><td>{e(str(m['before_score']))}</td>"
                     f"<td>{e(str(m['after_score']))}</td>"
                     f"<td style='color:{c}'><b>{e(str(dscore))}</b></td>"
                     f"<td>{m['before_findings']} → {m['after_findings']}</td></tr>")
    parts.append("</tbody></table>")

    for label, items in (("New findings", delta["findings"]["new"]),
                         ("Resolved findings", delta["findings"]["removed"])):
        parts.append(f"<h2>{e(label)} ({len(items)})</h2>")
        if not items:
            parts.append("<p class='ok'>None.</p>")
            continue
        parts.append("<table><thead><tr><th>Severity</th><th>Module</th>"
                     "<th>Finding</th><th>Evidence</th></tr></thead><tbody>")
        for f in items:
            sev = f.get("severity", "info")
            parts.append(f"<tr><td><b>{e(sev)}</b></td><td>{e(f.get('module',''))}</td>"
                         f"<td>{e(str(f.get('title','')))}"
                         f"<div class='src'>{e(str(f.get('source','')))}</div></td>"
                         f"<td><code>{e(str(f.get('evidence','')))}</code></td></tr>")
        parts.append("</tbody></table>")

    parts.append("<h2>Severity changes (" + str(len(delta["findings"]["severity_changed"])) + ")</h2>")
    if delta["findings"]["severity_changed"]:
        parts.append("<table><thead><tr><th>Finding</th><th>Before</th><th>After</th></tr></thead><tbody>")
        for change in delta["findings"]["severity_changed"]:
            fb, fa = change["before"], change["after"]
            parts.append(f"<tr><td>{e(str(fb.get('title','')))}</td>"
                         f"<td>{e(fb.get('severity',''))}</td>"
                         f"<td>{e(fa.get('severity',''))}</td></tr>")
        parts.append("</tbody></table>")
    else:
        parts.append("<p class='ok'>None.</p>")

    parts.append(_FOOT)
    parts.append("</body></html>")
    return "\n".join(parts)


_STYLE = """
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 1000px;
         padding: 0 1rem; color: #202124; }
  .banner { background: #1a73e8; color: #fff; padding: .5rem 1rem; border-radius: 4px; }
  .scorebox { background: #f8f9fa; border: 1px solid #dadce0; border-radius: 8px;
              padding: 1rem; margin: 1rem 0; }
  .scorenum { font-size: 1.6rem; font-weight: 700; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
  th, td { border: 1px solid #dadce0; padding: .4rem .5rem; text-align: left; font-size: .9rem; }
  th { background: #f1f3f4; }
  .src { color: #5f6368; font-size: .75rem; }
  .ok { color: #188038; }
  code { background: #f1f3f4; padding: .1rem .3rem; border-radius: 3px; word-break: break-all; }
</style>
"""
_FOOT = "<p class='foot' style='color:#5f6368;font-size:.8rem;'>f7-edr-auditor — " \
        "blue-team endpoint hardening auditor. Authorized/machine-you-own use only.</p>"