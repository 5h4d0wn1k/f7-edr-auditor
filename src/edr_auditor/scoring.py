"""Weighted scoring algorithm.

Final score is a weighted average of per-module scores in the range 0-100:

    module_score = clamp(100 - penalty, 0, 100)
    penalty      = sum(SEVERITY_POINTS[f.severity] for in-scope findings)
    min_severity = config score.min_severity (lower-severity findings are
                  still reported but do not lower the score)

Severity points: critical=40, high=25, medium=12, low=5, info=1.
"""

from edr_auditor.models import SEVERITY_POINTS, SEVERITIES, severity_rank
from edr_auditor.config import get

DEFAULT_MIN_SEVERITY = "low"


def normalize_weights(cfg):
    """Return module weights (ints) and the total; tolerant of partial config."""
    weights = dict(get(cfg, "score", "weights", default={}) or {})
    for name in ("persistence", "services", "sockets", "patches", "hardening"):
        weights.setdefault(name, 10)
    return weights


def _min_severity(cfg):
    value = get(cfg, "score", "min_severity", default=DEFAULT_MIN_SEVERITY)
    if value not in SEVERITIES:
        value = DEFAULT_MIN_SEVERITY
    return value


def score_report(report, cfg):
    """Score the modules present in a report dict; returns score summary dict."""
    weights = normalize_weights(cfg)
    min_sev = _min_severity(cfg)
    total_weight = sum(weights.values()) or 1.0

    modules_out = {}
    in_scope_findings_count = 0
    worst = "info"
    for name in weights:
        mod = (report.get("modules") or {}).get(name) or {}
        findings = mod.get("findings") or []
        in_scope = [f for f in findings if severity_rank(f["severity"]) >= severity_rank(min_sev)]
        in_scope_findings_count += len(in_scope)
        for f in in_scope:
            if severity_rank(f["severity"]) > severity_rank(worst):
                worst = f["severity"]
        points = sum(SEVERITY_POINTS.get(f["severity"], 0) for f in in_scope)
        modules_out[name] = {
            "weight": weights.get(name, 0),
            "score": max(0.0, 100.0 - points),
            "points": points,
            "min_severity": min_sev,
            "findings_in_scope": len(in_scope),
            "findings_total": len(findings),
        }

    total = round(
        sum(modules_out[n]["score"] * modules_out[n]["weight"] for n in weights)
        / total_weight,
        1,
    )
    return {
        "total": total,
        "severity": worst,
        "min_severity": min_sev,
        "in_scope_findings": in_scope_findings_count,
        "modules": modules_out,
    }


def score_findings(findings_by_module, cfg):
    """Convenience: score a {module: [Finding]} mapping directly."""
    from edr_auditor.models import Finding

    report = {
        "modules": {
            name: {"findings": [f if isinstance(f, dict) else f.as_dict() for f in module]}
            for name, module in (findings_by_module or {}).items()
        }
    }
    return score_report(report, cfg)