"""Shared data model types for f7-edr-auditor."""

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}


def severity_rank(sev):
    """Ordinal rank of a severity string (higher == worse)."""
    return _SEVERITY_RANK.get(str(sev).lower(), 0)


def in_scope(sev, min_severity):
    """True if a finding's severity is at least as severe as min_severity."""
    return severity_rank(sev) >= severity_rank(min_severity)


@dataclass
class Finding:
    """A single audit finding: what, why, the evidence, and how to fix it."""

    module: str
    severity: str
    title: str
    description: str
    remediation: str
    evidence: str = ""
    source: str = ""
    tags: tuple = field(default_factory=tuple)

    def as_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "source": self.source,
            "tags": sorted(set(self.tags)),
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            module=str(data.get("module", "")),
            severity=data.get("severity", "info"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            evidence=data.get("evidence", ""),
            source=data.get("source", ""),
            tags=tuple(data.get("tags", [])),
        )

    def key(self):
        return (self.module, self.title, self.source, self.evidence)