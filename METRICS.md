# F7 — Metrics

How the upgraded tool is measured. Everything here is collected from the
tool's own artifacts (`reports/audit-*.json`, `compare-*.json`) — no external
dependency, no network.

## 1. What we measure

| Metric | Source | Goal |
|---|---|---|
| Hardening score (0–100, higher = better) | `report.score.total` | Baseline per host; ≤10 point run-to-run drift on an untouched host |
| Posture severity | `report.score.severity` (critical…clean) | Monotonic improvement after remediation |
| Missing patch count | `patches` findings (`Outdated package`), watchlist size | 0 on live-lab target |
| Auto-start / service drift | `persistence` + `services` findings | 0 new items between a clean baseline and a clean re-run |
| Exposure | `sockets` findings (wildcard / risky / unowned listeners) | ≤ N reviewers-approved listeners |
| Detection coverage | % of the 5 modules producing in-scope findings in `hive` mode | 100% on every audit (offline/online alike) |
| Self-test health | `edr selftest` exit code + check count | 27/27 checks, <15 s, exit 0 on every run |
| Report artifacts | `reports/audit-<host>-<mode>-<ts>.{json,html}` + `compare-*.` | Present and round-trippable for every audit |

## 2. Score delta discipline

Every change (config tuning, hardening step, new scanner) must be gated by a
measured before/after delta:

```bash
edr audit --host <target> --out json --report-dir reports        # baseline
edr audit --host <target> --out json --report-dir reports        # after hardening
edr compare --before reports/audit-<target>-<when>-before.json \
            --after  reports/audit-<target>-<when>-after.json
```

Rules:

- **Regression** (score delta < 0) blocks the change unless a finding
  explicitly justifies it.
- **Noise** (delta > 0 on an untouched host) must stay under 1 point; if it
  does not, the collector or module is nondeterministic — investigate.
- Findings must be **actionable**: every `JSON` finding carries
  `title`, `description`, `evidence`, `remediation`, `source`.

## 3. Coverage tracking

The live-lab target (see README „Live Lab Test Plan“) gets its own score card
recorded after each lab session:

| Date | Run id | Score | Posture | new findings | resolved findings | Severity changes | Self-test 27/27 |
|---|---|---|---|---|---|---|---|
| _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |

Fill from the `summary` block of `compare-*.json`:

```json
"summary": {"new": 0, "removed": 0, "changed": 0}
```

## 4. Module benchmark expectations (fixture)

Reproducible via `edr audit --host fixture --out json` with the shipped
`config/edr.yaml` (empty baseline/watchlist are intentionally the *hardened
posture*, so the fixture is a guaranteed-vulnerable demo):

| Module | In-scope findings | Module score |
|---|---|---|
| persistence | 14 | 0 (fixture is the vulnerable case) |
| services | 1 | 88 |
| sockets | 3 | 85 |
| patches | 0 | 100 |
| hardening | 9 | 0 |
| **total** | **27 in-scope** | **46/100** |

`edr selftest` runs the same fixtures but with the stricter demo watchlist
(total ≈ 26/100); if either number shifts while fixtures are unchanged, a
scanner behavior changed and must be reviewed.

## 5. Publication gate (usage metrics)

Only aggregate, non-PII metrics may be shared (e.g. `58→96` on the live-lab
box). Hostnames, IPs and evidence strings stay in `reports/` (gitignored).