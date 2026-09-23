> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# F7 — EDR Auditor (Endpoint Hardening Auditor, Blue-Team)

Dependency-free Python toolkit that audits an endpoint's hardening posture — persistence, services, sockets, patches, hardening policy — scores it 0–100, and produces measurable before/after delta reports. Read-only and offline by design.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/f7-edr-auditor.svg)](https://github.com/5h4d0wn1k/f7-edr-auditor)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/f7-edr-auditor.svg)](https://github.com/5h4d0wn1k/f7-edr-auditor)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/f7-edr-auditor.svg)](https://github.com/5h4d0wn1k/f7-edr-auditor)

## Why

Defensive teams need a repeatable, quantitative picture of an endpoint before, during, and after hardening. F7 measures what a real EDR would watch — persistence mechanisms, enabled services, exposed sockets, package patch levels, and hardening policy — and turns findings into a single 0–100 score plus a `compare` delta, so remediation is provable, not anecdotal. Auditing is read-only, offline-first, and safe to run on machines you own.

## Features

- **Weighted audit modules** — `persistence` (desktop autostart, crontab, systemd, Windows Run/RunOnce hive keys), `services` (allowlist diff), `sockets` (listening + owning process, wildcard/risky ports), `patches` (version watchlist), `hardening` (SSH config, permissions, password policy, firewall)
- **0–100 hardening score** with severity bands on every report
- **`compare` remediation delta** between a before/after audit pair
- **JSON + self-contained HTML reports** (stdlib only) to `reports/` (gitignored)
- **Passive Windows hive mode** — parse your own `NTUSER.DAT` / `SOFTWARE` / `SYSTEM` copies from Linux with no privileged Windows access
- **Offline self-test** — synthetic `/tmp` sandbox, 27/27 checks, exit 0 in under 15 s

## Quickstart

```bash
git clone https://github.com/5h4d0wn1k/f7-edr-auditor.git && cd f7-edr-auditor
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                      # provides the `edr` console command

edr selftest                          # offline self-test, exit 0
edr modules --list                    # audit modules + data sources
edr audit --host fixture --out both   # synthetic sandbox only — never touches your host
edr audit --host hive --out json      # passive audit of your own Windows hive copies
edr audit --host local --out html     # read-only audit of the local Linux host
edr score reports/audit-<host>-*.json # re-score an existing report
edr compare --before before.json --after after.json --out both
```

Configure weights, severity threshold, hive paths, service baselines and patch watchlists in `config/edr.yaml` (placeholders only — review before use).

## Project structure

- `src/edr_auditor/` — CLI, pipeline, scoring, reporting and the five modules
- `config/edr.yaml` — weighted configuration (placeholders only)
- `tests/` — 99 unit tests; `firmware/` — legacy demo kept for reference
- [METRICS.md](METRICS.md) — benchmark score cards and delta discipline

## Documentation

- [METRICS.md](METRICS.md) — scoring, benchmarks and before/after discipline
- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New audit modules, platform support, and hardening guidance are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); the auditor must remain read-only, offline, and defensive.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized defensive security use only.