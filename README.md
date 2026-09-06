# F7 — EDR Auditor (endpoint hardening auditor, blue-team)

A dependency-free Python toolkit that audits the hardening posture of an
endpoint (persistence, services, sockets, patches, hardening policy), scores
it 0–100, and turns findings into measurable before/after delta reports —
all **read-only** and **offline** by design.

This is the production upgrade of `firmware/edr_auditor.py` (legacy demo,
kept on the repo for reference).

## Overview

- **Audit modules** (weighted, pluggable):
  - `persistence` — Linux autostart `.desktop` files, crontab, systemd units;
    Windows Run/RunOnce registry-hive keys (passive)
  - `services` — enabled services vs. a baseline allowlist (systemctl;
    Windows `ControlSet001\Services` Start=2 from hive files)
  - `sockets` — listening TCP/UDP sockets + owning process; wildcard /
    risky-port exposure
  - `patches` — installed package/update status vs. a version watchlist
  - `hardening` — SSH config + file permissions, password policy
    (login.defs / PAM / shadow), host firewall status
- **Scoring**: weighted findings → 0–100 score; severity band (critical …
  clean) exposed on every report; `compare` measures remediation delta.
- **Reports**: JSON + self-contained HTML (stdlib only), written to
  `reports/` (gitignored).
- **Offline self-test**: builds a synthetic sandbox in `/tmp`, runs every
  module, asserts findings + report artifacts, exits 0 in well under 15 s.
- **Passive hive mode**: audit your own Windows `NTUSER.DAT` / `SOFTWARE` /
  `SYSTEM` hive copies from Linux, no privileged Windows access required.

## IMPORTANT: Read before use.

This project is provided for **educational and defensive security purposes only**.

### Authorization Requirements
- This tool audits the hardening posture of systems you are **authorized to
  defend** (your own machines, lab VMs, or hosts under your organization's
  written authorization)
- It must NEVER be run against systems you do not own or are not authorized
  to assess

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer
  systems is a federal crime
- **Computer Misuse / Data Protection Laws**: Accessing a system (including
  running local audits such as `--host local`) or exfiltrating its data
  without authorization is unlawful
- **State Laws**: Many states have additional computer crime statutes
- **Export / End-Use Controls**: Defensive security tools may be subject to
  export-control obligations

### Acceptable Use
- Auditing your own machines and lab targets
- Authorized SOC / blue-team vulnerability-and-hardening assessments
- Academic research in controlled lab environments
- Security education and training on defensive posture

### Prohibited Use
- Using this tool to find weaknesses on systems you are not authorized to test
- Leveraging findings to attack or bypass controls on third-party systems
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is
not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover weaknesses using this tool, follow responsible disclosure:
1. Report to the owning organization (your own or a client) privately
2. Provide the vendor with the gap findings and remediation guidance
3. Do not weaponize findings against third parties

## Installation

```bash
# Python 3.8+ stdlib only — no third-party dependencies.
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # provides the `edr` console command
# or run without installing:
PYTHONPATH=src python3 -m edr_auditor --help
```

## Usage

```bash
# Offline self-test (should always exit 0, <15s)
edr selftest

# List modules + data sources
edr modules --list

# Synthetic sandbox audit (never touches the real host)
edr audit --host fixture --out both

# Passive audit of your own Windows hive copies (declare paths in config)
edr audit --host hive --out json

# Live audit of the local Linux host (read-only; best as root)
edr audit --host local --out html

# Recompute the score of an existing report
edr score reports/audit-<host>-<mode>-<ts>.json

# Remediation delta between two runs
edr compare --before reports/audit-A-before.json --after reports/audit-A-after.json \
            --out both
```

Reports land in `reports/` by default (gitignored; filenames embed host, mode
and timestamp). Point `--report-dir` somewhere else to keep artifacts.

Configuration lives in `config/edr.yaml` (weights, severity threshold, report
dir, scan scope / hive paths, baseline + watchlists). Placeholders only —
review before use.

## Metrics

Scoring, benchmark tables, and the before/after discipline are documented in
[`METRICS.md`](METRICS.md). Every hardening change must be gated by
`edr compare` and must not regress the score.

## Live Lab Test Plan

Purpose: prove the auditor detects a *known* persistence drop on a box under
your control — end-to-end, offline, with a measured score delta.

1. **Target**: a disposable Linux VM (fresh OS install) or
   `edr audit --host local` on a machine you own.
2. **Baseline**: `edr audit --host local --out json` → record score
   (expect ~90–100 on a stock install; lower if already misconfigured).
3. **Install known persistence** (on the target, as root):
   ```bash
   mkdir -p /tmp/edrlab
   echo '#!/bin/sh'                  > /tmp/edrlab/helper.sh
   echo 'nc -lp 31337'              >> /tmp/edrlab/helper.sh
   chmod +x /tmp/edrlab/helper.sh
   # autostart
   printf '[Desktop Entry]\nType=Application\nExec=/tmp/edrlab/helper.sh\nHidden=false\n' \
     > /etc/xdg/autostart/edrlab.desktop
   # cron
   (crontab -l 2>/dev/null; printf '*/5 * * * * /tmp/edrlab/helper.sh\n') | crontab -
   # systemd
   printf '[Unit]\nDescription=edrlab\n[Service]\nExecStart=/tmp/edrlab/helper.sh\n' \
     > /etc/systemd/system/edrlab.service
   systemctl daemon-reload && systemctl enable --now edrlab.service
   ```
4. **Re-audit**: `edr audit --host local --out json` → score must **drop**,
   and the persistence module must **name each planted item**
   (edrlab.desktop, the cron line, edrlab.service).
5. **Delta**: `edr compare --before <baseline.json> --after <after.json>` →
   `new findings` ≥ 3, delta must be negative (score drop); record the delta
   in the METRICS.md score card.
6. **Cleanup**: remove the three items, re-run the audit, confirm the delta
   returns to ~0 and the findings resolve.
7. **Pass criteria**: score drop ↔ findings named ↔ resolution verified; no
   findings against an untouched stock install; self-test still 27/27.

## Platform Support

| Mode | OS | Data source | Privilege |
|---|---|---|---|
| `--host hive` | any (parse copies of your own hives) | NTUSER.DAT / SOFTWARE / SYSTEM (passive) | none |
| `--host fixture` | any | synthetic sandbox in `/tmp` | none |
| `--host local` | **Linux** (Debian/Ubuntu & friends tested) | systemctl, ss, dpkg-query, /etc files, ufw/nft/iptables | read-only; root recommended for shadow/socket attribution |
| `--host local` | Windows | not supported yet — use `--host hive` instead | — |

macOS / *BSD local collection is not yet implemented (patch module and live
pipeline); hive parsing and reports are platform-independent.

## Tests

```bash
python3 -m py_compile src/edr_auditor/*.py src/edr_auditor/modules/*.py firmware/edr_auditor.py
PYTHONPATH=src python3 -m unittest discover -s tests -v   # 99 tests
PYTHONPATH=src python3 -m edr_auditor selftest            # 27/27 checks, exit 0
```

## License

MIT