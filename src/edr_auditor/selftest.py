"""Offline self-test: builds a synthetic sandbox in /tmp, runs every audit
module against it, asserts each finding class plus a produced score and report
artifacts, then exits 0. Never touches real host configuration."""

import json
import os
import tempfile
import time

from edr_auditor import __version__
from edr_auditor.config import load_config
from edr_auditor.pipeline import collect_fixture
from edr_auditor.modules import run_all
from edr_auditor.report import build_report, write_reports
from edr_auditor.scoring import score_report

SELFTEST_TIMEOUT_S = 15.0

EXPECTED_SUBSTRINGS = {
    "persistence": [
        "evil-helper.desktop",      # autostart entry surfaced
        "Suspicious autostart command",
        "Suspicious cron job",
        "evil-watcher.service",     # systemd unit surfaced
        "Registry Run key entry",
        "EvilUpdater",
    ],
    "services": [
        "Service enabled outside baseline",
        "evil-watcher.service",
        "evilsvc",                  # Windows hive service Start=2 surfaced
    ],
    "sockets": [
        "0.0.0.0:22",
        "31337",
        "Listening service",
    ],
    "patches": [
        "Outdated package",
        "openssh-server",
    ],
    "hardening": [
        "PermitRootLogin",
        "No host firewall detected",
        "blank password",
        "World-writable",
    ],
}


def all_findings_report(report):
    out = []
    for mod in report["modules"].values():
        out.extend(mod["findings"])
    return out


def run_selftest(fixture_root=None, report_dir=None, verbose=False):
    """Returns exit code 0 or 1. Also returns (checks, report, score, elapsed)."""
    started = time.monotonic()
    checks = []

    def expect(check_name, ok, detail=""):
        checks.append((check_name, bool(ok), detail))
        if verbose:
            print(("  [ok] " if ok else "  [FAIL] ") + check_name + (f" — {detail}" if detail else ""))

    fixture_root = fixture_root or os.path.join(tempfile.gettempdir(),
                                                "edr_selftest_%d" % os.getpid())
    from edr_auditor.fixtures import build
    build(fixture_root)

    expect("fixture tree built",
           all(os.path.isfile(p) for p in (
               os.path.join(fixture_root, "data/autostart/evil-helper.desktop"),
               os.path.join(fixture_root, "hives/SOFTWARE"),
               os.path.join(fixture_root, "config/edr.yaml"),
           )))

    cfg = load_config(os.path.join(fixture_root, "config", "edr.yaml"))
    ctx = collect_fixture(fixture_root)
    findings = run_all(ctx, cfg)
    report = build_report(ctx, findings, cfg, "fixture")
    score = score_report(report, cfg)
    report["score"] = score

    for module, expected in EXPECTED_SUBSTRINGS.items():
        text = json.dumps([f.as_dict() if hasattr(f, "as_dict") else f
                           for f in findings[module]])
        for needle in expected:
            expect(f"{module} surfaces {needle!r}", needle in text)

    expected_modules = set(EXPECTED_SUBSTRINGS)
    found_modules = set(findings)
    expect("all audit modules ran", expected_modules <= found_modules,
           "found: " + ", ".join(sorted(found_modules)))

    have = all_findings_report(report)
    expect("findings are structurally complete",
           all(f.get("title") and f.get("severity") and f.get("description")
               and f.get("remediation") for f in have))

    total = score.get("total")
    expect("a 0-100 score was produced", isinstance(total, (int, float))
           and 0.0 <= total <= 100.0, f"score={total}")
    expect("fixtures lower the score below 100", total < 100.0, f"score={total}")

    report_dir = report_dir or os.path.join(fixture_root, "reports")
    written = write_reports(report, "both", report_dir)
    expect("JSON + HTML report artifacts written",
           len(written) == 2 and all(os.path.isfile(p) for p in written),
           ", ".join(os.path.basename(p) for p in written))

    json_path = next(p for p in written if p.endswith(".json"))
    with open(json_path, "r", encoding="utf-8") as fh:
        reparsed = json.load(fh)
    expect("JSON report round-trips", reparsed.get("score", {}).get("total") == total)

    # HTML must escape the <evil&co> marker embedded in the fixture hive value.
    # But the fixture holds "evil<c2>", so the escaped form is "evil&lt;c2&gt;".
    html_path = next(p for p in written if p.endswith(".html"))
    with open(html_path, "r", encoding="utf-8") as fh:
        html_text = fh.read()
    expect("HTML report escapes untrusted strings",
           "evil&lt;c2&gt;" in html_text and "evil<c2>" not in html_text)

    elapsed = time.monotonic() - started
    expect(f"self-test under {SELFTEST_TIMEOUT_S}s", elapsed < SELFTEST_TIMEOUT_S,
           f"{elapsed:.1f}s")

    failed = [c for c in checks if not c[1]]
    print(f"\nf7-edr-auditor v{__version__} offline self-test: "
          f"{len(checks) - len(failed)}/{len(checks)} checks ok "
          f"({elapsed:.1f}s)")
    if failed:
        for name, _, detail in failed:
            print(f"  FAIL {name} — {detail}")
        return 1, checks, report, score, elapsed
    print("  fixture score: %.1f — reports in %s" % (total, report_dir))
    print("self-test complete (exit 0).")
    return 0, checks, report, score, elapsed


def main(argv=None):
    verbose = "-v" in (argv or []) or "--verbose" in (argv or [])
    code, *_ = run_selftest(verbose=verbose)
    return code


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))