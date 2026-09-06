"""Command-line interface for f7-edr-auditor.

Commands:
  edr audit --out json|html|both [--host fixture|local|hive]
  edr compare --before <before.json> --after <after.json>
  edr score <report.json>
  edr modules --list
  edr selftest
"""

import argparse
import json
import os
import platform
import sys

from edr_auditor import __version__
from edr_auditor.config import load_config
from edr_auditor.pipeline import collect
from edr_auditor.modules import run_all, MODULES
from edr_auditor.report import build_report, write_reports
from edr_auditor.scoring import score_report
from edr_auditor.selftest import run_selftest

HOST_MODES = ("fixture", "local", "hive")


def _parser():
    parser = argparse.ArgumentParser(
        prog="edr",
        description="F7 — blue-team endpoint hardening auditor. Run only against "
                    "machines you own. See README 'IMPORTANT: Read before use'.",
        epilog="Examples:\n"
               "  edr audit --host fixture --out both\n"
               "  edr audit --host local --out html     # Linux only\n"
               "  edr audit --out json                  # passive Windows hive parse\n"
               "  edr compare --before before.json --after after.json\n"
               "  edr score reports/audit-<host>.json\n"
               "  edr modules --list",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    p_audit = sub.add_parser("audit", help="run an endpoint audit")
    p_audit.add_argument("--config", metavar="PATH", default=None,
                         help="config file (default: config/edr.yaml)")
    p_audit.add_argument("--host", choices=HOST_MODES, default="hive",
                         help="hive = passive Windows registry-hive parse (default); "
                              "local = live collection on this Linux host; "
                              "fixture = synthetic sandbox, never touches the host")
    p_audit.add_argument("--out", choices=("json", "html", "both"), default="both",
                         help="report format(s) to write (default: both)")
    p_audit.add_argument("--report-dir", default=None,
                         help="where reports are written (default: config report.dir)")
    p_audit.add_argument("-v", "--verbose", action="store_true",
                         help="print every finding")
    p_audit.set_defaults(func=cmd_audit)

    p_cmp = sub.add_parser("compare", help="diff two audit runs (delta report)")
    p_cmp.add_argument("--before", required=True, metavar="BEFORE.json")
    p_cmp.add_argument("--after", required=True, metavar="AFTER.json")
    p_cmp.add_argument("--config", default=None)
    p_cmp.add_argument("--out", choices=("json", "html", "both"), default="both")
    p_cmp.add_argument("--report-dir", default=None)
    p_cmp.set_defaults(func=cmd_compare)

    p_score = sub.add_parser("score", help="print the score for a report JSON")
    p_score.add_argument("report", metavar="REPORT.json")
    p_score.add_argument("--config", default=None)
    p_score.set_defaults(func=cmd_score)

    p_mods = sub.add_parser("modules", help="list audit modules")
    p_mods.add_argument("--list", action="store_true", default=True,
                        help="list the audit modules and their data sources")
    p_mods.set_defaults(func=cmd_modules)

    p_self = sub.add_parser("selftest", help="offline self-test on synthetic fixtures")
    p_self.add_argument("--report-dir", default=None,
                        help="where self-test reports land (default: fixture reports/)")
    p_self.add_argument("-v", "--verbose", action="store_true")
    p_self.set_defaults(func=cmd_selftest)

    return parser


def _unsupported_local_message():
    sys_platform = platform.system()
    return (f"edr audit --host local is currently supported on Linux only "
            f"(this host: {sys_platform}).\n"
            "For Windows endpoints, run `edr audit --host hive` against copies of "
            "your own NTUSER.DAT / SOFTWARE / SYSTEM hives declared under "
            "scan_scope.hives in config/edr.yaml. See README -> Platform Support.")


def cmd_audit(args):
    cfg = load_config(args.config)

    if args.host == "local" and platform.system() != "Linux":
        print(_unsupported_local_message())
        return 2

    report_dir = args.report_dir or cfg["report"]["dir"]
    if args.host == "fixture":
        from edr_auditor.fixtures import build
        fixture_root = os.path.join("/tmp", "edr_demo_fixtures")
        build(fixture_root)
        ctx = collect("fixture", cfg, fixture_root=fixture_root)
    else:
        config_dir = os.path.dirname(cfg.get("search_paths", {}).get("config") or "")
        ctx = collect(args.host, cfg, config_dir=config_dir)

    _print_context_header(ctx)

    findings = run_all(ctx, cfg)
    report = build_report(ctx, findings, cfg, args.host)
    report["score"] = score_report(report, cfg)

    written = write_reports(report, args.out, report_dir)

    if args.verbose:
        _print_findings(findings)

    _print_summary(report)
    print("reports written:")
    for path in written:
        print("  " + os.path.abspath(path))
    return 0


def _print_context_header(ctx):
    print(f"host      : {ctx.get('host', '?')}")
    print(f"platform  : {ctx.get('platform', '?')} {ctx.get('distro', '')}".rstrip())
    print(f"mode      : {ctx.get('mode', '?')}")
    hives = ctx.get("hives") or {}
    if hives:
        print(f"hives     : {', '.join(sorted(hives))}")
    print()


def _print_findings(findings):
    for name in ("persistence", "services", "sockets", "patches", "hardening"):
        rows = findings.get(name, [])
        if not rows:
            continue
        print(f"[{name}]")
        for f in rows:
            print(f"  {f.severity:<8} {f.title:60} {f.evidence}")
        print()


def _print_summary(report):
    score = report["score"]
    print(f"hardening score : {score['total']:.1f}/100  (posture: {score['severity']})")
    for name, mod in report["modules"].items():
        mscore = score["modules"][name]
        print(f"  {name:<12} {mscore['score']:5.1f}  "
              f"findings={len(mod['findings'])} "
              f"(in-scope {mscore['findings_in_scope']})")
    print()


def cmd_compare(args):
    cfg = load_config(args.config)
    try:
        with open(args.before, "r", encoding="utf-8") as fh:
            before = json.load(fh)
        before["_file"] = args.before
        with open(args.after, "r", encoding="utf-8") as fh:
            after = json.load(fh)
        after["_file"] = args.after
    except (OSError, ValueError) as exc:
        print(f"[!] could not read before/after reports: {exc}")
        return 1

    from edr_auditor.compare import compare_reports, write_compare_reports
    delta = compare_reports(before, after, cfg)

    score = delta["score"]
    direction = "IMPROVED" if score["delta"] < 0 else ("regressed" if score["delta"] > 0 else "unchanged")
    print(f"score {score['before']} -> {score['after']} "
          f"(delta {score['delta']:+g}) — posture "
          f"{score['severity_before']} -> {score['severity_after']}")
    print(f"new findings      : {delta['summary']['new']}")
    print(f"resolved findings : {delta['summary']['removed']}")
    print(f"severity changes  : {delta['summary']['changed']}")
    for name, m in delta["modules"].items():
        print(f"  {name:<12} {m['before_score']:5} -> {m['after_score']:5} "
              f"({m['delta']:+g})  findings {m['before_findings']} -> {m['after_findings']}")

    report_dir = args.report_dir or cfg["report"]["dir"]
    written = write_compare_reports(delta, args.out, report_dir)
    print("delta reports written:")
    for path in written:
        print("  " + os.path.abspath(path))
    return 0


def cmd_score(args):
    cfg = load_config(args.config)
    try:
        with open(args.report, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"[!] could not read {args.report}: {exc}")
        return 1
    if "modules" not in report:
        print(f"[!] {args.report} is not a valid edr-auditor report")
        return 1

    score = score_report(report, cfg)
    print(f"report      : {os.path.abspath(args.report)}")
    print(f"host        : {report.get('host', '?')}   generated {report.get('generated_at', '?')}")
    print(f"hardening score : {score['total']:.1f}/100  (posture: {score['severity']})")
    for name, m in score["modules"].items():
        print(f"  {name:<12} {m['score']:5.1f}  weight {m['weight']:<3}  "
              f"in-scope {m['findings_in_scope']}/{m['findings_total']}")
    return 0


def cmd_modules(args):
    width = max(len(name) for name in MODULES)
    print(f"{'module':<{width}}  weight  modes             checks")
    print("-" * 110)
    for name in ("persistence", "services", "sockets", "patches", "hardening"):
        spec = MODULES[name]
        print(f"{name:<{width}}  {spec['weight_default']:<6}  {spec['modes']:<17}  {spec['checks']}")
    return 0


def cmd_selftest(args):
    from edr_auditor.fixtures import build
    fixture_root = os.path.join("/tmp", "edr_selftest_%d" % os.getpid())
    build(fixture_root)
    return run_selftest(fixture_root=fixture_root,
                        report_dir=args.report_dir,
                        verbose=args.verbose)[0]


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())