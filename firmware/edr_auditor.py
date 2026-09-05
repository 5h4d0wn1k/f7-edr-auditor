#!/usr/bin/env python3
"""
F7 — EDR coverage auditor (LLM-assisted, defensive)
Pure-Python EDR behavioral-surface auditor: maps an EDR's claimed behavioral
detections onto ATT&CK technique coverage, uses a deterministic mock-LLM
heuristic (keyword/description matching) to predict evasions in silico,
produces a coverage heatmap (technique x present/missing), and generates
gap-closing Sigma-like rule templates. Offline demo. Defensive framing only.

Educational / authorized use only (improving defensive posture, never attacking).

Usage:
    python3 edr_auditor.py        # run the offline self-test demo (exit 0)
"""

import hashlib
import json
import sys
from collections import defaultdict

# ---------------------------------------------------------------------------
# Embedded sample data: EDR claimed detections + ATT&CK technique mappings
# ---------------------------------------------------------------------------

# ATT&CK techniques: id -> {name, description, key_procedures[]}
TECHNIQUES = {
    "T1059.001": {"name": "PowerShell", "desc": "Obfuscated PowerShell execution / script block logging", "procedures": ["powershell", "scriptblock", "obfuscation", "executionpolicy"]},
    "T1059.003": {"name": "Windows Command Shell", "desc": "cmd.exe abuse / batch / LOLBins", "procedures": ["cmd", "batch", "lolbin", "shell"]},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "desc": "Persistence via Run keys", "procedures": ["registry", "runkey", "persistence", "startup"]},
    "T1552.001": {"name": "Credentials In Files", "desc": "Searching files for credentials", "procedures": ["credential", "password", "dump", "lsass"]},
    "T1036.005": {"name": "Masquerading: Match Legit Name", "desc": "Renaming malware to look legitimate", "procedures": ["masquerade", "rename", "legit", "processname"]},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "desc": "Email attachment delivery", "procedures": ["email", "attachment", "macro", "phish"]},
}

# EDR claimed behavioral detections: name -> keywords that map to procedures
EDR_DETECTIONS = [
    {"name": "Powershell script-block logging", "keywords": ["powershell", "scriptblock", "obfuscation"]},
    {"name": "Cmdline LOLBins execution", "keywords": ["cmd", "lolbin", "shell", "batch"]},
    {"name": "LSASS credential access", "keywords": ["lsass", "credential", "dump"]},
    {"name": "Autorun / runkey modification", "keywords": ["runkey", "registry", "persistence", "startup"]},
    {"name": "Email attachment sandbox", "keywords": ["email", "attachment", "macro", "phish"]},
]

# Missing areas the mock-LLM should predict as evadable (procedures not covered)
GAP_PROCEDURES = [
    {"technique": "T1036.005", "procedure": "rename"},
    {"technique": "T1059.003", "procedure": "batch"},
]


# ---------------------------------------------------------------------------
# Coverage mapping: EDR detections -> ATT&CK techniques
# ---------------------------------------------------------------------------

def map_coverage(detections, techniques):
    """Map each EDR detection to the techniques whose procedures overlap."""
    tech_covered = set()
    mapping = []
    det_keywords = {d["name"]: set(d["keywords"]) for d in detections}
    for tid, t in techniques.items():
        t_proc_set = set(t["procedures"])
        matches = []
        for dname, kws in det_keywords.items():
            if kws & t_proc_set:
                matches.append(dname)
        if matches:
            tech_covered.add(tid)
        mapping.append({"technique": tid, "name": t["name"], "detections": sorted(matches)})
    return mapping, tech_covered


# ---------------------------------------------------------------------------
# Deterministic mock-LLM evasion predictor (in silico, keyword/desc matching)
# ---------------------------------------------------------------------------

# A simple keyword-> meaning profile the "model" uses to reason about bypass.
EVASION_KEYWORDS = {
    "executionpolicy": "bypass", "obfuscation": "bypass", "rename": "bypass",
    "batch": "bypass", "macro": "bypass", "lolbin": "bypass",
}

MOCK_LLM = {
    "name": "mock-llm-heuristic-v1",
    "model": "deterministic-keyword-matching (no network, no external AI)",
}


def predict_evasions(techniques, coverage_by_tech, gap_procedures):
    """Return a list of predicted evasion scenarios for coverage gaps."""
    predictions = []
    for g in gap_procedures:
        tid = g["technique"]
        proc = g["procedure"]
        tech = techniques[tid]
        covered = coverage_by_tech.get(tid, False)
        bypass_reason = EVASION_KEYWORDS.get(proc, "unmapped-procedure")
        predictions.append({
            "technique": tid,
            "name": tech["name"],
            "procedure": proc,
            "covered_by_edr": covered,
            "predicted_evadable": not covered,
            "rationale": f"no EDR detection keyword matches '{proc}' "
                         f"(likely bypass vector: {bypass_reason})",
            "confidence": 0.80 if not covered else 0.20,
        })
    return predictions


# ---------------------------------------------------------------------------
# Coverage heatmap + Sigma-like rule templates + accuracy table
# ---------------------------------------------------------------------------

def build_heatmap(mapping):
    """technique x present/missing 2D heatmap (text glyphs)."""
    heat = []
    print("  " + f"{'Technique':<14} {'Present':<9} {'Missing':<9} status")
    print("  " + "-" * 46)
    for m in mapping:
        present = "Y" if m["detections"] else " "
        missing = " " if m["detections"] else "!"
        status = "covered" if m["detections"] else "GAP"
        heat.append({"technique": m["technique"], "present": bool(m["detections"]), "status": status})
        print(f"  {m['technique']:<14} {present:<9} {missing:<9} {status}")
    return heat


def generate_sigma_rules(mapping):
    """Generate gap-closing Sigma-like YAML rule templates for missing coverage."""
    rules = []
    for m in mapping:
        if m["detections"]:
            continue
        tid = m["technique"]
        tech = TECHNIQUES[tid]
        rules.append({
            "title": f"Detect {tech['name']} ({tid})",
            "id": "rule-" + hashlib.sha1(tid.encode()).hexdigest()[:12],
            "status": "experimental",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "CommandLine|contains": tech["procedures"],
                },
                "condition": "selection",
            },
            "level": "medium",
            "generated_by": "f7-edr-auditor",
        })
    return rules


def build_accuracy_table(predictions, ground_truth_evadable):
    """Predicted-vs-observed accuracy table (defensive validation)."""
    rows = []
    correct = 0
    for p in predictions:
        key = (p["technique"], p["procedure"])
        observed = ground_truth_evadable.get(key, True)
        hit = (p["predicted_evadable"] == observed)
        correct += int(hit)
        rows.append({
            "technique": p["technique"],
            "procedure": p["procedure"],
            "predicted_evadable": p["predicted_evadable"],
            "observed_evadable": observed,
            "correct": hit,
        })
    acc = (correct / len(rows)) * 100 if rows else 100.0
    return rows, acc


# ---------------------------------------------------------------------------
# Offline demo
# ---------------------------------------------------------------------------

def main(argv=None):
    print("=" * 60)
    print("  F7 — EDR coverage auditor (LLM-assisted, defensive)")
    print("=" * 60)

    print("\n[1/4] Map EDR claimed detections onto ATT&CK coverage ...")
    mapping, tech_covered = map_coverage(EDR_DETECTIONS, TECHNIQUES)
    print(f"  techniques present in dataset : {len(TECHNIQUES)}")
    print(f"  techniques with >=1 detection : {len(tech_covered)}")

    print("\n[2/4] Deterministic mock-LLM evasion prediction (in silico) ...")
    coverage_by_tech = {m["technique"]: bool(m["detections"]) for m in mapping}
    predictions = predict_evasions(TECHNIQUES, coverage_by_tech, GAP_PROCEDURES)
    print(f"  predictions: {len(predictions)}  (engine: {MOCK_LLM['name']})")
    for p in predictions:
        print(f"    - {p['technique']} {p['procedure']:<12} evadable={p['predicted_evadable']}  [{p['rationale']}]")

    print("\n[3/4] Coverage heatmap (technique x present/missing) ...")
    heat = build_heatmap(mapping)
    gaps = [h["technique"] for h in heat if not h["present"]]
    print(f"  total coverage gaps: {len(gaps)}")

    print("\n[4/4] Sigma-like rule templates (gap closing) + accuracy table ...")
    rules = generate_sigma_rules(mapping)
    print(f"  generated rule templates: {len(rules)}")
    for r in rules:
        print(f"    - {r['title']} [{r['id']}]")

    # Defensive ground-truth: gaps we know are evadable (from GAP_PROCEDURES)
    ground_truth = {(g["technique"], g["procedure"]): True for g in GAP_PROCEDURES}
    rows, acc = build_accuracy_table(predictions, ground_truth)
    print("\n  Predicted-vs-Observed accuracy table:")
    print(f"    {'technique':<12} {'procedure':<12} {'pred':<6} {'obs':<6} ok")
    print("    " + "-" * 44)
    for r in rows:
        print(f"    {r['technique']:<12} {r['procedure']:<12} {str(r['predicted_evadable']):<6} "
              f"{str(r['observed_evadable']):<6} {'Y' if r['correct'] else 'N'}")
    print(f"\n  mock-LLM prediction accuracy (vs observed envelope): {acc:.1f}%")

    print("\nDefensive recommendation: close gaps")
    for g in gaps:
        print(f"    - add Sigma coverage for {g} ({TECHNIQUES[g]['name']})")

    print("\nDemo complete (exit 0).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
