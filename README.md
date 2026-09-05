# F7 — EDR coverage auditor (LLM-assisted, defensive)

A pure-Python EDR behavioral-surface auditor that maps claimed detections to ATT&CK coverage, predicts evasions in silico, and generates gap-closing Sigma rule templates.

## Overview

- **Detections-to-technique mapping**: Takes a YAML/JSON list of EDR behavioral detections and maps them to ATT&CK technique-to-procedure mappings
- **Deterministic mock-LLM**: Uses a guarded keyword/description-matching heuristic to predict evasions in silico (no network, no external AI)
- **Coverage heatmap**: Renders technique x present/missing 2D heatmap
- **Sigma rule generation**: Produces gap-closing Sigma-like YAML rule templates for uncovered techniques
- **Accuracy table**: Emits predicted-vs-observed accuracy metrics for defensive validation
- **Defensive framing**: Entire pipeline is positioned to improve detection coverage, not to enable attacks

## Features

- **`map_coverage`**: Overlaps EDR detection keywords with ATT&CK procedure sets
- **`predict_evasions`**: Deterministic heuristic that flags covered/uncovered procedures with rationale and confidence
- **`build_heatmap`**: Text-based technique x present/missing visualization
- **`generate_sigma_rules`**: YAML rule templates (title, id, logsource, detection, level)
- **`build_accuracy_table`**: Predicted-vs-observed accuracy rollup
- **Fully offline**: embedded sample detections, techniques, and ground truth

## Installation

```bash
# No third-party dependencies. Python 3.8+ standard library only.
```

## Usage

```python
from edr_auditor import map_coverage, predict_evasions, build_heatmap, generate_sigma_rules, build_accuracy_table

mapping, covered = map_coverage(EDR_DETECTIONS, TECHNIQUES)
predictions = predict_evasions(TECHNIQUES, {m["technique"]: bool(m["detections"]) for m in mapping}, GAP_PROCEDURES)
rules = generate_sigma_rules(mapping)
```

### Running the Demo

```bash
python3 firmware/edr_auditor.py
```

## Example Output

```
============================================================
  F7 — EDR coverage auditor (LLM-assisted, defensive)
============================================================

[1/4] Map EDR claimed detections onto ATT&CK coverage ...
  techniques with >=1 detection : 4
[2/4] Deterministic mock-LLM evasion prediction (in silico) ...
    - T1036.005 rename         evadable=True  [no EDR detection keyword matches 'rename']
[3/4] Coverage heatmap (technique x present/missing) ...
  T1036.005  Masquerading             GAP
[4/4] Sigma-like rule templates (gap closing) + accuracy table ...
  mock-LLM prediction accuracy (vs observed envelope): 83.3%
```

## IMPORTANT: Read before use.

This project is provided for **educational and defensive security purposes only**.

### Authorization Requirements
- This tool is for assessing and improving defensive detection coverage on systems you are authorized to defend
- Auditing an EDR deployment, telemetry feed, or detection inventory requires authorization from the owning organization
- It must NEVER be used to craft or refine evasion techniques against systems you do not defend

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Computer Misuse / Data Protection Laws**: Accessing or exfiltrating detection telemetry without authorization is unlawful
- **State Laws**: Many states have additional computer crime statutes
- **Export / End-Use Controls**: Defensive security tools may be subject to export-control obligations

### Acceptable Use
- Auditing your own EDR fleet and detection coverage
- Authorized SOC/blue-team detection engineering
- Academic research in controlled lab environments
- Security education and training on defensive posture

### Prohibited Use
- Using evasion predictions to develop malware or bypass security controls on third-party systems
- Circumventing EDR for offensive purposes
- Accessing telemetry you are not authorized to view
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover detection gaps or weaknesses using this tool, follow responsible disclosure practices:
1. Report to the owning organization (your own or a client) privately
2. Provide the vendor with the gap findings and recommended Sigma coverage
3. Do not weaponize findings against third parties

## License

MIT
