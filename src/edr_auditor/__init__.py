"""F7 — EDR auditor.

Cross-platform endpoint hardening auditor (blue team). Reads persistence,
services, sockets, patches and hardening posture from Linux live hosts and/or
passively from Windows registry hive files (no privileged APIs). Produces a
weighted 0-100 hardening score plus JSON/HTML reports, and can diff two runs.

Design intent: the tool ONLY reads machines you own. See README "IMPORTANT:
Read before use" before running it anywhere.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]