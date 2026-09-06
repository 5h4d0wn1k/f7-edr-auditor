"""Hardening module: SSH config & file perms, password policy, firewall.

All checks are read-only. File-permission checks come from stat metadata the
pipeline collects (never touched), password-policy checks parse login.defs and
PAM config, and the firewall check inspects ufw / nft / iptables state.
"""

import re

from edr_auditor.models import Finding


def _parse_ssh_options(text):
    """First-wins sshd_config directive parser (matches sshd semantics)."""
    options = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " " in line:
            key, _, value = line.partition(" ")
            key = key.strip().lower()
            value = value.strip()
        else:
            key, value = line.lower(), ""
        if key and key not in options:
            options[key] = value
    return options


def _login_defs(text):
    values = {}
    for line in (text or "").splitlines():
        tokens = line.split()
        if len(tokens) >= 2 and tokens[0].startswith("PASS_"):
            values[tokens[0].strip()] = tokens[1].strip()
    return values


def _shadow_entries(text):
    for line in (text or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            yield parts[0], parts[1]


def audit_hardening(ctx, cfg):
    findings = []
    mode = ctx.get("mode")

    # -- SSH ---------------------------------------------------------------
    options = _parse_ssh_options(ctx.get("sshd_config"))

    if options:
        root = options.get("permitrootlogin", "").strip().lower()
        if root == "yes":
            findings.append(Finding(
                module="hardening",
                severity="high",
                title="SSH root login permitted",
                description="sshd_config sets PermitRootLogin yes; interactive root login "
                            "over SSH broadens the attack surface.",
                remediation="Set 'PermitRootLogin no' (or prohibit-password / with key-only "
                            "access) in /etc/ssh/sshd_config and restart sshd.",
                evidence="PermitRootLogin yes",
                source="sshd-config",
                tags=("ssh", "posture"),
            ))
        elif not root:
            findings.append(Finding(
                module="hardening",
                severity="low",
                title="SSH root login not explicitly restricted",
                description="sshd_config does not set PermitRootLogin; rely on the distro "
                            "default (often prohibit-password).",
                remediation="Explicitly set PermitRootLogin no for defense in depth.",
                evidence="PermitRootLogin unset",
                source="sshd-config",
                tags=("ssh", "posture"),
            ))
        pw = options.get("passwordauthentication", "").strip().lower()
        if pw == "yes":
            findings.append(Finding(
                module="hardening",
                severity="medium",
                title="SSH password authentication enabled",
                description="sshd_config permits password logins; key-based auth is "
                            "stronger against brute force.",
                remediation="Set PasswordAuthentication no (use keys) or enforce a strong "
                            "password policy + rate limiting (fail2ban).",
                evidence="PasswordAuthentication yes",
                source="sshd-config",
                tags=("ssh", "posture"),
            ))

    if mode not in ("hive",):
        for path, (perms, owner) in (ctx.get("file_perms") or {}).items():
            if perms & 0o002:
                findings.append(Finding(
                    module="hardening",
                    severity="high",
                    title=f"World-writable configuration file: {path}",
                    description=f"{path} is writable by 'other' (mode {oct(perms)}).",
                    remediation=f"chmod 640 (or 600) {path} and verify ownership.",
                    evidence=f"mode={oct(perms)} owner={owner}",
                    source="stat",
                    tags=("perms", "ssh"),
                ))
            elif perms & 0o020:
                findings.append(Finding(
                    module="hardening",
                    severity="low",
                    title=f"Group-writable configuration file: {path}",
                    description=f"{path} is writable by its group (mode {oct(perms)}).",
                    remediation=f"chmod 640 {path} if only root should write it.",
                    evidence=f"mode={oct(perms)} owner={owner}",
                    source="stat",
                    tags=("perms", "ssh"),
                ))

    # -- Password policy -----------------------------------------------------
    login = _login_defs(ctx.get("login_defs"))
    if login:
        try:
            max_days = int(login.get("PASS_MAX_DAYS", "0"))
        except ValueError:
            max_days = 0
        if max_days == 0 or max_days > 90:
            findings.append(Finding(
                module="hardening",
                severity="medium",
                title="Password expiry not enforced",
                description=f"PASS_MAX_DAYS is {max_days or 'unset'}; passwords never age out.",
                remediation="Set PASS_MAX_DAYS 90 (or lower) in /etc/login.defs and apply "
                            "'chage --maxdays 90' to accounts.",
                evidence=f"PASS_MAX_DAYS={max_days}",
                source="login.defs",
                tags=("password-policy",),
            ))
        try:
            min_days = int(login.get("PASS_MIN_DAYS", "0"))
        except ValueError:
            min_days = 0
        if min_days < 1:
            findings.append(Finding(
                module="hardening",
                severity="low",
                title="Minimum password age not enforced",
                description="PASS_MIN_DAYS is unset/0; users can rotate passwords freely.",
                remediation="Set PASS_MIN_DAYS 1 in /etc/login.defs.",
                evidence=f"PASS_MIN_DAYS={min_days}",
                source="login.defs",
                tags=("password-policy",),
            ))
        try:
            min_len = int(login.get("PASS_MIN_LEN", "0"))
        except ValueError:
            min_len = 0
        if 0 < min_len < 8:
            findings.append(Finding(
                module="hardening",
                severity="medium",
                title="Minimum password length weak",
                description=f"PASS_MIN_LEN is {min_len}, below the recommended 8+.",
                remediation="Raise PASS_MIN_LEN to at least 8 (and prefer pam_pwquality).",
                evidence=f"PASS_MIN_LEN={min_len}",
                source="login.defs",
                tags=("password-policy",),
            ))

    pwq = ctx.get("common_password")
    if pwq:
        low = pwq.lower()
        if "pam_pwquality" in low:
            m = re.search(r"minlen\s*=\s*(\d+)", low)
            if not m or int(m.group(1)) < 8:
                findings.append(Finding(
                    module="hardening",
                    severity="medium",
                    title="Weak password quality policy",
                    description="pam_pwquality is configured without an adequate minlen.",
                    remediation="Add 'minlen=12' (or at least 8) to the pam_pwquality.so line.",
                    evidence="minlen=" + (m.group(1) if m else "unset"),
                    source="pam",
                    tags=("password-policy",),
                ))
        else:
            findings.append(Finding(
                module="hardening",
                severity="low",
                title="No password quality module configured",
                description="PAM (common-password) does not reference pam_pwquality.",
                remediation="Enable pam_pwquality with minlen=12 in the password auth stack.",
                evidence="pam_pwquality absent",
                source="pam",
                tags=("password-policy",),
            ))

    shadow = ctx.get("shadow")
    if shadow is None:
        if mode not in ("hive",):
            findings.append(Finding(
                module="hardening",
                severity="info",
                title="shadow file not readable",
                description="Account password hashes were not checked (needs root to read "
                            "/etc/shadow).",
                remediation="Optional: re-run the audit as root to check for empty passwords.",
                evidence="",
                source="shadow",
                tags=("coverage-gap",),
            ))
    else:
        for (name, hash_field) in _shadow_entries(shadow):
            if hash_field in ("!", "*", "!!"):
                continue
            if not hash_field:
                findings.append(Finding(
                    module="hardening",
                    severity="critical",
                    title=f"Account with blank password: {name}",
                    description=f"Account {name} has an empty password field — anyone can "
                                "log in without a password.",
                    remediation=f"Lock the account or set a strong password: 'passwd {name}' "
                                "then 'chage --mindays 1 --maxdays 90 {name}'.",
                    evidence=f"user={name}",
                    source="shadow",
                    tags=("password-policy", "critical"),
                ))
            else:
                # Weak/legacy hash: `1`/`a1` = MD5 crypt, `2` = Blowfish-ok.
                kind = hash_field[0:2]
                if kind in ("$1", "$a"):
                    findings.append(Finding(
                        module="hardening",
                        severity="medium",
                        title=f"Weak password hash on account: {name}",
                        description=f"Account {name} uses a legacy {kind} hash which is "
                                    "cheap to brute force.",
                        remediation="Force a hash upgrade (passwd) or reinstall with SHA-512/"
                                    "argon2 policies.",
                        evidence=f"user={name} hash={kind}$...",
                        source="shadow",
                        tags=("password-policy", "hash"),
                    ))

    # -- Firewall -------------------------------------------------------------
    fw = ctx.get("firewall") or {}
    ufw_text = fw.get("ufw") or ""
    nft_text = (fw.get("nft") or "").strip()
    ipt_text = (fw.get("iptables") or "").strip()
    ufw_active = "status: active" in ufw_text.lower()
    nft_active = bool(nft_text)
    ipt_active = len(ipt_text.splitlines()) > 2  # chain headers only => no rules

    if mode != "hive":
        if ufw_active or nft_active or ipt_active:
            labels = [t for t, ok in (("ufw", ufw_active), ("nft", nft_active),
                                      ("iptables", ipt_active)) if ok]
            findings.append(Finding(
                module="hardening",
                severity="info",
                title="Host firewall active",
                description="A host firewall is present and loaded: " + ", ".join(labels),
                remediation="Nothing to do; keep rules reviewed.",
                evidence=", ".join(labels),
                source="firewall-status",
                tags=("firewall", "overview"),
            ))
        else:
            findings.append(Finding(
                module="hardening",
                severity="high",
                title="No host firewall detected",
                description="No ufw/nftables/iptables filter rules appear to be active.",
                remediation="Enable a host firewall and default-deny inbound traffic.",
                evidence="ufw=inactive nft=absent iptables=empty",
                source="firewall-status",
                tags=("firewall", "posture"),
            ))

    return findings