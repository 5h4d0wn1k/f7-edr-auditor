"""Configuration loading for f7-edr-auditor.

The shipped config is ``config/edr.yaml`` — placeholders only, no real paths
or secrets. This module includes a small, deliberate YAML-subset parser so the
tool stays 100% stdlib (no third-party YAML dependency). Supported subset:
mappings (scalar values, nested mappings) and nested scalar lists, e.g.

    weights:
      persistence: 30
    sockets:
      risky_ports: [23, 25, 3306]
    patches:
      watch:
        - "openssh-server>=9.0p1"

Anything outside that subset raises :class:`ConfigError`.
"""

import copy
import os
import re

DEFAULT_CONFIG = {
    "report": {"dir": "reports"},
    "score": {
        "min_severity": "low",
        "weights": {
            "persistence": 30,
            "services": 15,
            "sockets": 15,
            "patches": 20,
            "hardening": 20,
        },
    },
    "scan_scope": {
        "hives": {},
        "services": {"baseline": []},
        "patches": {"watch": []},
        "sockets": {"risky_ports": [23, 25, 3306, 5432, 6379, 5900, 6000], "critical_watch": []},
    },
    "search_paths": {
        "config": None,
    },
}

ENV_CONFIG_VAR = "EDR_CONFIG"


class ConfigError(Exception):
    """Raised when configuration can not be loaded or parsed."""


# ---------------------------------------------------------------------------
# YAML-subset parser
# ---------------------------------------------------------------------------

def _scalar(token):
    token = token.strip()
    if not token:
        return ""
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part) for part in inner.split(",")]
    if (token.startswith('"') and token.endswith('"')) or (
        token.startswith("'") and token.endswith("'")
    ):
        return token[1:-1]
    low = token.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", "none"):
        return None
    if re.fullmatch(r"[-+]?\d+", token):
        return int(token)
    if re.fullmatch(r"[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?", token):
        return float(token)
    return token


def _split_key_value(token):
    if ":" not in token:
        return None
    key, _, rhs = token.partition(":")
    key = key.strip().strip("\"'")
    if not key:
        return None
    return key, rhs.strip()


def _parse_block(lines, start, indent):
    """Parse sibling items sharing ``indent`` starting at ``start``.

    Returns ``(value, next_index)`` where value is a dict (mapping items) or
    list (dash items).
    """
    i = start
    kind = None  # 'map' or 'list'
    mapping = {}
    listing = []

    while i < len(lines):
        ind, tok = lines[i]
        if ind < indent:
            break
        if ind > indent:
            raise ConfigError(f"unexpected indentation (line near: {tok!r})")

        if tok.startswith("- "):
            if kind is None:
                kind = "list"
            if kind != "list":
                raise ConfigError(f"mixed mapping/list at line {tok!r}")
            item = tok[2:].strip()
            # Supports scalar lists; nested list-of-mappings is out of subset.
            if (item,):
                pass
            listing.append(_scalar(item))
            i += 1
            continue

        kv = _split_key_value(tok)
        if kv is None:
            raise ConfigError(f"cannot parse mapping line: {tok!r}")
        key, rhs = kv
        if kind is None:
            kind = "map"
        if kind != "map":
            raise ConfigError(f"mixed mapping/list at line {tok!r}")

        if rhs == "":
            # Nested block if next line is indented deeper, else empty value.
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                value, i = _parse_block(lines, i + 1, lines[i + 1][0])
            else:
                value = ""
                i += 1
        else:
            value = _scalar(rhs)
            i += 1
        mapping[key] = value

    if kind == "list":
        return listing, i
    return mapping, i


def parse_yaml_subset(text):
    """Parse the supported YAML subset into Python objects."""
    lines = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        lines.append((len(line) - len(line.lstrip(" ")), stripped))
    if not lines:
        return {}
    value, end = _parse_block(lines, 0, lines[0][0])
    if end != len(lines):
        raise ConfigError(f"trailing lines after line {end} could not be parsed")
    return value


# ---------------------------------------------------------------------------
# Loading / merging
# ---------------------------------------------------------------------------

def _deep_merge(base, override):
    result = copy.deepcopy(base)
    if not isinstance(override, dict):
        return result
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def default_config_path():
    """Resolve the config path: --config > $EDR_CONFIG > ./config/edr.yaml."""
    env = os.environ.get(ENV_CONFIG_VAR)
    if env:
        return env
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    candidate = os.path.join(here, "config", "edr.yaml")
    if os.path.exists(candidate):
        return candidate
    return os.path.join(os.getcwd(), "config", "edr.yaml")


def load_config(path=None):
    """Load configuration, deep-merging over defaults.

    ``path`` may be a file, a directory containing ``edr.yaml``, or None.
    Returns a dict with every default key present.
    """
    if path is None:
        path = default_config_path()
    if os.path.isdir(path):
        path = os.path.join(path, "edr.yaml")

    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            user_cfg = parse_yaml_subset(fh.read())
        cfg = _deep_merge(cfg, user_cfg)
    cfg["search_paths"]["config"] = path
    return cfg


def get(cfg, *keys, default=None):
    """Safely walk nested config dicts."""
    cur = cfg
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def resolve_path(cfg, value):
    """Resolve a possibly-relative config value against the config file dir."""
    if not isinstance(value, str) or os.path.isabs(value):
        return value
    base = os.path.dirname(cfg.get("search_paths", {}).get("config") or "")
    if not base:
        return value
    return os.path.join(base, value)