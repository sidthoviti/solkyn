"""Configuration loader — YAML loading with env var substitution and defaults merging."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from solkyn.config.schema import ScanConfig

_ENV_VAR_RE = re.compile(r"\$\{([^}]+)\}")

DEFAULT_CONFIG_PATH = Path("configs/default.yaml")


def _resolve_env_vars(value: Any) -> Any:
    """Recursively resolve ${VAR_NAME} references in config values.

    Returns the raw ${VAR} string unchanged if the env var is not set,
    allowing unused providers to remain in config without blocking startup.
    """
    if isinstance(value, str):
        def _replace(match: re.Match) -> str:
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))
        return _ENV_VAR_RE.sub(_replace, value)
    if isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_vars(item) for item in value]
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base dict. Override values win."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_yaml(path: str | Path) -> dict:
    """Load a YAML file and return raw dict."""
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_config(
    path: str | Path | None = None,
    resolve_env: bool = True,
) -> ScanConfig:
    """Load and validate scan configuration.

    Args:
        path: Path to config YAML. If None, uses configs/default.yaml.
        resolve_env: Whether to resolve ${VAR} references. Set False in tests
                     to avoid requiring real env vars.

    Returns:
        Validated ScanConfig instance.
    """
    # Load defaults
    defaults = {}
    if DEFAULT_CONFIG_PATH.exists():
        defaults = load_yaml(DEFAULT_CONFIG_PATH)

    # Load user config (or use defaults if no path given)
    if path is not None:
        user_config = load_yaml(path)
        raw = _deep_merge(defaults, user_config)
    else:
        raw = defaults

    # Resolve env vars
    if resolve_env:
        raw = _resolve_env_vars(raw)

    return ScanConfig(**raw)
