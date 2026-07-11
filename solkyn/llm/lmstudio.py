"""LM Studio CLI integration — model lifecycle management via `lms` CLI."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

# Default context length for model reloads
DEFAULT_CONTEXT_LENGTH = 120000


def _find_lms_binary() -> str | None:
    """Find the `lms` CLI binary."""
    # Check common locations
    lmstudio_bin = os.path.expanduser("~/.lmstudio/bin/lms")
    if os.path.isfile(lmstudio_bin):
        return lmstudio_bin
    # Fallback to PATH
    return shutil.which("lms")


def _run_lms(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Run an `lms` CLI command."""
    binary = _find_lms_binary()
    if not binary:
        raise FileNotFoundError(
            "LM Studio CLI (`lms`) not found. "
            "Install from: https://lmstudio.ai/docs/cli"
        )
    cmd = [binary, *args]
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def reload_model(model_name: str, context_length: int = DEFAULT_CONTEXT_LENGTH) -> None:
    """Unload all models and reload the specified one to reset KV cache.

    This is critical between challenge runs to prevent KV cache accumulation
    that causes model crashes (observed: 28/104 challenges crashed from this).

    Args:
        model_name: Model identifier (e.g., 'bugtraceai-apex-g4-26b').
        context_length: Context window size. Default 120000.
    """
    logger.info("Reloading model: %s (context=%d)", model_name, context_length)

    # Step 1: Unload all models
    result = _run_lms(["unload", "--all", "--yes"])
    if result.returncode != 0:
        logger.warning("Model unload returned non-zero: %s", result.stderr.strip())
    else:
        logger.info("All models unloaded")

    # Step 2: Load the model fresh
    result = _run_lms(
        ["load", model_name, "-c", str(context_length), "--gpu", "max", "--yes"],
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to load model '{model_name}': {result.stderr.strip()}"
        )
    logger.info("Model loaded: %s", model_name)


def is_lm_studio_provider(provider: str) -> bool:
    """Check if a provider name is an LM Studio provider."""
    return provider.startswith("lm-studio")


def get_model_from_env() -> str | None:
    """Get the LM Studio model name from environment variable."""
    return os.environ.get("LM_STUDIO_MODEL")
