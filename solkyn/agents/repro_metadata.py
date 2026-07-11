"""Reproducibility metadata helpers.

Captures the small set of environment facts every per-attempt
``config.json`` should pin so a result can be re-run later: the git
commit Solkyn was on, and the SHA-256 digest of the docker image used
for the challenge. Both lookups are best-effort \u2014 if git or docker is
missing or the call errors out we record ``"unknown"`` rather than
crash the run, since metadata capture must never break a sweep.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def get_git_sha(repo_root: str | Path | None = None) -> str:
    """Return the current commit SHA, or ``"unknown"`` if unavailable.

    ``repo_root`` defaults to the Solkyn package root. The lookup is
    silenced (no stderr) so a non-git working tree doesn't pollute the
    sweep log; we just fall back to ``"unknown"``.
    """
    if shutil.which("git") is None:
        return "unknown"
    cwd = str(repo_root) if repo_root is not None else None
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return "unknown"
    return out.strip() or "unknown"


def get_docker_image_digest(image_name: str) -> str:
    """Return the SHA-256 ID of the named docker image, or ``"unknown"``.

    Used to pin which exact challenge container was attacked. Failures
    (docker missing, image not built, daemon down) all return
    ``"unknown"`` rather than raise \u2014 metadata capture is best-effort.
    """
    if not image_name or shutil.which("docker") is None:
        return "unknown"
    try:
        out = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.Id}}", image_name],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return "unknown"
    return out.strip() or "unknown"
