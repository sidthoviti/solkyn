"""XBOW benchmark platform adapter — load, build, start, stop challenges."""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

DEFAULT_BENCHMARKS_DIR = Path("benchmarks/xbow/benchmarks")

# Env override so mysql:5.7 (no ARM64 image) builds via Rosetta on Apple Silicon
_DOCKER_ENV = {**os.environ, "DOCKER_DEFAULT_PLATFORM": "linux/amd64"}


@dataclass
class ChallengeInfo:
    """Parsed challenge metadata."""

    id: str
    name: str
    description: str
    level: str
    tags: list[str]
    win_condition: str
    challenge_dir: Path
    files: list[str] = field(default_factory=list)
    file_contents: dict[str, str] = field(default_factory=dict)


class XBOWPlatform:
    """Adapter for XBOW validation-benchmarks."""

    def __init__(self, benchmarks_dir: Path | str = DEFAULT_BENCHMARKS_DIR):
        self.benchmarks_dir = Path(benchmarks_dir)
        # Track active challenges for cleanup
        self._active: dict[str, ChallengeInfo] = {}

    def list_challenges(self) -> list[str]:
        """Return sorted list of challenge IDs."""
        return sorted(
            d.name for d in self.benchmarks_dir.iterdir()
            if d.is_dir() and d.name.startswith("XBEN-")
        )

    def load_challenge(self, challenge_id: str) -> ChallengeInfo:
        """Load challenge metadata from benchmark.json."""
        challenge_dir = self.benchmarks_dir / challenge_id
        if not challenge_dir.exists():
            raise FileNotFoundError(f"Challenge not found: {challenge_id}")

        benchmark_json = challenge_dir / "benchmark.json"
        if not benchmark_json.exists():
            raise FileNotFoundError(f"No benchmark.json in {challenge_id}")

        with open(benchmark_json) as f:
            data = json.load(f)

        # Collect source files for context (limit to 50 most relevant)
        skip_dirs = {"node_modules", ".next", "__pycache__", ".git", "vendor"}
        skip_exts = {".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2",
                     ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz"}
        files = []
        for p in challenge_dir.rglob("*"):
            if p.is_file() and p.name not in ("benchmark.json", "benchmark.yaml"):
                rel = str(p.relative_to(challenge_dir))
                # Skip build artifacts, binary assets, and data files
                if any(f"/{d}/" in f"/{rel}" or rel.startswith(f"{d}/") for d in skip_dirs):
                    continue
                if p.suffix.lower() in skip_exts:
                    continue
                # Skip S3rver metadata/object files (binary data)
                if "_S3rver_" in p.name:
                    continue
                files.append(rel)

        # Prioritize config/entry files; cap at 50 to avoid blowing up context
        priority_names = {
            "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
            "Makefile", ".env", "README.md", "flag.txt", "main.py",
            "app.py", "index.php", "index.html", "server.js", "requirements.txt",
        }
        priority = [f for f in files if any(f.endswith(n) for n in priority_names)]
        rest = [f for f in files if f not in priority]
        files = (priority + rest)[:50]

        # Read content of key source files to include in prompt
        key_patterns = {
            ".env", "app.py", "main.py", "server.js", "index.php",
            "auth.ts", "auth.js", "user.ts", "user.js", "login.ts", "login.js",
            "s3.js", "s3.ts", "download.php", "upload.php",
            "routes.py", "models.py", "__init__.py",
            "haproxy.cfg", "nginx.conf", "Caddyfile",
        }
        key_dirs = {"api/", "pages/api/", "routes/", "includes/lib/", "actions/", "db/"}
        key_exts = {".ts", ".tsx", ".py", ".php", ".js", ".jsx"}
        file_contents: dict[str, str] = {}
        total_chars = 0
        max_total = 30000  # Cap total included content
        for f in files:
            fname = f.rsplit("/", 1)[-1] if "/" in f else f
            fext = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""
            in_key_dir = any(d in f for d in key_dirs)
            is_key_file = fname in key_patterns
            # Include docker-compose for architecture, app source for logic
            is_compose = fname in ("docker-compose.yml", "docker-compose.yaml", "Dockerfile")
            is_app_source = in_key_dir and fext in key_exts
            if is_key_file or is_compose or is_app_source:
                fpath = challenge_dir / f
                if fpath.exists() and fpath.stat().st_size < 12000:
                    try:
                        content = fpath.read_text(errors="replace")
                        if total_chars + len(content) <= max_total:
                            file_contents[f] = content
                            total_chars += len(content)
                    except Exception:
                        pass

        return ChallengeInfo(
            id=challenge_id,
            name=data.get("name", challenge_id),
            description=data.get("description", ""),
            level=str(data.get("level", "?")),
            tags=data.get("tags", []),
            win_condition=data.get("win_condition", "flag"),
            challenge_dir=challenge_dir,
            files=files,
            file_contents=file_contents,
        )

    def build_challenge(self, challenge_id: str, flag: str | None = None) -> str:
        """Build the challenge Docker image with a random flag.

        Returns the flag value.
        """
        info = self.load_challenge(challenge_id)

        if flag is None:
            flag = f"FLAG{{{secrets.token_hex(32)}}}"

        logger.info("Building %s with flag %s...", challenge_id, flag[:20] + "...")

        result = subprocess.run(
            [
                "docker", "compose", "build",
                "--build-arg", f"FLAG={flag}",
                "--build-arg", f"flag={flag}",
            ],
            cwd=info.challenge_dir,
            capture_output=True,
            text=True,
            timeout=300,
            env=_DOCKER_ENV,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Build failed for {challenge_id}:\n{result.stderr[-2000:]}")

        self._active[challenge_id] = info
        logger.info("Built %s successfully", challenge_id)
        return flag

    def start_challenge(self, challenge_id: str) -> str:
        """Start the challenge and return the target URL."""
        info = self._active.get(challenge_id) or self.load_challenge(challenge_id)

        logger.info("Starting %s...", challenge_id)

        result = subprocess.run(
            ["docker", "compose", "up", "-d", "--wait"],
            cwd=info.challenge_dir,
            capture_output=True,
            text=True,
            timeout=120,
            env=_DOCKER_ENV,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Start failed for {challenge_id}:\n{result.stderr[-2000:]}")

        # Discover the port
        main_service = self._get_main_service(info)
        url = self._discover_url(info, main_service)

        # Discover additional ports (SSH, etc.) and add to description
        extra_ports = self._discover_extra_ports(info, main_service)
        if extra_ports:
            port_info = ", ".join(f"{proto} on host.docker.internal:{port}" for proto, port in extra_ports)
            info.description = info.description + f"\nAdditional services: {port_info}"
            logger.info("Extra ports for %s: %s", challenge_id, port_info)

        self._active[challenge_id] = info
        logger.info("Started %s at %s", challenge_id, url)
        return url

    def stop_challenge(self, challenge_id: str) -> None:
        """Stop and remove challenge containers."""
        info = self._active.pop(challenge_id, None) or self.load_challenge(challenge_id)

        subprocess.run(
            ["docker", "compose", "down", "-v", "--remove-orphans"],
            cwd=info.challenge_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        logger.info("Stopped %s", challenge_id)

    def verify_flag(self, agent_output: str, expected_flag: str) -> bool:
        """Check if the expected flag appears in the agent's output."""
        return expected_flag in agent_output

    def _get_main_service(self, info: ChallengeInfo) -> str | None:
        """Determine the main service name from benchmark.yaml or docker-compose.yml."""
        # Check benchmark.yaml for main-service override
        benchmark_yaml = info.challenge_dir / "benchmark.yaml"
        if benchmark_yaml.exists():
            with open(benchmark_yaml) as f:
                data = yaml.safe_load(f) or {}
            if "main-service" in data:
                return data["main-service"]

        # Parse docker-compose.yml to find the service with 'ports'
        compose_file = info.challenge_dir / "docker-compose.yml"
        if not compose_file.exists():
            compose_file = info.challenge_dir / "docker-compose.yaml"
        if not compose_file.exists():
            return None

        with open(compose_file) as f:
            compose = yaml.safe_load(f) or {}

        services = compose.get("services", {})
        for svc_name, svc_config in services.items():
            if "ports" in svc_config:
                return svc_name

        return None

    def _discover_url(self, info: ChallengeInfo, service: str | None) -> str:
        """Discover the published port for a service."""
        # Use docker compose port to find the mapped port
        cmd = ["docker", "compose", "port"]
        if service:
            cmd.append(service)
        else:
            # If no service identified, try the first one
            cmd.append("")
        cmd.append("80")

        result = subprocess.run(
            cmd,
            cwd=info.challenge_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0 and result.stdout.strip():
            # Output is like "0.0.0.0:32768" or ":::32768"
            port_str = result.stdout.strip()
            match = re.search(r":(\d+)$", port_str)
            if match:
                port = match.group(1)
                return f"http://localhost:{port}"

        # Fallback: parse docker compose ps for port info
        result = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=info.challenge_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                try:
                    container = json.loads(line)
                    publishers = container.get("Publishers") or []
                    for pub in publishers:
                        if pub.get("PublishedPort", 0) > 0:
                            return f"http://localhost:{pub['PublishedPort']}"
                except (json.JSONDecodeError, KeyError):
                    continue

        raise RuntimeError(f"Could not discover port for {info.id}")

    def _discover_extra_ports(
        self, info: ChallengeInfo, service: str | None
    ) -> list[tuple[str, str]]:
        """Discover non-HTTP ports (SSH, , etc.) across all services."""
        # Well-known container ports to check
        known_ports = {
            "22": "SSH",
            "3306": "MySQL",
            "5432": "PostgreSQL",
            "8333": "",
            "9000": "MinIO",
        }

        # Get all services from docker-compose
        compose_file = info.challenge_dir / "docker-compose.yml"
        if not compose_file.exists():
            compose_file = info.challenge_dir / "docker-compose.yaml"

        services_to_check = [service] if service else []
        if compose_file.exists():
            with open(compose_file) as f:
                compose = yaml.safe_load(f) or {}
            for svc_name in compose.get("services", {}):
                if svc_name not in services_to_check:
                    services_to_check.append(svc_name)

        extra = []
        for svc in services_to_check:
            if not svc:
                continue
            for container_port, proto in known_ports.items():
                result = subprocess.run(
                    ["docker", "compose", "port", svc, container_port],
                    cwd=info.challenge_dir,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env=_DOCKER_ENV,
                )
                if result.returncode == 0 and result.stdout.strip():
                    match = re.search(r":(\d+)$", result.stdout.strip())
                    if match:
                        extra.append((proto, match.group(1)))
        return extra
