"""Container lifecycle management for Kali Docker containers."""

from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)

# Tools we expect in the Kali image
KNOWN_TOOLS = [
    "nmap", "sqlmap", "ffuf", "gobuster", "dirb", "nikto", "nuclei",
    "whatweb", "wafw00f", "wpscan", "curl", "wget", "jq", "python3",
    "netcat-openbsd", "socat", "whois",
]

DEFAULT_IMAGE = "solkyn/kali:latest"
DEFAULT_NETWORK = "solkyn-net"


class ContainerManager:
    """Manages Kali Docker container lifecycle."""

    def __init__(self, image: str = DEFAULT_IMAGE):
        self.image = image

    def create(self, scan_id: str, network: str = DEFAULT_NETWORK) -> str:
        """Create and start a named container on the specified network.

        Returns the container name.
        """
        container_name = f"solkyn-{scan_id}"
        self.ensure_network(network)

        cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "--network", network,
            "--hostname", container_name,
            self.image,
            "sleep", "infinity",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to create container: {result.stderr.strip()}")

        logger.info("Created container %s on network %s", container_name, network)
        return container_name

    def destroy(self, container_name: str) -> None:
        """Stop and remove a container."""
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            text=True,
        )
        logger.info("Destroyed container %s", container_name)

    def is_healthy(self, container_name: str) -> bool:
        """Check if a container is running."""
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"

    def ensure_network(self, network: str) -> None:
        """Create a Docker network if it doesn't exist."""
        result = subprocess.run(
            ["docker", "network", "inspect", network],
            capture_output=True,
        )
        if result.returncode != 0:
            subprocess.run(
                ["docker", "network", "create", network],
                capture_output=True,
                text=True,
                check=True,
            )
            logger.info("Created network %s", network)

    def connect_to_network(self, container_name: str, network: str) -> None:
        """Connect an existing container to an additional network."""
        result = subprocess.run(
            ["docker", "network", "connect", network, container_name],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            # Ignore "already connected" errors
            if "already exists" not in result.stderr:
                raise RuntimeError(f"Failed to connect to network: {result.stderr.strip()}")

    def list_tools(self, container_name: str) -> list[str]:
        """Check which known pentesting tools are available in the container."""
        check_cmd = " && ".join(f'which {t} >/dev/null 2>&1 && echo {t}' for t in KNOWN_TOOLS)
        result = subprocess.run(
            ["docker", "exec", container_name, "bash", "-c", check_cmd],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
