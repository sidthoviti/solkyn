"""Integration test: Kali container can reach other containers on the same Docker network.

This proves the agent can communicate with XBOW challenge containers.
"""

from __future__ import annotations

import subprocess
import time
import uuid

import pytest

from solkyn.tools.container import ContainerManager

NETWORK = "solkyn-cross-test"


@pytest.fixture(autouse=True)
def _check_docker():
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "solkyn/kali:latest"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            pytest.skip("Image solkyn/kali:latest not built")
    except FileNotFoundError:
        pytest.skip("Docker not installed")


@pytest.fixture
def manager():
    return ContainerManager()


@pytest.mark.integration
def test_cross_network_http(manager):
    """Start an HTTP server container, curl it from Kali container."""
    server_name = f"http-server-{uuid.uuid4().hex[:8]}"
    kali_name = f"kali-client-{uuid.uuid4().hex[:8]}"

    manager.ensure_network(NETWORK)
    try:
        # Start a simple Python HTTP server container
        subprocess.run(
            [
                "docker", "run", "-d",
                "--name", server_name,
                "--network", NETWORK,
                "python:3.12-slim",
                "python3", "-m", "http.server", "80",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # Start Kali container on same network
        kali_name = manager.create(kali_name.replace("solkyn-", ""), network=NETWORK)

        # Give the HTTP server a moment to start
        time.sleep(1)

        # Curl the HTTP server from Kali container
        result = subprocess.run(
            ["docker", "exec", kali_name, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"http://{server_name}:80/"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.stdout.strip() == "200", f"Expected 200, got {result.stdout.strip()}. stderr: {result.stderr}"

    finally:
        # Cleanup
        subprocess.run(["docker", "rm", "-f", server_name], capture_output=True)
        manager.destroy(kali_name)
        subprocess.run(["docker", "network", "rm", NETWORK], capture_output=True)
