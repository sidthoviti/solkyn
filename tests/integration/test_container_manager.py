"""Integration tests for ContainerManager.

Requires: Docker running and solkyn/kali:latest image built.
"""

from __future__ import annotations

import subprocess
import uuid

import pytest

from solkyn.tools.container import ContainerManager

SCAN_ID = f"test-{uuid.uuid4().hex[:8]}"
NETWORK = "solkyn-test-net"


@pytest.fixture(autouse=True)
def _check_docker():
    """Skip if Docker is not available."""
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


@pytest.fixture
def container(manager):
    """Create a container, yield its name, then destroy it."""
    name = manager.create(SCAN_ID, network=NETWORK)
    yield name
    manager.destroy(name)


@pytest.fixture(autouse=True)
def _cleanup_network():
    """Clean up test network after all tests."""
    yield
    subprocess.run(["docker", "network", "rm", NETWORK], capture_output=True)


@pytest.mark.integration
class TestContainerLifecycle:
    def test_create_and_healthy(self, manager, container):
        assert manager.is_healthy(container)

    def test_list_tools(self, manager, container):
        tools = manager.list_tools(container)
        assert len(tools) >= 10
        assert "nmap" in tools
        assert "sqlmap" in tools
        assert "curl" in tools

    def test_destroy(self, manager):
        name = manager.create(f"destroy-{uuid.uuid4().hex[:8]}", network=NETWORK)
        manager.destroy(name)
        assert not manager.is_healthy(name)

    def test_exec_in_container(self, container):
        result = subprocess.run(
            ["docker", "exec", container, "echo", "hello"],
            capture_output=True,
            text=True,
        )
        assert result.stdout.strip() == "hello"

    def test_two_containers_can_ping(self, manager):
        id1 = f"ping1-{uuid.uuid4().hex[:8]}"
        id2 = f"ping2-{uuid.uuid4().hex[:8]}"
        c1 = manager.create(id1, network=NETWORK)
        c2 = manager.create(id2, network=NETWORK)
        try:
            result = subprocess.run(
                ["docker", "exec", c1, "ping", "-c", "1", "-W", "3", c2],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, f"Ping failed: {result.stderr}"
        finally:
            manager.destroy(c1)
            manager.destroy(c2)
