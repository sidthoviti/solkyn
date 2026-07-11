"""Integration tests for DockerExecutor.

Requires: Docker running and solkyn/kali:latest image built.
"""

from __future__ import annotations

import subprocess
import uuid

import pytest

from solkyn.tools.container import ContainerManager
from solkyn.tools.executor import DockerExecutor

SCAN_ID = f"executor-test-{uuid.uuid4().hex[:8]}"


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


@pytest.fixture(scope="module")
def container_name():
    """Create a container for the test module, destroy after."""
    mgr = ContainerManager()
    name = mgr.create(SCAN_ID)
    yield name
    mgr.destroy(name)


@pytest.mark.integration
class TestDockerExecutor:
    def test_echo(self, container_name):
        executor = DockerExecutor(container_name)
        result = executor.execute('echo "hello world"')
        assert result["exit_code"] == 0
        assert "hello world" in result["stdout"]
        assert not result["timed_out"]

    def test_tool_exists(self, container_name):
        executor = DockerExecutor(container_name)
        result = executor.execute("ls /usr/bin/nmap")
        assert result["exit_code"] == 0

    def test_nonexistent_file(self, container_name):
        executor = DockerExecutor(container_name)
        result = executor.execute("cat /nonexistent_file_xyz")
        assert result["exit_code"] != 0
        assert result["stderr"]

    def test_timeout_handling(self, container_name):
        executor = DockerExecutor(container_name, timeout=2)
        result = executor.execute("sleep 300")
        assert result["timed_out"]
        assert "TIMED OUT" in result["stderr"]
        assert result["exit_code"] == -1

    def test_blocked_command(self, container_name):
        executor = DockerExecutor(container_name)
        result = executor.execute("docker ps")
        assert result["exit_code"] == -1
        assert "BLOCKED" in result["stderr"]

    def test_ansi_codes_stripped(self, container_name):
        executor = DockerExecutor(container_name)
        # Generate ANSI output
        result = executor.execute("echo -e '\\033[31mred\\033[0m'")
        assert result["exit_code"] == 0
        assert "\\033" not in result["stdout"]
        assert "\x1b" not in result["stdout"]

    def test_whoami(self, container_name):
        executor = DockerExecutor(container_name)
        result = executor.execute("whoami")
        assert result["exit_code"] == 0
        assert result["stdout"].strip() == "solkyn"


@pytest.mark.integration
class TestDockerExecutorWithRegistry:
    def test_bash_exec_tool(self, container_name):
        from solkyn.tools.registry import create_default_tools

        executor = DockerExecutor(container_name)
        registry = create_default_tools(executor)
        result = registry.execute_tool("bash_exec", {"command": "whoami"})
        assert "solkyn" in result

    def test_file_write_and_read(self, container_name):
        from solkyn.tools.registry import create_default_tools

        executor = DockerExecutor(container_name)
        registry = create_default_tools(executor)

        # Write a file
        write_result = registry.execute_tool(
            "file_write", {"path": "/tmp/test_tool.txt", "content": "hello from tool"}
        )
        assert "Written" in write_result

        # Read it back
        read_result = registry.execute_tool("file_read", {"path": "/tmp/test_tool.txt"})
        assert "hello from tool" in read_result
