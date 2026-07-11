"""Integration tests for the Kali Docker image.

Requires: Docker running and solkyn/kali:latest image built.
Build with: docker build -t solkyn/kali:latest -f docker/Dockerfile.kali docker/
"""

import subprocess

import pytest

IMAGE = "solkyn/kali:latest"

REQUIRED_TOOLS = [
    "nmap",
    "sqlmap",
    "ffuf",
    "gobuster",
    "dirb",
    "nikto",
    "nuclei",
    "whatweb",
    "wafw00f",
    "wpscan",
    "curl",
    "wget",
    "jq",
    "python3",
    "socat",
    "whois",
]


def _docker_run(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "run", "--rm", IMAGE, "bash", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.fixture(autouse=True)
def _check_docker():
    """Skip all tests if Docker is not available or image not built."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            pytest.skip(f"Image {IMAGE} not built")
    except FileNotFoundError:
        pytest.skip("Docker not installed")


@pytest.mark.integration
class TestKaliImage:
    def test_nmap_available(self):
        result = _docker_run("which nmap")
        assert result.returncode == 0
        assert "nmap" in result.stdout

    def test_required_tools_available(self):
        check_cmd = "; ".join(f'which {t} && echo "OK:{t}" || echo "MISSING:{t}"' for t in REQUIRED_TOOLS)
        result = _docker_run(check_cmd)
        missing = [line.split(":")[1] for line in result.stdout.strip().split("\n") if line.startswith("MISSING:")]
        assert not missing, f"Missing tools: {missing}"

    def test_at_least_10_tools(self):
        check_cmd = "; ".join(f"which {t} && echo OK" for t in REQUIRED_TOOLS)
        result = _docker_run(check_cmd)
        found = result.stdout.count("OK")
        assert found >= 10, f"Only {found} tools found, expected >= 10"

    def test_runs_as_non_root(self):
        result = _docker_run("whoami")
        assert result.stdout.strip() == "solkyn"

    def test_sudo_works(self):
        result = _docker_run("sudo id -u")
        assert result.stdout.strip() == "0"

    def test_python_packages(self):
        result = _docker_run("python3 -c 'import requests; import bs4; import lxml; import pwn; print(\"OK\")'")
        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_workspace_directory(self):
        result = _docker_run("pwd")
        assert result.stdout.strip() == "/workspace"
