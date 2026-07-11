"""Verify file_write base64 encoding preserves special characters."""

import base64
import re

from solkyn.tools.registry import create_default_tools


class TestFileWriteEscaping:
    """Test that file_write generates correct base64 commands."""

    def _capture_command(self, content: str) -> str:
        """Execute file_write and capture the generated command."""
        captured = {}

        class MockExecutor:
            def execute(self, command):
                captured["command"] = command
                return {"stdout": "", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        registry.execute_tool("file_write", {"path": "/tmp/test.txt", "content": content})
        return captured["command"]

    def _decode_from_command(self, command: str) -> str:
        """Extract base64 payload from command and decode it."""
        # Command format: printf '%s' BASE64_DATA | base64 -d > /tmp/test.txt
        match = re.search(r"printf '%s' (\S+) \| base64 -d", command)
        assert match, f"Could not find base64 data in: {command}"
        return base64.b64decode(match.group(1)).decode()

    def test_single_quotes_preserved(self):
        content = "url = 'http://target.local'\n"
        cmd = self._capture_command(content)
        assert self._decode_from_command(cmd) == content

    def test_double_quotes_preserved(self):
        content = 'payload = "<script>alert(1)</script>"\n'
        cmd = self._capture_command(content)
        assert self._decode_from_command(cmd) == content

    def test_backslashes_preserved(self):
        content = "path = 'C:\\\\Users\\\\test'\n"
        cmd = self._capture_command(content)
        assert self._decode_from_command(cmd) == content

    def test_mixed_quotes_xss_payload(self):
        content = (
            "import requests\n"
            "url = 'http://target/page'\n"
            'payload = "<img src=x onerror=alert(\'XSS\')>"\n'
            "r = requests.post(url, data={'solution': payload})\n"
        )
        cmd = self._capture_command(content)
        assert self._decode_from_command(cmd) == content

    def test_special_shell_chars(self):
        content = "echo $HOME && rm -rf /; `whoami` | $(id)\n"
        cmd = self._capture_command(content)
        assert self._decode_from_command(cmd) == content

    def test_heredoc_delimiter_in_content(self):
        content = "SOLKYN_EOF\nstill writing\nSOLKYN_EOF\n"
        cmd = self._capture_command(content)
        assert self._decode_from_command(cmd) == content
