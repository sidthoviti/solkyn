"""Unit tests for safety checker and tool registry."""

from __future__ import annotations

import pytest

from solkyn.tools.registry import ToolRegistry, create_default_tools
from solkyn.tools.safety import SafetyChecker


class TestSafetyChecker:
    def setup_method(self):
        self.checker = SafetyChecker()

    def test_normal_commands_allowed(self):
        safe_commands = [
            "nmap -sV -p 80 target.local",
            "curl http://target.local:8080/login",
            "sqlmap -u 'http://target.local/page?id=1'",
            "cat /etc/hosts",
            "ls -la /workspace/",
            "python3 exploit.py",
            "echo hello",
            "whoami",
            "ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.local/FUZZ",
        ]
        for cmd in safe_commands:
            is_safe, reason = self.checker.check_command(cmd)
            assert is_safe, f"Command should be safe: {cmd!r} — blocked: {reason}"

    def test_rm_workspace_allowed(self):
        is_safe, _ = self.checker.check_command("rm -rf /workspace/tmp")
        assert is_safe

    def test_fork_bomb_blocked(self):
        is_safe, reason = self.checker.check_command(":(){ :|:& };:")
        assert not is_safe
        assert "fork bomb" in reason

    def test_mkfs_blocked(self):
        is_safe, reason = self.checker.check_command("mkfs.ext4 /dev/sda1")
        assert not is_safe
        assert "disk formatting" in reason

    def test_shutdown_blocked(self):
        for cmd in ["shutdown -h now", "reboot", "poweroff", "halt"]:
            is_safe, reason = self.checker.check_command(cmd)
            assert not is_safe, f"Should be blocked: {cmd}"

    def test_rm_rf_root_blocked(self):
        is_safe, reason = self.checker.check_command("rm -rf /")
        assert not is_safe
        assert "root filesystem" in reason

    def test_docker_commands_blocked(self):
        for cmd in ["docker ps", "docker exec other bash", "docker run -it kali"]:
            is_safe, reason = self.checker.check_command(cmd)
            assert not is_safe, f"Docker command should be blocked: {cmd}"
            assert "container escape" in reason

    def test_etc_passwd_overwrite_blocked(self):
        is_safe, reason = self.checker.check_command("echo 'root::0:0::/root:/bin/bash' > /etc/passwd")
        assert not is_safe


class TestToolRegistry:
    def test_register_and_get_schemas(self):
        registry = ToolRegistry()
        registry.register(
            name="test_tool",
            description="A test tool",
            parameters={
                "type": "object",
                "properties": {"arg1": {"type": "string"}},
                "required": ["arg1"],
            },
            handler=lambda arg1: f"result: {arg1}",
        )
        schemas = registry.get_schemas()
        assert len(schemas) == 1
        assert schemas[0]["type"] == "function"
        assert schemas[0]["function"]["name"] == "test_tool"
        assert schemas[0]["function"]["description"] == "A test tool"
        assert "arg1" in schemas[0]["function"]["parameters"]["properties"]

    def test_execute_tool(self):
        registry = ToolRegistry()
        registry.register(
            name="echo",
            description="echo",
            parameters={"type": "object", "properties": {"msg": {"type": "string"}}, "required": ["msg"]},
            handler=lambda msg: f"echo: {msg}",
        )
        result = registry.execute_tool("echo", {"msg": "hello"})
        assert result == "echo: hello"

    def test_execute_unknown_tool_raises(self):
        registry = ToolRegistry()
        with pytest.raises(KeyError, match="Unknown tool"):
            registry.execute_tool("nonexistent", {})

    def test_schema_format_matches_openai(self):
        registry = ToolRegistry()
        registry.register(
            name="my_tool",
            description="Does stuff",
            parameters={"type": "object", "properties": {}, "required": []},
            handler=lambda: "ok",
        )
        schema = registry.get_schemas()[0]
        # Validate OpenAI function-calling format
        assert schema["type"] == "function"
        func = schema["function"]
        assert "name" in func
        assert "description" in func
        assert "parameters" in func
        assert func["parameters"]["type"] == "object"


class TestCreateDefaultTools:
    def test_creates_three_tools(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "mock", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        schemas = registry.get_schemas()
        assert len(schemas) == 3
        names = {s["function"]["name"] for s in schemas}
        assert names == {"bash_exec", "file_read", "file_write"}

    def test_bash_exec_returns_stdout(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "hello world\n", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        result = registry.execute_tool("bash_exec", {"command": "echo hello world"})
        assert "hello world" in result

    def test_file_read_returns_content(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "file content here", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        result = registry.execute_tool("file_read", {"path": "/tmp/test.txt"})
        assert result == "file content here"

    def test_bash_exec_includes_stderr(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "", "stderr": "error msg", "exit_code": 1, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        result = registry.execute_tool("bash_exec", {"command": "bad_cmd"})
        assert "STDERR: error msg" in result

    def test_bash_exec_blocks_heredoc(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        result = registry.execute_tool(
            "bash_exec",
            {"command": "cat > /tmp/exploit.py << 'EOF'\nimport requests\nEOF"},
        )
        assert "ERROR" in result
        assert "file_write" in result

    def test_bash_exec_blocks_heredoc_variant(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        result = registry.execute_tool(
            "bash_exec",
            {"command": "cat <<EOF > /tmp/test.sh\n#!/bin/bash\nEOF"},
        )
        assert "ERROR" in result
        assert "file_write" in result

    def test_bash_exec_blocks_file_write_in_bash(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        result = registry.execute_tool(
            "bash_exec",
            {"command": "file_write{path: /tmp/test.py, content: print('hi')}"},
        )
        assert "ERROR" in result
        assert "file_write" in result

    def test_bash_exec_allows_normal_commands(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "ok", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        # These should NOT be blocked
        for cmd in [
            "curl http://target.local",
            "cat /tmp/exploit.py",
            "python3 /tmp/exploit.py",
            "sqlmap -u 'http://target.local?id=1'",
            "ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target/FUZZ",
        ]:
            result = registry.execute_tool("bash_exec", {"command": cmd})
            assert "ERROR" not in result, f"Command should not be blocked: {cmd}"

    def test_bash_exec_description_lists_kali_tools(self):
        class MockExecutor:
            def execute(self, command):
                return {"stdout": "", "stderr": "", "exit_code": 0, "timed_out": False}

        registry = create_default_tools(MockExecutor())
        schemas = registry.get_schemas()
        bash_schema = next(s for s in schemas if s["function"]["name"] == "bash_exec")
        desc = bash_schema["function"]["description"]
        assert "ffuf" in desc
        assert "nuclei" in desc
        assert "sqlmap" in desc
        assert "searchsploit" in desc
        assert "file_write" in desc  # warns against heredocs
