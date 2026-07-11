"""Unit tests for solver agent, flag detector, result, and state."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.result import AgentResult
from solkyn.agents.solver import SolverAgent
from solkyn.agents.state import ScanState
from solkyn.config.schema import AgentConfig
from solkyn.tools.registry import ToolRegistry

# --- FlagDetector tests ---

class TestFlagDetector:
    def setup_method(self):
        self.detector = FlagDetector()

    def test_detect_in_plain_text(self):
        flags = self.detector.scan("The flag is FLAG{abcdef0123456789}")
        assert flags == ["FLAG{abcdef0123456789}"]

    def test_detect_in_html(self):
        html = '<div class="flag">FLAG{deadbeef}</div>'
        flags = self.detector.scan(html)
        assert flags == ["FLAG{deadbeef}"]

    def test_detect_in_json(self):
        text = '{"result": "FLAG{aabbccdd}", "status": "ok"}'
        flags = self.detector.scan(text)
        assert flags == ["FLAG{aabbccdd}"]

    def test_detect_in_multiline(self):
        text = "line1\nline2\nFLAG{1234abcd}\nline4"
        flags = self.detector.scan(text)
        assert flags == ["FLAG{1234abcd}"]

    def test_detect_lowercase(self):
        flags = self.detector.scan("flag{abcd1234}")
        assert flags == ["flag{abcd1234}"]

    def test_no_false_positive(self):
        flags = self.detector.scan("the flag is unknown")
        assert flags == []

    def test_no_false_positive_braces(self):
        # Phase 7 P0 fix: the detector now ACCEPTS arbitrary printable text
        # inside flag{...} because real XBOW flags use UUIDs / phrases that
        # contain hyphens, apostrophes, etc. The old hex-only pattern
        # rejected every real XBOW flag.
        flags = self.detector.scan("FLAG{not-hex-chars!}")
        assert flags == ["FLAG{not-hex-chars!}"]

    def test_multiple_flags(self):
        text = "first FLAG{aaa111aa} and second FLAG{bbb222bb}"
        flags = self.detector.scan(text)
        assert len(flags) == 2
        assert "FLAG{aaa111aa}" in flags
        assert "FLAG{bbb222bb}" in flags

    def test_deduplication(self):
        text = "FLAG{abcd1234} repeated FLAG{abcd1234}"
        flags = self.detector.scan(text)
        assert flags == ["FLAG{abcd1234}"]

    def test_custom_patterns(self):
        detector = FlagDetector(patterns=[r"HTB\{.*?\}"])
        flags = detector.scan("The flag is HTB{some_flag_here}")
        assert flags == ["HTB{some_flag_here}"]

    def test_stderr_content(self):
        stderr = "Error: FLAG{cafe0001} leaked in error output"
        flags = self.detector.scan(stderr)
        assert flags == ["FLAG{cafe0001}"]


# --- ScanState tests ---

class TestScanState:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = ScanState(
                scan_id="test-001",
                target_url="http://localhost:8080",
                description="Test target",
                iterations=5,
                flags=["FLAG{abc}"],
            )
            state.save(tmpdir)

            loaded = ScanState.load(tmpdir)
            assert loaded.scan_id == "test-001"
            assert loaded.target_url == "http://localhost:8080"
            assert loaded.iterations == 5
            assert loaded.flags == ["FLAG{abc}"]

    def test_partial_state_loads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = ScanState(
                scan_id="partial",
                target_url="http://target.local",
                description="Partial scan",
                phase="executing",
                iterations=3,
            )
            state.save(tmpdir)

            loaded = ScanState.load(tmpdir)
            assert loaded.phase == "executing"
            assert loaded.iterations == 3
            assert loaded.flags == []

    def test_append_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = ScanState(
                scan_id="log-test",
                target_url="http://target.local",
                description="Test",
            )
            state.append_log(tmpdir, {"role": "user", "content": "hello"})
            state.append_log(tmpdir, {"role": "assistant", "content": "hi"})

            log_file = Path(tmpdir) / "logs" / "solver.jsonl"
            assert log_file.exists()
            lines = log_file.read_text().strip().split("\n")
            assert len(lines) == 2
            assert json.loads(lines[0])["role"] == "user"
            assert json.loads(lines[1])["role"] == "assistant"


# --- AgentResult tests ---

class TestAgentResult:
    def test_defaults(self):
        result = AgentResult(success=False)
        assert result.flag is None
        assert result.iterations == 0
        assert result.messages == []
        assert result.error is None

    def test_with_flag(self):
        result = AgentResult(success=True, flag="FLAG{abc}", iterations=5)
        assert result.success
        assert result.flag == "FLAG{abc}"


# --- SolverAgent tests ---

def _make_mock_llm(responses: list[dict]) -> MagicMock:
    """Create a mock LLMManager that returns predefined responses."""
    mock = MagicMock()
    mock.chat = MagicMock(side_effect=responses)
    mock.get_usage.return_value = {"input_tokens": 100, "output_tokens": 50}
    return mock


def _make_mock_registry(tool_results: dict[str, str]) -> ToolRegistry:
    """Create a ToolRegistry with mock tools that return predefined results."""
    registry = ToolRegistry()
    for name, result in tool_results.items():
        registry.register(
            name=name,
            description=f"Mock {name}",
            parameters={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
            handler=lambda command, _r=result: _r,
        )
    return registry


class TestSolverAgent:
    def test_agent_finds_flag(self):
        """Agent gets tool calls, executes them, finds flag in output."""
        responses = [
            # Iteration 1: LLM wants to run curl
            {
                "content": "Let me explore the target.",
                "tool_calls": [{"id": "tc1", "name": "bash_exec", "arguments": {"command": "curl http://target"}}],
                "usage": {"input_tokens": 50, "output_tokens": 20},
            },
            # Iteration 2: LLM wants to run sqlmap
            {
                "content": "Found a form, trying SQLi.",
                "tool_calls": [{"id": "tc2", "name": "bash_exec", "arguments": {"command": "sqlmap -u target"}}],
                "usage": {"input_tokens": 80, "output_tokens": 30},
            },
        ]
        mock_llm = _make_mock_llm(responses)

        # Second tool call returns the flag
        call_count = [0]
        def mock_handler(command):
            call_count[0] += 1
            if call_count[0] == 1:
                return "<html><form action='/login'></form></html>"
            return "Database: app\nFLAG{deadbeef1234}"

        registry = ToolRegistry()
        registry.register(
            name="bash_exec",
            description="Execute bash",
            parameters={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
            handler=mock_handler,
        )

        agent = SolverAgent(
            llm_manager=mock_llm,
            tool_registry=registry,
            config=AgentConfig(max_iterations=10),
        )

        result = agent.run("http://target", "Test challenge")

        assert result.success
        assert result.flag == "FLAG{deadbeef1234}"
        assert result.iterations == 2
        assert len(result.tool_calls_log) == 2
        assert result.tool_calls_log[0]["tool"] == "bash_exec"

    def test_agent_max_iterations(self):
        """Agent stops at max iterations without finding flag."""
        # LLM always returns a tool call, never a flag
        def infinite_responses(*args, **kwargs):
            return {
                "content": "Trying again...",
                "tool_calls": [{"id": "tc", "name": "bash_exec", "arguments": {"command": "nmap target"}}],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }

        mock_llm = MagicMock()
        mock_llm.chat = MagicMock(side_effect=infinite_responses)
        mock_llm.get_usage.return_value = {"input_tokens": 30, "output_tokens": 15}

        registry = ToolRegistry()
        registry.register(
            name="bash_exec",
            description="Execute bash",
            parameters={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
            handler=lambda command: "No flag here",
        )

        agent = SolverAgent(
            llm_manager=mock_llm,
            tool_registry=registry,
            config=AgentConfig(max_iterations=3),
        )

        result = agent.run("http://target", "Test")

        assert not result.success
        assert result.flag is None
        assert result.iterations == 3

    def test_agent_no_tool_calls_stops(self):
        """Agent nudges up to 3x when LLM returns no tool calls without a flag, then stops."""
        # Agent will be nudged 3 times before giving up → 4 total LLM calls
        no_tool_resp = {
            "content": "I've analyzed the target and found nothing exploitable.",
            "tool_calls": None,
            "usage": {"input_tokens": 50, "output_tokens": 30},
        }
        responses = [no_tool_resp] * 4
        mock_llm = _make_mock_llm(responses)

        registry = ToolRegistry()
        agent = SolverAgent(
            llm_manager=mock_llm,
            tool_registry=registry,
            config=AgentConfig(max_iterations=10),
        )

        result = agent.run("http://target", "Test")

        assert not result.success
        # 1 initial + 3 nudges = 4 iterations
        assert result.iterations == 4

    def test_agent_flag_in_llm_response(self):
        """Agent detects flag in LLM text content (not tool output)."""
        responses = [
            {
                "content": "I found the flag: FLAG{abcd1234}",
                "tool_calls": None,
                "usage": {"input_tokens": 50, "output_tokens": 20},
            },
        ]
        mock_llm = _make_mock_llm(responses)

        registry = ToolRegistry()
        agent = SolverAgent(
            llm_manager=mock_llm,
            tool_registry=registry,
        )

        result = agent.run("http://target", "Test")

        assert result.success
        assert result.flag == "FLAG{abcd1234}"

    def test_agent_tool_error_doesnt_crash(self):
        """Tool execution error is passed to LLM as error message."""
        no_tool_resp = {
            "content": "That failed, giving up.",
            "tool_calls": None,
            "usage": {"input_tokens": 20, "output_tokens": 10},
        }
        responses = [
            {
                "content": "Let me try.",
                "tool_calls": [{"id": "tc1", "name": "bash_exec", "arguments": {"command": "bad"}}],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            # Iter 2 returns no tool calls → nudged 3 times → iter 5 stops
            no_tool_resp,
            no_tool_resp,
            no_tool_resp,
            no_tool_resp,
        ]
        mock_llm = _make_mock_llm(responses)

        registry = ToolRegistry()
        registry.register(
            name="bash_exec",
            description="Execute bash",
            parameters={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
            handler=lambda command: (_ for _ in ()).throw(RuntimeError("Connection refused")),
        )

        agent = SolverAgent(
            llm_manager=mock_llm,
            tool_registry=registry,
        )

        result = agent.run("http://target", "Test")

        # Should not crash — error message is returned to LLM
        assert not result.success
        assert result.iterations == 5
        assert "ERROR" in result.messages[2]["content"] or any(
            "ERROR" in str(m.get("content", "")) for m in result.messages
        )

    def test_agent_with_state_persistence(self):
        """Agent persists state and logs when scan_dir is provided."""
        no_tool_resp = {
            "content": "Done, no flag.",
            "tool_calls": None,
            "usage": {"input_tokens": 20, "output_tokens": 10},
        }
        responses = [
            {
                "content": "Exploring...",
                "tool_calls": [{"id": "tc1", "name": "bash_exec", "arguments": {"command": "curl target"}}],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            # Iter 2+ returns no tool calls → solver-internal nudge fires 3
            # times, then orchestrator  stuck-handling injects 1 more
            # try-harder, then final termination → need 6 no_tool responses.
            no_tool_resp,
            no_tool_resp,
            no_tool_resp,
            no_tool_resp,
            no_tool_resp,
        ]
        mock_llm = _make_mock_llm(responses)

        registry = ToolRegistry()
        registry.register(
            name="bash_exec",
            description="Execute bash",
            parameters={"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
            handler=lambda command: "200 OK",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = SolverAgent(
                llm_manager=mock_llm,
                tool_registry=registry,
            )
            result = agent.run("http://target", "Test", scan_dir=tmpdir)
            assert result.iterations >= 1

            # State file should exist
            state_file = Path(tmpdir) / "state.json"
            assert state_file.exists()
            state = json.loads(state_file.read_text())
            assert state["phase"] == "complete"

            # Log file should exist
            log_file = Path(tmpdir) / "logs" / "solver.jsonl"
            assert log_file.exists()
            lines = log_file.read_text().strip().split("\n")
            assert len(lines) >= 2  # at least assistant + tool result


class TestNormalizeCommandSig:
    """Test the command signature normalization for loop detection."""

    def test_curl_basic(self):
        sig = SolverAgent._normalize_command_sig("bash_exec", {"command": "curl http://target"})
        assert sig == "bash_exec:curl"

    def test_curl_post(self):
        sig = SolverAgent._normalize_command_sig("bash_exec", {"command": "curl -X POST http://target"})
        assert sig == "bash_exec:curl_post"

    def test_python(self):
        sig = SolverAgent._normalize_command_sig("bash_exec", {"command": "python3 /tmp/exploit.py"})
        assert sig == "bash_exec:python"

    def test_nmap(self):
        sig = SolverAgent._normalize_command_sig("bash_exec", {"command": "nmap -sV target"})
        assert sig == "bash_exec:nmap"

    def test_file_write_tool(self):
        sig = SolverAgent._normalize_command_sig("file_write", {"path": "/tmp/test.py", "content": "print(1)"})
        assert sig.startswith("file_write:")

    def test_empty_command(self):
        sig = SolverAgent._normalize_command_sig("bash_exec", {"command": ""})
        assert sig == "bash_exec:empty"
