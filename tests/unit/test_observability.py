"""Unit tests for observability: EventLogger and RunDisplay."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from solkyn.observability.events import EventLogger


class TestEventLogger:
    def test_scan_start_event(self):
        logger = EventLogger()
        logger.scan_start(
            challenge_id="XBEN-001-24",
            target_url="http://target:8080",
            description="Test challenge",
            tags=["sqli"],
            level="1",
            model="gpt-5.4",
            max_iterations=25,
        )
        assert len(logger.events) == 1
        assert logger.events[0]["type"] == "scan_start"
        assert logger.events[0]["challenge_id"] == "XBEN-001-24"
        assert logger.events[0]["model"] == "gpt-5.4"
        assert logger.events[0]["mode"] == "whitebox"

    def test_tool_call_event(self):
        logger = EventLogger()
        logger.tool_call(
            iteration=1,
            tool_name="bash_exec",
            command="curl http://target",
            result_length=500,
            duration=0.3,
            result_preview="<html>...",
        )
        assert len(logger.events) == 1
        assert logger.events[0]["type"] == "tool_call"
        assert logger.events[0]["tool"] == "bash_exec"
        assert logger.events[0]["result_length"] == 500

    def test_flag_detected_event(self):
        logger = EventLogger()
        logger.flag_detected(iteration=5, flag="FLAG{abc123}", source="tool_output")
        assert logger.events[0]["type"] == "flag_detected"
        assert logger.events[0]["flag"] == "FLAG{abc123}"

    def test_loop_detected_event(self):
        logger = EventLogger()
        logger.loop_detected(iteration=10, nudge_number=2)
        assert logger.events[0]["type"] == "loop_detected"
        assert logger.events[0]["nudge_number"] == 2

    def test_scan_end_event(self):
        logger = EventLogger()
        logger.scan_end(
            success=True,
            iterations=5,
            flag="FLAG{abc123}",
            total_time=60.0,
            input_tokens=5000,
            output_tokens=1000,
            tool_calls=10,
        )
        assert logger.events[0]["type"] == "scan_end"
        assert logger.events[0]["success"] is True
        assert logger.events[0]["iterations"] == 5

    def test_events_written_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = EventLogger(scan_dir=tmpdir)
            logger.scan_start(
                challenge_id="XBEN-001-24",
                target_url="http://target",
                description="Test",
                tags=["sqli"],
                level="1",
                model="test",
                max_iterations=10,
            )
            logger.tool_call(
                iteration=1,
                tool_name="bash_exec",
                command="curl http://target",
                result_length=100,
                duration=0.1,
            )
            logger.scan_end(
                success=False,
                iterations=1,
                flag=None,
                total_time=10.0,
                input_tokens=100,
                output_tokens=50,
                tool_calls=1,
            )

            log_file = Path(tmpdir) / "logs" / "events.jsonl"
            assert log_file.exists()
            lines = log_file.read_text().strip().split("\n")
            assert len(lines) == 3

            # Verify each line is valid JSON
            for line in lines:
                event = json.loads(line)
                assert "timestamp" in event
                assert "elapsed" in event
                assert "type" in event

            # Verify event types
            events = [json.loads(line) for line in lines]
            assert events[0]["type"] == "scan_start"
            assert events[1]["type"] == "tool_call"
            assert events[2]["type"] == "scan_end"

    def test_multiple_events_have_increasing_elapsed(self):
        logger = EventLogger()
        logger.iteration_start(1, 25)
        logger.iteration_start(2, 25)
        assert logger.events[1]["elapsed"] >= logger.events[0]["elapsed"]

    def test_llm_call_event(self):
        logger = EventLogger()
        logger.llm_call(
            iteration=1,
            input_tokens=1000,
            output_tokens=200,
            duration=2.5,
            has_tool_calls=True,
            reasoning="Let me explore the target...",
        )
        assert logger.events[0]["type"] == "llm_call"
        assert logger.events[0]["has_tool_calls"] is True
        assert "Let me explore" in logger.events[0]["reasoning_preview"]


class TestRunDisplay:
    """Test that RunDisplay methods don't crash (output goes to console)."""

    def test_run_header(self):
        from solkyn.observability.display import RunDisplay
        d = RunDisplay(total_challenges=5, model="test-model")
        d.run_header(model="test-model", total=5)

    def test_challenge_lifecycle(self):
        from solkyn.observability.display import RunDisplay
        d = RunDisplay(total_challenges=1, model="test")
        d.challenge_start(
            idx=1, challenge_id="XBEN-001-24", name="Test",
            level="1", tags=["sqli"], target_url="http://target",
        )
        d.iteration_start(1, 25)
        d.thinking()
        d.reasoning("Let me explore the target application...")
        d.tool_call("bash_exec", command="curl http://target")
        d.tool_result(500, 0.3, preview="<html>...")
        d.flag_found("FLAG{abc123}", 1)
        d.loop_detected(1)
        d.challenge_end(
            success=True, iterations=1, total_time=10.0,
            tool_calls=1, input_tokens=100, output_tokens=50,
        )

    def test_run_summary(self):
        from solkyn.observability.display import RunDisplay
        d = RunDisplay(total_challenges=2, model="test")
        d.run_summary([
            {"challenge_id": "XBEN-001", "level": "1", "tags": ["sqli"],
             "success": True, "iterations": 3, "time": 30, "tool_calls": 5},
            {"challenge_id": "XBEN-002", "level": "1", "tags": ["xss"],
             "success": False, "iterations": 25, "time": 120, "tool_calls": 30},
        ])
