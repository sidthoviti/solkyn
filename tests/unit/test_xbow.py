"""Unit tests for XBOWPlatform and BenchmarkRunner."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from solkyn.platforms.runner import BenchmarkResult, BenchmarkRunner, BenchmarkSummary
from solkyn.platforms.xbow import ChallengeInfo, XBOWPlatform


@pytest.fixture
def sample_challenge_dir(tmp_path):
    """Create a minimal challenge directory for testing."""
    challenge_dir = tmp_path / "XBEN-TEST-24"
    challenge_dir.mkdir()

    (challenge_dir / "benchmark.json").write_text(json.dumps({
        "name": "XBEN-TEST-24 Test Challenge",
        "description": "A test challenge",
        "level": "1",
        "win_condition": "flag",
        "tags": ["sqli", "test"],
    }))

    (challenge_dir / "benchmark.yaml").write_text(
        "name: XBEN-TEST-24 Test Challenge\n"
        "level: 1\n"
        "tags:\n- sqli\n- test\n"
    )

    (challenge_dir / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    build: ./app\n"
        "    ports:\n"
        "      - 80\n"
    )

    app_dir = challenge_dir / "app"
    app_dir.mkdir()
    (app_dir / "Dockerfile").write_text("FROM python:3.12\n")

    return tmp_path


class TestXBOWPlatform:
    def test_load_challenge(self, sample_challenge_dir):
        platform = XBOWPlatform(sample_challenge_dir)
        info = platform.load_challenge("XBEN-TEST-24")
        assert info.id == "XBEN-TEST-24"
        assert info.name == "XBEN-TEST-24 Test Challenge"
        assert info.level == "1"
        assert "sqli" in info.tags
        assert info.win_condition == "flag"

    def test_load_challenge_not_found(self, sample_challenge_dir):
        platform = XBOWPlatform(sample_challenge_dir)
        with pytest.raises(FileNotFoundError):
            platform.load_challenge("XBEN-NONEXISTENT-24")

    def test_list_challenges(self, sample_challenge_dir):
        platform = XBOWPlatform(sample_challenge_dir)
        ids = platform.list_challenges()
        assert "XBEN-TEST-24" in ids

    def test_verify_flag_found(self):
        platform = XBOWPlatform()
        assert platform.verify_flag("The flag is FLAG{abc123}", "FLAG{abc123}")

    def test_verify_flag_not_found(self):
        platform = XBOWPlatform()
        assert not platform.verify_flag("No flag here", "FLAG{abc123}")

    def test_get_main_service(self, sample_challenge_dir):
        platform = XBOWPlatform(sample_challenge_dir)
        info = platform.load_challenge("XBEN-TEST-24")
        service = platform._get_main_service(info)
        assert service == "app"

    def test_load_real_challenges(self):
        """Test loading from the actual XBOW repo if available."""
        real_dir = Path("benchmarks/xbow/benchmarks")
        if not real_dir.exists():
            pytest.skip("XBOW benchmarks not cloned")

        platform = XBOWPlatform(real_dir)
        ids = platform.list_challenges()
        assert len(ids) == 104

        # Load a specific challenge
        info = platform.load_challenge("XBEN-038-24")
        assert info.name == "XBEN-038-24 Simple GraphQL"
        assert "sqli" in info.tags
        assert info.level == "1"


class TestBenchmarkRunner:
    def test_run_single_success(self, sample_challenge_dir):
        """Mock solver that returns the expected flag."""
        platform = MagicMock(spec=XBOWPlatform)
        platform.load_challenge.return_value = ChallengeInfo(
            id="XBEN-TEST-24",
            name="Test",
            description="A test",
            level="1",
            tags=["sqli"],
            win_condition="flag",
            challenge_dir=sample_challenge_dir / "XBEN-TEST-24",
        )
        platform.build_challenge.return_value = "FLAG{abc123}"
        platform.start_challenge.return_value = "http://localhost:9999"
        platform.verify_flag.return_value = True

        runner = BenchmarkRunner(platform)

        def mock_solver(url, desc, cfg):
            return "Found FLAG{abc123}"

        result = runner.run_single("XBEN-TEST-24", mock_solver)

        assert result.success is True
        assert result.challenge_id == "XBEN-TEST-24"
        assert result.flag_expected == "FLAG{abc123}"
        assert result.flag_found == "FLAG{abc123}"
        assert result.error is None
        platform.stop_challenge.assert_called_once()

    def test_run_single_failure(self, sample_challenge_dir):
        """Mock solver that returns wrong output."""
        platform = MagicMock(spec=XBOWPlatform)
        platform.load_challenge.return_value = ChallengeInfo(
            id="XBEN-TEST-24",
            name="Test",
            description="A test",
            level="1",
            tags=["sqli"],
            win_condition="flag",
            challenge_dir=sample_challenge_dir / "XBEN-TEST-24",
        )
        platform.build_challenge.return_value = "FLAG{abc123}"
        platform.start_challenge.return_value = "http://localhost:9999"
        platform.verify_flag.return_value = False

        runner = BenchmarkRunner(platform)

        def mock_solver(url, desc, cfg):
            return "Could not find the flag"

        result = runner.run_single("XBEN-TEST-24", mock_solver)

        assert result.success is False
        assert result.flag_found is None
        platform.stop_challenge.assert_called_once()

    def test_run_single_error(self, sample_challenge_dir):
        """Mock solver that raises an exception."""
        platform = MagicMock(spec=XBOWPlatform)
        platform.load_challenge.return_value = ChallengeInfo(
            id="XBEN-TEST-24",
            name="Test",
            description="A test",
            level="1",
            tags=["sqli"],
            win_condition="flag",
            challenge_dir=sample_challenge_dir / "XBEN-TEST-24",
        )
        platform.build_challenge.side_effect = RuntimeError("Build failed")

        runner = BenchmarkRunner(platform)

        result = runner.run_single("XBEN-TEST-24", lambda *a: "")

        assert result.success is False
        assert result.error is not None
        assert "Build failed" in result.error

    def test_run_batch(self, sample_challenge_dir):
        platform = MagicMock(spec=XBOWPlatform)
        platform.load_challenge.return_value = ChallengeInfo(
            id="XBEN-TEST-24",
            name="Test",
            description="A test",
            level="1",
            tags=["sqli"],
            win_condition="flag",
            challenge_dir=sample_challenge_dir / "XBEN-TEST-24",
        )
        platform.build_challenge.return_value = "FLAG{abc}"
        platform.start_challenge.return_value = "http://localhost:9999"
        platform.verify_flag.return_value = True

        runner = BenchmarkRunner(platform)
        summary = runner.run_batch(
            ["XBEN-TEST-24", "XBEN-TEST-24"],
            lambda url, desc, cfg: "FLAG{abc}",
        )

        assert summary.total == 2
        assert summary.passed == 2
        assert summary.pass_rate == 100.0

    def test_summary_by_level_and_tag(self):
        results = [
            BenchmarkResult("C1", "N1", "1", ["sqli"], True, "F1", "F1", 5, 10.0, 0.01),
            BenchmarkResult("C2", "N2", "1", ["xss"], False, "F2", None, 10, 20.0, 0.02),
            BenchmarkResult("C3", "N3", "2", ["sqli"], True, "F3", "F3", 3, 5.0, 0.005),
        ]
        runner = BenchmarkRunner(MagicMock())
        summary = runner._build_summary(results)

        assert summary.total == 3
        assert summary.passed == 2
        assert summary.by_level["1"]["total"] == 2
        assert summary.by_level["1"]["passed"] == 1
        assert summary.by_level["2"]["passed"] == 1
        assert summary.by_tag["sqli"]["passed"] == 2
        assert summary.by_tag["xss"]["passed"] == 0

    def test_save_results(self, tmp_path):
        summary = BenchmarkSummary(
            total=1, passed=1, failed=0, errors=0, pass_rate=100.0,
            results=[
                BenchmarkResult("C1", "N1", "1", ["sqli"], True, "F1", "F1", 5, 10.0, 0.01),
            ],
        )
        output = tmp_path / "results.json"
        BenchmarkRunner.save_results(summary, output)

        data = json.loads(output.read_text())
        assert data["total"] == 1
        assert data["passed"] == 1
        assert len(data["results"]) == 1
