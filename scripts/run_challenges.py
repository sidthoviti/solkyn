#!/usr/bin/env python3
"""Run Solkyn agent against XBOW benchmark challenges.

Usage:
    python scripts/run_challenges.py -c XBEN-038-24          # Single challenge
    python scripts/run_challenges.py -t sqli                  # All SQLi challenges
    python scripts/run_challenges.py -t command_injection      # All CmdI challenges
    python scripts/run_challenges.py -l 1                     # All Level 1
    python scripts/run_challenges.py -c XBEN-038-24 -v        # Verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from solkyn.agents.solver import SolverAgent  # noqa: E402
from solkyn.config.schema import AgentConfig  # noqa: E402
from solkyn.llm.config import create_llm_from_config  # noqa: E402
from solkyn.llm.lmstudio import get_model_from_env, is_lm_studio_provider, reload_model  # noqa: E402
from solkyn.observability.display import RunDisplay  # noqa: E402
from solkyn.observability.events import EventLogger  # noqa: E402
from solkyn.platforms.xbow import XBOWPlatform  # noqa: E402
from solkyn.tools.container import ContainerManager  # noqa: E402
from solkyn.tools.executor import DockerExecutor  # noqa: E402
from solkyn.tools.registry import create_default_tools, register_pty_tools  # noqa: E402

logger = logging.getLogger("solkyn.runner")


def _build_cost_reconciliation(
    local: float | None, upstream: float | None
) -> dict | None:
    """T34c.1 \u2014 reconcile our locally-computed USD ledger against
    the provider-billed ground truth (currently surfaced by OpenRouter
    via ``response.usage.cost``).

    Returns a dict with ``local_cost_usd``, ``upstream_cost_usd`` and
    ``delta_pct = (local - upstream) / upstream * 100`` when both
    sides are present; returns ``None`` when neither is available
    (no run happened) so the field is omitted cleanly. When only one
    side is present, ``delta_pct`` is ``None`` and the present value
    is reported \u2014 useful for native OpenAI/Anthropic where the
    provider doesn't echo a per-call cost.
    """
    if local is None and upstream is None:
        return None
    delta_pct: float | None = None
    if local is not None and upstream is not None and upstream > 0:
        delta_pct = round(((local - upstream) / upstream) * 100.0, 2)
    return {
        "local_cost_usd": local,
        "upstream_cost_usd": upstream,
        "delta_pct": delta_pct,
    }


def load_env() -> None:
    """Load .env file into environment (simple key=value parser)."""
    env_file = PROJECT_ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def _connect_to_challenge_networks(info, container_name: str) -> str | None:
    """Connect the Kali container to the challenge's Docker networks for RFI.

    Returns the Kali container's IP on the challenge network, or None.
    """
    compose_file = info.challenge_dir / "docker-compose.yml"
    if not compose_file.exists():
        compose_file = info.challenge_dir / "docker-compose.yaml"
    if not compose_file.exists():
        return None

    # Docker compose uses the directory name (lowercased) as the project name
    project_name = info.challenge_dir.name.lower()
    # List challenge networks
    result = subprocess.run(
        ["docker", "network", "ls", "--filter", f"name={project_name}_", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        return None

    kali_ip = None
    for network in result.stdout.strip().split("\n"):
        network = network.strip()
        if not network or network == "solkyn-net":
            continue
        # Try connecting (ignore errors if already connected)
        conn = subprocess.run(
            ["docker", "network", "connect", network, container_name],
            capture_output=True, text=True, timeout=5,
        )
        if conn.returncode == 0:
            logger.info("Connected %s to challenge network %s", container_name, network)
        elif "already exists" not in conn.stderr:
            logger.debug("Could not connect to %s: %s", network, conn.stderr.strip())

    # Get the Kali container's IP on any challenge network
    ip_result = subprocess.run(
        ["docker", "inspect", container_name],
        capture_output=True, text=True, timeout=5,
    )
    if ip_result.returncode == 0:
        import json as json_mod
        try:
            inspect_data = json_mod.loads(ip_result.stdout)
            networks = inspect_data[0].get("NetworkSettings", {}).get("Networks", {})
            for net_name, net_info in networks.items():
                if project_name in net_name.lower() and net_info.get("IPAddress"):
                    kali_ip = net_info["IPAddress"]
                    break
        except (json_mod.JSONDecodeError, IndexError, KeyError):
            pass

    if kali_ip:
        logger.info("Kali container IP on challenge network: %s", kali_ip)
    return kali_ip


OOB_CATCHER_PORT = 8888


def _start_oob_catcher(container_name: str) -> bool:
    """Start the in-Kali OOB callback catcher in the background.

    Release/v1: blind-vuln confirmation channel for SSRF / XXE-OOB /
    blind RCE / DNS exfil. Runs as a detached `docker exec -d` so it
    persists for the lifetime of the container. Returns True on
    successful launch (port reachable). Idempotent: if the catcher is
    already running on the port, returns True without starting a new
    instance.
    """
    # Already running? `docker exec` returns 0 from a probe; we use a
    # simple healthz hit via curl from inside Kali (curl is always
    # installed in the image).
    health_cmd = (
        f"curl -fs --max-time 2 http://127.0.0.1:{OOB_CATCHER_PORT}/healthz "
        "> /dev/null"
    )
    probe = subprocess.run(
        ["docker", "exec", container_name, "bash", "-c", health_cmd],
        capture_output=True, text=True, timeout=5,
    )
    if probe.returncode == 0:
        return True

    # Launch detached.
    launch_cmd = (
        f"nohup python3 /tools/oob_catcher.py serve --port {OOB_CATCHER_PORT} "
        "> /tmp/oob_catcher.log 2>&1 &"
    )
    launch = subprocess.run(
        ["docker", "exec", "-d", container_name, "bash", "-c", launch_cmd],
        capture_output=True, text=True, timeout=5,
    )
    if launch.returncode != 0:
        logger.warning("Failed to launch oob_catcher: %s", launch.stderr.strip())
        return False

    # Poll for readiness up to ~3s.
    deadline = time.time() + 3.0
    while time.time() < deadline:
        probe = subprocess.run(
            ["docker", "exec", container_name, "bash", "-c", health_cmd],
            capture_output=True, text=True, timeout=5,
        )
        if probe.returncode == 0:
            logger.info(
                "OOB catcher ready on %s:%d", container_name, OOB_CATCHER_PORT
            )
            return True
        time.sleep(0.2)

    logger.warning(
        "OOB catcher did not become ready within 3s on %s; "
        "blind-vuln OOB confirmation will be unavailable",
        container_name,
    )
    return False


def _build_oob_prompt_block(kali_ip: str | None) -> str:
    """Generate the OOB-catcher instructions appended to the challenge
    description so the agent knows the URL + API to use for blind
    vulnerabilities.

    When ``kali_ip`` is None (compose network discovery failed), we
    fall back to telling the agent to run ``python3
    /tools/oob_catcher.py kali-ip`` itself — the URL the target uses
    to reach the agent depends on which network the target is on.
    """
    if kali_ip:
        url = f"http://{kali_ip}:{OOB_CATCHER_PORT}"
    else:
        url = (
            "http://$(python3 /tools/oob_catcher.py kali-ip):"
            f"{OOB_CATCHER_PORT}"
        )
    return (
        "\n\n## Out-of-band callback catcher (for blind vulns)\n"
        "An OOB HTTP catcher is running inside this Kali container at "
        f"{url}. Use it to confirm BLIND vulnerabilities (blind SSRF, "
        "blind XXE, blind RCE with no output, DNS exfil, RFI).\n"
        "\n"
        "Workflow:\n"
        "```\n"
        "TOKEN=$(python3 /tools/oob_catcher.py new-token)\n"
        f"CB_URL=\"{url}/cb/$TOKEN\"\n"
        "# Embed $CB_URL in your payload, e.g.:\n"
        "#   curl 'http://target/?url='\"$CB_URL\"\n"
        "#   <!ENTITY % e SYSTEM \"'\"$CB_URL\"'\">\n"
        "# Then poll (waits up to 5s for a hit, exit 0 if hit, 1 if not):\n"
        "python3 /tools/oob_catcher.py poll \"$TOKEN\" --wait 5\n"
        "```\n"
        "\n"
        "An incoming hit is L3 proof: the target made a request to "
        "infrastructure you control, confirming the vulnerability "
        "even when the response shows no output.\n"
    )


def _disconnect_from_challenge_networks(info, container_name: str) -> None:
    """Disconnect the Kali container from a challenge's Docker networks.

    Must be called before `docker compose down`, otherwise the network keeps
    Kali as an active endpoint and can't be removed — causing Docker's address
    pool to fill up across many challenges.
    """
    project_name = info.challenge_dir.name.lower()
    result = subprocess.run(
        ["docker", "network", "ls", "--filter", f"name={project_name}_", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        return
    for network in result.stdout.strip().split("\n"):
        network = network.strip()
        if not network or network == "solkyn-net":
            continue
        subprocess.run(
            ["docker", "network", "disconnect", "-f", network, container_name],
            capture_output=True, text=True, timeout=5,
        )


def resolve_max_iter(level: str, default: int, l3_override: int | None) -> int:
    """Pick the effective max-iterations cap for a challenge.

    L3 ("hard") XBOW challenges consistently exhaust the default
    iteration budget mid-exploitation ( post-mortem: XBEN-010, 030, 066
    all hit the cap inside an active exploit chain). When ``l3_override``
    is provided AND the challenge level resolves to 3, return the override;
    otherwise return ``default``.

    ``level`` is the raw string from ``ChallengeInfo.level`` — the inventory
    JSON has both string ("3") and int (3) forms, but the platform loader
    normalises everything to ``str`` (see ``solkyn/platforms/xbow.py:131``).
    We compare on the stripped string to be defensive.
    """
    if l3_override is not None and str(level).strip() == "3":
        return l3_override
    return default


def run_challenge(
    challenge_id: str,
    platform: XBOWPlatform,
    llm,
    tools,
    max_iterations: int = 30,
    output_dir: str = "scans",
    display: RunDisplay | None = None,
    container_name: str | None = None,
    mode: str = "whitebox",
    max_time_seconds: float | None = None,
    max_cost_usd: float | None = None,
    cost_tracker=None,
    disable_playbooks: bool = False,
    progress_content: str | None = None,
    generate_progress: bool = True,
    solver_name: str = "single_loop",
) -> dict:
    """Run a single XBOW challenge and return a result dict."""
    info = platform.load_challenge(challenge_id)
    start_time = time.time()

    try:
        # Build with random flag
        flag_expected = platform.build_challenge(challenge_id)

        # Start and discover the host-mapped URL
        target_url = platform.start_challenge(challenge_id)

        # Re-read info in case start_challenge updated it (e.g., extra ports in description)
        info = platform._active.get(challenge_id, info)

        # Connect Kali container to the challenge's Docker networks for RFI callbacks
        if container_name:
            kali_ip = _connect_to_challenge_networks(info, container_name)
            if kali_ip:
                info.description = info.description + (
                    f"\nFor RFI/reverse connections: the agent Kali container is reachable "
                    f"from the target at {kali_ip}. Start a server on port 8888 in Kali, "
                    f"and the target can reach it at http://{kali_ip}:8888/"
                )
            # Release/v1 — append OOB catcher usage block. Always
            # appended (even when kali_ip is None — the agent can
            # resolve the IP itself via the catcher's `kali-ip` cmd).
            info.description = info.description + _build_oob_prompt_block(kali_ip)

        # Rewrite localhost → host.docker.internal so the Kali container can reach it
        target_url_internal = target_url.replace("localhost", "host.docker.internal")

        logger.info("Target: %s (from Kali: %s)", target_url, target_url_internal)
        logger.info("Expected flag: %s", flag_expected[:30] + "...")

        # per-attempt directory layout. Each invocation creates a
        # fresh `{ts}_attempt_{N}/` under the challenge dir so retries
        # don't overwrite each other and pass@N becomes natural.
        from solkyn.agents.attempt_dir import (
            create_attempt_dir,
            write_config_json,
            write_conversation_json,
            write_stats_json,
        )
        from solkyn.agents.exit_reasons import validate_exit_reason
        from solkyn.agents.repro_metadata import (
            get_docker_image_digest,
            get_git_sha,
        )
        attempt_dir = create_attempt_dir(output_dir, challenge_id)
        scan_dir = str(attempt_dir)

        # capture reproducibility metadata before the run so
        # even an early crash leaves a forensically-complete config.json.
        # All three lookups are best-effort and resolve to "unknown" on
        # any failure rather than crash the sweep.
        git_sha = get_git_sha()
        kali_image_digest = (
            get_docker_image_digest(container_name) if container_name else "unknown"
        )

        # Persist the run config up-front so a crash leaves at least
        # config.json behind for forensics.
        write_config_json(attempt_dir, {
            "challenge_id": challenge_id,
            "name": info.name,
            "level": info.level,
            "tags": info.tags,
            "target_url": target_url_internal,
            "model": llm.model,
            "provider": llm.provider,
            "solver": solver_name,
            "mode": mode,
            "max_iterations": max_iterations,
            "max_time_seconds": max_time_seconds,
            "max_cost_usd": max_cost_usd,
            "disable_playbooks": disable_playbooks,
            "expected_flag": flag_expected,
            # reproducibility metadata.
            "git_sha": git_sha,
            "kali_image_digest": kali_image_digest,
            "effective_llm_params": llm.effective_params(),
        })

        # Create event logger for structured traces
        event_logger = EventLogger(scan_dir=scan_dir)
        event_logger.scan_start(
            challenge_id=challenge_id,
            target_url=target_url_internal,
            description=info.description,
            tags=info.tags,
            level=info.level,
            model=llm.model,
            max_iterations=max_iterations,
            mode=mode,
        )

        # Create solver agent with challenge tags for playbook selection
        agent = SolverAgent(
            llm_manager=llm,
            tool_registry=tools,
            config=AgentConfig(
                max_iterations=max_iterations,
                max_time_seconds=max_time_seconds,
                max_cost_usd=max_cost_usd,
            ),
            tags=info.tags,
            display=display,
            event_logger=event_logger,
            mode=mode,
            cost_tracker=cost_tracker,
            disable_playbooks=disable_playbooks,
            progress_content=progress_content,
            solver_name=solver_name,
        )

        # Run the agent
        # In greybox mode we still pass the file list (so the platform can build/start),
        # but the SolverAgent itself decides what to forward to the model based on `mode`.
        result = agent.run(
            target_url=target_url_internal,
            description=info.description,
            scan_dir=scan_dir,
            files=info.files,
            file_contents=info.file_contents,
        )

        # Copy evidence screenshot from container to scan dir
        if result.evidence_screenshot and container_name:
            screenshot_dest = Path(scan_dir) / "evidence.png"
            cp_result = subprocess.run(
                ["docker", "cp", f"{container_name}:{result.evidence_screenshot}", str(screenshot_dest)],
                capture_output=True, text=True,
            )
            if cp_result.returncode == 0:
                logger.info("Evidence screenshot saved to %s", screenshot_dest)
            else:
                logger.warning("Failed to copy screenshot: %s", cp_result.stderr.strip())

        # Check if expected flag was found
        success = result.flag is not None and flag_expected in result.flag
        elapsed = time.time() - start_time

        # write per-attempt stats.json + conversation.json.
        # include canary string for trace integrity / leak detection.
        # +.3+.4 — cache splits, upstream USD ground truth, refusal
        # count, and a vocabulary-validated exit_reason so downstream
        # analytics can rely on a fixed schema.
        write_stats_json(attempt_dir, {
            "success": success,
            "exit_reason": validate_exit_reason(result.exit_reason, strict=False),
            "flag": result.flag,
            "iterations": result.iterations,
            "duration_seconds": round(elapsed, 2),
            "tool_calls": len(result.tool_calls_log),
            "input_tokens": result.token_usage.get("input_tokens", 0),
            "output_tokens": result.token_usage.get("output_tokens", 0),
            "cache_read_input_tokens": result.cache_read_input_tokens,
            "cache_creation_input_tokens": result.cache_creation_input_tokens,
            "cost_usd": result.cost_usd,
            "upstream_cost_usd": result.upstream_cost_usd,
            # T34c.1 \u2014 reconciliation between locally-computed cost
            # (tokencost \u00d7 list pricing) and the provider-billed
            # ground truth. ``delta_pct`` = (local - upstream) / upstream
            # \u00d7 100 \u2014 positive means we over-estimated, negative
            # means provider billed more (e.g. cache-read discount).
            # ``upstream_cost_usd is None`` when the provider doesn't
            # surface usage.cost (native OpenAI/Anthropic without the
            # OpenRouter ``usage.cost`` echo); reconciliation is then
            # ``None`` rather than guessed.
            "cost_reconciliation": _build_cost_reconciliation(
                local=result.cost_usd,
                upstream=result.upstream_cost_usd,
            ),
            "refusal_count": result.refusal_count,
            "canary": result.canary,
            "error": result.error,
        })
        write_conversation_json(attempt_dir, result.conversation or result.messages)

        # generate progress.md for failed attempts so subsequent
        # attempts (via --attempts N or --resume-from) can pick up cleanly.
        # Best-effort: a summariser failure must not crash the run.
        progress_md_path: Path | None = None
        if generate_progress and not success:
            try:
                from solkyn.agents.progress_summarizer import (
                    generate_progress_summary,
                    write_progress_md,
                )
                body = generate_progress_summary(
                    llm,
                    target_url=target_url_internal,
                    description=info.description,
                    iterations=result.iterations,
                    exit_reason=result.exit_reason or "unknown",
                    messages=result.messages,
                    tags=info.tags,
                )
                progress_md_path = write_progress_md(attempt_dir, body)
                logger.info("progress.md saved to %s", progress_md_path)
            except Exception as e:
                logger.warning("Failed to generate progress.md for %s: %s", challenge_id, e)

        # Log scan end event
        event_logger.scan_end(
            success=success,
            iterations=result.iterations,
            flag=result.flag,
            total_time=elapsed,
            input_tokens=result.token_usage.get("input_tokens", 0),
            output_tokens=result.token_usage.get("output_tokens", 0),
            tool_calls=len(result.tool_calls_log),
        )

        # Generate Markdown trace report from the JSONL logs.
        # also generate summary.md + attack_graph.md via ReportGenerator.
        try:
            from solkyn.core.reporting import ReportGenerator
            artifacts = ReportGenerator(Path(scan_dir), llm=llm).generate_all()
            for name, path in artifacts.items():
                if path:
                    logger.info("Report artifact %s saved to %s", name, path)
        except Exception as e:
            logger.warning("Failed to generate reports for %s: %s", challenge_id, e)

        # Display challenge result
        if display:
            display.challenge_end(
                success=success,
                iterations=result.iterations,
                total_time=elapsed,
                tool_calls=len(result.tool_calls_log),
                input_tokens=result.token_usage.get("input_tokens", 0),
                output_tokens=result.token_usage.get("output_tokens", 0),
            )

        return {
            "challenge_id": challenge_id,
            "name": info.name,
            "level": info.level,
            "tags": info.tags,
            "success": success,
            "flag_expected": flag_expected,
            "flag_found": result.flag,
            "iterations": result.iterations,
            "time": round(elapsed, 2),
            "token_usage": result.token_usage,
            "error": result.error,
            "tool_calls": len(result.tool_calls_log),
            # / additions — old fields preserved above.
            "exit_reason": result.exit_reason,
            "cost_usd": result.cost_usd,
            "attempt_dir": str(attempt_dir),
            "progress_md": str(progress_md_path) if progress_md_path else None,
        }

    except Exception as e:
        elapsed = time.time() - start_time
        logger.error("Error on %s: %s", challenge_id, e, exc_info=True)
        if display:
            display.challenge_end(
                success=False, iterations=0, total_time=elapsed,
                tool_calls=0, input_tokens=0, output_tokens=0, error=str(e),
            )
        return {
            "challenge_id": challenge_id,
            "name": info.name,
            "level": info.level,
            "tags": info.tags,
            "success": False,
            "flag_expected": "",
            "flag_found": None,
            "iterations": 0,
            "time": round(elapsed, 2),
            "token_usage": {},
            "error": str(e),
            "tool_calls": 0,
        }
    finally:
        try:
            if container_name:
                _disconnect_from_challenge_networks(info, container_name)
        except Exception as e:
            logger.warning("Failed to disconnect from %s networks: %s", challenge_id, e)
        try:
            platform.stop_challenge(challenge_id)
        except Exception as e:
            logger.warning("Failed to stop %s: %s", challenge_id, e)


def run_challenge_with_attempts(
    challenge_id: str,
    *,
    attempts: int,
    initial_progress: str | None,
    generate_progress: bool,
    run_fn,
    solver_chain: list[str] | None = None,
) -> dict:
    """Run a challenge up to `attempts` times, chaining each failed attempt's
    ``progress.md`` into the next attempt's ``progress_content`` slot.

    Stops early on the first success. ``run_fn(challenge_id, progress_content,
    solver_name)`` must return the per-attempt result dict produced by
    ``run_challenge``. ``solver_name`` is taken from ``solver_chain[i-1]`` for
    attempt ``i``; if the chain is shorter than the attempt count, the last
    entry is reused (so a single-element chain matches the legacy behaviour).
    When ``solver_chain`` is ``None``, ``run_fn`` is called with
    ``solver_name=None`` and the closure picks its own default — also
    legacy behaviour.

    Differentiated pass@N: pass ``["single_loop", "hacksynth"]`` to get
    a cheap-then-different second attempt with progress.md handoff.

    Returns the final attempt's dict, augmented with ``attempts_used`` (1-based),
    ``progress_chain`` (list of progress.md paths chained in), and
    ``solver_chain_used`` (list of solver names actually invoked).
    """
    progress_content = initial_progress
    progress_chain: list[str] = []
    solver_chain_used: list[str] = []
    last_result: dict = {}
    attempts_used = 0
    for i in range(1, attempts + 1):
        attempts_used = i
        if solver_chain:
            solver_for_attempt = solver_chain[min(i - 1, len(solver_chain) - 1)]
        else:
            solver_for_attempt = None
        solver_chain_used.append(solver_for_attempt or "<default>")
        last_result = run_fn(challenge_id, progress_content, solver_for_attempt)
        if last_result.get("success"):
            break
        if i == attempts or not generate_progress:
            break
        # Chain the just-written progress.md into the next attempt's prompt.
        next_progress = last_result.get("progress_md")
        if next_progress and Path(next_progress).exists():
            progress_chain.append(next_progress)
            progress_content = Path(next_progress).read_text(encoding="utf-8")
        else:
            logger.warning(
                "Attempt %d for %s failed but produced no progress.md — "
                "next attempt will not be chained.",
                i, challenge_id,
            )
    last_result["attempts_used"] = attempts_used
    last_result["progress_chain"] = progress_chain
    last_result["solver_chain_used"] = solver_chain_used
    return last_result


def print_summary(results: list[dict]) -> None:
    """Print a results summary table."""
    total = len(results)
    if not total:
        print("No results.")
        return

    passed = sum(1 for r in results if r["success"])
    print("\n" + "=" * 70)
    print(f"  RESULTS: {passed}/{total} passed ({passed / total * 100:.0f}%)")
    print("=" * 70)

    for r in results:
        status = "PASS" if r["success"] else "FAIL"
        err = f" — {r['error'][:60]}" if r.get("error") else ""
        print(
            f"  [{status}] {r['challenge_id']} (L{r['level']}) "
            f"{r['time']:.0f}s {r['iterations']}iter "
            f"{r['tool_calls']}calls{err}"
        )

    # Per-tag breakdown
    tags: dict[str, dict[str, int]] = {}
    for r in results:
        for tag in r["tags"]:
            if tag not in tags:
                tags[tag] = {"total": 0, "passed": 0}
            tags[tag]["total"] += 1
            if r["success"]:
                tags[tag]["passed"] += 1

    if tags:
        print("\n  By tag:")
        for tag, counts in sorted(tags.items()):
            pct = counts["passed"] / counts["total"] * 100
            print(f"    {tag}: {counts['passed']}/{counts['total']} ({pct:.0f}%)")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Solkyn agent on XBOW challenges")
    parser.add_argument("--challenge", "-c", action="append", help="Challenge ID (repeatable: -c X -c Y)")
    parser.add_argument("--tag", "-t", help="Run all challenges with this tag")
    parser.add_argument("--level", "-l", help="Run all challenges at this level")
    parser.add_argument("--all", action="store_true", help="Run all challenges")
    parser.add_argument("--config", default="configs/default.yaml", help="Config file path")
    parser.add_argument("--provider", help="LLM provider name from config")
    parser.add_argument("--max-iterations", type=int, default=30, help="Max agent iterations")
    parser.add_argument(
        "--max-iterations-l3",
        type=int,
        default=None,
        help=(
            "Optional iteration cap override applied ONLY to challenges with "
            "level == '3'. When unset, --max-iterations is used for all "
            "levels. L3 challenges can exhaust the default budget mid-exploit; "
            "50 is the recommended starting point."
        ),
    )
    parser.add_argument(
        "--max-time",
        type=float,
        default=None,
        help="Per-challenge wall-clock budget in MINUTES (None = unbounded).",
    )
    parser.add_argument(
        "--max-cost",
        type=float,
        default=None,
        help="Per-challenge LLM cost budget in USD (None = unbounded).",
    )
    parser.add_argument(
        "--no-playbooks",
        action="store_true",
        default=False,
        help=(
            "Strip the vulnerability playbook block (and its priority directive) "
            "from the system prompt. Used by the playbook A/B harness to measure "
            "whether playbooks actually move the XBOW solve rate."
        ),
    )
    parser.add_argument("--output", "-o", default="scans", help="Output directory")
    parser.add_argument(
        "--attempts",
        type=int,
        default=1,
        help=(
            "Sequential attempts per challenge. Each failed attempt's progress.md "
            "is chained into the next attempt's system prompt. Stops early "
            "on first success."
        ),
    )
    parser.add_argument(
        "--resume-from",
        default=None,
        help=(
            "Path to a previous attempt directory (or its progress.md). Its "
            "progress content is injected into the system prompt of the FIRST "
            "attempt of every challenge in this run."
        ),
    )
    parser.add_argument(
        "--no-generate-progress",
        action="store_true",
        default=False,
        help=(
            "Skip post-attempt progress.md generation on failure. "
            "Disables --attempts chaining."
        ),
    )
    parser.add_argument(
        "--solver",
        choices=["single_loop", "single_loop_compact", "hacksynth"],
        default="single_loop",
        help=(
            "Solver strategy. 'single_loop' (default) is the original. "
            "'single_loop_compact' adds conversation compaction at the "
            "context-window threshold. 'hacksynth' is the "
            "planner+summarizer dual-LLM solver from arXiv:2412.01778 "
            " — keeps a rolling 1-3 line working memory instead of "
            "the full conversation."
        ),
    )
    parser.add_argument(
        "--solver-chain",
        default=None,
        help=(
            "Comma-separated list of solver names, one per attempt. "
            "Overrides --solver when set. If the chain is shorter than "
            "--attempts, the last entry is reused. Use this for "
            "differentiated pass@N runs, e.g. "
            "'--attempts 2 --solver-chain single_loop,hacksynth' to retry "
            "failed challenges with a different solver architecture and "
            "the previous attempt's progress.md chained in."
        ),
    )
    parser.add_argument(
        "--executor",
        choices=["docker", "pty"],
        default="docker",
        help=(
            "Tool execution backend. 'docker' (default) registers only "
            "bash_exec/file_read/file_write (stateless). 'pty' ALSO registers "
            "pty_open/pty_run/pty_close for persistent shell sessions "
            "(reverse-shell listeners, msfconsole, mysql, cd/export/source). "
            "bash_exec stays available either way."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["blackbox", "greybox", "whitebox"],
        default="whitebox",
        help=(
            "What target information is exposed to the agent.\n"
            "  whitebox (default) — URL + description + scope tags + filenames + key source contents.\n"
            "  greybox            — URL + description + scope tags only (no source / no filenames).\n"
            "  blackbox           — URL only. Agent must reconnoitre and classify the vuln itself."
        ),
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    # Setup logging — quiet when rich display is active
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)-25s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )

    # Load .env
    load_env()

    # Create LLM from config
    config_path = str(PROJECT_ROOT / args.config)
    llm = create_llm_from_config(config_path, args.provider)
    logger.info("LLM: provider=%s model=%s", llm.provider, llm.model)

    # load price table for cost tracking. Always create the
    # tracker (even when --max-cost is unset) so cost_usd is reported.
    import yaml

    from solkyn.core.cost import CostTracker, load_prices_from_config
    with open(config_path) as _f:
        _cfg = yaml.safe_load(_f) or {}
    cost_tracker = CostTracker(prices=load_prices_from_config(_cfg))

    # Create Kali container (shared across all challenges)
    cm = ContainerManager()
    scan_id = f"s9-{int(time.time())}"
    container_name = cm.create(scan_id)
    logger.info("Kali container: %s", container_name)

    # Release/v1 — start OOB catcher inside the Kali container. One
    # instance per container, persists for the duration of this sweep.
    _start_oob_catcher(container_name)

    try:
        executor = DockerExecutor(container_name, timeout=120)
        tools = create_default_tools(executor)

        # register PTY tools when --executor pty.
        pty_executor = None
        if args.executor == "pty":
            from solkyn.tools.pty_executor import PTYExecutor
            pty_executor = PTYExecutor(container_name)
            register_pty_tools(tools, pty_executor)
            logger.info("PTY executor registered (pool max=%d)", pty_executor.max_sessions)

        # Determine which challenges to run
        platform = XBOWPlatform()

        if args.challenge:
            challenge_ids = args.challenge
        elif args.tag:
            challenge_ids = [
                cid for cid in platform.list_challenges()
                if args.tag in platform.load_challenge(cid).tags
            ]
        elif args.level:
            challenge_ids = [
                cid for cid in platform.list_challenges()
                if platform.load_challenge(cid).level == str(args.level)
            ]
        elif args.all:
            challenge_ids = platform.list_challenges()
        else:
            parser.error("Specify --challenge, --tag, --level, or --all")
            return

        logger.info("Running %d challenge(s)", len(challenge_ids))

        # resume from a prior attempt's progress.md if requested.
        initial_progress: str | None = None
        if args.resume_from:
            from solkyn.agents.progress_summarizer import load_progress_md
            initial_progress = load_progress_md(args.resume_from)
            logger.info(
                "Resuming with progress.md (%d chars) from %s",
                len(initial_progress), args.resume_from,
            )
        generate_progress = not args.no_generate_progress

        # parse --solver-chain into a list, validating each entry.
        solver_chain: list[str] | None = None
        if args.solver_chain:
            valid_solvers = {"single_loop", "single_loop_compact", "hacksynth"}
            solver_chain = [s.strip() for s in args.solver_chain.split(",") if s.strip()]
            invalid = [s for s in solver_chain if s not in valid_solvers]
            if invalid:
                parser.error(
                    f"--solver-chain contains unknown solver(s): {invalid}. "
                    f"Valid choices: {sorted(valid_solvers)}"
                )
            logger.info("Solver chain: %s (over %d attempts)", solver_chain, args.attempts)

        # Create rich display
        display = RunDisplay(total_challenges=len(challenge_ids), model=llm.model)
        display.run_header(model=f"{llm.provider}/{llm.model}", total=len(challenge_ids))

        # Run challenges sequentially
        results = []
        lm_model = get_model_from_env() if is_lm_studio_provider(llm.provider) else None
        for i, cid in enumerate(challenge_ids, 1):
            info = platform.load_challenge(cid)
            logger.info("Challenge %d/%d: %s", i, len(challenge_ids), cid)

            # Display challenge header
            display.challenge_start(
                idx=i,
                challenge_id=cid,
                name=info.name,
                level=info.level,
                tags=info.tags,
                target_url="(building...)",
                files=info.files,
            )

            # Reload LM Studio model between challenges to reset KV cache
            if lm_model and i > 1:
                try:
                    reload_model(lm_model)
                except Exception as e:
                    logger.error("Model reload failed: %s — continuing anyway", e)

            # per-level max-iter override. L3 challenges optionally get
            # a higher iteration cap (e.g. 50 vs the default 25/30) because
            # they tend to exhaust the budget mid-exploitation.
            effective_max_iter = resolve_max_iter(
                info.level, args.max_iterations, args.max_iterations_l3,
            )
            if effective_max_iter != args.max_iterations:
                logger.info(
                    "L3 max-iter override applied: %d → %d for %s (level=%s)",
                    args.max_iterations, effective_max_iter, cid, info.level,
                )

            result = run_challenge_with_attempts(
                cid,
                attempts=args.attempts,
                initial_progress=initial_progress,
                generate_progress=generate_progress,
                solver_chain=solver_chain,
                run_fn=lambda cid, pc, sn, _mi=effective_max_iter: run_challenge(
                    cid, platform, llm, tools,
                    max_iterations=_mi,
                    output_dir=args.output,
                    display=display,
                    container_name=container_name,
                    mode=args.mode,
                    max_time_seconds=(args.max_time * 60.0) if args.max_time else None,
                    max_cost_usd=args.max_cost,
                    cost_tracker=cost_tracker,
                    disable_playbooks=args.no_playbooks,
                    progress_content=pc,
                    generate_progress=generate_progress,
                    solver_name=sn or args.solver,
                ),
            )
            results.append(result)

        # Rich summary replaces old print_summary
        display.run_summary(results)

        # Save JSON results
        output_path = Path(args.output) / f"results-{scan_id}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results saved to %s", output_path)

    finally:
        # reap any PTY sessions before destroying the container.
        if pty_executor is not None:
            try:
                pty_executor.close_all()
            except Exception as e:
                logger.warning("Failed to close PTY sessions: %s", e)
        cm.destroy(container_name)
        logger.info("Cleaned up Kali container: %s", container_name)


if __name__ == "__main__":
    main()
