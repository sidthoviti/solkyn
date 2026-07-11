"""Solkyn CLI — command-line interface for autonomous penetration testing."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime

import click

import solkyn
from solkyn.config.loader import load_config


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
def cli(verbose: bool) -> None:
    """Solkyn — Autonomous Penetration Testing Agent."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


@cli.command()
def version() -> None:
    """Print version and exit."""
    click.echo(f"solkyn {solkyn.__version__}")


@cli.command()
@click.option("--config", "config_path", type=click.Path(exists=True), default=None,
              help="Path to config YAML (default: configs/default.yaml).")
def config(config_path: str | None) -> None:
    """Print resolved configuration."""
    try:
        cfg = load_config(config_path, resolve_env=False)
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    click.echo(json.dumps(cfg.model_dump(), indent=2, default=str))


@cli.command()
@click.option("--target", required=True, help="Target URL to scan.")
@click.option("--config", "config_path", type=click.Path(exists=True), default=None,
              help="Path to config YAML.")
@click.option("--model", "model_name", default=None, help="Override default model provider.")
@click.option("--max-iterations", type=int, default=None, help="Override max iterations.")
@click.option("--output-dir", type=click.Path(), default=None, help="Output directory for results.")
def scan(
    target: str,
    config_path: str | None,
    model_name: str | None,
    max_iterations: int | None,
    output_dir: str | None,
) -> None:
    """Run an autonomous penetration test against a target."""
    logger = logging.getLogger("solkyn.cli")

    try:
        cfg = load_config(config_path)
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    # Apply CLI overrides
    cfg.target.url = target
    if model_name:
        cfg.models.default = model_name
    if max_iterations:
        cfg.agent.max_iterations = max_iterations
    if output_dir:
        cfg.output_dir = output_dir
    else:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        cfg.output_dir = f"scans/{timestamp}"

    logger.info("Target: %s", cfg.target.url)
    logger.info("Model: %s", cfg.models.default)
    logger.info("Max iterations: %d", cfg.agent.max_iterations)
    logger.info("Output: %s", cfg.output_dir)

    # TODO: Wire up SolverAgent in
    click.echo("Scan command registered. Agent not yet implemented (see ).")


@cli.command()
def tools() -> None:
    """List available pentesting tools in the Kali container."""
    try:
        from solkyn.tools.container import ContainerManager

        mgr = ContainerManager()
        container = mgr.create("tool-check")
        try:
            available = mgr.list_tools(container)
            click.echo(f"{'Tool':<20} {'Status'}")
            click.echo("-" * 30)
            for tool_name in sorted(available):
                click.echo(f"{tool_name:<20} ✓")
            click.echo(f"\n{len(available)} tools available")
        finally:
            mgr.destroy(container)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Make sure Docker is running and solkyn/kali:latest is built.")
        sys.exit(1)
