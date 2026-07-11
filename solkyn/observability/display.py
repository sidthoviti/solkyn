"""Rich terminal display for solver agent runs.

Provides beautiful, real-time output showing challenge info, tool calls,
reasoning, iteration progress, and running statistics.
"""

from __future__ import annotations

import time

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

console = Console()


class RunDisplay:
    """Rich terminal display for solver agent runs."""

    def __init__(self, total_challenges: int = 1, model: str = "unknown") -> None:
        self._total = total_challenges
        self._model = model
        self._passed = 0
        self._failed = 0
        self._current_idx = 0
        self._run_start = time.time()

    def run_header(self, model: str, total: int) -> None:
        """Display run header at start."""
        self._model = model
        self._total = total
        console.print()
        console.print(
            Panel(
                f"[bold cyan]Solkyn Agent[/] — [white]{model}[/]\n"
                f"[dim]Challenges: {total} | Mode: whitebox | Max iterations per challenge: configurable[/]",
                title="[bold]Run Started[/]",
                border_style="cyan",
            )
        )
        console.print()

    def challenge_start(
        self,
        idx: int,
        challenge_id: str,
        name: str,
        level: str,
        tags: list[str],
        target_url: str,
        files: list[str] | None = None,
    ) -> None:
        """Display challenge header."""
        self._current_idx = idx
        tag_str = " ".join(f"[magenta]{t}[/]" for t in tags)

        info_lines = [
            f"[bold white]{challenge_id}[/] — {escape(name)}",
            f"Level [bold yellow]{level}[/] | Tags: {tag_str}",
            f"Target: [underline]{escape(target_url)}[/]",
        ]
        if files:
            info_lines.append(f"Source files: [dim]{len(files)} files (whitebox)[/]")

        stats = f"[dim]{self._passed}✓ {self._failed}✗ / {self._total}[/]"

        console.print()
        console.rule(f"[bold]Challenge {idx}/{self._total}[/] {stats}", style="blue")
        for line in info_lines:
            console.print(f"  {line}")

        # Show what context the agent receives
        self._show_agent_context(tags, files)
        console.print()

    def _show_agent_context(
        self,
        tags: list[str],
        files: list[str] | None = None,
    ) -> None:
        """Display what information the agent receives before solving."""
        from solkyn.agents.prompt_builder import _TAG_TO_PLAYBOOK

        console.print()
        console.print("  [bold cyan]Agent Context (what the model knows):[/]")

        # Tags → playbook selection
        if tags:
            tag_list = ", ".join(tags)
            console.print(f"    [yellow]Tags sent:[/] {tag_list}")
            playbooks = sorted({_TAG_TO_PLAYBOOK.get(t, "playbook_general.md") for t in tags})
            console.print(f"    [yellow]Playbooks loaded:[/] {', '.join(playbooks)}")
        else:
            console.print("    [yellow]Tags sent:[/] [dim]none[/]")
            console.print("    [yellow]Playbooks loaded:[/] [dim]all (no tag filtering)[/]")

        # Source files
        if files:
            console.print(f"    [yellow]Source filenames sent:[/] {len(files)} filenames (no content)")
        else:
            console.print("    [yellow]Source filenames sent:[/] [dim]none (blackbox)[/]")

    def iteration_start(self, iteration: int, max_iterations: int) -> None:
        """Display iteration header."""
        pct = iteration / max_iterations * 100
        bar_len = 20
        filled = int(bar_len * iteration / max_iterations)
        bar = "█" * filled + "░" * (bar_len - filled)
        console.print(
            f"  [bold blue]Iter {iteration}/{max_iterations}[/] [{bar}] {pct:.0f}%",
            highlight=False,
        )

    def thinking(self) -> None:
        """Show the model is thinking."""
        console.print("    [dim italic]Thinking...[/]")

    def reasoning(self, text: str) -> None:
        """Display model reasoning/content."""
        if not text or not text.strip():
            return
        # Show first 200 chars of reasoning
        preview = text.strip()[:200]
        if len(text.strip()) > 200:
            preview += "..."
        console.print(f"    [italic dim]{escape(preview)}[/]")

    def tool_call(
        self,
        tool_name: str,
        command: str | None = None,
        args_preview: str | None = None,
    ) -> None:
        """Display a tool call."""
        if tool_name == "bash_exec" and command:
            # Show command with syntax highlighting hint
            cmd_display = command[:120]
            if len(command) > 120:
                cmd_display += "..."
            console.print(f"    [green]▶ bash[/] [white]{escape(cmd_display)}[/]")
        elif tool_name == "file_write":
            path = args_preview or "?"
            console.print(f"    [green]▶ file_write[/] [white]{escape(path)}[/]")
        elif tool_name == "file_read":
            path = args_preview or "?"
            console.print(f"    [green]▶ file_read[/] [white]{escape(path)}[/]")
        else:
            console.print(f"    [green]▶ {escape(tool_name)}[/] {escape(args_preview or '')}")

    def tool_result(self, result_length: int, duration: float, preview: str | None = None) -> None:
        """Display tool result summary."""
        size_str = f"{result_length:,} chars" if result_length < 10000 else f"{result_length / 1000:.1f}K chars"
        line = f"    [dim]  → {size_str} in {duration:.1f}s[/]"
        if preview:
            # Show first line of result if short
            first_line = preview.strip().split("\n")[0][:100]
            if first_line:
                line += f" [dim]| {escape(first_line)}[/]"
        console.print(line)

    def flag_found(self, flag: str, iteration: int) -> None:
        """Display flag found."""
        console.print(f"\n    [bold green]🚩 FLAG FOUND[/] at iteration {iteration}")
        console.print(f"    [green]{escape(flag[:40])}...[/]")

    def loop_detected(self, nudge_number: int) -> None:
        """Display loop detection."""
        console.print(f"    [bold yellow]⚠ Loop detected[/] (nudge #{nudge_number})")

    def challenge_end(
        self,
        success: bool,
        iterations: int,
        total_time: float,
        tool_calls: int,
        input_tokens: int,
        output_tokens: int,
        error: str | None = None,
    ) -> None:
        """Display challenge result."""
        if success:
            self._passed += 1
            status = "[bold green]PASS[/]"
        else:
            self._failed += 1
            status = "[bold red]FAIL[/]"

        token_str = f"{input_tokens:,}in/{output_tokens:,}out"
        console.print()
        console.print(
            f"  {status} — {iterations} iterations, {tool_calls} tool calls, "
            f"{total_time:.0f}s, {token_str} tokens"
        )
        if error:
            console.print(f"  [red]Error: {escape(error[:100])}[/]")

    def run_summary(self, results: list[dict]) -> None:
        """Display final run summary table."""
        total = len(results)
        passed = sum(1 for r in results if r["success"])
        failed = total - passed
        elapsed = time.time() - self._run_start

        console.print()
        console.print(
            Panel(
                f"[bold]{'PASS' if passed > 0 else 'FAIL'}[/]: "
                f"[green]{passed}[/] / [red]{failed}[/] / {total} "
                f"([bold]{passed / total * 100:.0f}%[/])\n"
                f"Model: {self._model} | Time: {elapsed / 60:.1f} min",
                title="[bold]Run Complete[/]",
                border_style="green" if passed == total else "yellow",
            )
        )

        # Results table
        table = Table(title="Results", show_lines=False, pad_edge=False)
        table.add_column("Challenge", style="white", min_width=14)
        table.add_column("Level", justify="center", width=5)
        table.add_column("Tags", style="magenta")
        table.add_column("Status", justify="center", width=6)
        table.add_column("Iter", justify="right", width=4)
        table.add_column("Time", justify="right", width=6)
        table.add_column("Calls", justify="right", width=5)

        for r in results:
            status = "[green]PASS[/]" if r["success"] else "[red]FAIL[/]"
            tags = ", ".join(r.get("tags", []))
            table.add_row(
                r["challenge_id"],
                str(r.get("level", "?")),
                tags[:30],
                status,
                str(r.get("iterations", 0)),
                f'{r.get("time", 0):.0f}s',
                str(r.get("tool_calls", 0)),
            )

        console.print(table)

        # Per-tag breakdown
        tags_stats: dict[str, dict[str, int]] = {}
        for r in results:
            for tag in r.get("tags", []):
                if tag not in tags_stats:
                    tags_stats[tag] = {"pass": 0, "fail": 0}
                if r["success"]:
                    tags_stats[tag]["pass"] += 1
                else:
                    tags_stats[tag]["fail"] += 1

        if tags_stats:
            tag_table = Table(title="By Tag", show_lines=False, pad_edge=False)
            tag_table.add_column("Tag", style="magenta")
            tag_table.add_column("Pass", justify="right", style="green")
            tag_table.add_column("Total", justify="right")
            tag_table.add_column("Rate", justify="right")

            for tag in sorted(
                tags_stats,
                key=lambda t: tags_stats[t]["pass"] / (tags_stats[t]["pass"] + tags_stats[t]["fail"]),
                reverse=True,
            ):
                s = tags_stats[tag]
                total_tag = s["pass"] + s["fail"]
                pct = s["pass"] / total_tag * 100
                rate_style = "green" if pct >= 75 else "yellow" if pct >= 50 else "red"
                tag_table.add_row(tag, str(s["pass"]), str(total_tag), f"[{rate_style}]{pct:.0f}%[/]")

            console.print(tag_table)
        console.print()
