"""Command-line interface.

Exit codes of ``scan``: ``0`` no findings at or above ``--fail-on``; ``1`` findings at or above
``--fail-on``; ``2`` a usage error, or a file that could not be parsed (when there are no failing
findings). Info notes, such as an unknown MCP server, never change the exit code.
"""

from __future__ import annotations

import errno
import io
import os
import sys
from collections.abc import Sequence
from enum import StrEnum
from importlib.metadata import version as _dist_version
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from taintmap.model import Finding, ParseWarning, Severity
from taintmap.report import json_report, terminal
from taintmap.scan import scan as run_scan

app = typer.Typer(
    name="taintmap",
    help="Map how untrusted input flows through AI agents, automations and code.",
    no_args_is_help=True,
    add_completion=False,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"


class FailOn(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    NEVER = "never"


class TokenPermissions(StrEnum):
    WRITE = "write"
    READ = "read"


@app.callback()
def main() -> None:
    """Map how untrusted input flows through AI agents, automations and code."""


@app.command()
def version() -> None:
    """Print the installed taintmap version."""
    typer.echo(_dist_version("taintmap"))


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Directory to scan.")] = Path("."),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to this file.")
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", help="Print only the terminal summary line.")
    ] = False,
    min_severity: Annotated[
        Severity, typer.Option("--min-severity", help="Only report findings at or above this.")
    ] = Severity.INFO,
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", help="Exit with 1 when a finding is at or above this level."),
    ] = FailOn.LOW,
    default_token_permissions: Annotated[
        TokenPermissions,
        typer.Option(
            "--default-token-permissions",
            help="What GITHUB_TOKEN may do in workflows that declare no permissions. "
            "Repositories created since 2023-02-02 default to read; older ones often to write.",
        ),
    ] = TokenPermissions.WRITE,
    include: Annotated[
        list[str] | None,
        typer.Option("--include", help="Only scan files matching this glob (repeatable)."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude", help="Skip files and directories matching this glob (repeatable)."
        ),
    ] = None,
) -> None:
    """Scan a directory for paths from untrusted input to sensitive actions."""
    if quiet and output_format is OutputFormat.JSON:
        raise typer.BadParameter("--quiet cannot be used with --format json")
    try:
        result = run_scan(
            path,
            include=include or (),
            exclude=exclude or (),
            default_token_permissions="read"
            if default_token_permissions is TokenPermissions.READ
            else "write",
        )
    except (NotADirectoryError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from None

    if output_format is OutputFormat.JSON:
        text = json_report.render(result, min_severity)
        if output:
            output.write_text(text, encoding="utf-8")
        else:
            write_stdout(text)
    elif output:
        buffer = io.StringIO()
        terminal.render(
            result, Console(file=buffer, width=120, color_system=None), min_severity, quiet=quiet
        )
        output.write_text(buffer.getvalue(), encoding="utf-8")
    else:
        console = Console(highlight=False, soft_wrap=True)
        if console.is_terminal:
            terminal.render(result, console, min_severity, quiet=quiet)
        else:
            buffer = io.StringIO()
            terminal.render(
                result,
                Console(
                    file=buffer,
                    width=console.width,
                    color_system=None,
                    highlight=False,
                    soft_wrap=True,
                ),
                min_severity,
                quiet=quiet,
            )
            write_stdout(buffer.getvalue())

    raise typer.Exit(exit_code(result.findings, result.parse_errors, fail_on))


def write_stdout(text: str) -> None:
    """Stop quietly on a closed pipe, including Windows' EINVAL for this case."""
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except OSError as exc:
        if exc.errno != errno.EPIPE and not (sys.platform == "win32" and exc.errno == errno.EINVAL):
            raise
        # Prevent Python's final flush from raising again and replacing the scan exit code.
        with open(os.devnull, "w", encoding="utf-8") as sink:
            os.dup2(sink.fileno(), sys.stdout.fileno())


def exit_code(
    findings: Sequence[Finding], parse_errors: Sequence[ParseWarning], fail_on: FailOn
) -> int:
    """``1`` for failing findings, else ``2`` for parse errors, else ``0``."""
    if fail_on is not FailOn.NEVER:
        threshold = Severity(fail_on.value)
        if any(f.severity.rank >= threshold.rank for f in findings):
            return EXIT_FINDINGS
    return EXIT_ERROR if parse_errors else EXIT_OK


class BenchSplit(StrEnum):
    DEV = "dev"
    TEST = "test"


@app.command()
def bench(
    split: Annotated[BenchSplit, typer.Option("--split", help="Which cases to run.")] = (
        BenchSplit.DEV
    ),
    final: Annotated[
        bool,
        typer.Option("--final", help="Required to run the held-out test split (for releases)."),
    ] = False,
    benchmark: Annotated[Path, typer.Option("--benchmark", help="Benchmark directory.")] = Path(
        "benchmark"
    ),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="terminal (text) or json.")
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the result to this file.")
    ] = None,
) -> None:
    """Run the benchmark and report recall, precision and false-positive rate."""
    from taintmap import bench as harness
    from taintmap.rules import all_rules

    if split is BenchSplit.TEST and not final:
        typer.echo(
            "error: the test split is held out; run it only for a release, with --final",
            err=True,
        )
        raise typer.Exit(EXIT_ERROR)
    try:
        result = harness.run(
            benchmark,
            "test" if split is BenchSplit.TEST else "dev",
            [r.info.id for r in all_rules()],
        )
    except harness.BenchError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from None
    if output_format is OutputFormat.JSON:
        import json

        text = json.dumps(harness.to_json(result), indent=2) + "\n"
    else:
        text = harness.render_text(result)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8", newline="\n")
    else:
        typer.echo(text, nl=False)
