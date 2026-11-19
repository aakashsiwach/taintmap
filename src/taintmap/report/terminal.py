"""Terminal report: findings grouped by source and agent, each hop with ``file:line``.

Findings that start at the same untrusted source and pass through the same AI agent (the last one
on the path, the one holding the tools) are shown together under one heading, so one risky agent
reads as one problem with several consequences. Groups are ordered by their most severe finding;
findings without an agent (such as TM005) are grouped by source alone. The JSON report keeps one
flat list of findings per rule.

Output is plain ASCII so it prints on any console, including legacy Windows code pages.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from taintmap.model import Finding, Node, Severity
from taintmap.report import at_least, counts, inferred_reasons, role
from taintmap.scan import ScanResult
from taintmap.taxonomy import CarrierCategory, plain_controls

STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}
LABEL_WIDTH = 8


def render(
    result: ScanResult,
    console: Console,
    min_severity: Severity = Severity.INFO,
    *,
    quiet: bool = False,
) -> None:
    findings = at_least(result.findings, min_severity)
    if not quiet:
        for (source_id, agent_id), group in groups(result, findings):
            console.print(_heading(result, source_id, agent_id, group))
            console.print()
            for finding in group:
                _finding(result, finding, console)
                console.print()
        _notes(result, console)
    console.print(_summary(result, findings, min_severity))


GroupKey = tuple[str, str | None]


def agent_of(result: ScanResult, finding: Finding) -> str | None:
    """The last AI agent on a finding's path, if any."""
    agents = [
        n for n in finding.path[1:-1] if result.graph.node(n).category == CarrierCategory.LLM_AGENT
    ]
    return agents[-1] if agents else None


def groups(result: ScanResult, findings: list[Finding]) -> list[tuple[GroupKey, list[Finding]]]:
    """Findings grouped by (source, agent), most severe group first, then by location."""
    grouped: dict[GroupKey, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault((finding.path[0], agent_of(result, finding)), []).append(finding)

    def order(item: tuple[GroupKey, list[Finding]]) -> tuple[int, str, str, str]:
        (source_id, agent_id), members = item
        source = result.graph.node(source_id).location
        agent = result.graph.node(agent_id).location if agent_id else None
        return (
            -max(f.severity.rank for f in members),
            str(source),
            str(agent) if agent else "",
            agent_id or "",
        )

    ordered = sorted(grouped.items(), key=order)
    return [
        (key, sorted(members, key=lambda f: (-f.severity.rank, f.rule_id, f.path)))
        for key, members in ordered
    ]


def _heading(
    result: ScanResult, source_id: str, agent_id: str | None, group: list[Finding]
) -> Text:
    graph = result.graph
    source = graph.node(source_id)
    worst = max(group, key=lambda f: f.severity.rank).severity
    text = Text("== ", style="bold")
    text.append(f"{source.label} ({source.location})", style="bold")
    text.append(" -> ", style="bold")
    if agent_id:
        agent = graph.node(agent_id)
        text.append(f"agent {agent.label} ({agent.location})", style="bold")
    else:
        text.append("no AI agent", style="bold")
    count = len(group)
    text.append(f"  [{count} finding{'s' if count != 1 else ''}, highest ")
    text.append(worst.value.upper(), style=STYLES[worst])
    text.append("]")
    return text


def _row(label: str, location: str, text: str, location_width: int) -> Text:
    row = Text("  ")
    row.append(f"{label:<{LABEL_WIDTH}}", style="dim")
    row.append(f"{location:<{location_width}}  ", style="cyan")
    row.append(text)
    return row


def _finding(result: ScanResult, finding: Finding, console: Console) -> None:
    graph = result.graph
    head = Text()
    head.append(f"{finding.severity.value.upper():<8}", style=STYLES[finding.severity])
    head.append(f" {finding.rule_id}  ", style="bold")
    head.append(finding.title, style="bold")
    if finding.inferred:
        head.append("  [inferred]", style="magenta")
    console.print(head)

    hops = [
        (graph.node(n), str(loc)) for n, loc in zip(finding.path, finding.evidence, strict=True)
    ]
    related = [
        (graph.node(n), str(loc))
        for n, loc in zip(finding.related, finding.related_evidence, strict=True)
    ]
    servers = [(graph.node(s), str(graph.node(s).location)) for s in finding.via_servers]
    width = max(len(loc) for _, loc in [*hops, *related, *servers])

    for node, loc in hops:
        console.print(_row(role(node), loc, _describe(node), width))
    for node, loc in servers:
        console.print(_row("via", loc, f"MCP server {node.label}", width))
    for node, loc in related:
        console.print(_row("also", loc, _describe(node), width))
    console.print(_row("missing", "", plain_controls(finding.missing_control), 0))
    console.print(_row("fix", "", finding.fix, 0))
    if finding.inferred:
        for reason in inferred_reasons(graph, finding):
            console.print(_row("inferred", "", reason, 0))
    if finding.permissions_assumed:
        console.print(
            _row("note", "", "token permissions are assumed (none declared); severity lowered", 0)
        )


def _describe(node: Node) -> str:
    """The node's label, with its category when the label does not already say it."""
    return node.label if node.category in node.label else f"{node.label}  ({node.category})"


def _notes(result: ScanResult, console: Console) -> None:
    if not result.warnings:
        return
    console.print(Text("== NOTES", style="bold"))
    for warning in result.warnings:
        style = "yellow" if warning.level == "warning" else "dim"
        line = Text("  ")
        line.append(f"{warning.level:<{LABEL_WIDTH}}", style=style)
        line.append(f"{warning.file}:{warning.line}  ", style="cyan")
        line.append(warning.message)
        console.print(line)
    console.print()


def _summary(result: ScanResult, shown: list[Finding], min_severity: Severity) -> Text:
    by_severity = ", ".join(f"{n} {s}" for s, n in counts(shown).items() if n)
    text = Text(f"{len(shown)} finding{'s' if len(shown) != 1 else ''}", style="bold")
    if by_severity:
        text.append(f" ({by_severity})")
    hidden = len(result.findings) - len(shown)
    if hidden:
        text.append(f", {hidden} below {min_severity.value} not shown")
    files = len(result.files)
    text.append(f" in {files} file{'s' if files != 1 else ''}")
    errors = len(result.parse_errors)
    if errors:
        text.append(f"; {errors} file problem{'s' if errors != 1 else ''}", style="yellow")
    return text
