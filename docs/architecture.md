# Architecture

This document describes how taintmap is built. The plan for building it is in [plan.md](plan.md), and the
taxonomy of sources, sinks and controls is in [threat-model.md](threat-model.md).

## Pipeline

```text
repository
   │
   ▼
1. discover      find files each parser understands (workflows, MCP configs, agent configs, code)
   │
   ▼
2. parse         each parser turns its files into a GraphFragment: nodes + edges, with file/line locations
   │
   ▼
3. link          merge fragments and connect them across files (agent → MCP server by name,
   │             tool → code by endpoint or method, workflow step → action catalog entry)
   ▼
4. find paths    walk from every source node to every sink node; drop paths blocked by an effective control
   │
   ▼
5. classify      rules turn remaining paths into findings with a rule id, severity, missing control and fix
   │
   ▼
6. report        terminal, JSON, and later SARIF
```

Every stage is deterministic. No stage calls an LLM or the network. The same input always produces the
same output, which keeps findings explainable and the benchmark reproducible.

## Data model

All models are Pydantic v2 classes in `src/taintmap/model.py`.

### Location
`file` (path relative to the scanned root, POSIX separators), `line` (1-based), optional `end_line`,
optional `snippet` (one line, trimmed).

### Node
| Field | Meaning |
|---|---|
| `id` | Stable, unique string, e.g. `gha:.github/workflows/triage.yml:job:triage:step:2` |
| `kind` | `source`, `carrier`, `capability`, `code`, `sink`, `control` |
| `category` | Taxonomy id from the threat model, e.g. `source.untrusted.issue_text`, `sink.repo.write` |
| `label` | Short human-readable name |
| `location` | Where it is defined |
| `attrs` | Free-form dict for parser-specific details |

### Edge
| Field | Meaning |
|---|---|
| `src`, `dst` | Node ids |
| `kind` | `passes_input`, `can_call`, `runs_with`, `invokes`, `writes_to`, `guarded_by` |
| `location` | Where the relationship is declared |
| `attrs` | Free-form dict, e.g. the author of the input a `passes_input` edge carries, or `evidence` |

`guarded_by` edges point from a node to a `control` node. A control is **effective** for a path when it
guards any node on that path and its category blocks the path's risk class (see threat model).

### Finding
`rule_id`, `severity` (`info`, `low`, `medium`, `high`, `critical`; `info` is worth knowing but not a
vulnerability on its own, never fails a scan and is not counted by the benchmark), `title`, `path` (ordered node ids),
`evidence` (one location per node on the path), `missing_control`, `fix` (one or two sentences),
`inferred` (the path relies on an inferred catalog claim), `permissions_assumed` (the sink exists only
because default token permissions were assumed), `via_servers` (MCP servers whose tool results carry the
input), `related` and `related_evidence` (nodes a finding depends on that are not on its path, such as
TM004's sensitive data), and `fingerprint` (stable hash of rule id + path node ids, used to track a
finding across runs).

### Linking, controls and path search

`link.py` merges fragments with `build_graph` and adds cross-file edges. A workflow step running a
catalogued AI action with `mcp_configs` (for example `claude-code-action`, which loads the repository's
`.mcp.json`) gets a `can_call` edge to each server of that config that its tool config allows
(`mcp__<server>` in `claude_args` or `settings`), and each allowed server's untrusted source capabilities pass
input to the step. Link edges carry `attrs.link` and the catalog's evidence level.

`controls.py` decides whether a control blocks a path: it must guard a node on the path, and its category
must block the path (see the module docstring and the threat model). A trusted-actor gate on
`author_association` blocks only input whose entry edges name an author it checks, so it never blocks MCP
tool results; `control.input_isolation` blocks only a non-interpolated `run:` script.

`paths.py` lists candidate paths from every source to every sink (`max_depth` 8 by default). It examines
paths shortest first, drops blocked ones, and then keeps at most 5 per pair, so an unblocked longer path is
never hidden behind blocked shorter ones. Each path is marked `inferred` (it relies on an inferred catalog
claim) and `permissions_assumed` (its sink exists only because default token permissions were assumed),
and lists `via_servers`, the MCP servers whose tool results carry the input. Rules read these candidates.

### Graph
`src/taintmap/graph.py` wraps a `networkx.MultiDiGraph`. It offers `add_fragment`, `nodes_of_kind`,
`paths(source, sink, max_depth)`, and JSON export (`taintmap graph --json`) for debugging.

Node ids are unique: re-adding an identical node is a no-op, while the same id with different content is an
error. `paths` returns sorted simple paths of at most `max_depth` edges and does not follow `guarded_by`
edges, since those point to controls rather than carrying input. The JSON export carries `schema_version: 1`.

## Parsers

A parser implements:

```python
class Parser(Protocol):
    name: str

    def matches(self, path: Path) -> bool: ...
    def parse(self, path: Path, root: Path) -> GraphFragment: ...
```

A fragment also carries the parse warnings for its file (`GraphFragment.warnings`), so they reach the
report; the graph does not store them and they are not part of the graph's JSON export.

Parsers are registered through the `taintmap.parsers` entry-point group, so third-party packages can add
parsers without changing taintmap. Built-in parsers for v0.1:

| Parser | Files |
|---|---|
| `github_actions` | `.github/workflows/*.yml`, `.github/workflows/*.yaml` |
| `mcp_config` | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, and files listed in `taintmap.yaml` |

Planned: `java_spring` (v0.2), `taintmap_manifest` for hand-declared agents and tools (v0.2), and importers
for SARIF from other scanners (v0.3).

### GitHub Actions

`parsers/github_actions.py` maps a workflow to the graph like this (its module docstring lists node ids):

| Workflow element | Graph |
|---|---|
| Trigger in the triggers catalog | `source` node with the catalog's category |
| Job, step | `carrier.workflow_step`; a step using a catalogued AI action is `carrier.llm_agent` |
| `${{ }}` reading an untrusted context in `with:`, `env:` or `run:` | `passes_input` edge from each workflow trigger that fills the context, one per author of the input (`attrs.author`, `attrs.author_association`, `attrs.contexts`); workflow and job `env:` feed the job, which passes input to its steps |
| AI action with `reads_event: true` | `passes_input` from every untrusted trigger, even without an expression; the edge carries the catalog's evidence level (`inferred` for `claude-code-action`) |
| `run:` | `sink.code_exec` (`attrs.expression_injection` when untrusted input is interpolated) |
| AI action input that allows a shell tool from `code_exec_tools` (e.g. `Bash` in `claude_args`) | `sink.code_exec` on the agent step, located at that input's line (`attrs.via_input`, `attrs.via_tool`) |
| Effective `GITHUB_TOKEN` permissions | one sink per category the write scopes grant (`sink.repo.write`, `sink.deploy`, `sink.secret.read` for `id-token`). Job level overrides workflow level. With neither, the write default is assumed because the repository setting is not visible (`--default-token-permissions read` changes that); such sinks have `attrs.permissions_assumed = true`. The job's declared permissions are kept in `attrs.permissions` for fix text |
| `secrets.*` in `env:` or `with:` | `sink.secret.read` (workflow and job level reach every step) |
| `if:` requiring `author_association` OWNER, MEMBER or COLLABORATOR (`==` or `contains(fromJSON('[...]'), ...)`), or a label | `control.trusted_actor_gate`; every `\|\|` alternative must be such a check. `attrs.checks` lists the `author_association` contexts all alternatives require; the gate only blocks input whose `passes_input` edge names one of them (checking the issue author does not cover a commenter). Label gates block input from any author |
| `environment:` | `control.human_approval`, recorded as declared but not verified (required reviewers live in repository settings) |
| `run:` with no interpolation whose untrusted input arrives only through `env:` | `control.input_isolation`, which blocks only `sink.code_exec` reached by expression injection; the input still flows to the step's other sinks |

### MCP configs

`parsers/mcp_config.py` reads `mcpServers`, and the `servers` key VS Code uses, from the supported files.
Each file's client (`.mcp.json` Claude Code, `.cursor/mcp.json` Cursor, `.vscode/mcp.json` VS Code,
`claude_desktop_config.json` Claude Desktop) is one `carrier.llm_agent` that `can_call` each server.

| Config element | Graph |
|---|---|
| Server entry | `carrier.mcp_server`, matched to the MCP catalog by package, image or URL |
| Catalogued `source.untrusted.*` capability | `source` node that passes input straight to the client (tool results; `attrs.via_server` names the server, and candidate paths list it in `via_servers`), so a path can read through a server and act through the same one |
| Catalogued `sink.*` capability | `sink` node reached from the server |
| Unknown server | `attrs.unknown = true` and an info-level note (`ParseWarning.level = "info"`), never a finding |
| Literal secret-looking value in `env` or `headers` (not `${...}`, `$VAR` or `<placeholder>`) | `sink.secret.read` with `attrs.hardcoded = true`; only the key name is recorded |
| `${...}` references under credential-looking keys | `attrs.credential_references` on the server (key names only) |

### Line numbers
YAML is loaded with `ruamel.yaml` in round-trip mode, which keeps line information for every mapping and
sequence item. JSON has no line information in the standard library, so `src/taintmap/loaders/json_lines.py`
provides a small locator that maps a JSON pointer to its line by scanning tokens. Evidence without a line
number is a bug.

Malformed files never crash a scan: the loaders return a parse warning (file, line, message, level) instead.
Warning messages name keys but never quote values, so a secret in a broken file is not echoed. YAML is
read as YAML 1.2 (`on:` stays a string) and duplicate keys are an error. JSON must be strict (no comments
or trailing commas); when a JSON object repeats a key, the last value is used and a warning is raised.

## Catalogs

Knowledge about third-party components lives in data files, not code, so contributors can extend it with a
small pull request:

- `src/taintmap/catalog/ai_actions.yaml`: GitHub Actions that run AI agents, and which inputs carry
  prompts, tool allow-lists and credentials.
- `src/taintmap/catalog/mcp_servers.yaml`: known MCP servers (matched by package name or command) and
  the capabilities their tools provide: reads untrusted content, writes files, executes commands, makes
  outbound requests, accesses a database.
- `src/taintmap/catalog/gha_triggers.yaml`: workflow triggers and expression contexts that carry
  untrusted input.

Each catalog entry has an id, a description, a `source_url` (the documentation it relies on), an
`evidence` level with a one-line `evidence_reason`, and the taxonomy categories it maps to. `evidence` is
`documented` when the source states the claim and `inferred` when it is taintmap's reading of the source.
Claims inside an entry that are less certain than the entry carry their own level: each MCP capability,
and an AI action's `reads_event` (for example, `claude-code-action` reading the triggering comment is
inferred). Graph nodes and edges built from an inferred claim carry `attrs.evidence = "inferred"`, and
reports mark findings whose path depends on one as inferred. The structure is defined by Pydantic models in
`src/taintmap/catalog/__init__.py`; the JSON schemas in `src/taintmap/catalog/schemas/` are generated from
them with `python -m taintmap.catalog`, and a test fails when the checked-in schemas are out of date or an
entry does not validate.

## Rules

Rules live in `src/taintmap/rules/`, one module per rule, each with an id (`TM001`...), a title, the risk
class it detects, a severity function and a fix template. A rule receives candidate paths and returns
findings. Rules never parse files; they only read the graph. A test checks ids, titles and default
severities against the table in the threat model.

- TM001–TM003 report `untrusted source → … LLM agent … → sink` paths (write, secret, code execution).
  For TM002, an AI action's own model credential (`model_credential_inputs` in the AI actions catalog,
  such as `anthropic_api_key`) is `high` only when the same input, through the same agent, also reaches
  `sink.code_exec` or `sink.network.outbound`; otherwise it is `info`. Other secrets stay `high`.
  A model-credential finding raised to `high` is marked inferred (`Finding.inferred_reasons`), since that
  untrusted input can make the agent leak its own key is taintmap's judgement.
  An agent step can run commands when its tool config allows a tool listed in the AI action catalog's
  `code_exec_tools` (for `claude-code-action`, `Bash` in `--allowedTools`).
- TM004 groups paths by agent and source: when the same source reaches, through the same agent, both a
  sensitive sink (`sink.data.read_sensitive` or `sink.secret.read`) and `sink.network.outbound`, one
  finding is reported. Its path ends at the outbound sink and the sensitive sinks are in `related`.
- TM005 reports paths through a workflow step to a `run:` script with interpolated untrusted input.
- Each rule reports one finding per source and sink, choosing documented paths over inferred ones and
  then the shortest.
- A finding whose sink exists only because default token permissions were assumed is one severity level
  lower than the rule's default, and its fix text ends with "Declare `permissions:` explicitly".

## Reporters

`src/taintmap/scan.py` runs the pipeline for the CLI; reporters live in `src/taintmap/report/`.

- `terminal`: findings grouped by untrusted source and AI agent (the last agent on the path), most
  severe group first, one block per finding showing each hop with file:line (rich, plain ASCII). Findings
  without an agent, such as TM005, are grouped by source alone. Each block also shows the MCP servers the input came through (`via`), related nodes (`also`),
  the missing control in plain language (`taxonomy.CONTROL_PLAIN_NAMES`; the JSON report keeps the
  ids), the fix, an `[inferred]` tag with the reasons when the finding relies on an
  inferred catalog claim, and a note when token permissions were assumed. Parse warnings and info notes
  follow the findings, then a summary line.
- `json`: one flat list of findings per rule (not grouped); stable schema, versioned with a `schema_version` field (currently `1`): `summary`, `findings`
  (each with `path`, `via_servers` and `related` hops carrying `file`, `line`, `role` and `category`,
  plus `inferred`, `inferred_reasons`, `permissions_assumed`, `missing_control`, `fix`, `fingerprint`),
  `warnings` and `files`. `tests/snapshots/demo_scan.json` pins it; regenerate it with
  `UPDATE_SNAPSHOTS=1 pytest tests/test_cli.py` when the schema changes on purpose.
- `sarif` (v0.2): SARIF 2.1.0 for GitHub code scanning.

## CLI

```text
taintmap scan [PATH] [--format terminal|json] [--output FILE] [--min-severity LEVEL]
              [--fail-on low|medium|high|critical|never] [--default-token-permissions write|read]
              [--include GLOB]... [--exclude GLOB]... [--quiet]
taintmap graph [PATH] --json          # dump the graph for debugging
taintmap bench [--split dev|test] [--final] [--format terminal|json] [--output FILE]
                                      # run the benchmark (docs/benchmark.md); test needs --final
taintmap version
```

`--quiet` prints only the terminal summary line, including the count of any file problems,
and suppresses finding details and notes. It also applies to reports written with `--output`.
It does not change exit codes. Combining `--quiet` with `--format json` is a usage error (exit `2`).

Exit codes: `0` no findings at or above `--fail-on`, `1` findings found, `2` usage or parse error.
Findings take precedence: a scan with failing findings and a broken file exits `1`, and one with only a
broken file exits `2`. Info notes (such as an unknown MCP server) never change the exit code.
If a pipe reader closes early, `scan` stops writing quietly and keeps the exit code from its findings
and parse errors. Other output errors, including failures writing a report file, are still reported.
`--min-severity` (default `info`) only filters the report; `--fail-on` (default `low`) looks at every finding, and
`never` makes the scan report-only. `--default-token-permissions` (default `write`) is what the
`GITHUB_TOKEN` may do in workflows that declare no permissions; such findings are one severity level
lower and ask for explicit permissions.

## Project layout

```text
src/taintmap/
  cli.py              Typer app
  model.py            Location, Node, Edge, Finding, GraphFragment
  graph.py            Graph wrapper, path search
  discover.py         file discovery with include/exclude
  taxonomy.py         category ids from threat-model.md and what each control blocks
  loaders/            yaml_lines.py, json_lines.py
  parsers/            Parser protocol, github_actions.py, mcp_config.py
  catalog/            *.yaml data + loader + schemas
  link.py             merging fragments and cross-file linking
  controls.py         control evaluation
  paths.py            candidate paths from sources to sinks
  scan.py             the pipeline for `taintmap scan`
  bench.py            benchmark harness
  rules/              tm001_*.py ...
  report/             terminal.py, json_report.py
benchmark/
  cases/<case-id>/    files of a minimal example system + expected.yaml
  splits.yaml         dev and test case ids
tests/                unit tests per module, plus end-to-end tests on benchmark cases
```

## Technology choices

| Need | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Matches the tooling ecosystem and contributors' skills |
| Packaging | `pyproject.toml` with hatchling | Standard, simple |
| CLI | Typer + rich | Clear help text, readable output |
| Models | Pydantic v2 | Validation and stable JSON |
| Graph | NetworkX | Mature path algorithms |
| YAML | ruamel.yaml | Line numbers |
| Java (v0.2) | tree-sitter + tree-sitter-java | Fast, robust parsing |
| Quality | pytest, ruff, mypy (strict on `src/`) | Run in CI on every push |
