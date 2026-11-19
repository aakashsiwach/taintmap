# Build plan

Work through the tasks **in order**. Each task is small enough for one focused session and one commit
(or a few). Tick the checkbox in this file in the same commit that completes the task.

Every task is done only when:
- its acceptance criteria are met,
- `ruff check`, `ruff format --check`, `mypy src` and `pytest` all pass,
- new behaviour has tests,
- docs are updated if behaviour or commands changed.

Design references: [architecture.md](architecture.md), [threat-model.md](threat-model.md),
[benchmark.md](benchmark.md).

---

## Milestone v0.1: the map for workflows and MCP configs

### T0. Project skeleton
- [x] `pyproject.toml` (hatchling, Python ≥ 3.11, package `taintmap` in `src/`), console script `taintmap`.
- [x] Dependencies: typer, rich, pydantic>=2, networkx, ruamel.yaml. Dev extra: pytest, ruff, mypy.
- [x] `taintmap version` prints the version from package metadata.
- [x] `.gitignore` for Python, venvs, caches, `dist/`.
- [x] GitHub Actions CI: ruff, mypy, pytest on Python 3.11 and 3.12, ubuntu and windows. Pin actions to
      full commit SHAs and set `permissions: contents: read`.
- [x] `CONTRIBUTING.md` with setup commands for Windows PowerShell and bash.

**Acceptance:** fresh clone → `pip install -e ".[dev]"` → `taintmap version` works; CI is green.

### T1. Core model and graph
- [x] `model.py`: `Location`, `Node`, `Edge`, `Finding`, `GraphFragment` as in architecture.md, with the
      `kind` and edge-kind enums.
- [x] `graph.py`: `Graph` with `add_fragment`, `nodes_of_kind`, `paths(source_id, sink_id, max_depth=8)`
      returning simple paths, and `to_json()`.
- [x] Node ids are unique; adding a duplicate id with different content raises a clear error.

**Acceptance:** unit tests cover fragment merging, duplicate ids, path search on a small hand-built graph,
and JSON round-trip.

### T2. Discovery
- [x] `discover.py`: walk a root, skip `.git`, `node_modules`, virtualenvs, `dist`, `build` and hidden
      directories except `.github`, `.cursor`, `.vscode`, `.mcp.json`.
- [x] Include/exclude globs from CLI options.
- [x] Never follow symlinks that point outside the root.

**Acceptance:** tests with a temporary directory tree, including a symlink escaping the root.

### T3. Loaders with line numbers
- [x] `loaders/yaml_lines.py`: load YAML with ruamel round-trip; helper to get the line of any key or
      sequence item.
- [x] `loaders/json_lines.py`: load JSON and map a JSON pointer (e.g. `/mcpServers/github/env/TOKEN`) to
      its 1-based line.
- [x] Malformed files produce a parse warning (file, line, message), not a crash.

**Acceptance:** tests for nested keys, lists, duplicate-looking keys, CRLF files, and malformed input.

### T4. Threat-model taxonomy in code
- [x] `taxonomy.py`: the source, carrier, sink and control category ids from threat-model.md as constants
      or enums, plus which control categories block which risk classes.
- [x] A test that every category id mentioned in threat-model.md exists in code (parse the markdown table).

**Acceptance:** taxonomy test passes; docs and code cannot drift silently.

### T5. Catalogs
- [x] `catalog/gha_triggers.yaml`: untrusted triggers (`issues`, `issue_comment`, `pull_request_target`,
      `discussion`, `discussion_comment`, `pull_request_review_comment`, `workflow_run`) and untrusted
      expression contexts (`github.event.issue.title`, `.body`, `github.event.comment.body`,
      `github.event.pull_request.title`, `.body`, `.head.ref`, and similar), each with a documentation link.
- [x] `catalog/ai_actions.yaml`: GitHub Actions that run AI agents. Start with entries you can verify
      from the action's own README (inputs that carry the prompt, tool allow-lists, and credentials).
      Each entry needs a source link. Do not guess input names.
- [x] `catalog/mcp_servers.yaml`: well-known MCP servers matched by package name or command, with
      capabilities mapped to taxonomy categories. Each entry needs a source link.
- [x] JSON schemas for the catalogs and a test that validates every entry.

**Acceptance:** schema tests pass; every entry has a source link.

### T6. GitHub Actions parser
- [x] Parse workflows into nodes and edges:
  - triggers → `source` nodes when listed in the triggers catalog
  - jobs and steps → `carrier.workflow_step`; steps using a catalogued AI action → `carrier.llm_agent`
  - `${{ ... }}` expressions with untrusted contexts in `with:`, `env:` or `run:` → `passes_input` edges
  - `run:` steps → `sink.code_exec`
  - effective permissions (workflow and job level, including the default when absent) → capability and
    sink nodes such as `sink.repo.write`
  - `secrets.*` references in `env:`/`with:` → `sink.secret.read`
  - `if:` conditions on `author_association` or maintainer-only labels → `control.trusted_actor_gate`
  - `environment:` on a job → `control.human_approval` (note: required reviewers cannot be verified from
    the file; record it as "declared")
  - untrusted input passed via `env:` and referenced as `$VAR` in `run:` → `control.input_isolation`
- [x] Every node and edge has a location with a line number.

**Acceptance:** tests with at least 8 small workflow fixtures covering each bullet.

### T7. MCP config parser
- [x] Parse `mcpServers` (and the `servers` key used by some clients) from supported files.
- [x] Each server → `carrier.mcp_server` node; capabilities from the MCP catalog → sink/source nodes.
- [x] Unknown servers → a node with `attrs.unknown = true` and an info-level note, not a finding.
- [x] Literal secret-looking values in `env` (not `${...}` references) → `sink.secret.read` with
      `attrs.hardcoded = true`. Never print the value; show only the key name.
- [x] The client that loads the config → one `carrier.llm_agent` node connected to all its servers.

**Acceptance:** fixtures for each supported file format; tests for unknown servers and hardcoded secrets.

### T8. Linking and path search
- [x] `link.py`: merge fragments; connect nodes across files where names match (for example, a workflow
      step that loads a repo's `.mcp.json`).
- [x] `controls.py`: given a path, decide whether an effective control blocks it, using the taxonomy.
- [x] Path search from every source to every sink with a depth limit and a cap on paths per pair.

**Acceptance:** tests where a control blocks a path and where an unrelated control does not.

### T9. Rules TM001–TM005
- [x] One module per rule as specified in threat-model.md, each with title, severity, missing control and
      fix text.
- [x] Stable fingerprints.
- [x] Findings that reach a sink only through assumed default token permissions
      (`attrs.permissions_assumed`) are one severity level lower, and their fix text says
      "declare `permissions:` explicitly".

**Acceptance:** each rule has a vulnerable and a safe test fixture.

### T10. Reporters and `scan` command
- [x] `taintmap scan [PATH]` with `--format terminal|json`, `--output`, `--min-severity`, `--fail-on`.
- [x] Terminal report as in the README example: one block per finding, each hop with `file:line`.
- [x] JSON report with `schema_version: 1`.
- [x] Exit codes as in architecture.md.
- [x] `--default-token-permissions write|read` (default `write`), passed to the GitHub Actions parser.
- [x] Findings whose path depends on an `inferred` catalog claim (`attrs.evidence` on a node or edge)
      are shown as "inferred" in both reports.
- [x] `--include` / `--exclude` globs (repeatable), passed to discovery.
- [x] `--quiet` for a summary-only terminal report, preserving exit codes and rejecting JSON.

**Acceptance:** end-to-end test running the CLI on a fixture repository; snapshot test of JSON output.

### T11. Benchmark harness and first cases
- [x] `taintmap bench` implementing benchmark.md (matching, metrics, per-rule table, misses list).
- [x] At least 20 cases: for each rule, at least 2 vulnerable and 2 safe. `splits.yaml` with about 70% dev
      and 30% test, stratified by rule.
- [x] `--final` is required to run the test split.

**Acceptance:** `taintmap bench --split dev` runs in CI and its output is saved under `results/`.

### T12. Release v0.1.0 *(needs the maintainer)*
- [x] README: replace planned wording with real usage; add benchmark numbers from the test split.
- [x] `CHANGELOG.md`.
- [ ] Stop here and ask the maintainer to review, tag and publish. Do not tag, publish or push without
      being asked.

---

## Milestone v0.2: into the code

- T13. `taintmap.yaml` manifest: declare agents, tools and controls that cannot be discovered from files.
- T14. Tool manifest import: read a dumped MCP `tools/list` result to get exact tools and descriptions.
- T15. Java/Spring layer with tree-sitter: endpoints, controllers, services, repositories; link MCP tools
       or HTTP calls to the code they reach; repository write methods → `sink.data.write`.
- T16. SARIF 2.1.0 reporter.
- T17. Benchmark: Java/Spring cases.

## Milestone v0.3: in every pipeline

- T18. Composite GitHub Action `taintmap-action` that uploads SARIF.
- T19. pre-commit hook.
- T20. Importers for SARIF from other scanners, attached to graph nodes.
- T21. Policy file: allowed paths, enforced in CI.
