# taintmap

**taintmap helps you see how a small piece of untrusted information can travel through software and reach something important.**

Think of it like following a trail through a big building. You start at the door where a visitor comes in. Then you follow the hallways, rooms and doors they can reach. You want to know whether that visitor can get all the way to the room where the important things are kept.

That is what taintmap does for software.

> **Project status: v0.1.0, early.** Today, taintmap scans GitHub Actions workflows and MCP client configuration files. Java/Spring code analysis and SARIF reporting are planned. Contributions and feedback are welcome.

---

## First: what does the name mean?

### What does "taint" mean?

"Taint" is a security word. It means **data that we should not trust yet**.

Imagine someone gives you a note. The note says:

> "Please open the school cupboard and take everything inside."

You do not know who wrote the note. You should not let the note control what happens.

Computers receive notes like this all the time:
- A message in a GitHub issue.
- A comment on a pull request.
- An email or support ticket.
- A web page.
- A message typed by an app user.

These things are not automatically bad. Most are perfectly normal. But they were written by someone else, so software should treat them as **untrusted input**.

The important question is: what happens after the software reads that information?

### What does "map" mean?

A map shows how places are connected.

A road map shows roads between towns. A treasure map shows the route to a treasure chest.

taintmap makes a map of how information moves inside a software project:
1. Where the information comes from.
2. Which AI agent, workflow or tool receives it.
3. Which other tools or parts of the program it can reach.
4. Whether it can reach something important, such as a secret, a database, or a way to change the project.

It draws these connections as a graph, which is a set of points joined by lines.

### Put the two words together

**taint + map = a map that follows untrusted information.**

It helps developers see whether information from an unknown or untrusted person can travel through their software and reach an action it should not control.

---

## Why is this useful?

Imagine a robot helper in a school.

The robot can:
- Read notes from children.
- Use a computer.
- Open cupboards.
- Read private files.
- Send messages.

Each ability may be useful. But what if a note from a stranger tells the robot to open a cupboard and send a private file?

The danger is not just the note. It is the whole route:

```text
A note from a stranger
        |
        v
     AI helper
        |
        v
   A computer tool
        |
        v
   Private information
        |
        v
   Send it somewhere
```

A single part may look harmless. The full route may not be safe.

Software has the same problem. An AI agent may read a GitHub issue, use an MCP tool, access a token, run a command, or change a repository. taintmap looks at how those parts connect.

---

## What does taintmap actually do?

You point taintmap at a software repository. It reads supported configuration files and builds a map of the connections it can see.

It then looks for paths from untrusted information to sensitive actions.

For example:

```text
GitHub issue comment
        |
        v
GitHub Actions workflow
        |
        v
AI coding agent
        |
        v
GitHub token with write permission
        |
        v
Can change the repository
```

taintmap can report that the comment reaches an AI agent that has permission to change the repository, and explain what protection may be missing.

### The four important parts of the map

| Simple name | Security name | Meaning |
|---|---|---|
| Starting point | **Source** | Where untrusted information enters, such as an issue or web page |
| Middle step | **Carrier** | Something that passes the information along, such as an AI agent or workflow |
| Important action | **Sink** | Something that can cause harm, such as reading a secret or changing data |
| Safety guard | **Control** | A protection, such as human approval, a trusted-person check or limited permissions |

A source is not automatically dangerous. A sink is not automatically a bug. taintmap looks for a **path** connecting them without a protection that blocks that path.

### What can taintmap look for?

The current version understands:

- **GitHub Actions:** workflows that run when issues, comments, pull requests or other events happen. It checks how event information reaches workflow steps and AI actions, and what permissions those steps have.
- **MCP client configuration:** files that tell AI applications which tools they can use, such as GitHub, filesystem or browser tools.
- **Connections between them:** for example, an AI action that loads an MCP configuration and can use one of its tools.

The current version does not yet analyse Java/Spring application code. That is planned for a later milestone.

### What kinds of risky paths can it report?

The current rules look for patterns such as:

- Untrusted information reaching an AI agent that can write to a repository.
- Untrusted information reaching an AI agent that can access secrets.
- Untrusted information reaching an AI agent that can run commands.
- An AI agent combining untrusted information, sensitive access and outbound network access.
- Untrusted information being inserted into a shell command in a workflow.

These are warning signs to investigate, not proof that an attacker has already done something.

---

## How does it help developers?

For every finding, taintmap tries to show:

- **Where it starts:** the file and line containing the untrusted input.
- **Where it goes:** the workflow, agent or tool that carries it.
- **Where it can end:** the sensitive permission or action.
- **Why it matters:** the missing protection.
- **What to consider changing:** for example, limiting permissions, checking who can trigger a workflow, or requiring human approval.

It uses the actual file locations it can find, so a developer can open the file and inspect the evidence.

taintmap is a helper for finding and understanding risks. A person should review the evidence and decide what to change.

---

## Try it

Install the v0.1.0 release and scan the current folder:

```bash
pip install "git+https://github.com/aakashsiwach/taintmap@v0.1.0"

# Scan the current repository
taintmap scan .

# Save the report as JSON
taintmap scan . --format json --output taintmap.json

# Return a failing exit code for high-severity findings
taintmap scan . --fail-on high --default-token-permissions read
```

You can also scan a repository by giving its folder path:

```bash
taintmap scan ./my-project
```

### Example finding

Here is a simplified example of what taintmap may report:

```text
HIGH  TM001  Untrusted input reaches an AI agent with write access

START
  GitHub issue comment
  .github/workflows/respond.yml:2

THROUGH
  AI coding agent
  .github/workflows/respond.yml:9

CAN REACH
  GitHub token with issues: write permission
  .github/workflows/respond.yml:4

WHY IT MATTERS
  The agent receives text written by someone else and has permission
  to make changes in the repository.

POSSIBLE FIX
  Check that the person triggering the workflow is trusted,
  remove permissions the agent does not need, or require human approval.
```

The exact output includes the rule, evidence path and suggested protection. The example above is simplified to make it easier to read.

### What do the exit codes mean?

| Code | Meaning |
|---|---|
| `0` | No findings at or above the selected severity |
| `1` | One or more findings at or above the selected severity |
| `2` | A command or input error, or a file that could not be parsed (when there are no failing findings) |

See [docs/architecture.md](docs/architecture.md#cli) for all command options.

---

## How does it decide what to report?

taintmap follows three important rules:

1. **Show the evidence.** A finding should show the path and file locations that support it. It should not make a claim just because something sounds scary.
2. **Be honest about uncertainty.** Some information comes directly from documentation; other connections are inferred. Reports mark inferred paths so developers can judge them.
3. **Help people fix problems.** taintmap explains the missing protection and suggests a safer approach. It does not create exploits or attack systems.

The project includes a public benchmark with small, deliberately designed safe and vulnerable examples. This lets us measure how many expected problems the tool finds and how often it raises unexpected findings.

## Results

Accuracy is measured on the open benchmark described in [docs/benchmark.md](docs/benchmark.md). The v0.1.0 numbers below were measured on commit `411c672` (tag `v0.1.0`) in a single `--final` run of the held-out test split, against the original expectations of its eight independently written cases.

| Split | Cases | Recall | Precision | False-positive rate on safe cases |
|---|---|---|---|---|
| test (held out) | 8 (5 vulnerable, 3 safe) | 0.80 (4/5) | 0.67 (4/6) | 0.00 (0/3) |
| dev (used for tuning) | 20 (10 vulnerable, 10 safe) | 1.00 (12/12) | 1.00 (12/12) | 0.00 (0/10) |

Per rule on the test split (recall / precision): TM001 1.00 / 1.00, TM002 1.00 / 0.50, TM003 0.00 / 0.00, TM004 1.00 / 1.00, TM005 1.00 / 1.00. Both errors are in one case, `tm003-pr-agent-bash`: the command-execution sink was reported on a different line than expected, and a TM002 finding for the agent's model credential was not expected. The full output is in [results/bench-test-v0.1.txt](results/bench-test-v0.1.txt). Changes made after v0.1.0 are listed under *Unreleased* in the [changelog](CHANGELOG.md); they do not change the v0.1.0 numbers, which stay as measured.

## What taintmap does not do

It is important to know the limits:

- It does not prove that a system is completely safe.
- It does not run attacks or try to steal information.
- It does not know every tool or framework. Unknown MCP servers are reported as notes, not guessed risks.
- It does not currently analyse Java/Spring application code. That is planned.
- It cannot see every protection that exists outside the files being scanned, such as organisation settings, unless those protections are declared in a future manifest.

A clean scan means "taintmap did not find a matching risky path in the files and patterns it understands." It does not mean "there are no security problems."

---

## The roadmap

| Milestone | What we plan to add |
|---|---|
| **v0.1 — now** | Map GitHub Actions workflows and MCP client configurations; find paths from untrusted input to sensitive actions; terminal and JSON reports |
| **v0.2 — next** | A project manifest for extra information, more detailed MCP tool data, Java/Spring code analysis and SARIF reports |
| **v0.3 — after that** | A GitHub Action, a pre-commit hook and importing results from other security scanners |
| **Later** | Python and Node.js code, automation tools such as n8n, runtime traces and suggested fixes |

See [docs/plan.md](docs/plan.md) for the detailed task list.

## Documentation

| Document | What it covers |
|---|---|
| [VISION.md](VISION.md) | Why taintmap exists and where it is going |
| [docs/architecture.md](docs/architecture.md) | How the graph, parsers, rules and CLI work |
| [docs/threat-model.md](docs/threat-model.md) | Sources, carriers, sinks, controls and security rules |
| [docs/benchmark.md](docs/benchmark.md) | How accuracy is measured |
| [docs/plan.md](docs/plan.md) | Development plan and acceptance criteria |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release |

## Contributing

Want to help? Great! Small contributions are welcome.

Some useful ways to help:
- Add safe and unsafe examples to the benchmark.
- Add information about tools and the things they can do.
- Help improve GitHub Actions or MCP scanning.
- Help build the planned Java/Spring support.
- Improve documentation and tests.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Security vulnerabilities in taintmap itself should be reported privately using [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Aakash Siwach
