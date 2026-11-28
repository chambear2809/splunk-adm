# Operating model

## Role assignment

Cursor project subagents live in `.cursor/agents/`. Codex agents live in `.codex/agents/`. The two stay in sync; `tests/test_agent_definitions.py` fails if a role exists in only one tool, a reviewer is not read-only, or the instruction text drifts.

| Role | Cursor | Codex | Responsibility | Write access |
| --- | --- | --- | --- | --- |
| Distinguished Engineer — Orchestrator | Gemini Neon (`gemini-4-neon-high`), chosen in the model picker | GPT-6.1 Sol | Architecture, plan, delegate, integrate, verify, report | Workspace, within sandbox |
| Staff Protocol Engineer (`protocol-worker`) | Gemini Hydrogen (`.cursor/agents/protocol-worker.md`) | GPT-6.1 Terra (medium) (`.codex/agents/protocol_worker.toml`) | Implement bounded protocol-lens subtasks | Disjoint lens paths |
| Staff Ecosystem & Data Engineer (`ecosystem-worker`) | Gemini Hydrogen (`.cursor/agents/ecosystem-worker.md`) | GPT-6.1 Terra (medium) (`.codex/agents/ecosystem_worker.toml`) | Implement bounded non-lens ecosystem, trace, impact, and data-adapter subtasks | Disjoint feature paths |
| Principal Security & Reliability Reviewer (`code-reviewer`) | Claude Opus 5.5 (`.cursor/agents/code-reviewer.md`) | GPT-6 Astra (medium) (`.codex/agents/reviewer.toml`) | Independently inspect the finished diff and report defects | Read-only |
| Principal Design & UX Reviewer (`ux-reviewer`) | Claude Opus 5.5 (`.cursor/agents/ux-reviewer.md`) | GPT-6 Astra (medium) (`.codex/agents/ux_reviewer.toml`) | Independently inspect screenshots and UI diffs against the Protocol Lens UX contract | Read-only |
| Human | You / authorized maintainer | You / authorized maintainer | Resolve product decisions; approve commits, pushes, releases, and merges | Explicitly authorized actions |

The project default requests `gpt-6.1-terra` workers with medium reasoning. The named reviewer configuration requests `gpt-6-astra` with medium reasoning; `review_model` selects Astra for review routing but does not itself establish reasoning effort. Verify the effective model and reasoning effort in the active surface. If a named role pins another model, use an explicitly configured default agent with the requested model and medium reasoning, supplying a bounded task and fresh context. Do not silently substitute models or claim that repository settings changed an already-running agent. The reviewer must remain read-only regardless of the role used to launch it.

## Task sizing

Delegate only work that has a clear boundary and can proceed without simultaneous edits to the same files. Good examples include mapping call sites, writing tests for an agreed interface, or implementing a separate module. Keep schema changes, shared configuration, dependency changes, and cross-cutting refactors with one owner unless a lead explicitly coordinates sequencing.

Each worker assignment should state:

- the desired outcome and acceptance criteria;
- allowed files or directories;
- files or behaviors that must remain untouched;
- relevant commands and expected outputs;
- the required handoff: changed paths, decisions, tests, failures, and unresolved risks.

Protocol-lens workers use the template in [docs/superpowers/specs/2026-11-27-protocol-worker-brief.md](superpowers/specs/2026-11-27-protocol-worker-brief.md). Ecosystem workers use [docs/superpowers/specs/2026-11-27-ecosystem-worker-brief.md](superpowers/specs/2026-11-27-ecosystem-worker-brief.md). The UI/UX reviewer uses [docs/superpowers/specs/2026-11-27-protocol-lenses-ux.md](superpowers/specs/2026-11-27-protocol-lenses-ux.md).

The default cap is four concurrent subagent threads. The root agent counts separately. Keep nesting disabled so the root owns the task graph and review path.

## Review and merge gates

1. Root agent confirms the task scope and acceptance criteria.
2. Workers implement disjoint tasks and return evidence.
3. Root agent integrates changes, examines the full diff, and runs checks.
4. Astra reviewer independently challenges assumptions and examines the final diff read-only.
5. Root agent fixes verified findings and reruns affected checks.
6. A human examines the final patch and authorizes any commit, push, or merge.

Reviewers should not be rewarded for finding a fixed number of issues. They should report only specific problems introduced by the change, with evidence and impact.

## Operational evidence

For each substantial change, retain the task statement, role/model assignment, changed-path list, relevant commands and exit status, review findings, remediation, and final human disposition. Use the repository's approved CI and PR records; do not put secrets or unrestricted transcripts into git.
