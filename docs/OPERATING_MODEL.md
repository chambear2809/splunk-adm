# Operating model

## Role assignment

| Role | Model | Responsibility | Write access |
| --- | --- | --- | --- |
| Orchestrator | GPT-6.1 Sol | Understand request, plan, delegate, integrate, verify, report | Workspace, within sandbox |
| Implementation workers | GPT-6.1 Terra (medium) | Implement bounded, independent subtasks | Workspace, within sandbox |
| Reviewer | GPT-6 Astra (medium) | Independently inspect the finished diff and report defects | Read-only |
| Human | You / authorized maintainer | Resolve product decisions; approve commits, pushes, releases, and merges | Explicitly authorized actions |

The project default requests `gpt-6.1-terra` workers with medium reasoning. The named reviewer configuration requests `gpt-6-astra` with medium reasoning; `review_model` selects Astra for review routing but does not itself establish reasoning effort. Verify the effective model and reasoning effort in the active surface. If a named role pins another model, use an explicitly configured default agent with the requested model and medium reasoning, supplying a bounded task and fresh context. Do not silently substitute models or claim that repository settings changed an already-running agent. The reviewer must remain read-only regardless of the role used to launch it.

## Task sizing

Delegate only work that has a clear boundary and can proceed without simultaneous edits to the same files. Good examples include mapping call sites, writing tests for an agreed interface, or implementing a separate module. Keep schema changes, shared configuration, dependency changes, and cross-cutting refactors with one owner unless a lead explicitly coordinates sequencing.

Each worker assignment should state:

- the desired outcome and acceptance criteria;
- allowed files or directories;
- files or behaviors that must remain untouched;
- relevant commands and expected outputs;
- the required handoff: changed paths, decisions, tests, failures, and unresolved risks.

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
