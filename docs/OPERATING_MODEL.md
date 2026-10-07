# Operating model

## Role assignment

| Role | Model | Responsibility | Write access |
| --- | --- | --- | --- |
| Orchestrator | GPT-6.1 Sol | Understand request, plan, delegate, integrate, verify, report | Workspace, within sandbox |
| Implementation workers | GPT-6 Luna | Implement bounded, independent subtasks | Workspace, within sandbox |
| Reviewer | GPT-6.1 Sol | Independently inspect the finished diff and report defects | Read-only |
| Human | You / authorized maintainer | Resolve product decisions; approve commits, pushes, releases, and merges | Explicitly authorized actions |

The project default makes spawned workers Luna. The named reviewer role and `/review` model setting route reviews to Sol. If the current Codex surface does not expose named roles, use `/review`; do not assume a worker has the reviewer role merely because its task says “review.” Confirm actual roles/models in the agent details when available.

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
4. Sol reviewer examines the final diff read-only.
5. Root agent fixes verified findings and reruns affected checks.
6. A human examines the final patch and authorizes any commit, push, or merge.

Reviewers should not be rewarded for finding a fixed number of issues. They should report only specific problems introduced by the change, with evidence and impact.

## Operational evidence

For each substantial change, retain the task statement, role/model assignment, changed-path list, relevant commands and exit status, review findings, remediation, and final human disposition. Use the repository's approved CI and PR records; do not put secrets or unrestricted transcripts into git.
