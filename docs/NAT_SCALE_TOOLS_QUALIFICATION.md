# NAT, search measurement and operational tooling qualification

Task date: 2026-10-25. Starting remote main:
`2c1e702d278ce12b5e7342fff6bd73a87ae37eea`.

## Roles and isolated resources

Actual session `turn_context` metadata verified the orchestrator as
`gpt-6.1-sol` / `medium` and each implementation worker as `gpt-6-luna` / `max`.
The independent reviewer uses `gpt-6-astra` / `medium`; its verification and
review disposition are recorded below when complete. No persistent model
configuration was changed.

The task identifier is `nat-scale-20261025`. Every lab uses
`adm-nat-scale-20261025-<owner>` as its container name, `<name>-net` as its
network and `<name>-etc` / `<name>-var` as its volumes. All carry exact task and
lab ownership labels. Resources use `splunk/splunk:10.6.0.5`, image ID
`sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4`.

| Owner | Worktree directory under `~/.codex/worktrees/` | Web / management / HEC ports |
| --- | --- | --- |
| NAT | `nat-scale-20261025-nat/splunk-adm` | 28000 / 28089 / 28088 |
| Performance | `nat-scale-20261025-performance/splunk-adm` | 28100 / 28189 / 28188 |
| Refactor | `nat-scale-20261025-refactor/splunk-adm` | 28200 / 28289 / 28288 |
| Integration | `nat-scale-tools/splunk-adm` | 28300 / 28389 / 28388 |
| Reviewer | `nat-scale-20261025-reviewer/splunk-adm` | 28400 / 28489 / 28488 |

All endpoints bind only `127.0.0.1`. The cross-checkout lock for each is
`/tmp/splunk-adm-lab-<uid>-<name>.lock`. Private credentials, environment
configuration, resource manifest, container identities, and retained evidence
live outside disposable resources under
`~/.codex/task-evidence/nat-scale-20261025/<owner>/`. The resource manifest
contains no credential values.

The Docker daemon exposes 12 CPUs and 8,214,585,344 bytes RAM. Only one task
Splunk lab runs at a time. Pre-existing collectors and other resources remain
untouched. This is namespace isolation; host CPU, memory, storage and background
activity are not controlled production measurement conditions.

## Acceptance and ownership

- Orchestrator owns lab infrastructure, integration, shared configuration,
  source/package bindings, final checks and evidence reconciliation.
- NAT worker owns supported translation evidence, regression coverage and NAT
  instructions. Missing, malformed or ambiguous evidence must remain unresolved;
  firewall NAT cannot establish a separate load balancer's selected backend.
- Performance worker owns benchmark tooling, bounded measurements, workload
  correctness tests and methodology. Local results cannot establish production
  capacity or qualify the 20,000-row topology limit.
- Refactor worker owns the migration entrypoint and cohesive extracted modules.
  Fixture-generator ownership transfers only after any NAT/workload baseline
  changes are integrated. CLI, import, journal, safety and deterministic-output
  compatibility must be preserved.
- The reviewer independently inspects the integrated candidate and corrections;
  publication follows review, required CI and repository protection gates.

Isolation checks exercised separate labelled resource creation and cleanup,
showing that removing NAT's resources left performance's resources present.
Unit coverage checks foreign lab/task labels, public/wrong port bindings,
network/volume mismatch, invalid identities, authentication ordering, and Docker
inventory failure. Existing named-lock concurrency and private staging tests
remain in use. See [task lab procedure](TASK_LABS.md).

## Workstream results

Pending integrated acceptance. Historical qualification records remain bound to
their original sources and packages; they are not evidence for this candidate.
