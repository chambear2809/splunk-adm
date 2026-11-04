# Device-path fault gate decision record

Status: recommendation for review, not authorization or an active policy. The production gate remains strict. Traversal remains `not_observed`. The single-group run `34a0232fbb62` completed with independent `RESTORED_VERIFIED`; its stage-v5-r6 exception was approved for one attempt and is spent.

## Alternatives and decision

1. **Strict stop (current):** any finding under the existing complete, authenticated fault comparison stops the operation and invokes recovery. It detects unrelated changes, including the recorded power-supply flap, but transient attach faults can prevent observation.
2. **Bounded settle-and-clear (future candidate):** suspend progress while a specifically identified attach fault clears, with complete repeated captures and a fixed deadline. This reduces nuisance stops while refusing an active fault at the end of the wait; it delays the operation and cannot prove that an unobserved intermediate fault did not occur. It needs qualified fault lifecycle and timestamp semantics and explicit future approval.
3. **Documented acceptance allowlist:** permit an active matching fault while proceeding, with narrowly pinned scope and an audit trail. This offers more availability but accepts a potentially consequential fault during observation; stale identity, re-raise, or an overly broad entry can hide a real problem. A document or matching code is not authorization.

Recommend retaining strict stop now and investigating option 2 for a future explicitly approved operation. Do not deploy or activate it on the strength of this record. Option 3 is not recommended as a standing production policy. Neither option changes authentication, capture completeness, clock, fault-gap, observation, recovery, or evidence guarantees.

## Candidate settle contract for review

These are proposed requirements, not a claim of APIC semantics. An operator must first verify fault lifecycle meanings, timestamp precision and clock error, complete capture behavior, and the relationship between attach and fault creation on the target version. An approved policy would bind an operation ID, exact class, code, finite set of exact DNs derived from a reviewed plan, a maximum count, severity ceiling, allowed lifecycle transitions, attach time, bounded clock uncertainty, creation interval, settle budget, poll cadence, and immutable policy hash. No wildcard, prefix, global code exemption, implicit default, or reuse of a prior authorization is permitted. The candidate starts disabled and missing or invalid policy inputs fail closed.

For review, define creation interval `[attach - 10 s, attach + 60 s]`, inclusive, only after the clock uncertainty has been explicitly bounded and accounted for in these limits; these historical numbers are not production defaults. Require a timezone-aware creation time, and `lastTransition > created` on first encounter. Each subsequent observation must retain the same identity and creation instant, have nondecreasing transition time, and conform to a reviewed lifecycle transition graph. A new creation time, a return to raised/active after clearing, severity above the ceiling, unknown value or malformed timestamp stops and recovers. The exact terminal state and whether absence in a complete capture means cleared are unresolved source-specific decisions; until approved, neither permits continuation. A candidate must require a positive, source-qualified terminal clear and a complete confirming capture; no finding can simply be filtered from the final comparison.

State machine: `STRICT` stops on any finding unless a fresh operation-specific approval selects the candidate. On the first matching finding enter `WAITING`, pin its identity and creation time, and record all findings. While waiting, repeat complete fault captures at an approved cadence; any unrelated or additional fault, invalid capture, change of pinned identity, invalid transition or deadline exhaustion enters `STOP` and recovery. Only all matching faults positively clear and a confirming capture passes the unchanged strict comparison permits `CLEARED` and further progress. Continued polling remains strict, and a re-raise stops. After restoration run the unchanged strict final delta: no new exception, including for a previously seen identity. Failure to obtain complete after-restore evidence fails the operation, even if recovery itself is verified.

The wait budget and every read must fit within the existing monotonic operation deadline, fault-gap limits, lease and clock bounds, health windows, guardian recovery reservation and caller deadline. It cannot extend any deadline or borrow recovery time. Refuse to start a poll without enough bounded time to complete it and preserve recovery; timeouts, cancellation, partial results, time rollback or uncertainty trigger stop and recovery. Record policy and plan hashes, approval identifier and scope, baseline and complete capture references and hashes, wall and monotonic times, clock bounds, each finding and transition, deadlines, decisions, recovery and after-restore outcomes in the protected audit journal. Record no credentials or customer data in repository documentation.

## Acceptance test matrix for a future implementation

Tests assume an otherwise valid, complete authenticated baseline and captures; all decisions below remain subject to the unchanged strict gate. Boundary cases use representable timestamp precision and separately test the immediately adjacent representable instant.

| Case | Expected candidate behavior |
| --- | --- |
| Exact class, code and DN; approved lifecycle, severity and first transition; creation within interval | Wait, never immediately continue; continue only after positively qualified clear and confirming strict capture. |
| Creation exactly at either bound | Eligible to wait; immediately below lower or above upper bound stops. Earlier creation within the interval remains eligible only if other checks pass; before the lower bound stops. |
| Different DN, code or class; third fault beyond approved maximum | Stop and recover, including when matching faults are also present. |
| Lifecycle changes | Only reviewed forward transitions can remain waiting; unknown, active/re-raised, regressions or unapproved state stops. Terminal semantics require separate approval. |
| Severity equal to ceiling / immediately above | Equal may wait; above, unknown or missing stops. |
| First `lastTransition` equal to or before `created` / just after | Equal or before stops; just after may wait. Later transition equal to prior transition may remain waiting if otherwise valid; regression stops. |
| Repeated polls | Preserve original creation identity, monotonic timestamps, complete captures and gap/deadline limits; unchanged still-active finding cannot extend the budget. Changed creation, missing or malformed data, partial capture or timeout stops. |
| Re-raise | Stop, even with same DN and code; a changed creation time also stops. |
| After restore | Any new or unresolved finding is evaluated by strict final delta; no new or continuing allowance. Incomplete final evidence fails. |

## Historical source identity and limits

The locally available `launch-v4/stage-v5-r6/controller.py` SHA-256 is `f49da2c845d8041ed423e9196b92e917f52bc05f8731e870e9d34c35df6a1782`; its `bundle-manifest.json` SHA-256 is `d28461f2f0807a9a0c8f9ea9c1ac1d3d0760209d6bc1dc3177de429b03c66107`. Both match the prefixes in the [checkpoint](DEVICE_PATH_QUALIFICATION_STATUS.md). This establishes local byte identity against that record, not independent custody of the source or every bundle member. The historical code accepted specified F2571 findings during capture with creation from attach minus 10 through plus 60 seconds, lifecycle `soaking-clearing` or `retaining`, severity at most major, and first transition strictly after creation; later matching used the same creation string and allowed `lastTransition >= created`. Its final-delta filter could recognize previously accepted entries, but did not admit a new exception after restore. These are historical observations, not the proposed settle policy or a standing authorization.

## Port decision

No r6 fault-filter implementation is ported into `tools/`. The repository has no equivalent complete trial-controller fault-evidence pipeline to integrate it with, and the proposed wait depends on unresolved terminal lifecycle, absence, clock-error and confirmation semantics. Extracting the historical acceptance filter alone would create a callable relaxation without its collection, time, recovery and journal guards. A future port requires an independently reviewed contract and tests for those integrated guards; the historical reviewed source and spent approval do not resolve that dependency.
