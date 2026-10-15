# Phase 5 — Data health and administrator Setup

Phase 4 was committed locally as `aa3b173`. Phase 5 is on
`codex/atlas-phase-5`; these changes are committed locally.

## Changes

Data health now has its own page with Toolkit tables for sources, flow quality
and saved-search history. The shared header indicator links to that page and
refreshes live evidence every five minutes. Missing permissions, unavailable
results and Demo remain unknown or need review. Demo selection moved into Map
settings; navigation preserves the selected mode. The standard dashboard panel
boundary is retained.

Setup reads the nine index macros, summary-index availability, stored observer
mappings, seven builder schedules and last-run evidence from `adm_health_jobs`.
It checks both `observer_kind` and `observer` for uppercase stored keys, rejects
blank keys, pages the collection with a 20,000-row completeness limit, and shows
a labeled preview of the first 20 rows. An absent/hidden index response stays
unconfirmed. Summary reader/writer mismatch or incomplete prerequisites prevent
schedule activation.

Native REST writes use Toolkit CSRF defaults, fixed endpoint allowlists,
administrator role checks and each object's write ACL. Index edits accept one
lowercase index name; schedule activation preserves the configured cadence.
Requests have a 30-second deadline, forward cancellation and never automatically
retry writes. After each mutation, the requested target state must be read back
before success is shown. Prune and recovery searches have no enable action.
Cloud index creation links to ACS, and recovery and observer configuration link
to the operator documentation. The contradictory prune instructions in the
setup guide now agree with the pilot guide.

## Verification

- `npm run lint` and `npm test`: passed; 310 unit tests across 28 files.
- `python3 -m unittest discover -s tests -p 'test_*.py'`: 161 passed after lab cleanup. The earlier concurrent attempt was blocked by the held lab lock.
- `npm run test:browser`: 29 passed, including actual clock advancement across
  the five-minute refresh, unknown/uppercase/empty prerequisites, write
  verification failure and classic-dashboard input styling.
- `npm run typecheck:browser`, `npm run package`, and
  `python3 tools/check_release.py --dist dist`: passed.
- Python 3.11 Cloud AppInspect precert and `tools/check_appinspect.py`: passed,
  zero failures, zero errors and the same five warnings.
- Focused Splunk 10.6.0.5 qualification passed: two viewer write-denial tests
  and the native administrator Setup browser test (3 tests, 5.872 seconds).
  The native restricted-viewer browser test also passed, exercising light/dark
  themes, live Data health, catalog/Find/map flows and Demo.
- `ruff check tools tests`, `ruff format --check tools tests`, and
  `git diff --check`: passed.
- The full data-layer suite was not rerun in Phase 5; this phase changes UI and
  administrative REST clients, with focused live qualification above.
- Independent read-only review found and resolved request deadlines, write
  verification, blank observer keys, stale health status and stale progress copy.
- Visual inspection covered the Setup checklist and dark Data health tables.

## Native endpoint qualification

The original plan expected HTTP 403 for Setup writes. The real server returns
403 for forbidden macro writes, 404 for hidden administrator-only saved-search
writes, and 400 (`is_scheduled` unsupported by the restricted handler) for the
combined scheduling payload. Tests assert these observed responses and verify
that definitions and schedule fields remain unchanged. The 400 alone does not
prove an ACL-specific rejection; the administrator browser separately verifies
that the same scheduling payload succeeds with the intended permissions.
Client-side role and object-ACL guards also prevent viewer mutations. Existing
administrator-only saved-search permissions are retained.

Initial live test attempts exposed two harness assumptions: viewer config reads
were forbidden, and saved-search writes did not uniformly return 403. Those
assertions were corrected using admin before/after reads and the actual denial
responses. A lightweight admin fixture now waits for KV readiness after restart.

The lab lifecycle held the cooperative lock, refused a pre-existing container,
and installed the source app. Permission tests restored modified baselines and
removed their temporary users/roles; the administrator browser restored its
macro, schedule flags and cadence and removed its temporary observer row.
Cleanup removed the owned container, volumes, image, secrets and temporary
research link. The three foreign collector containers were untouched. The
temporary preview server and browser tab were closed.

Final archive SHA-256:
`ea00d9fb7bcc4bb52705c01f2ddef3dad1970db466c306d0e32075f27ea94d4c`.

Native Setup screenshot: `dist/atlas-phase5-setup-native.png`.

## Limits

Splunk Cloud runtime and formal Cloud vetting remain unverified. Local
AppInspect is a compatibility check, not formal Cloud approval. The bundle
is 2,301,293 raw / 575,907 gzip bytes, above the original 1.2 MB raw / 350 KB gzip comparison budget.
No production resources were changed.
