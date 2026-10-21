# Phase 6 — Map readability

Phase 5 is committed locally as `8e1a506`. Phase 6 is on
`codex/atlas-phase-6`; its changes are committed locally.

## Changes

Service frontends now share one compact card by default. VIP, NodePort and
Ingress labels summarize frontend types; mixed policies are not presented as
one shared policy. Every original node ID remains a selection and routing
anchor. The inspector offers a frontend selector when a card represents several
frontends. The grouping setting restores individual frontend rows. Services
with the same name in different namespaces or clusters stay separate.

Network, Devices and Table views support identity, server port, evidence source,
blocked-only and infrastructure filters. Facets combine with AND semantics
before layout. Matching conversations retain their Service ownership context;
unrelated sibling workloads and traffic are excluded. Infrastructure hiding
uses the same no-application-traffic distinction as the layout. KPI buttons
provide identity and blocked shortcuts.

Focus keeps a one-, two- or three-hop neighborhood around a selected card.
Changing focus clears any selection that is no longer in the displayed graph.
A count and Clear action explain the reduced view. Findings and JSON/CSV exports
continue to use the full loaded evidence, which the UI now states explicitly.
Network-only facets clear when entering Services; Services retains traced-call
semantics and its own focus control.

Map settings offer explicit Network operations (Network view) and Application
operations (Services view) defaults. Preferences and grouping are stored per
Splunk username in optional browser storage. Explicit view links take precedence.
No persona or permissions are inferred from a role. Legend starts collapsed and
lists only relationship styles present in the displayed graph.

The standard dashboard panel boundary and existing captured demo data remain.
No data-layer schemas, saved searches, permissions, dependencies or native write
operations changed. Facets and focus are local page state; saved/shared views
remain Phase 8 scope.

## Verification

- Lint, TypeScript and formatting: passed.
- Vitest: 323 tests across 30 files passed, including dense frontend routing,
  cross-cluster identity, dense combined filtering, ownership and bounded focus.
- Playwright: 34 tests passed, including filter clearing, full-graph JSON export,
  focus depth selection cleanup, Services transitions and persona precedence.
- Browser TypeScript, Ruff check and Ruff formatting: passed.
- Offline Python suite: 161 tests passed after lab cleanup.
- Package and release archive validator: passed.
- Python 3.11 AppInspect Cloud precert: 0 errors, 0 failures, 5 existing warnings.
- Independent read-only review: no remaining actionable findings.
- Native Splunk Enterprise 10.6.0.5 search-only viewer: passed in both themes
  (1 test, 176.212 seconds), including live filters, focus, collapsed Legend,
  scope/time, catalog/Find, evidence, Data health and captured demo flows.
  The first attempt used a demo-only VM name for focus and timed out; the
  corrected check selects the actual live entry Service.
- Visual review: native dark and light filter/focus screenshots inspected.
- Lab cleanup: owned container, volumes, image, lab secrets and temporary
  research link removed; ephemeral viewer user/role cleanup completed.

Screenshots (uncommitted local diagnostics in the ignored `dist/` directory): Dark focus (`dist/atlas-phase6-focus-dark.png`) and
Light focus (`dist/atlas-phase6-focus-light.png`).

## Limits

Cloud runtime and formal Cloud vetting are not qualified by local AppInspect.
The bundle remains above the original raw/gzip size budget: 2,309,884 raw bytes
and 578,382 gzip bytes. The full data-layer suite was not rerun for these
frontend-only changes; native viewer checks exercise the unchanged search
integration.

Release archive: `dist/splunk_adm-0.2.0.tar.gz`.
SHA256: `72474dc29dfeeabe89b13416e5cb09fec335f57948011de2d5fb196c695b89d4`.
