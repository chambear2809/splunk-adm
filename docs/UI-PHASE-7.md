# Phase 7 — Panels and language

Phase 6 is committed as `b9ba941`. Phase 7 is committed as
`74d8a4a` (`74d8a4a85c896ab1b647619b6e3856e05ee555ee`).

## Changes

Candidate path strips appear only on Network and Services. Table and Devices
retain a “Show candidate path” action in the inspector, which opens Network.
Path visibility accurately controls whether the inspector offers that action.

Inspector headings truncate to one line. “Full name” reveals the exact collected
name and offers Copy name, with success or failure feedback. The copy button is
disabled while a request is pending to prevent conflicting results. Failed
clipboard access leaves the complete selectable name available. The inspector
grid is constrained so long names truncate instead of widening the panel.

A banner explains map dimming caused by a highlight or selection. Its counts
use the same predicates as the rendered cards and routed connections, including
grouped frontends, collapsed pods and combined handoffs. Search emphasis takes
precedence over selection. Clear removes both highlight and selection without
changing graph filters, focus or the loaded evidence. Banner interactions do
not initiate canvas dragging.

Toolkit Tooltip now supplies keyboard-accessible definitions through InfoTip
and the typed glossary. Inspector and path labels explain DSR, Local, IPIP,
SNAT, Hybrid, inferred, Determined, Not determined and policy Intent.
Definitions distinguish backend evidence from a proven packet route. Tests
check definitions for UI term references and shared emphasis behavior.

The standard Splunk dashboard panel boundary, captured demos, native search
client, permissions and data-layer definitions are unchanged.

## Verification

- Lint, TypeScript, formatting, package and release validation: passed.
- Unit suite: 331 passed across 32 files.
- Offline Python suite: 161 passed after lab cleanup; Ruff checks passed.
- Browser checks: 40 passed, including copy success/failure, pending-copy
  protection, keyboard tooltips and genuine collected-name truncation.
- Independent read-only review: no remaining actionable findings.
- Cloud AppInspect precertification: passed the report gate; 0 errors,
  0 failures, 5 existing warnings.
- Native search-only viewer on Splunk Enterprise 10.6.0.5: passed against
  the final package in dark and light themes (200.516 seconds). Both live
  searches and captured demo flows exercised path navigation, copy, dimming,
  keyboard tooltips and long-name truncation.
- The additional browser assertion comparing banner counts with rendered
  card/connection dimming passed.
- Owned lab container, volumes, image and secrets were purged; the temporary
  research link and viewer identity were removed. Foreign containers were
  preserved.

Native screenshots (local, ignored build artifacts):

- [Dark inspector](../dist/atlas-phase7-long-name-dark.png)
- [Light inspector](../dist/atlas-phase7-long-name-light.png)
- [Dark tooltip](../dist/atlas-phase7-tooltip-dark.png)
- [Light tooltip](../dist/atlas-phase7-tooltip-light.png)

The final archive SHA256 is
`5a7cabddeac05c628ad3245f82fe9df18cca0e500d39318765fa6a265f55b159`.
The shared bundle is 2,316,080 bytes raw and 580,625 bytes gzip.

## Limits

Cloud runtime and formal Cloud vetting remain unverified. Bundle size remains
above the original budget. No data-layer definitions changed; the full data-layer
suite is not rerun for this phase. Native browser qualification exercises the
unchanged live search integration.
