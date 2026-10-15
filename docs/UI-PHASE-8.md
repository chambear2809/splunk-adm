# Phase 8 — Changes, exports and saved views

Phase 7 is committed locally as `74d8a4a`. Phase 8 is on
`codex/atlas-phase-8`; its changes remain local and uncommitted.

## Behavior

Changes compares the loaded graph with the immediately preceding window of
exactly the same duration. It uses the loaded snapshot's bounds and scope,
not unfinished picker edits or a newly evaluated relative time. Requests can
be cancelled and are aborted when the panel closes or its snapshot changes.

Connections are matched by exact edge ID. Pod entities are compared by
cluster, namespace and owner/service, ignoring replacement UID, generated
name and address. Connection IDs containing a pod UID can still appear as an
added/removed connection; the panel explains this distinction. Rotating span
references and evidence ordering do not create false changes. Counts, bytes,
confidence and policy evidence remain comparable. Unoriented conversations
use a bidirectional arrow. Coverage warnings remain visible, and differences
in collected evidence are not presented as proof that traffic started/stopped.

The ACI demo's preceding window is captured with `adm_graph` from generated
TA-shaped events, shifted 15 minutes and omitting the blocked database
conversation. No search rows are fabricated in the UI. The fixture records
its query, window, fields and hashes of the complete macro file, generator and
source scenario. Offline grounding checks cover those inputs and output
fields. NX-OS demo comparison explicitly reports that a preceding capture is
unavailable.

PNG exports the complete current Network/Services diagram, including its
filters, focus and emphasis, with resolved theme styles and an opaque
background. Pan/zoom do not crop the export. Canvas dimensions and pixel
allocation are bounded. Print/PDF uses an isolated full-map SVG, a landscape
print stylesheet and the browser print dialog. Empty filtered diagrams disable
image/print actions. Required-flows CSV and full-graph JSON remain available
from the existing export implementations.

Copy link preserves validated scope, time, tab and highlight URL state. Named
views are stored in a per-user browser localStorage list, with validation,
name limits, a 50-view cap and storage-failure feedback. Unknown users cannot
save. Reopening reconstructs a same-origin URL from validated state; no
arbitrary URL or shared KV collection is stored. Local filters and focus are
not part of the shared URL, as the panel explains.

## Verification

The final package passed native browser qualification on Splunk Enterprise
10.6.0.5 as an ephemeral search-only viewer, in light and dark themes.
`python3 -m unittest tests.splunk.test_views_viewer.ViewerBrowserTest -v`
ran under the parent-owned cooperative LabLock: passed in 191.801 seconds.
It exercised live and demo comparison, copy/save/reopen/delete, PNG signature
and full-map output, and print invocation, SVG bounds and cleanup. Native PNG
and UI screenshots were visually reviewed in both themes.

The owned container, volumes, image and lab secrets were purged. The temporary
research link and viewer identity were removed. Foreign containers were
preserved. The full data-layer integration suite was not rerun because no
search definitions or production data-layer behavior changed.

- `npm run lint`: passed.
- `npm test`: 349 tests passed across 37 files.
- `npm run test:browser`: 46 passed.
- `npm run typecheck:browser`: passed.
- `ruff check tools tests` and `ruff format --check tools tests`: passed.
- `python3 -m unittest tests.test_previous_demo -v`: 4 passed.
- `python3 -m unittest discover -s tests -p 'test_*.py'`: 165 passed after cleanup.
- `npm run package` and `python3 tools/check_release.py --dist dist`: passed.
- Python 3.11 AppInspect Cloud precertification and report gate: passed,
  0 errors, 0 failures, 5 existing warnings.
- Independent review identified comparison, cancellation and export edge cases;
  fixes were integrated with regressions.

Capture reproduction in an owned, locked lab:

1. `python3 tools/gen_raw_fixtures.py --scenario aci-prev`
2. Install the app and required lab TAs.
3. `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 tools/capture_previous_demo.py --initialize`

The initialize option resets lab data and loads the preceding batch. Use only
an owned disposable lab; the command does not start or purge the container.

## Limits

Cloud runtime and formal Cloud vetting remain unverified. The shared bundle
remains above the original size budget. The PDF destination is provided by
the user's browser; no server PDF renderer or extra dependency is added.
No data-layer search definitions or production configurations changed.

Final package SHA256: `9efec78cbc2596e8561a3cdf3eb0903473d915d7eb855ca38f1f35a34b8df8d1`.
Shared bundle: 2,330,488 bytes raw / 585,059 bytes gzip.


Native artifacts (ignored local build outputs):

- [Dark PNG](../dist/atlas-phase8-map-dark.png)
- [Light PNG](../dist/atlas-phase8-map-light.png)
- [Change comparison](../dist/atlas-phase8-changes-light.png)
- [Saved views](../dist/atlas-phase8-saved-views-dark.png)
