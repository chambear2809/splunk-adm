# Protocol Lens UX contract

Status: approved for protocol workbenches (2026-11-27)

Builds on [docs/UX_REVIEW_2026-11.md](../../UX_REVIEW_2026-11.md). The UI/UX reviewer enforces this contract. Every protocol lens uses the same layout, budgets, status vocabulary, and primitives.

## Intent

Network engineers, Splunk admins, application teams, and SREs should digest protocol evidence in seconds. The screen answers one question above the fold, then offers a matrix and a drawer. Chrome stays short. Exceptions come first.

## Layout (identical in every lens)

- One header row: lens name, scope, UTC window, Investigate, coverage pill. Data starts within 120 px of the top.
- One plain-language **verdict line** always above the fold, for example "2 of 14 resolvers need attention: 12% SERVFAIL on 10.0.0.53".
- At most 4 KPI tiles, each with a unit and a sparkline.
- Overview, then Matrix, then a detail drawer. Raw events are one click deeper.

## Concision budgets

- Under 60 **chrome words**: visible interface text outside the data. Chrome includes header, verdict, KPI labels (not values), column headers, empty-state copy, and buttons. Chrome excludes matrix cells, drawer event rows, sparkline ticks, and copied IPs.
- At most 8 columns.
- At most 3 InfoTips per view.
- Caveats appear once (Help → About evidence). Reasons go in tooltips.
- Exceptions sort first. Healthy rows sit behind "Show all (n)".

## Status

Each of these always has an icon and a label as well as a colour. The on-screen label for a missing source is **Not covered**. Copy may say "not collected" in Help; the chip never does. Not covered never looks like None observed.

| State | Icon | Meaning |
| --- | --- | --- |
| OK | check | Observed and within expected bounds |
| Attention | warning | Observed exception that needs a look |
| Not covered | hatch | Source is not collected for this scope |
| None observed | minus | Source is collected; no matching events in the window |
| Unknown | question | Caller cannot tell (missing capability, search error, or Estimate-only stream) |

## Visual vocabulary

Only these shared SVG primitives. No new chart libraries.

- KPI tile and sparkline
- Heat matrix, with an equivalent accessible table
- Swimlane timeline
- p50/p95 distribution bar
- Adjacency overlay
- Status chip

Splunk theme tokens drive the palette. Light and dark themes are both required.

## Formatting and states

- Units are always shown. Values are human-readable.
- IPs are monospace and copyable.
- One shared component handles loading, empty-with-reason, partial or capped, blocked, unavailable, and stale-configuration.

## Accessibility

WCAG 2.2 AA. Keyboard navigation of the matrix and drawer. Status chips and the Not covered hatch meet 3:1 non-text contrast in both themes. Interactive chips meet the 24 px minimum target size. Accessibility is checked by the UX reviewer by hand; this contract does not add a new dependency.

## Measured in `tests/browser/protocols.spec.ts`

- The verdict is above the fold.
- Chrome text is under 60 words.
- No horizontal scroll at 1280 px.
- Screenshot baselines exist for light and dark.

## Review capture

The orchestrator captures 1440×900 and 1280×800, light and dark, plus loading, empty, partial, and blocked states. Each UX finding names the lens, view, element, the rule it breaks, and a concrete fix.

## Anti-goals

The work fails, even if it renders, if it:

- puts the verdict below the fold or behind a click;
- uses more than 60 words of chrome or more than 8 columns;
- presents "not collected" as an empty healthy matrix;
- adds a chart library or a palette outside Splunk theme tokens;
- repeats caveats on every view.
