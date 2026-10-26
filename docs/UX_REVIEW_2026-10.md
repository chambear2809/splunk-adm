# UX and frontend review, October 2026

Scope: frontend changes merged between 2026-10-23 (commit `d3a7016`) and 2026-10-25
(`origin/main` at `0be8574`), plus the uncommitted working-tree changes of 2026-10-25 on
branch `review/weekend-ux-hardening`. Measurements come from the synthetic demo data
(`fixtures/demo-*.json`) in Chromium at 1440x900 and 390x844; nothing is estimated.
"Before" figures were taken on `0be8574` with the working-tree frontend changes absent;
"after" figures are reproduced with the commands under Verification.

## Journeys as found

| Journey | Path before | Observation |
| --- | --- | --- |
| Identify an application from an address | Applications, type address, Find, Open map (4 actions) | The Find box sat below four explanatory paragraphs (about 391 px from the top in the Meraki scenario). |
| Find an unhealthy application | Applications catalog, then Open map, then Findings panel | The catalog was alphabetical, so the scope with 3 unknown peers was row 6 of 10 with no cue. |
| Blast radius | Select a card, Focus 1-3 hops | Focus was undirected. From a service card, 1 hop returned 3 of 25 nodes and 1 of 27 connections because a service links only to its pods and traced callers; its pods' network conversations were not included until 2 hops. A blocked attempt and a real dependency looked alike. |
| Reduce a large result | Filters, highlight, Focus | Works, but Focus was disabled with no explanation of why. |
| Reach a next action | Findings, Show path | One click to inspector plus candidate path. Unchanged. |
| Narrow viewport | Map at 390 px | Findings panel overlapped the filter controls and the map collapsed to zero height. |

## Changes

| Change | Before | After |
| --- | --- | --- |
| Focus gains **Callers** (observed reaching the selection) and **Dependencies** (observed from the selection), 1-3 hops, in the existing Focus control | Any-direction only | Same two actions (select card, choose Focus). For `orders-db-01`: Callers 1 hop 4 of 25 nodes, Callers 2 hops 10 of 25, Dependencies: no dependency observed (not evidence that none exist). Any-direction 2 hops returns 13 of 25. |
| A focused service card now stands for its pods | `checkout` 1 hop any direction: 3 of 25 nodes, 1 of 27 connections | 7 of 25 nodes, 5 of 27 connections |
| Directed focus rules | n/a | Only observed conversations and traced calls are followed; `forwards_to` hand-offs cost no hop; the filter summary states the observed-only limit, an empty result ("none observed, not none exist"), followed connections of unknown or port-inferred direction, and blocked conversations drawn between shown cards but not followed; unknown-direction conversations are followed both ways; blocked conversations are not followed |
| Focus tooltip when disabled | none | "Select a card on the map to focus on its connections" |
| Applications: Find box moved above the catalog notes | Find box at y=391 | y=271 (120 px higher); the catalog-window caveat now sits directly above the catalog |
| Applications: catalog sorts blocked then unknown peers first (any column header still sorts; ties break on problems then name) and adds a "Review first: N blocked, M unknown peers in the window ending <window end>" line | Meraki scenario: 3-unknown-peer scope at row 6 of 10 | Row 1 of 10 |
| Map at 900 px and narrower: page grows and scrolls, map keeps at least 420 px, toolbar wraps | Findings overlapped the filters; map height 0 | Findings sit below the map; no overlap |
| Help page explains Callers and Dependencies and their limits | none | One section |

Wording rules kept: Callers and Dependencies describe only conversations and calls
observed in the loaded window and sources. They are not an impact analysis or proof of
impact, and the Help text and filter summary say so.

Auto-fit: a focused or filtered layout whose fit scale is at least 0.72 is fitted whole
(card text about 9px). Selecting a conversation too long to show may zoom out to 0.6 to show both
ends. Below those scales the earlier behaviour (collapse pods, anchor at 85%) applies.
Measured at 1440x900: blocked-path map 66%, `orders-db-01` Callers 2 hops 77%.

## Defects found and fixed

| Severity | Where | Trigger | Impact | Resolution |
| --- | --- | --- | --- | --- |
| Medium | `styles.css` map shell, narrow viewport | Open Map at <=900 px | Findings overlapped the filters and the map had zero height | CSS media rule; browser regression test |
| Medium | `filters.ts` `focusHops` | Focus on a service card in Network view | 1 hop showed pods and traced callers only, hiding the pods' network conversations | Service seeds its pods; unit and browser tests |
| Low | `ApplicationsPage.tsx` | Large catalogs | Problem scopes buried alphabetically | Default sort and cue |

## Reviewed, not changed

| Item | Why left |
| --- | --- |
| `MapDnsInspection.tsx` compares only the first config fingerprint | The second read covers a different address list and the fingerprint includes identities, so equality is not expected. No defect. |
| `o11yHealth.ts` accepts a mapping with an invalid `observability_origin` and silently falls back to the public host | Fails closed to a public Splunk Observability URL; recommend validating the origin for `o11y_health` in `evidenceConfig.ts`. |
| Realm patterns differ between `evidenceConfig.ts` (`[a-z][a-z0-9-]{1,15}`) and `o11yDetectorEvents.ts`/`o11yNavigation.ts` (`[a-z][a-z0-9]{0,7}`) | A hyphenated or long realm passes configuration and then fails at load with a generic error. Share one validator. |
| `csv.ts` `evidence_truncated` is filled only for NAT rows | The column name suggests all kinds; blank can read as complete. Rename or populate. |
| `AppDynamicsEvidencePanel.tsx` clears the previous result on refresh | The Cancel and prior-result-with-error branches are unreachable. Minor. |
| No React error boundary | A render throw blanks the app; currently latent because inputs are validated upstream. |
| Candidate-path strip takes about 300 px at 900 px height | The map shrinks while a path is shown; it can be dismissed. Candidate for a collapsible strip. |

## Verification

Run `npm run dev -- --port 5173`, then open these URLs at 1440x900. `ACI` means
`http://127.0.0.1:5173/map?mode=demo&scenario=aci&service=frontend&environment=demo&cluster=demo-cluster&namespace=shop`.

| Scenario | Steps | Expected | Covered by (`tests/browser/app.spec.ts`) |
| --- | --- | --- | --- |
| Blast radius | Open ACI, focus the card "VM orders-db-01" (click or Tab, Enter), choose Focus "Callers · 1 hop", then "Callers · 2 hops", then "Dependencies · 1 hop" | 4 of 25 nodes and 2 of 27 connections; 10 of 25 and 13 of 27; 1 of 25 and 0 of 27 with "No dependencies were observed here" | "focus follows caller and dependency direction for blast radius", "directed focus discloses empty, inferred and blocked evidence", "a wider focus refits so no retained card is clipped" |
| Service focus | Open ACI, focus the card "Service checkout", choose "1 hop" | 7 of 25 nodes and 5 of 27 connections (3 of 25 and 1 of 27 on `0be8574`) | `frontend/src/filters.test.ts` ("treats a service as its pods") |
| Blocked path | Open ACI, click Show path in the "Blocked conversation" finding | Map area at least 360 px, whole topology at about 66%, path strip in view | "showing a candidate path keeps the map usable and fits both ends" |
| Find an application | Open `/applications?mode=demo&scenario=meraki-nxos`, Find `10.71.0.20` | Find box at y=271 (391 on `0be8574`); catalog row 1 is `checkout` on `cilium-nxos-west` with 3 unknown peers | "applications catalog lists blocked and unknown-peer scopes first" |
| Wide tables | Same page, 1440 wide | Every catalog and client-attachment column reachable, persistent scrollbar | "applications tables use the page width and every column stays reachable" |
| Narrow map | Open ACI at 390x844 | Findings below the map, no overlap | "narrow maps keep findings below the controls instead of overlapping them" |

Commands: `npm run lint`, `npx vitest run`, `npm run build`, `npx playwright test`
(add `tests/browser/app.spec.ts -g "<test name>"` to run one scenario).
