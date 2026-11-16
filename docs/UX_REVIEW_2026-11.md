# UX review 2026-11 — Phase 1 declutter

Demo mode, 1440×900, Chromium. Words = visible text outside the map canvas and table bodies.
Screenshots: `docs/screenshots/2026-11/` (`before-*`, `after-*`).

## Measurements

| View                   | Metric          | Before | After | Target |
| ---------------------- | --------------- | -----: | ----: | -----: |
| Map                    | Canvas top (px) |    400 |   119 |  ≤ 120 |
| Map                    | Chrome words    |    170 |    28 |   < 80 |
| Explore (Applications) | Chrome words    |    191 |    52 |   < 60 |
| Explore (Endpoints)    | Chrome words    |     40 |    26 |      — |
| Admin · Data health    | Chrome words    |     29 |    20 |      — |
| Admin · Setup          | Chrome words    |     73 |    73 |      — |
| Nav                    | Entries         |      6 | 3 + ? |      3 |

## Changes

| Area      | Before                                                                   | After                                                                              |
| --------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Nav       | Applications, Map, Endpoints, Data health, Setup, Help                   | Explore, Map, Admin · health dot · `?` Help                                        |
| Explore   | Six preamble paragraphs, separate Find, duplicate scope form             | Omnibox (app/IP/MAC/EPG/device) + time + Demo pill; Trace path + Device slots      |
| Catalog   | 11 columns, two window columns, per-row “Review first”/“No captured map” | 8 columns (Scope merged, one Window end); exceptions coloured; reasons in tooltips |
| Map       | Scope bar, caveat, header, action row, toolbar, filter row (~400 px)     | One header row (scope popover, time, ≤4 KPIs, Demo pill, ⋯) + one toolbar row      |
| Filters   | Always-visible row                                                       | `Filters (n)` popover; Focus stays inline                                          |
| Actions   | Changes, Saved views, help, export, settings, Legend link                | One ⋯ menu                                                                         |
| Findings  | Always-open right column with intro + per-card demo caveat               | Drawer, closed by default, count badge; one “Demo evidence · not searchable” line  |
| Inspector | One long column, 12 InfoTips, multi-sentence callouts                    | Overview / Flows / Evidence tabs; 3 InfoTip sites; callouts are labels             |
| Badges    | “Identified” on every row                                                | Exceptions only: Unknown, Multiple owners, External, Blocked                       |
| Caveats   | Repeated per view                                                        | Once, in Help → About evidence                                                     |

## Routes

| URL                           | Renders                          |
| ----------------------------- | -------------------------------- |
| `applications`, `explore`     | Explore · Applications           |
| `endpoints`                   | Explore · Endpoints              |
| `setup`, `admin`              | Admin · Setup                    |
| `data_health`                 | Admin · Data health              |
| `device?id=`                  | Device stub (coming soon)        |
| `map?…&trace_src=&trace_dst=` | Map; params parsed, not yet used |
| `impact?element=…&mode=fails\|depends&window=` | Impact (blast radius); up to 5 `element`s fail together |
| `map?…&impact=<element>`      | Map with the Impact overlay      |

## Open

| Item                                                     | Owner       |
| -------------------------------------------------------- | ----------- |
| `device`, `explore`, `admin` Splunk views (`splunk_app`) | Platform    |
| Trace path and Device lookup behaviour                   | Path/Device |
| Setup copy (73 words)                                    | Phase 2     |
