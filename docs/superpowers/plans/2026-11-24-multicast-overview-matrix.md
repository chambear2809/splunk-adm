# Multicast Overview, Matrix and Group Detail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a scope-wide Overview (default) and Matrix view to the Multicast page, plus a group detail with an IGMP timeline and observed-querier strip, without weakening the page's evidence rules.

**Architecture:** A new bounded, on-demand "group summary" search runs once per IGMP/NetFlow profile in the selected scope and window. A pure function derives the evidence flags. Overview and Matrix render that result. Selecting a group runs the existing `investigateMulticast` and renders the existing tree and evidence, plus two new evidence views. The current IGMP adapter learns to keep general queries.

**Tech Stack:** TypeScript, React, Vitest, Playwright, Splunk SPL via `SearchClient` and `optionalJobs`. This is a separate Vite IIFE bundle (`vite.multicast.config.ts`).

**Spec:** `docs/superpowers/specs/2026-11-24-multicast-views-design.md`

**Scope of this plan:** Overview, Matrix, group detail and general queries. The Topology view (LLDP readers, device identity, scope precedence, profile `devices`/`device` fields, cohort hostname enforcement) is a separate plan, `2026-11-24-multicast-topology.md`, written after this one lands. Leave a disabled **Topology** tab labelled "Not yet available" so the shell does not change twice.

## Global Constraints

- Window ≤ 3600 s (`MAX_WINDOW_SECONDS`); input/evidence rows ≤ 256 (`MAX_INPUT_ROWS`, `MAX_EVIDENCE_ROWS`); ≤ 16 profiles (`MAX_PROFILES`).
- Group summary cap: **256 groups per profile**. Exceeding it sets the outcome to `partial` and the UI says how many were dropped. Never truncate silently.
- All searches run through `optionalJobs.run(source, key, …)`, which allows at most two leases and one per source. Report `complete | partial | blocked | unavailable` per profile, exactly as `loadMulticastSource` does.
- The configuration fingerprint is checked before and after every scope search, as in `investigateMulticast`. A mismatch throws `MulticastConfigurationChangedError`.
- A profile whose validity does not cover the whole window is reported `unavailable` with "Source verification does not cover the selected time window." Do not search it.
- Copy rules:
  - Never say "delivered", "member", "joined" or "elected querier".
  - Use "receiver interest observed", "query senders observed" and "comparison unavailable".
  - Flags describe evidence, not faults.
- Multicast bundle ≤ 64 KiB gzip. The build fails above it.
- Fixtures use only Stream IGMP and NetFlow fields that the existing adapters already read (`fixtures/raw/FIELDS.md`).
- Support Splunk Cloud and Enterprise 10.6+. Use no SPL commands beyond those the existing multicast searches already use (`eval`, `where`, `stats`, `eventstats`, `appendpipe`, `mvexpand`, `json_extract`, `json_array_to_mv`).

## Review Focus

1. **An IGMPv3 report with several group records, including one for the selected group.** Each group is counted under its own row, once per record. Owner: Task 2. Test `counts each IGMPv3 group record under its own group`.
2. **A capture whose only queries are general queries (group `0.0.0.0`).** The leave is followed by a general query, so "Leave without query" does not fire, and `0.0.0.0` never appears as a group row. Owner: Tasks 1, 2 and 3. Tests `keeps general queries as query evidence`, `excludes general queries from group rows` and `a general query after a leave clears the flag`.
3. **A scope where one profile is capped or blocked and another is complete.** The rows from the complete profile still render, every row carries "Source coverage partial", and Matrix cells for the failed profile read "not covered". Owner: Tasks 3 and 5. Tests `partial coverage flags every group` and `failed profile column reads not covered`.
4. **The previous window falls outside profile validity.** "New since previous window" shows "comparison unavailable" with the reason, never a false "new". Owner: Task 4. Test `previous window outside validity is unavailable`.
5. **The user edits scope or window while a scope search is running.** The search is aborted, and stale results never render under the new inputs. Owner: Task 7. Test `editing inputs cancels the overview search`.

---

## File Structure

- `frontend/src/multicast/contract.ts`: modify. Add `queryScope` to `IgmpEvidence` and add the scope types (Task 1, Task 2).
- `frontend/src/multicast/adapters.ts`: modify. Keep general queries (Task 1).
- `frontend/src/multicast/groupSummary.ts`: create. Search builder and loader for one profile (Task 2).
- `frontend/src/multicast/flags.ts`: create. Pure flag derivation (Task 3).
- `frontend/src/multicast/scopeOverview.ts`: create. Scope orchestration, fingerprint checks and previous-window comparison (Task 4).
- `frontend/src/multicast/inputs.ts`: modify. Add the `mc_view` URL key and a scope-only link (Task 4).
- `frontend/src/multicast/OverviewView.tsx` and `MatrixView.tsx`: create (Task 5).
- `frontend/src/multicast/IgmpTimeline.tsx` and `QuerierStrip.tsx`: create (Task 6).
- `frontend/src/multicast/MulticastPage.tsx`: modify. Add view tabs, the scope search, group drill-in and the detail layout (Task 7).
- `frontend/src/multicast/multicast.css`: modify. Add view styles (Tasks 5–7).
- `frontend/src/glossary.ts`: modify. Add multicast terms (Task 5).
- `fixtures/multicast/candidates.json`: modify. Add summary fixture rows (Task 2).
- `tests/browser/multicast.spec.ts`, `docs/operators/multicast.md`, `README.md` screenshots: modify (Task 8).

---

### Task 1: Keep general IGMP queries

**Files:**
- Modify: `frontend/src/multicast/contract.ts`
- Modify: `frontend/src/multicast/adapters.ts` (the search filter in `buildMulticastSearch`; the type 17 branch of `parseRow`)
- Test: `frontend/src/multicast/adapters.test.ts`

**Interfaces:**
- Produces: `IgmpEvidence.queryScope?: "general" | "group"`. Set it only when `operation === "query"`.

- [ ] **Step 1: Write the failing tests**

In `adapters.test.ts`, write `keeps general queries as query evidence`. A type 17 row with `multicast_address: "0.0.0.0"`, `num_sources: 0` and `src_ip: "192.0.2.1"` on the profile's capture interface becomes one evidence row with `operation: "query"`, `queryScope: "general"` and `reporter: "192.0.2.1"`. A type 17 row for the selected group gives `queryScope: "group"`. Also assert that `buildMulticastSearch(igmp, request)` contains `json_extract(_raw,"multicast_address")="0.0.0.0"` combined with `json_extract(_raw,"type")` equal to 17, OR-ed into the group filter.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run frontend/src/multicast/adapters.test.ts`
Expected: FAIL. The general query is rejected, and `queryScope` is undefined.

- [ ] **Step 3: Implement the change**

Add `queryScope` to `IgmpEvidence`. In the IGMP filter, OR in `(tonumber(json_extract(_raw,"type"))=17 AND json_extract(_raw,"multicast_address")="0.0.0.0")`. In `parseRow`, accept type 17 when `multicast_address` is `0.0.0.0` or the requested group, and set `queryScope` to match. Every other type keeps the existing group equality check.

- [ ] **Step 4: Run the multicast tests and confirm they pass**

Run: `npx vitest run frontend/src/multicast`
Expected: PASS, including the existing correlation and page tests. General queries carry no receiver interest. Confirm that `correlation.ts` builds receivers only from report and include/exclude operations, and that no receiver test changes.

- [ ] **Step 5: Commit**

`git commit -m "Keep general IGMP queries as multicast query evidence"`

---

### Task 2: Group summary search for one profile

**Files:**
- Modify: `frontend/src/multicast/contract.ts`
- Modify: `frontend/src/multicast/inputs.ts` (add `validateScopeWindow`)
- Create: `frontend/src/multicast/groupSummary.ts`
- Modify: `fixtures/multicast/candidates.json` (add a `groupSummary` section)
- Test: `frontend/src/multicast/groupSummary.test.ts`

**Interfaces:**
- Consumes: `parseProfile`, `scopeName` and `MAX_WINDOW_SECONDS` from `inputs.ts` and `contract.ts`; `optionalJobs`, `fingerprint`, `literal` and `requireNoSearchErrors` with the same usage as `adapters.ts`.
- Produces (in `contract.ts`):

```ts
export const MAX_GROUPS = 256;
export interface ScopeWindow { version: 1; scope: string; earliest: number; latest: number }
export interface IgmpGroupSummary {
  kind: "igmp"; profile: string; group: string; segment: Segment;
  reports: number; leaves: number; groupQueries: number;
  endpointReporters: string[]; otherReporters: number;
  firstSeen: number; lastSeen: number; lastLeave?: number; lastGroupQuery?: number;
}
export interface FlowGroupSummary {
  kind: "flow"; profile: string; group: string; observer: string; direction: "ingress" | "egress";
  senders: string[]; packets?: number; bytes?: number;
  samplingInterval: number; replication: "before" | "after" | "unknown"; counters: "delta" | "total";
  firstSeen: number; lastSeen: number;
}
export interface PointQueries { profile: string; querySenders: { address: string; first: number; last: number }[]; lastGeneralQuery?: number }
export type GroupSummary = IgmpGroupSummary | FlowGroupSummary;
export interface ProfileSummary { summaries: GroupSummary[]; queries?: PointQueries; droppedGroups: number; outcome: SourceOutcome }
```

- `validateScopeWindow(value: unknown, now?: number): ScopeWindow` in `inputs.ts`. It applies the same rules as `validateRequest`, minus group and sender.
- `buildGroupSummarySearch(profile: StreamProfile, window: ScopeWindow): string`
- `loadGroupSummary(client: SearchClient, profile: StreamProfile, window: ScopeWindow, signal: AbortSignal): Promise<ProfileSummary>`

- [ ] **Step 1: Write the failing tests**

In `groupSummary.test.ts`, use the fixture rows and the stub-client pattern from `adapters.test.ts`. Write these tests:
- `summarises IGMP reports, leaves and group queries per group`: v2 report, v2 leave and group query rows for `239.1.2.3` give one row with `reports: 1, leaves: 1, groupQueries: 1` and `lastLeave` set.
- `counts each IGMPv3 group record under its own group`: one type 34 row with records for `239.1.2.3` (include) and `239.1.2.4` (exclude) gives two rows, each with `reports: 1`.
- `excludes general queries from group rows`: a `0.0.0.0` query produces no group row. It appears in `queries.querySenders` and sets `lastGeneralQuery`.
- `attributes only attested endpoint reporters`: the endpoint reporter lands in `endpointReporters`. A proxy reporter only increments `otherReporters`.
- `summarises NetFlow by group with declared counter meaning`: two flows to one group from two senders give `senders` sorted and `samplingInterval`/`counters` copied from the profile.
- `caps at 256 groups and reports partial`: the completion row reports `group_count: 300`, so the result has 256 rows, `droppedGroups: 44` and `outcome.state` of `"partial"`.
- `blocks profiles that do not cover the window`: the client is never called.
- `the search binds scope inputs literally`: the profile index, observer and capture interface appear only inside `literal()`-escaped quotes. The window is not interpolated into the search text and is passed as `earliest`/`latest`.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run frontend/src/multicast/groupSummary.test.ts`
Expected: FAIL. The module does not exist.

- [ ] **Step 3: Implement `buildGroupSummarySearch`**

It uses the same base filters as `buildMulticastSearch` (index, sourcetype, `host`/`exporter_ip`, capture interface, domain, template and direction), with the group filter removed and the oversized guard kept. The search shape follows; it is the part the tests do not pin.

IGMP (one `stats … BY g`; the `g="0.0.0.0"` row carries the general-query senders):
```
| eval t=tonumber(json_extract(_raw,"type")), src=json_extract(_raw,"src_ip")
| eval rec=if(t=34,
    mvzip(mvzip(json_array_to_mv(json_extract(_raw,"group_record_multicast_address")),
                json_array_to_mv(json_extract(_raw,"group_record_type")),"|"),
          json_array_to_mv(json_extract(_raw,"group_record_num_sources")),"|"),
    json_extract(_raw,"multicast_address")."|0|0")
| mvexpand rec | eval g=mvindex(split(rec,"|"),0), op=tonumber(mvindex(split(rec,"|"),1)), n=tonumber(mvindex(split(rec,"|"),2))
| eval class=case(t=17 AND g="0.0.0.0","general", t=17,"query", t=23 OR op=6 OR (op=3 AND n=0),"leave", true(),"report")
| eventstats min(_time) AS qf max(_time) AS ql BY src class
| stats count(eval(class="report")) AS reports count(eval(class="leave")) AS leaves count(eval(class="query")) AS group_queries
        max(eval(if(class="leave",_time,null()))) AS last_leave max(eval(if(class="query",_time,null()))) AS last_group_query
        max(eval(if(class="general",_time,null()))) AS last_general_query
        values(eval(if(class="report",src,null()))) AS reporters
        values(eval(if(class="query" OR class="general",src."|".qf."|".ql,null()))) AS query_senders
        min(_time) AS first max(_time) AS last BY g
| eval reporters=mvindex(reporters,0,63), query_senders=mvindex(query_senders,0,15)
```
Then add `| eventstats dc(g) AS group_count | sort - last | head 258` and the `kind="completion"` appendpipe envelope with `returned_count` and `group_count`, as in `adapters.ts`. The `0.0.0.0` row is not counted toward `MAX_GROUPS`. `PointQueries` is the union of `query_senders` across rows, parsed as `address|first|last`. Leaves are v2 leave (type 23), v3 block-old-sources (6), and v3 change-to-include with zero sources. Split reporters into endpoint and other in TypeScript, against `profile.endpointReporters`.

NetFlow: `stats dc(src) values(src) AS senders sum(packets) sum(bytes) min(_time) max(_time) BY dest_ip`, with `values(src)` capped at 64 using `mvindex(…,0,63)`. Return the same envelope.

- [ ] **Step 4: Implement `loadGroupSummary`**

Mirror `loadMulticastSource`:
- **Coverage first:** a profile whose validity doesn't cover the window is `unavailable`, and the client is never called.
- **Search:** run it through `optionalJobs.run(profile.source, key, …)` with `maxRows: MAX_GROUPS + 2`.
- **Fail closed:** warnings or truncation, or an invalid envelope, mean `unavailable`. `SearchAccessDeniedError` means `blocked`. Reject any row whose group fails `groupAddress`.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `npx vitest run frontend/src/multicast/groupSummary.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

`git commit -m "Add bounded multicast group summary search per profile"`

---

### Task 3: Evidence flags

**Files:**
- Create: `frontend/src/multicast/flags.ts`
- Test: `frontend/src/multicast/flags.test.ts`

**Interfaces:**
- Consumes: `GroupSummary`, `ProfileSummary` and `PointQueries` from Task 2.
- Produces:

```ts
export type FlagId = "interest-no-sender" | "sender-no-interest" | "new-since-previous"
  | "leave-without-query" | "multiple-query-senders" | "coverage-partial";
export interface GroupRow { group: string; summaries: GroupSummary[]; flags: FlagId[] }
export const FLAG_LABEL: Record<FlagId, string>;
export function deriveGroupRows(current: ProfileSummary[], previous?: ProfileSummary[] | "unavailable"): GroupRow[];
```

Labels, copied verbatim from the spec:
- `interest-no-sender`: "Interest, no sender seen"
- `sender-no-interest`: "Sender, no interest seen"
- `new-since-previous`: "New since previous window"
- `leave-without-query`: "Leave without query"
- `multiple-query-senders`: "Multiple query senders"
- `coverage-partial`: "Source coverage partial"

- [ ] **Step 1: Write the failing tests**

- `interest-no-sender`: an IGMP row with `reports > 0` and no flow row for the group.
- `sender-no-interest`: a flow row and no IGMP row with `reports > 0`.
- `leave-without-query`: `lastLeave` is later than both `lastGroupQuery` and that profile's `lastGeneralQuery`.
- `a general query after a leave clears the flag`.
- `multiple-query-senders`: set on every group row of a profile whose `queries.querySenders.length > 1`.
- `partial coverage flags every group`: any profile with an outcome other than `complete` adds `coverage-partial` to every row.
- `new-since-previous`: absent when `previous` is undefined. When `previous` is `"unavailable"`, the flag is not set and the row is not otherwise marked. The UI shows "comparison unavailable" from Task 4's state instead. When `previous` is an array, the flag is set only for groups absent from it.
- `rows sort problem-first`: sort by flag count descending, then `lastSeen` descending, then group ascending.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run frontend/src/multicast/flags.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `deriveGroupRows`**

Group the summaries by `group` across profiles, apply the rules above, then sort.

- [ ] **Step 4: Run the tests and confirm they pass, then commit**

Run: `npx vitest run frontend/src/multicast/flags.test.ts`
Expected: PASS.
`git commit -m "Derive multicast evidence flags from group summaries"`

---

### Task 4: Scope orchestration, previous-window comparison and URL state

**Files:**
- Create: `frontend/src/multicast/scopeOverview.ts`
- Modify: `frontend/src/multicast/inputs.ts`
- Test: `frontend/src/multicast/scopeOverview.test.ts`, `frontend/src/multicast/inputs.test.ts`

**Interfaces:**
- Consumes: `readMulticastConfiguration` and `MulticastConfigurationChangedError` from `investigation.ts`; `loadGroupSummary` (Task 2); `deriveGroupRows` (Task 3).
- Produces:

```ts
export interface ScopeOverviewResult { version: 1; window: ScopeWindow; profiles: ProfileSummary[]; rows: GroupRow[];
  comparison: { state: "not-run" } | { state: "complete" } | { state: "unavailable"; reason: string };
  capturedAt: number; configurationFingerprint: string }
export async function investigateScope(client: SearchClient, window: ScopeWindow, configuration: MulticastConfiguration,
  signal: AbortSignal, options?: { comparePrevious?: boolean }): Promise<ScopeOverviewResult>;
export type MulticastView = "overview" | "matrix" | "topology";
export function parseMulticastView(params: URLSearchParams): MulticastView;          // default "overview"
export function parseScopeLink(params: URLSearchParams, now?: number): ScopeWindow | undefined;
export function scopeLink(window: ScopeWindow, view: MulticastView): URLSearchParams;
```

`mc_view` is added to `LINK_KEYS`. `parseMulticastLink` still requires `mc_group`, and `parseScopeLink` accepts a link without one. An unknown `mc_view` value throws "The multicast link contains unsupported parameters."

- [ ] **Step 1: Write the failing tests**

- `searches only IGMP and NetFlow profiles of the scope`: the forwarding profile is excluded.
- `configuration change during the search throws MulticastConfigurationChangedError`.
- `previous window outside validity is unavailable`: when `comparePrevious` is true and a profile's `validFrom` is later than `earliest - (latest - earliest)`, the result is `comparison.state = "unavailable"` with reason "Source verification does not cover the previous window.", and the previous search is not run for any profile.
- `previous window incomplete is unavailable`: one previous-window profile comes back `partial`, so the result is `"unavailable"` with reason "The previous-window search did not complete."
- `compare runs as a second admitted search`: the stub records two `optionalJobs.run` keys per profile.

In `inputs.test.ts`:
- `round-trips scope link and view`
- `rejects unknown mc_view`
- `group link still requires mc_group`

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run frontend/src/multicast/scopeOverview.test.ts frontend/src/multicast/inputs.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

Follow the structure of `investigateMulticast`:
1. Validate the window.
2. Re-read the configuration and compare fingerprints.
3. Filter to the scope's stream profiles.
4. Apply a 45 s deadline.
5. Use `Promise.all` over `loadGroupSummary`.
6. Re-verify the fingerprint.

When `comparePrevious` is set, check coverage of the previous window for every profile first, then run the previous window and pass `previous` to `deriveGroupRows`.

- [ ] **Step 4: Run the tests and confirm they pass, then commit**

Run: `npx vitest run frontend/src/multicast`
Expected: PASS.
`git commit -m "Orchestrate scope-wide multicast summaries and view links"`

---

### Task 5: Overview and Matrix views

**Files:**
- Create: `frontend/src/multicast/OverviewView.tsx`, `frontend/src/multicast/MatrixView.tsx`
- Modify: `frontend/src/multicast/multicast.css`, `frontend/src/glossary.ts`
- Test: `frontend/src/multicast/views.test.tsx`

**Interfaces:**
- Consumes: `ScopeOverviewResult` and `GroupRow` (Tasks 3–4); `MulticastConfiguration` (for profile descriptions).
- Produces:

```tsx
export function OverviewView(props: { result: ScopeOverviewResult; onSelectGroup(group: string): void;
  onCompare(): void; comparing: boolean }): JSX.Element;
export function MatrixView(props: { result: ScopeOverviewResult; configuration: MulticastConfiguration;
  onSelectCell(group: string, profile: string): void }): JSX.Element;
```

**Overview**
- **Columns:** `Group | Senders | Receiver interest | Flow evidence | Flags | First / last seen`. "Receiver interest" shows endpoint reporters plus "+N other reports".
- **Flags:** each flag is a badge using `FLAG_LABEL` with an `InfoTip` from `glossary.ts`.
- **Compare:** a **Compare with previous window** button calls `onCompare`. When `comparison.state === "unavailable"`, show "Comparison unavailable: {reason}".
- **Caps:** when any profile has `droppedGroups > 0`, a notice reads "{n} groups not shown: the group limit was reached for {profile}."
- **Empty state:** "No caller-visible multicast groups in this window. This does not establish that none exist."

**Matrix**
- **Layout:** rows are groups in `rows` order. Columns are profiles: IGMP shows `segment.kind segment.id · domain`, and NetFlow shows `observer · direction`.
- **Cells:** each cell is exactly one of "Sender traffic" (flow), "Receiver interest" (IGMP with reports), "None observed" or "Not covered". "Not covered" applies when the profile's outcome is not `complete`.
- **Recency:** shown as a CSS class of `recent` or `older`. It is `recent` when `lastSeen ≥ window.latest - 300`.
- **Interaction:** every cell is a button with an accessible name of "{group} at {column}: {state}".

**Glossary** gains entries keyed by each `FLAG_LABEL` value. Each states the evidence rule in one sentence, for example: "Leave without query: a leave was observed with no later query from that capture in this window. It may be normal; it is an evidence gap, not a fault."

- [ ] **Step 1: Write the failing tests (`views.test.tsx`, `renderToStaticMarkup` as in `MulticastPage.test.tsx`)**

- `overview lists problem rows first with flag labels`
- `overview shows the cap notice`
- `overview empty state does not claim absence`
- `failed profile column reads not covered`
- `matrix has no both state`: a group with flow evidence and IGMP reports renders two cells in two columns.
- `no forbidden words`: the markup of both views matches none of /deliver|member(ship)?|joined|elected/i, except inside glossary text, which must also avoid them.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run frontend/src/multicast/views.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement the components and CSS**

Reuse the existing `.adm-*` theme tokens in `multicast.css`, with no new colour constants.

- [ ] **Step 4: Run the tests and confirm they pass, then commit**

Run: `npx vitest run frontend/src/multicast/views.test.tsx`
Expected: PASS.
`git commit -m "Add multicast Overview and Matrix views"`

---

### Task 6: IGMP timeline and observed-querier strip

**Files:**
- Create: `frontend/src/multicast/IgmpTimeline.tsx`, `frontend/src/multicast/QuerierStrip.tsx`
- Test: `frontend/src/multicast/detail.test.tsx`

**Interfaces:**
- Consumes: `MulticastResult` (the existing contract) and `IgmpEvidence.queryScope` (Task 1).
- Produces:

```tsx
export function IgmpTimeline(props: { result: MulticastResult; timezone: string }): JSX.Element;
export function QuerierStrip(props: { result: MulticastResult; timezone: string }): JSX.Element;
```

**Timeline:** one SVG swimlane per distinct `segment` (`kind id · domain`), on a shared x-axis from `request.earliest` to `request.latest`. Mark shapes:
- reports and includes: filled circle
- leaves and blocks: hollow circle
- group queries: tick
- general queries: short tick

Each mark has a `<title>` with the operation, the reporter and the UTC time.

**Strip:** one row per segment, with one bar per query sender spanning first to last observed query. When a second sender appears, the row shows "Query senders changed". The heading reads "Observed query senders". Both components render "No IGMP evidence in this window" when there is none.

- [ ] **Step 1: Write the failing tests**

- `timeline places marks by time within the window`: x positions are monotonic in timestamp.
- `timeline distinguishes general and group queries`
- `querier strip reports a change of query sender`
- `querier strip never says elected`

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run frontend/src/multicast/detail.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement the components**

Use plain SVG with no new dependency.

- [ ] **Step 4: Run the tests and confirm they pass, then commit**

Run: `npx vitest run frontend/src/multicast/detail.test.tsx`
Expected: PASS.
`git commit -m "Add IGMP timeline and observed query sender strip"`

---

### Task 7: Page shell, scope search and group drill-in

**Files:**
- Modify: `frontend/src/multicast/MulticastPage.tsx`, `frontend/src/multicast/multicast.css`
- Test: `frontend/src/multicast/MulticastPage.test.tsx`

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces: no new exports beyond the props of the existing `MulticastPage` and `MulticastResults`.

**Behaviour**
- **Form:** the form becomes Scope, From and To, then **Investigate**. Group and sender move into the group detail header, which is prefilled from a clicked row or cell and still editable.
- **Tabs:** `Overview | Matrix | Topology`. Topology is disabled, with `aria-disabled`, and has the tooltip "Not yet available".
- **Investigate:** runs `investigateScope` and writes `scopeLink(window, view)` to the URL. `mode` is preserved, as today.
- **Drill-in:** selecting a group runs the existing `investigateMulticast` with `{scope, group, earliest, latest}` and writes the existing group link plus `mc_view`. The detail shows `MulticastResults`, then `IgmpTimeline` and `QuerierStrip`, with a **Back to {view}** button.
- **Old links:** a URL with `mc_group` opens the group detail directly, so old links keep working.
- **Cancellation:** editing scope or window aborts both the scope search and the group search, using the existing `active` controller pattern, and clears stale results.

- [ ] **Step 1: Write the failing tests**

- `defaults to the overview tab`
- `topology tab is disabled with a reason`
- `an old group link opens the group detail`
- `editing inputs cancels the overview search`: the abort signal passed to the stub client is aborted after a scope edit.
- Keep all existing `Multicast page` tests passing. They now render inside the group detail.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `npx vitest run frontend/src/multicast/MulticastPage.test.tsx`
Expected: FAIL on the new tests.

- [ ] **Step 3: Implement the changes**

- [ ] **Step 4: Run the full checks**

Run: `npm run lint && npx vitest run && npm run build`
Expected: all pass. The build log has no "Multicast optional asset exceeds its 64 KiB gzip budget."

- [ ] **Step 5: Commit**

`git commit -m "Make Overview the default multicast view with group drill-in"`

---

### Task 8: Browser test, operator docs and lab verification

**Files:**
- Modify: `tests/browser/multicast.spec.ts`, `docs/operators/multicast.md`, `README.md` (screenshot references), `docs/screenshots/readme/`

- [ ] **Step 1: Extend the browser spec**

Use the existing harness. Cover these paths:
- Overview loads from a scope link.
- Clicking a flagged row opens the detail with the timeline.
- Back returns to Overview.
- The Matrix tab renders cells.
- Topology is disabled.

- [ ] **Step 2: Run the browser tests**

Run: `npm run test:browser -- multicast`
Expected: PASS.

- [ ] **Step 3: Update the operator doc**

In `docs/operators/multicast.md`, describe the Overview, Matrix and group detail. Explain what each flag means, using the glossary wording. Cover the Compare action and its cost, which is a second search per profile. Note that general queries now count.

- [ ] **Step 4: Run the lab check**

Package the app (`npm run package`) and install it on the validation lab. Open Multicast on a scope with the fixture-backed or lab IGMP and NetFlow profiles. Capture fresh screenshots `08-multicast-igmp.png` and `11-multicast-forwarding-tree.png`, plus a new `12-multicast-overview.png` and `13-multicast-matrix.png`. Never include the stack hostname in docs.

- [ ] **Step 5: Commit**

`git commit -m "Document and verify multicast Overview and Matrix"`
