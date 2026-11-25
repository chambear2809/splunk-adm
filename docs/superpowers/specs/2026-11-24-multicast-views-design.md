# Multicast views: Overview, Matrix and Topology

Status: draft for review (2026-11-24)

## Intent

The Multicast page today answers one narrow question: for one scope, one group and an optional sender over at most one hour, what evidence exists? It shows a three-column tree (senders, forwarding branches, receiver interest) and an evidence table. Users — network engineers, Splunk admins, application teams, SREs and IT operations — want a **visual understanding of their multicast network**: what groups exist, who sends, who is interested, where traffic is replicated, and where visibility stops.

The page keeps its existing evidence discipline. Observed traffic and IGMP messages are evidence, not proof of delivery or membership. Only a verified device-state snapshot draws forwarding branches. Missing evidence never establishes absence.

## Goals

- A scope-wide **Overview** that lists observed groups with senders, receiver interest, flow evidence and plain-language health flags, as the default view.
- A **Matrix** view: groups by observation point, so gaps and outliers are visible at a glance.
- A **Topology** view: the physical network (CDP + LLDP) for the scope, with the verified forwarding tree highlighted and evidence attached where it can be placed.
- A **group detail** reached from any view: the existing tree and evidence table, plus an IGMP timeline and an observed-querier strip.
- Labels readable by non-specialists (application teams, SREs), with glossary tooltips for protocol terms.

## Non-goals

These are not supported by current qualified sources. The views show them as "not collected", never as empty:

- (*,G) shared trees, RPT-to-SPT switchover, RP/BSR/Auto-RP state.
- PIM neighbor overlays, IGMP snooping tables, mrouter ports.
- Route-change history (forwarding cohorts are point snapshots).
- Percent link utilization (interface speeds are not collected).
- mtrace-style per-hop error diagnosis (`WRONG_IF`, `NO_ROUTE`, …). The snapshot tool rejects cohorts with failed RPF/PIM checks, so those states never reach Splunk.
- IPv6/MLD.

Future source candidates (each needs qualification first): NX-API `show ip mroute`, `show ip pim neighbor`, `show ip igmp snooping groups` through the Cisco DC Networking TA's generic collection.

## Anti-goals

The work fails, even if it renders, if it:

- presents observed IGMP or flow evidence as delivery, membership or an elected querier;
- draws a forwarding branch, or places a device or receiver on the map, by inference rather than evidence;
- joins devices or evidence across routing scopes;
- adds unbounded or scheduled searches, or a write path, without an explicit decision.

## Constraints

- Existing contract: `frontend/src/multicast/contract.ts` (max window 3600 s, 256 input/evidence rows, 16 profiles). New contracts are versioned beside it.
- Searches run on demand within Atlas's optional-search admission budget and report caps, blocked requests and incomplete results, like the current sources.
- The Multicast bundle is a separate asset with a 64 KiB gzip budget (`vite.multicast.config.ts`). No graph-layout library is in the repo.
- Viewers need source-index access; scopes separate attribution and confer no access.
- Fixtures must mirror real TA schemas (`fixtures/raw/FIELDS.md`); no invented fields.
- Support targets: Splunk Cloud and Enterprise 10.6+.

## Approaches considered

1. **Topology-first** — open on a network map; choosing a group highlights its tree (Cisco NDFC Media Controller pattern). Familiar, but depends on topology and snapshot coverage most deployments will lack at first.
2. **Matrix-first** — open on a groups-by-segment grid (Nevion VideoIPath crosspoint pattern). Works with today's evidence; weak at conveying path.
3. **Overview → group → evidence** — scope-wide group list, drilling into a group detail with tree, timeline and evidence.

**Chosen:** 3 as the default, with 1 and 2 as switchable views over the same inputs and data. The user chose this to cover discovery (Overview), gap spotting (Matrix) and path context (Topology) without making any one source mandatory.

## Design

### Page shell

```
Multicast   [ Overview | Matrix | Topology ]   Scope ▾   From/To (UTC)   [Investigate]
```

- One scope and one window (≤ 1 h) drive all three views. The view choice is stored as `mc_view` in the URL; selections (`mc_group`, `mc_sender`) persist across views.
- Group selection from any view opens the **group detail** (below) in the same page.
- Each view shows the source-coverage summary already on the page (complete / partial / blocked / unavailable per profile).

### New scope-wide group search

Overview and Matrix need a bounded, on-demand search listing groups across a scope's IGMP and NetFlow profiles for the window. Per (group, observation point) it returns: IGMP message counts by operation, distinct reporters (endpoint vs proxy/anonymous), distinct senders, flow packets/bytes with the profile's sampling and counter meaning, first/last seen. It is capped (proposal: 256 groups, reported when exceeded), uses the same profile validation and admission budget, and reports its completeness like the current sources.

### Overview (default)

One row per observed group:

| Group | Senders | Receiver interest | Flow evidence | Flags | First / last seen |

Flags (fixed rules, plain-language label + glossary tooltip):

- **Interest, no sender seen** — IGMP interest observed, no flow evidence for the group in the window.
- **Sender, no interest seen** — flow evidence, no IGMP interest at any qualified capture.
- **New since previous window** — not computed by default. A **Compare with previous window** action runs the same group search over the equal-length window immediately before, as a second, separately admitted search. The flag shows only when every contributing profile fully covers the previous window and that search completed; otherwise it reads "comparison unavailable" with the reason. No stored baseline.
- **Leave without query** — a leave/block not followed by an observed query (group-specific or general) from that segment within the window (evidence gap, not a fault).
- **Multiple query senders** — more than one address sent queries (general or group-specific) on a capture segment.

General queries (group `0.0.0.0`) count as queries for these flags and the querier strip. The current group-filtered IGMP adapter drops them, so the scope-wide search and group detail must also fetch general queries per capture profile.
- **Source coverage partial** — one or more contributing sources were capped, blocked or unavailable.

Flags describe evidence; none asserts a fault.

### Matrix

Rows = groups; columns = **observation points**: each IGMP capture segment (profile `segment`) and each NetFlow exporter/direction (profile `observer` + `direction`). Senders come from NetFlow exporters, not segments, so columns are observation points, not VLANs alone.

Cell states: sender traffic (NetFlow columns), receiver interest (IGMP columns), none observed, not covered (no profile for that point in the window). There is no "both" state: nothing in the profiles relates a capture segment to an exporter interface, and the view does not infer one. Recency shade: last-seen within the window. Sort by flag count; filter by flag. Selecting a cell opens group detail scoped to that point.

### Topology

Canvas built by a **multicast-only topology reader** that reads the Map data layer's existing device and link rows (`adm_topology`) without changing that macro, its `link_source` values, or Map/Trace Path behaviour. Scope assignment, LLDP merging and conflict states live in this reader. Its code ships in the Multicast bundle (or as a new host module if the budget requires).

**Links:**
- CDP links: existing `row_type=link` rows (`link_source=cdp`).
- ACI links: existing rows, `link_source=aci` (leaf–spine) and `link_source=lldp` (host attachments from ACI `lldpAdjEp`).
- NX-OS LLDP links: new, from two collection paths normalised to one adjacency shape (`link_source=lldp`, plus `collector` = `ta` or `gnmi`):
  - **Cisco DC Networking TA** DME class `lldpAdjEp`.
  - **gNMI**, using the OpenConfig LLDP model (`/lldp/interfaces/interface/neighbors/neighbor/state`). The TA path uses the NX-OS DME model, so the two need separate parsers feeding one normalised shape.
  - Each path is enabled only after qualification with sanitized real indexed events; fixtures follow those events. Until then the reader reports the path as not qualified.
  - TA evidence: NX-OS `lldpAdjEp` is in the DC Networking TA 2.0.10 "Interfaces and neighbors" DME class set (`bin/cisco_dc_n9k_custom.py:53`).
- One physical adjacency seen by both protocols is one link with `link_source` = `cdp,lldp`. If CDP and LLDP disagree on a port, the link is drawn as **conflicting**, not as a clean edge.
- Physical links are thin and grey, labelled "observed adjacency" — possible paths, not traffic.

**Device scope (both sources, strict precedence):**
1. **Profile device list (authoritative).** Forwarding profiles gain an optional `devices` list. A listed device belongs to that scope and is the only kind that can carry highlighted branches.
2. **`adm_observer_scope` mapping (discovery).** New observer kind `switch` maps CDP/LLDP devices to a scope, following the collection's existing rules (lowercase keys, `sha256` `_key`, admin-only writes). Drawn and evidence-attachable, badged "scope-mapped".
3. **Neither** — not drawn; the view shows an excluded-device count.

Conflicts: a device listed in scope A's profile but mapped to scope B is drawn as a conflict, gets no evidence, and is listed for the admin. A device in two profiles' lists with overlapping validity makes the configuration document invalid, consistent with today's fail-closed profile parsing; the setup state names the duplicate device. A scope with no forwarding profile gets `adm_observer_scope` discovery only, and no branches. A link whose ends are in different scopes is drawn as a boundary stub; it never joins two scopes.

**Overlays for a selected group:**
- **Forwarding tree** — bold solid branches only from a verified NX-OS cohort (existing `ForwardingBranch.state = supported`). Break markers limited to what the data supports: *next hop unresolved*, *downstream device has no state*, *stale (snapshot older than the window end)*. Without a cohort: no branches, and the existing "forwarding tree unavailable" notice.
- **Senders** — attached to their NetFlow exporter's device. Required on day one, including exporters that send from a loopback or interface address:
  1. **Profile `device` (authoritative).** NetFlow profiles gain an optional `device` field naming the exporter's device (lower-cased hostname). Administrator-attested.
  2. **Management-address match (automatic).** Otherwise, an exporter IP equal to exactly one drawn device's `mgmt_ip` places on it, badged "matched by management address".
  3. Otherwise the sender stays in the side rail with the reason.

  If 1 and 2 disagree, the profile wins and the disagreement is listed for the admin.
- **Receiver interest** — attached to a leaf port only when LLDP or endpoint data (ACI `fvCEp`, Nexus Dashboard endpoints) proves the reporter's attachment; otherwise grouped under its capture segment in the side rail.
- **Flow load** — observed pps/bps on the exporter interface, labelled with sampling interval and before/after replication. No percentages.

Side rail lists everything that could not be placed, with the reason.

### Group detail

Reached from any view. Contains:

- Existing three-column tree and evidence table (unchanged semantics).
- **IGMP timeline** — swimlane per capture segment: joins/reports, leaves/blocks, queries as marks on a shared time axis; v3 operations labelled.
- **Observed querier strip** — per capture segment, which addresses sent queries over time and when that changed. Labelled "observed query senders", never "elected querier".
- When a snapshot exists, the window-end guidance already added: a snapshot is valid only at its anchor.

### Operator documentation and readiness

Update `docs/operators/multicast.md`: device lists in forwarding profiles, the `switch` observer kind, LLDP receive on host-facing ports, and how excluded/conflicting devices appear. Add readiness checks for "switch scope mapping present" and "LLDP adjacency data present".

## Decided by the user

- Approach 3 as default, with 1 and 2 as additional views.
- Audience: network engineers, Splunk admins, application teams, SREs, IT operations; purpose: visual understanding of the multicast network.
- LLDP is a link source alongside CDP.
- Both scope sources (profile device list + `adm_observer_scope`), with the precedence above.
- NetFlow exporters must place on their device on day one, including loopback/interface-address exporters.
- NX-OS LLDP must be supported through both the DC Networking TA and gNMI.

## Calls made by the author (open to correction)

- Baseline = the previous equal-length window, run only on request; nothing stored.
- General IGMP queries count as queries.
- No "both" Matrix state.
- Multicast-only topology reader; `adm_topology` and Map/Trace Path unchanged.
- Duplicate device lists fail the whole configuration closed, like other profile errors.
- Group-search cap 256 groups.
- Matrix columns are observation points, not VLANs.
- No percent utilization.
- Flags are evidence descriptions, not fault alerts.

## Left to the builder

- Layout algorithm for Topology within the bundle budget (hand-built layered layout vs raising the budget with justification).
- Visual styling, consistent with the Map page and the Splunk theme tokens.
- Exact search shapes, provided they stay bounded and report completeness.

## Market comparison

Sources were read by this session (Cisco, Nevion, RFC 8487) or by a separate Codex research pass that rendered the JavaScript-heavy Arista pages; Codex citations were not re-checked here. Claims marked unverified in that pass are excluded.

| Product | Relevant verified views | What Atlas takes from it | Atlas difference |
|---|---|---|---|
| Cisco NDFC Media Controller / IPFM ([guide](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/ip-fabric-for-media/cisco-nexus-9000-series-nx-os-ip-fabric-for-media-solution-guide-release-106x/m-media-controller.html)) | Group select highlights spine/leaf links with animated direction; link bandwidth colours <40 / 40–80 / >80 %; flow tabs Active, Inactive, Sender Only, Receiver Only; Fault Reason; red-circled drop switches; 7-day drop history | Topology group highlight; Overview "sender, no interest" / "interest, no sender" mirror Sender Only / Receiver Only | Controller state presented as fact; Atlas labels evidence vs verified state |
| Arista CloudVision ([MCS](https://www.arista.io/help/articles/devices-selected-device-mcs), [Routing](https://www.arista.io/help/articles/devices-selected-device-routing), [Topology](https://www.arista.io/help/articles/topology-overview)) | MCS Flows table (group, source, sender, hops, receivers, posted bandwidth, inactive receiver first; 1,000-row display cap); per-flow history (10 changes) and Failed Flows; per-device IPv4 multicast table and IGMP groups with ~90 days of add/modify/delete history; PIM neighbor table; generic Topology flow-path isolate with a continuous utilization scale; IGMP snooping and fastdrop views only as custom AQL dashboards | Sort problem rows first; show display caps; keep "no members observed" distinct from "not covered"; separate scale for load vs forwarding state | Tree highlight for generic PIM not verified; IGMP querier view and join/leave timeline not found |
| Kentik ([Data Explorer](https://kb.kentik.com/docs/data-explorer), [Matrix](https://kb.kentik.com/docs/chart-visualization-types#matrix-visualization), [Router config](https://kb.kentik.com/docs/router-configuration)) | Generic flow explorer and dimension matrix; interface multicast packet counters (IF-MIB `ifHCIn/OutMulticastPkts`); generic flow and NMS alert policies | Matrix of chosen dimensions with traffic per cell | No multicast group, receiver, IGMP or PIM view verified |
| Nevion VideoIPath ([product](https://nevion.com/videoipath/)) | Source-by-destination matrix and panel views; service-correlated alarms; multicast/VLAN pool assignment | Matrix layout | Orchestration of programmed flows, not observation |
| NetBrain IE 8.02 ([release notes](https://www.netbraintech.com/wp-content/uploads/2020/04/NetBrain_Customer_Release_Notes_8.02-1.pdf)) | Receiver-to-source multicast reverse path from route tables | Future receiver-anchored path once route state is collected | Requires mroute collection Atlas does not have |
| RFC 8487 mtrace2 ([RFC](https://www.rfc-editor.org/rfc/rfc8487.html)) | Per-hop forwarding codes | Vocabulary for future break labels | Not usable without RPF/route state |

**Gap Atlas fills:** no verified product shows an IGMP join/leave/query timeline, an observed-querier view, or a group-by-receiver matrix from packet evidence. All verified tree/path views depend on controller-programmed or device route state.

**Future-source note:** Arista's per-device IGMP group and mroute history (add/modify/delete with timestamps) is the model for a later NX-OS snapshot-diff source; such changes would be labelled "membership added/removed at observation time", not as IGMP messages.

## Device identity (decided)

- One device key everywhere: the lower-cased hostname used by `adm_topology` `device_id`. Profile `devices` entries, `switch` observer mappings and NetFlow profile `device` use it.
- A forwarding cohort's per-device `observer` must equal that key; `prepare_multicast_cohort.py` and the cohort parser enforce lower-cased hostnames.
- Exporter-to-device placement is required on day one (user decision), via the profile `device` field with management-address matching as fallback.

## Lab findings (2026-11-24)

LLDP collection was qualified on the validation lab; see [LLDP source qualification](../../lldp-source-qualification.md).

- Both paths work and agree with `show lldp neighbors` on every neighbor (33 across Leaf1, Leaf2, Spine1): the DC Networking TA (`nexus_9k_custom` input on `api/class/lldpAdjEp.json`, sourcetype `cisco:dc:nexus9k:custom`) and gNMI OpenConfig LLDP.
- The Splunk OTel `gnmi` receiver drops LLDP list keys and cannot be used; gNMI LLDP goes through gnmic with a Starlark processor, as a `lldp_neighbor` metric whose dimensions carry the neighbor fields.
- TA events identify the reporting switch by management IP, so the LLDP reader needs the IP → hostname device mapping; gNMI rows carry the device name set by the collector.
- 12 of 33 neighbors are host NICs advertising only MAC chassis/port IDs; they place only through endpoint/NIC inventory.
- Interface-name and peer-name normalisation (`eth`/`Ethernet`, FQDN vs bare name) is required before matching link ends; `mgmt0` neighbors are excluded.

## Open questions for the user

None blocking. The design is ready for approval.
