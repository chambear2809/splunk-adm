# Connected transport evidence

The selected edge Inspector's Flows section and optional Proxy evidence panel
now use a shared transport-leg display. Each card retains its evidence basis;
the UI does not join separate observations by matching addresses, time, stream
ID, proxy name or source label. A card is not a reconstructed packet route.

| Source                         | Admitted local relationship                                                | Evidence retained                                                                                                                                                            | Qualification boundary                                                                                                                                                                                      |
| ------------------------------ | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cisco FTD ConnectionEvent      | Reported tuple and translated tuple in the same source event               | Protocol, all tuple addresses/ports, separately reported OriginalInitiatorIP, scope, observer, event fingerprint, native and received times, selected window, truncation     | Uses existing same-event normalization and V1/V2 NAT projection; current Cloud emission and historical observer-scope mapping remain unqualified.                                                           |
| Envoy DownstreamEnd HTTP log   | Direct peer/listener and upstream local/selected remote in one request log | Source schema, scope/authority, index, observer, fingerprint, native/indexed time, selected window, stream reference, HTTP status/duration, attempt count, missing endpoints | Proposed v1.40 contract and fixture are synthetic; deployed schema, observer mapping, filtering and clock semantics must be qualified before optional collection can establish associations.                |
| Selected-client Hubble handoff | Only handoff metadata attached to the selected client-to-Service edge      | Client/Service/backend identities, exact record basis, per-association counts, receiving nodes, observers, available scope/cluster context and selected graph window         | Complete aggregate Service metadata cannot replace missing client metadata. Timing-only candidates remain inferred. Native event times, request/retry identity and absent scope/authority are not invented. |

These are three source-specific relationships, not a cross-source correlation
adapter. Matching a firewall tuple to a proxy or backend address does not create
a new connection, packet order or original-client claim. Observations from
different sources are never added to one traffic total. Client and backend
clusters may differ; conflicting Service/backend identity or explicit routing
scope prevents an assignment.

## Admission and gaps

Firewall events must pass the existing strict event validator and selected event
window. The UI groups records by their own recorded scope and does not infer
cross-scope equivalence. Caps retain visible omission warnings. Exact duplicates
within one source identity appear once. Conflicting versions retain every
distinct payload, mark the association unknown and remain inspectable/exportable.

Proxy records use the existing optional search and normalization pipeline. Source
selection, schema qualification, configuration, scope, exact inspected window,
completion, rejection/oversize counts and source budgets guard admission. Capped
input suppresses associations. An output cap preserves returned event evidence
and warns that more records may be absent. Port zero is retained as reported
context with a socket-uncertainty warning. Missing upstreams/local endpoints and
multiple attempts remain explicit; no retry endpoints are fabricated.

Hubble records use `clientHandoffResolution` on the selected edge and verify
explicit scope and backend cluster consistency. Partial/unresolved/invalid
metadata suppresses backend and receiving-node assignment. A `time_inferred`
record is a candidate even when coverage is complete. The narrow existing XFF
handoff basis is not generalized to arbitrary proxy logs.

## Exports and verification

Each section offers a separate version 1 journey JSON download after an unchecked
choice to include addresses and identities. The export contains only that
section's displayed records, known routing context, windows, proof labels,
limitations and conflicting evidence variants. It does not grant recipients
access and is not submitted to the shared notes store. Existing generic map
exports do not silently acquire optional Envoy evidence.

`tests/browser/journeys.html` is prominently labeled Synthetic journey replay.
It exercises same-event tuples, proxy missing/retry/capped states, exact versus
inferred/partial Hubble metadata and explicit protected exports. This replay and
model tests do not establish deployed-source or installed Splunk qualification.
No live collector, schedule, notification or source configuration is enabled by
this UI increment. Retain prior summaries on rollback; older V2 summaries need a
reviewed rebuild before newly projected NAT fields can appear.

## Optional assets and rollback

The journey module opens explicitly from the existing evidence controls. Its
fixed same-origin JavaScript and CSS must come from the same source version as
the Atlas host; load failure or version mismatch offers retry without changing
the selection. Focus moves into the opened region and returns to the trigger on
failure. Build manifests bind both asset hashes, and release qualification checks
the complete set and budgets. The main bundle retains its 670 KiB ceiling; the
journey module has a separate 32 KiB gzip ceiling. Roll out or roll back the main
script, optional script, stylesheet and manifest together. A partial asset update
is not supported. No optional code or evidence download grants source access.
