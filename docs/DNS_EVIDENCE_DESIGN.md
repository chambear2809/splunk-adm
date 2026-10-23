# Optional DNS evidence and endpoint investigations

Status: reviewed implementation plan, not implemented or runtime qualified. Date: 2026-10-23.

## Product decisions

Deliver optional Splunk Stream DNS and Hubble DNS L7 adapters. Present DNS names and resolution records as supplemental evidence in existing application maps and a new endpoint investigation workflow. The latter supports VM environments with networking evidence and no Kubernetes or trace-derived application entry point. Customers choose and configure their collection architecture, source indexes, routing mappings, retention and permissions.

DNS remains optional throughout setup, readiness and runtime. Application ownership, server membership, network traffic and application calls require their own evidence. DNS records do not change existing graph identifiers, labels, relationships, confidence or traffic counters. No scheduled DNS builder, DNS-derived ownership database or automatic collector/policy configuration is included.

Use on-demand, caller-context searches and explicitly versioned result contracts. Production readiness is an acceptance outcome for a particular package, source schema, platform and tested capacity. This plan does not establish that outcome.

## Corrections identified during review

| Finding in the earlier plan | Required correction |
| --- | --- |
| The VM monolith could not enter an existing application map. | Add an endpoint investigation entry point and an independent result schema. Do not fabricate service, cluster or namespace values to satisfy the application graph contract. |
| A flow observation start was treated as a connection opening. | Preserve source time semantics. DNS association indicates compatible observations; only independently qualified connection-start evidence can support a claim about opening time. |
| An edge was assumed to identify one scoped tuple and connection. | Resolve the actual scoped tuples and validity intervals. Preserve multi-address, multi-client and capped-history uncertainty. |
| A graph snapshot ID was treated as a data snapshot. | It is a client identifier. Independent evidence searches carry their own capture times, window and configuration fingerprint and cannot claim atomic consistency with the earlier graph. |
| A 64-row display cap was treated as a search budget. | Bound request windows, inputs, expansion, deadlines and concurrency as well as output; measure server resource use. |
| Partial results were assumed to pass through the shared search client. | Keep its strict checks. Use a validated bounded-result envelope and distinguish deliberate result capping from incomplete execution. |
| Shared macro validation was assumed to validate caller-context expansion. | Compile reviewed query templates with validated literal selectors. Resolve mapping data through explicit shared collection reads and avoid user-shadowable selector/normalization/lookup definitions in new searches. |
| New optional source entries were assumed to leave readiness unchanged. | Add an explicit readiness impact classification consumed by frontend and Python tooling. |
| Raw references, exports and settings rollback were underspecified. | Define safe drilldowns, explicit evidence export and disable-first, all-member rollback procedures. |

The relevant existing contracts are in `frontend/src/data/searchClient.ts`, `frontend/src/data/deploymentHealth.ts`, `frontend/src/drilldown.ts`, the graph SPL, and [Security](SECURITY.md). Existing shared graph/KV readers are entitled to the whole configured app dataset; routing scopes provide attribution isolation and do not implement tenant authorization.

## Scenarios and acceptance outcomes

| Scenario | Useful outcome | Required attribution boundary |
| --- | --- | --- |
| Two-server VM monolith | Show an application-name query, both returned addresses, and independently observed traffic to either server. | An answer does not establish application membership, successful failover or internal web/app/database relationships. |
| Multi-tier VM application | Add candidate database, application and external-service names to compatible observed traffic. | Ports and DNS names alone do not establish tier semantics or process ownership. |
| Microservices calling one another | Inspect resolution events beside observed service/workload conversations and existing traced calls. | DNS evidence does not create service calls or assign a query to every service sharing a host. |
| Microservices using shared databases, caches, queues or brokers | Retain each caller's observed resolution and destination candidates. | Preserve multiple applications, aliases and shared addresses; do not assign one owning application. |
| Kubernetes ClusterIP and headless Services | Distinguish an answer containing a Service address from one containing pod addresses; retain query/answer history. | Service/backend membership and selected backend require Kubernetes history and compatible handoff evidence. |
| Kubernetes churn and address reuse | Use pod UID/ownership history when available at the DNS and traffic observation times. | A recycled IP cannot carry a previous pod's DNS context into a different workload. |
| Mesh, sidecar, gateway or shared proxy | Show the endpoint the DNS and flow sources actually identify. | A sidecar can support pod-level context; a shared proxy does not establish the originating service without compatible traces or proxy evidence. |
| SaaS, third-party APIs and CDNs | Inspect candidate names behind changing public addresses, including microservice egress. | Preserve aliases and ambiguity on shared CDN addresses; never turn an IP match into a unique application identity. |
| Load balancer VIP and backend pool | Associate a name with a returned frontend address and display independent backend observations. | DNS cannot choose a backend or bridge NAT. |
| HA, disaster recovery and migration | Compare timestamped answer changes and observed traffic before and after a transition. | Cached, delayed or absent observations do not establish complete client migration or failover success. |
| Split DNS and overlapping private networks | Keep names and addresses separate by verified routing scope and source authority. | Same-name or same-IP records in different scopes never merge. |
| Search suffixes, retries and NodeLocal DNS | Inspect actual query names, response codes, measured latency and visible resolver context. | Preserve genuine retries and suffix variants; routine NXDOMAIN attempts do not prove application failure. |
| Resolution failure, explicit block or sinkhole | Inspect negative responses or source-provided policy outcomes even when there is no subsequent traffic. | No invented traffic edge, timeout, malicious classification or causal diagnosis. |
| Encrypted DNS, caching and collection gaps | Explain the source's coverage and what evidence is visible. | No DNS reconstruction from ordinary DoH/DoT ciphertext; absence of logs does not establish absence of lookups. |

SRV, MX, PTR, TXT, HTTPS/SVCB and unknown record types remain inspectable as typed resolution context when exported. The first version performs automatic address association only for qualified A/AAAA responses. It does not derive a destination port or application dependency from SRV/HTTPS records, synthesize CNAME chains, or perform external reverse lookups. DNSSEC status, DNS tunneling and DGA detection are not inferred.

## Product surfaces and public contracts

### Existing application maps

Add a DNS evidence section to endpoint/workload and network-connection inspection. It loads independently, after an active DNS source is selected, and has its own loading, cancel, refresh, empty, partial and unavailable states. DNS queries never block or invalidate the application map. An explicit narrower evidence window is required when the graph exceeds the supported evidence window.

Resolve scoped traffic context for the selected entity or edge using its graph arguments, absolute window and actual underlying observations. Use the same active data contract, replay protection, identity validity and source semantics as the map. Never reconstruct a connection by taking every combination of the displayed node address arrays. A selection with several routing contexts requires the user to choose a context before dispatch.

Results identify the earlier graph selection but are an independently captured investigation. Verify current observations still resolve to the selected identities; otherwise return context-only evidence with a reason. Late summary data, mapping changes and identity-history changes must not silently become evidence for a particular original graph connection. Capped or unavailable tuple history prevents complete connection attribution.

### Endpoint investigation

Add an `endpoints` navigation page, native Splunk view registration and strict URL handling. Input is one literal IPv4/IPv6 address, one verified routing scope and a time range. Default to the last hour; allow up to 24 hours. An administrator-configured active V1 or V2 summary source is required for traffic search; there is no namespace, trace or application-catalog prerequisite.

Present a one-hop network diagram and equivalent accessible conversation table, with the root scoped address, observed peers, ports, direction basis and source provenance. Use a dedicated `EndpointInvestigation` schema rather than changing or bypassing the existing application `Graph` validator. Reuse shared node/edge presentation primitives. An address investigated over time remains an address; changing or conflicting owners are shown as history/ambiguity, not collapsed into one workload identity.

Read compatible conversation summaries and, for V2, qualified traffic-observation summaries. Reuse existing replay deduplication, scope verification, sampling and counter semantics; keep nonauthoritative IPFIX observations distinguishable from conversation totals. Return at most 100 peers and 500 relationships with explicit result-capping status. DNS-only activity can appear in the root endpoint's evidence list when no conversations exist; it creates no network edge. Peer navigation starts a new scoped investigation rather than silently expanding to a transitive dependency graph.

Provide validated deep links and a return-to-application action when an explicit existing binding is available. Bookmark links retain only investigation inputs. Application membership editing and DNS-name graph entry are outside this delivery; the monolith scenario does not introduce an implicit application registry.

### Shared evidence interfaces

Add versioned `EvidenceSelection`, `DnsObservation` and `DnsEvidenceResult` types with strict validators:

- Selection: workflow, selection ID, active traffic contract, absolute window, verified scope, actual address/tuple context, identity basis and configuration fingerprint.
- Observation: adapter/source authority, client and resolver when known, query and type, message/transaction shape, response code, supplied answers and alias metadata, qualified TTL/time basis, event/index time, optional transaction identifier, observed identity and safe event fingerprint.
- Result: query capture time, requested/inspected windows, per-adapter configuration/access/execution state, input/result/expansion caps, normalization and attribution limitations, records and display ordering. Execution completeness and source coverage are separate facts.

DNS records are supplemental. Use explicit bases such as same scoped client IP, verified workload identity, compatible answer and observation time, or context only. No record claims that a queried name was actually used by an application merely because an address matches. An unknown client owner permits scoped IP context; a known conflicting/reused owner excludes workload attribution.

Keep DNS data out of the application graph snapshot schema. The endpoint result and evidence result have their own schema versions. Failed validation affects the evidence surface, not the valid traffic view.

## Adapter and correlation requirements

**Stream:** inspect `stream:dns` transaction events directly. Preserve request start, response/event end and their documented semantics; `_time` alone is insufficient. Convert DNS `response_time` and duration from microseconds to seconds where supplied. Verify the deployed stream is suitable for transaction inspection rather than assuming reference/default fields or an aggregated dashboard stream provide individual responses. Require a sensor/authority and routing mapping that preserves address-domain separation.

**Hubble:** parse DNS L7 export independently of `adm_flows_hubble`, preserving requests and responses and using their actual direction semantics. Recognize missing proto3/default fields only under a qualified producer schema. A transaction ID is optional; do not fabricate one. Flow UUIDs, where supplied, can identify duplicate exports. Qualify JSON envelope/field variants explicitly. The scalar TTL and unordered IP/CNAME lists do not establish ordered per-record alias chains. L7 policy and export changes remain customer operations. See the [Cilium flow schema](https://docs.cilium.io/en/stable/_api/v1/flow/README/) and [visibility requirements](https://docs.cilium.io/en/stable/observability/visibility/).

Normalize IP literals, IPv4-mapped IPv6, numeric response codes and comparison names consistently; preserve original names for inspection. DNS comparison is case insensitive and recognizes the root trailing dot. Do not strip search suffixes, collapse aliases or automatically transform arbitrary exported strings into URLs. Invalid/control-containing/oversized values are escaped for display and excluded from address association with a visible quality reason.

Only a qualified successful response whose address belongs to the answer for the selected query can supply candidate address context. Preserve supplied answer/type/TTL relationships; otherwise use context only. For an established chain/RRset use a conservative usable TTL derived from its relevant records; a missing, negative, nonfinite or zero TTL creates no persistent association. Do not treat an unknown TTL as the configured maximum. A newer answer does not universally invalidate a still-usable older answer held by another client.

Match against a compatible scoped client observation and qualified ownership interval, with destination equal to a supplied answer and ordering supported by the timestamps. TTL starts at response receipt/observation, not indexing or query start. If the producer provides an interval rather than a response instant, require the ordering and expiry to hold for that interval; otherwise remain context only. Preserve timestamp precision and configured clock uncertainty; unknown/incompatible clocks prevent temporal attribution. Flow export start and an actual connection opening remain distinct. Long-lived/reported flows, retries and connection pools cannot establish which lookup initiated a session.

Default the additional association-age cap to one hour; allow an administrator to set it from one minute through 24 hours. The query lookback equals that cap. It is a product search/association bound, not a DNS rule, and can omit older otherwise usable answers. TTL expiry does not prove an endpoint stopped using a name; resolvers may serve stale data under [RFC 8767](https://datatracker.ietf.org/doc/html/rfc8767). Do not infer an outage from that expiry.

Deduplicate only proven duplicate exports of the same observation. Preserve separate sensors as provenance and preserve genuine repeated transactions, different suffix names, question types and responses. If the source lacks a reliable duplicate identity, retain observations with a duplication limitation rather than collapsing events by a coarse timestamp/name key. No traffic counters are derived from DNS record counts.

## Configuration, permissions and health

Add `dns_stream` and `dns_hubble` to the shared source registry. They default to `not_selected`; old settings lacking either ID remain valid and effectively unselected. `active` permits enrichment and health probes; `staged` permits only explicitly requested diagnostic checks. DNS selection never selects a traffic source or enables a collector. An absent or unreadable settings snapshot never implicitly activates DNS.

Add `readinessImpact` with existing sources defaulting to core and DNS set to optional evidence. Apply the classification in UI health aggregation, setup readiness, quality warnings and Python readiness output/exit status. Preserve a separately visible optional-evidence status; DNS-only problems cannot turn a healthy core pipeline into failed/unknown readiness. A DNS-only selection does not make a missing traffic pipeline ready. Quiet event-driven DNS feeds are not declared failed solely because no recent query was logged; show receipt age and qualify silence separately from execution/parse failures.

Index and source selectors are administrator-managed, narrowly validated literals using the existing approved index-list grammar and explicit supported sourcetypes. Compile new query templates with those literals; do not dispatch selector or normalization macros that a user's private namespace can shadow. Obtain relevant mapping/identity data with caller-authenticated, explicitly app/shared collection reads and bounded typed results; do not execute a privately shadowed lookup definition. Shared scope/configuration reads are attribution data, not delegated authorization.

Use verified Hubble cluster mappings and explicit Stream sensor-to-scope mappings in the existing observer mapping collection under `observer_kind=dns_sensor`. For this first adapter, Stream's indexed `host` is the configured sensor authority; operators must verify that it identifies the capture sensor, with one routing scope per authority. A capture spanning overlapping address domains is context only until the customer separates its sensor authorities; adding event-domain profiles is a future adapter extension. Blank, reserved/unmapped, duplicate, conflicting or unverified mappings cannot correlate. DNS scope mappings are customer attestations and require sample validation against the actual resolver path. Explicit shared identity reads must reproduce the public identity lookup's legacy-default quarantine and validity/ambiguity rules rather than bypassing them by reading its underlying collection.

Fingerprint the validated selectors and relevant mapping rows for each request; bind response association, UI refresh and memory state to that configuration. Re-read relevant mapping/configuration after execution; changed or unreadable configuration invalidates temporal/identity association and offers refresh. New queries must not expand their index scope when any preflight fails.

Search with the caller's existing permissions and session. Do not add system/owner-context searches, broad index grants or direct-KV write bypasses. Results say what is visible to the caller; zero visible records do not prove index entitlement, complete coverage or no activity. Preserve the project's shared-dataset viewer boundary explicitly in operator documentation; this delivery does not establish tenant-separated authorization.

Add an allowlisted DNS drilldown builder using typed source, literal index configuration, bounded time/authority/address inputs and a fingerprint. Reconstruct the query through validators; never execute stored raw SPL or accept an event-provided URL. Apply the same permissions and configuration guards as inspection. A missing/expired raw record has a not-found/unavailable state and never triggers a broader fallback search. DNS names render as text. No active DNS queries, TXT payload collection for the UI, or public name-resolution services are introduced.

## Query budgets, completeness and lifecycle

The following are initial enforced product bounds, subject to qualification before release:

| Bound | Default behavior |
| --- | --- |
| Endpoint/evidence time window | Last hour by default; at most 24 hours per request. A larger application graph requires an explicitly selected evidence subwindow. |
| DNS lookback/association-age cap | One hour, administrator configurable from 60 seconds through 24 hours. Total DNS event-time search span is evidence window plus that lookback. |
| Input selection | One verified scope; at most eight actual addresses per endpoint side and 256 retained traffic observation contexts. Oversized selections require narrowing; no silent Cartesian expansion. |
| Source input processing | At most 10,000 matching source observations plus an overflow sentinel per adapter/request before answer expansion; hitting the cap marks input incomplete. Parse at most 1 MiB per individual source record, 1,024 characters per displayed name, 64 answers and 32 aliases per observation. Reject or truncate oversized content with explicit quality/cap reasons and suppress its address association. |
| Visible DNS records | At most 64 total, sorted by event time descending and stable source/fingerprint tie breakers. Per-source bounded summaries preserve whether more records exist. |
| DNS execution | Server search deadline 30 seconds and client deadline 35 seconds; configure server-side cancellation/expiry where supported. Verify actual native behavior on each qualified target. |
| Optional concurrency | At most two optional jobs per browser session, at most one per adapter. Inspection and optional DNS health probes share this budget; core traffic requests have priority. |
| Refresh/retry/cache | Coalesce identical in-flight requests. No polling or automatic retry. Retain only current-selection data in memory; clear it on identity, configuration, window or selection change. |

Output limits do not guarantee a bound on raw events scanned; field extraction can still examine many events. Use early index, sourcetype, authority, client and time filters; deadlines, role/search quotas and measured deployment capacity provide the execution boundary. Document scan cost and workload effects instead of equating a display cap with a license or CPU budget. Do not change customer quotas automatically.

Keep the shared search client strict about result counts, finalized/truncated jobs and ERROR/FATAL messages. Add optional request deadline/dispatch-budget parameters whose defaults preserve existing callers. Each adapter emits at most 64 records and exactly one validated completion envelope; cross-source merge applies the total display bound. The envelope reports deliberate input/output/array caps and rejected records. Missing/duplicate metadata, unverified result counts, peer errors, unexpected subsearch limits or early finalization make execution unavailable, not complete. Avoid hidden capped subsearch joins; treat any unavoidable bounded child as its own independently checked operation.

Deliberate display capping is distinct from incomplete input. Known positive observations can remain inspectable under a declared cap; incomplete input never supports uniqueness, exhaustive impact, global absence or complete connection attribution. Metadata lists the failed source even when another adapter succeeds. Complete execution means completion of the declared caller-visible request, not complete resolver/network coverage.

Cancel and invalidate evidence when the user changes page, selection, time window, configuration, user session or demo/live mode. Guard against late promises replacing current results. Client cancellation is best effort; test that server deadlines and expiry prevent abandoned jobs from continuing indefinitely. Track native job creation acknowledgements/identifiers and cleanup state. Superseding a request does not free a server execution slot until cancellation or server-side expiry is confirmed; queue replacements instead of launching an unbounded sequence of jobs. Native job-status checks for cleanup are permitted; they do not rerun DNS searches. Uncertain creation/cancellation keeps the affected slot occupied and shows a cleanup status. Browser limits are local resource controls, while Splunk's deployment/role quotas govern aggregate work across tabs and users.

## Exports, persistence and user experience

Provide selection-level evidence JSON and CSV downloads, explicitly requested by the user. Include result schema, scope/window, retrieval time, configuration fingerprint, attribution bases, per-source errors and cap/coverage metadata. Export only the evidence already loaded and authorized, clearly identifying it as a subset where applicable. Use existing CSV formula protection. Do not add DNS names to required-flow policy exports or infer firewall rules from queries.

Application graph JSON remains its existing schema. DNS data are not silently embedded into shared snapshots, saved views, browser storage, telemetry, exception logs or URLs. Endpoint bookmarks/deep links contain validated inputs and reread current evidence when opened; they are not historical evidence snapshots. Saved application views keep their existing format. Explicit evidence downloads are the portable record of an investigation; raw record references are not permanent guarantees.

Support accessible keyboard selection, table alternatives, status announcements, long-name wrapping, dark/light themes and loading/empty/error states. Show source/authority, event time, measured latency when supplied, resolution outcome, answers and attribution reason. Separate DNS response failure, missing response, policy rejection and absent evidence. Show source loss/redaction/coverage diagnostics where exported without inferring completeness from their absence. Explain cache, forwarding, NAT, NodeLocal DNS and mesh limitations in contextual help and operator handoffs.

## Validation and release gates

Implement in five reviewable increments: evidence/endpoint contracts and fixtures; source configuration/readiness; endpoint traffic investigation; DNS adapters and inspection/export UX; integration and deployment qualification. Preserve independent file ownership if work is delegated. Each increment receives targeted checks and independent review; integrated qualification binds results to the exact package/diff.

1. **Schema and protocol checks:** vendor-grounded fixtures for Stream transactions and Hubble request/response direction, optional/default fields, UUID presence/absence, timestamps/precision, scalar/list TTLs, aliases/multiple answers, record types, normalized IPs, NXDOMAIN/SERVFAIL/NOERROR-with-no-address, TCP fallback, duplicates versus genuine retries, policy rejection, redacted/malformed/oversized values and supplied loss diagnostics. Record producer/exporter/TA versions and sample provenance. Do not assume the existing Hubble Enterprise sample contains DNS qualification evidence.
2. **Attribution checks:** all scenario rows above, including same-IP/different-scope, recycled pod/client addresses, known ownership conflicts, missing owner history, sidecar/shared proxies, NAT64/DNS64 without translation evidence, shared resolver forwarding, multiple candidate names, delayed/out-of-order data, clock uncertainty, TTL boundaries, partially captured/long-lived flows and capped tuple history. Assert zero invented relationships, ownership, unique-name claims or counter changes.
3. **Query/security checks:** invalid and hostile identifiers, quotes/backticks/wildcards/control characters, private macro/lookup shadowing, configuration change between checks, partial index access, viewer/admin boundaries, raw-drilldown access loss and expired references. Exercise 0/64/65 output records, input overflow, missing/duplicate completion envelopes, finalized jobs, peer loss, malformed counts and one-adapter failure. Unselected sources dispatch no work and restricted DNS access cannot prevent core map/endpoint traffic results.
4. **Product checks:** application and standalone VM flows, microservice and mesh examples, DNS-only root evidence, forward/back/peer navigation, refresh/cancel/deep-link validation, stale-response rejection, multi-scope narrowing, accessibility, themes, explicit exports and absence of DNS in saved application state or required-flow exports. Test both V1 and V2 traffic contracts and old snapshots/settings with no DNS fields.
5. **Upgrade/rollback checks:** settings ledger fingerprints and concurrency semantics remain intact; absent source IDs are unselected; all serving search heads run the same app version before activation. Disable DNS and cancel investigations before rollback, preserve the settings ledger, and verify core operation with the older registry. Older code may hide/drop unknown source IDs when saving, so do not promise retained DNS intent through an older-version save. Re-enable only after a complete compatible upgrade. Test app removal/reinstall and read-only settings modes without bypassing persistence qualification.
6. **Runtime/performance checks:** run repository frontend lint/type/tests/build/package, Python static/contract checks and focused locked Splunk lab scenarios. Exercise a separate search peer and each claimed SHC member, cancellation and role limits. Initial load qualification uses ten simultaneous investigating users with both adapters, representative high-cardinality/noisy data, late events, minimum/maximum windows and cold/warm searches. Record server scan/resource cost, queue/rejection behavior, end-to-end latency, memory and effects on core builders/map searches. Target p95 evidence completion within ten seconds under the declared supported workload and no more than 10 percent increase in core-map p95 versus a repeated comparable baseline. A failed gate requires optimization or a narrower documented supported envelope; limits are not silently raised.
7. **Source and platform acceptance:** qualify genuine sanitized DNS feeds for both adapters before claiming production source support, in addition to synthetic fixture tests. Publish exact tested schema/product/platform versions and capacity. Start with the repository's qualified Enterprise 10.6.0.5 target; recorded baseline qualification does not qualify these additions. Other Enterprise versions, SHC production topologies and Splunk Cloud require their own evidence; the existing Cloud/settings gates remain effective. Missing access/samples leave the corresponding production claim unqualified.

Operator guidance covers sensor placement, client-preservation tests, DNS L7/export configuration, source/scope mapping, clock assumptions, permissions, collection losses, encrypted/cached DNS, ingestion/retention sizing, quiet-feed interpretation, search quotas, disabling and rollback. Deployment teams must attest to the data shared with app viewers. Operational diagnostics expose durations, counts, cap/parse/error reasons and configuration versions without recording queried names or client payloads in application telemetry.

Release requires independent review with no unresolved material correctness/security findings, passing target-specific gates, an exact candidate package/checksum and a completed operator acceptance record. Source or capacity claims remain limited to that evidence. No commit, publication, deployment or live source change is authorized by this design document.

## References

- [DNS ingestion research](DNS_INGESTION_RESEARCH.md), [data layer](DATA_LAYER.md), [deployment health](DEPLOYMENT_HEALTH.md), [security boundaries](SECURITY.md), and [deployment options](operators/deployment-options.md).
- [Stream infrastructure protocol fields](https://help.splunk.com/en/data-management/collect-stream-data/install-and-configure-splunk-stream/8.1/protocols/infrastructure) describe DNS latency in microseconds and TTL in seconds; the local inspected 8.1.6 packages provide concrete candidate field definitions.
- [Splunk search job properties](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/manage-jobs/view-search-job-properties) distinguish completion, early finalization and truncation; transport success alone cannot establish complete results.
