# DNS ingestion and its value for Application Atlas

Research date: 2026-10-23. Status: feasibility and proposed design; DNS ingestion and correlation are not implemented in Atlas.

The [reviewed integration plan](DNS_EVIDENCE_DESIGN.md) selects optional on-demand evidence, Stream and Hubble adapters, and a separate endpoint investigation workflow. Its implementation decisions supersede the candidate integration approach below, including the suggestion of a DNS history builder.

DNS is a useful next enrichment source for Atlas. It can explain which names workloads look up, associate observed destination IPs with candidate names, and expose failures that happen before an application opens a connection. The strongest initial use cases are naming external dependencies and troubleshooting resolution. DNS activity alone cannot establish that the client connected to the returned address or identify the business application behind a shared IP.

Splunk can ingest DNS through packet metadata collectors, resolver logs and cloud integrations. It also defines a [CIM Network Resolution DNS model](https://help.splunk.com/en/data-management/common-information-model/6.3/data-models/network-resolution-dns). Collection is feasible; selecting a source with the necessary answer and client context is the main design decision.

## What Atlas already supports

Atlas normalizes traffic into conversations and resolves endpoints using IP address, routing scope and validity intervals. Its [correlation design](TELEMETRY_CORRELATION_DESIGN.md) already treats DNS names as suggestive identity evidence and requires provenance and visible ambiguity.

- The synthetic scenario contains a UDP/53 conversation to a CoreDNS pod (`fixtures/raw/scenario.json`, conversation `c-dns`). Atlas can represent the resolver dependency using existing traffic and Kubernetes identity.
- `adm_flows_hubble` in `splunk_app/splunk_adm/default/macros.conf` handles L3/L4 traffic, translation evidence and selected HTTP requests. It does not extract DNS L7 queries or answers; its HTTP evidence filter is unsuitable for DNS responses.
- `adm_ip_identity` in `default/transforms.conf` holds scoped endpoint ownership and validity. Atlas has no dedicated DNS observation history, answer lookup or DNS health source.

Indexing DNS events would make them searchable in Splunk. Atlas would need an adapter, correlation history and UI support to use their contents. Existing traffic ingestion remains useful for the actual connections, including connections to resolvers.

## Benefits for the project

| Capability | Example question Atlas could answer | Evidence required |
| --- | --- | --- |
| Names on external dependencies | Which observed destination IPs might correspond to `api.vendor.example`? | A successful answer associated with the same client and routing scope, followed by compatible traffic. |
| Resolution troubleshooting | Did a workload receive NXDOMAIN, SERVFAIL or a policy block before its request failed? | Response codes or explicit timeout/block events, workload identity at that time, and latency where measured. |
| Change and migration review | Which workloads queried the database name before its address changed? | Historical client-to-name observations and answer history; traffic distinguishes observed connections. |
| Shared resolver exposure | Which application workloads were observed using the affected resolver? | Resolver identity, DNS observations and existing resolver conversations. Coverage must accompany impact counts. |
| Security investigation context | Did an application query a domain blocked by the DNS security service? | Source-provided action/category and client identity. Threat detections would be a separate feature. |

For example, a pod receives an answer for `payments.vendor.example` containing `203.0.113.20`, then a flow records that pod connecting to the address on TCP/443. Atlas could attach the queried name and DNS evidence to that connection. A failed lookup could instead appear in an investigation timeline even when there is no destination connection.

## Ingestion choices

| Source | Path into Splunk | Fit and material limits |
| --- | --- | --- |
| Splunk Stream DNS | Capture visible DNS packets with a Stream Forwarder or Independent Stream Forwarder; index DNS metadata. | Good candidate across VMs and Kubernetes where capture preserves client addresses. Requires a packet vantage point such as the resolver host or a suitable mirror. Existing NetFlow reception does not supply DNS payloads. |
| Hubble DNS L7 | Export DNS request and response flow events through the existing JSON/file collection path. | Strong Kubernetes fit because flow events carry endpoint context. Requires L7 DNS visibility and export filters that retain both requests and responses. Existing L3/L4 Hubble export alone is insufficient. |
| CoreDNS query logs | Collect resolver stdout through a container log pipeline into Splunk. | Useful for client, query, response code and duration. The standard format omits returned IPs and TTLs, so it supports troubleshooting without supplying full answer enrichment. |
| Windows DNS server logs | Use a qualified DNS log or ETW collection path, then normalize the selected event schema. | Covers enterprise resolver activity. Audit logs concern configuration changes; query analytics require the relevant analytical/debug events. Verify the collector can consume that channel and decode any needed packet data. |
| Route 53 Resolver query logs | Deliver to S3, CloudWatch Logs or Firehose, then use a compatible Splunk collection path. | Useful for AWS resource and routing context and returned answers. Cache-served queries are omitted. The documented schema does not expose TTL or response latency. |
| Cisco Umbrella or Secure Access | Collect exported S3 DNS event logs with the Cisco Secure Access Add-on for Splunk. | Useful for queried names, identities and explicit policy outcomes. Check the exact schema for answers/TTLs and client granularity. Internal queries forwarded by an Umbrella VA to internal resolvers are absent from Umbrella cloud logging. |
| Existing Zeek sensor | Collect its `dns.log` using a compatible parser. | An alternative when deployed already; DNS records can include client/resolver tuples, answers, TTLs and round trip time. Sensor visibility determines coverage. |

Splunk documents [DNS protocol extraction in Stream](https://help.splunk.com/en/splunk-enterprise/collect-stream-data/install-and-configure-splunk-stream/8.1/protocols/supported-protocols). The locally inspected **Stream App 8.1.6** `default/streams/dns` enables `query`, `query_type`, `host_addr`, `ttl`, `reply_code`, `transaction_id` and `response_time`; it describes response time in **microseconds**. **Wire Data 8.1.6** `default/props.conf:181` aliases `host_addr{}` to CIM `answer`. These package defaults establish candidate fields, not the contents of a deployed feed. Preserve answer/type/TTL associations from samples rather than assuming independently extracted arrays align. Package provenance and checksums are already in [the package manifest](../research/package-manifest.json); extracted packages are ignored research data.

Cilium's [DNS flow schema](https://docs.cilium.io/en/stable/_api/v1/flow/README/#dns) includes query, answer IPs, CNAMEs, TTL, response code and record types. [L7 visibility](https://docs.cilium.io/en/stable/observability/visibility/) requires proxy support and matching DNS policy rules; DNS visibility is egress only. Those policies can change allowed traffic, so enabling DNS visibility requires review of the actual cluster policy. The exported TTL is a scalar; do not invent per-record TTLs from it.

[CoreDNS log formatting](https://coredns.io/plugins/log/) documents the available fields and the cost of logging on busy resolvers. [Windows DNS logging](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics) distinguishes audit, analytical and debug events. [Zeek DNS logging](https://docs.zeek.org/en/current/reference/logs/dns.html) shows answer and TTL arrays and explains that encrypted DNS is outside ordinary packet DNS analysis.

AWS documents [Resolver query logging and its cache limitation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html) and [the event fields](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-format.html). Preserve account, Region and available VPC/resource identifiers; a Route 53 Profile association can replace `vpc_id` with a profile resource ID, which is insufficient by itself to resolve overlapping address spaces. Public hosted-zone query logs observe recursive resolvers and are a different source from workload Resolver query logs.

Cisco documents [S3 collection through its Secure Access add-on](https://developer.cisco.com/docs/cloud-security/cisco-cloud-security-add-on-for-splunk/). The documented [Secure Access DNS CSV schema](https://www.cisco.com/c/en/us/td/docs/security/secure-access/secure-access-help/CiscoSecureAccessHelp/logging-intro/log_formats_and_versioning.html) contains client internal/external IP, domain, response code, action and categories, but no answer IP or TTL. Its external IP is a client address, so it must not become the resolved destination. Cisco also explains the [Umbrella internal-domain visibility gap](https://www.cisco.com/c/en/us/support/docs/security/umbrella/225172-understand-why-queries-for-internal.html). Validate the selected product and export version instead of assuming the two products have identical schemas. Security alert push feeds should not be assumed to contain every DNS transaction.

## Proposed Atlas integration

Start with a separate DNS evidence path and attach its results to existing conversations:

```text
DNS collector -> raw Splunk index -> normalized DNS observations
                                          |
                               scoped answer history
                                          |
Flow or trace -> observed connection -> DNS context in Atlas
```

Normalize common fields toward CIM: client `src`, resolver `dest` where known, `query`, record type, `message_type`, `answer`, `reply_code`, `ttl`, transaction identifier and measured duration. Normalize latency units explicitly. Retain source fields when the source supplies only a completed transaction or omits the resolver; do not manufacture a request/response pair. CIM compatibility helps reuse searches but does not activate DNS support in Atlas.

Add Atlas context alongside those fields: observer/source authority, verified routing scope, event and index time, cluster, client workload identity, and policy action where supplied. Resolve the client against ownership history at the observation time. If only a node, forwarding resolver or NAT gateway is visible, retain that attribution; do not distribute its queries to all workloads behind it.

Maintain answer observations separately from authoritative endpoint ownership. For a proposed first adapter, retain the queried name, answer IP, available record/CNAME relationships, client identity, scope and evidence references. Prefer enrichment when an observed connection starts after the answer and within its usable TTL interval, with compatible client identity and scope. Use a conservative configured maximum age as an additional cap. Missing TTL permits historical observation context, not an invented validity period; TTL zero does not create a persistent binding. Long connections can retain the evidence matched at their start without extending DNS validity to new connections.

Keep several candidate names when a shared address or simultaneous lookups make the match ambiguous. CDN addresses, split DNS, caches, prefetching and application connection pools prevent a unique name assignment in many cases. Preserve IP/entity identifiers underneath display labels. A DNS answer must not merge endpoints, replace Kubernetes ownership, establish a Service backend or bridge NAT without the necessary evidence.

Deduplicate observations without increasing flow byte/packet counts. Distinguish request and response directions and scope transaction IDs by client/resolver tuple, observer and time; a DNS transaction ID alone is not unique. Restrict IP enrichment to validated address records and explicit alias relationships. PTR, TXT and unrelated additional records must not become destination-address bindings. Preserve explicit blocks or sinkhole responses as policy evidence rather than labeling a sinkhole as the intended application endpoint.

Likely implementation areas are DNS source macros and normalization in `default/macros.conf`, bounded history builders in `default/savedsearches.conf`, dedicated lookup/collection definitions, source expectations and health, and graph/UI evidence attributes. Any new builder must follow the project's existing replay, retention and completeness contracts. Start with names and evidence on existing edges; a separate `queried_name` relationship can follow if DNS-only investigations need a graph representation.

## Pilot scope and decision criteria

Prefer an answer-bearing source already available at a useful client vantage point. For the current Kubernetes integration, inspect existing Hubble exports for DNS L7 responses first. If those are absent, compare a bounded Stream capture with resolver logging. Use CoreDNS logs for a quick health investigation if answer history is not yet available. Add Umbrella when policy outcomes are a priority, or Route 53 when AWS resolver coverage is the target.

1. Select one application namespace or VM segment and its actual resolver path. Capture representative sanitized events, including success, failure, IPv6, aliases and multiple answers. Record collector/product versions, enabled fields and scope mapping.
2. Assess ingestion in Splunk first: timestamp parsing, query/response coverage, original client visibility, dropped/duplicate events, delivery delay and measured volume. Packet sensors cannot recover DNS names from ordinary DoH/DoT ciphertext; resolver-side logs may be needed.
3. Prototype DNS enrichment on a known set of existing flows. Compare correct candidate names, ambiguous matches and unresolved endpoints before and after. Verify that shared IPs and overlapping private scopes remain distinct.
4. Exercise answer changes, TTL expiry/zero/missing values, delayed logs, reused pod IPs, negative responses and explicit blocks. Confirm that DNS-only activity does not create application traffic or inflate counters. NXDOMAIN search-suffix attempts and NOERROR with no address answer require separate interpretation; missing responses alone do not prove a timeout.
5. Proceed when the application owner can validate useful name attribution, failures remain inspectable, misleading matches are prevented, and ingestion/search cost fits the deployment. Select numeric targets after measuring the source's baseline.

Estimate raw daily volume as `events_per_second * average_event_bytes * 86400`. For an illustrative **1,000 logged events/second at 800 bytes/event**, that is **69.12 GB/day** in decimal units, before storage replication and other overhead. A query and response logged separately may produce two events per transaction. Measure the selected feed rather than equating workload QPS with logged events; caching, aggregation and duplicate sensors change the ratio. Account for collection/delivery, Splunk entitlement, retention and search cost, and restrict access to DNS names and client identity according to existing deployment policy.

The next concrete deliverable should be a sample-based DNS field contract and one adapter prototype. The expected project value is clearer dependency context and earlier failure evidence; production coverage, attribution accuracy and performance need that pilot's measurements.
