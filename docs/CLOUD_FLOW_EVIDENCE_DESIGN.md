# AWS VPC Flow Logs evidence design

**Status:** source-specific initial design for optional, on-demand evidence. This does not qualify an AWS account, Splunk topology, feed, or production deployment.

## Boundary

The source adapter consumes only an AWS custom VPC Flow Logs v5 whitespace record with a fixed, reviewed 29-field order and the dedicated Splunk sourcetype **aws:vpcflow:v5**. It does not ingest, configure, or query AWS APIs. It does not modify scheduled searches, graph output, traffic counters, or identity writers. The shared optional-evidence loader owns execution leases, completion envelope, source configuration recheck, and input/output bounds.

The source publishes only typed projected values. The raw Splunk event is never returned to the browser. No arbitrary JSON, free-form producer field list, macro execution, lookup, join, or current AWS state is used to interpret a row.

## Record contract

The fixed source field order is:

    version srcaddr dstaddr srcport dstport protocol start end type packets bytes account-id vpc-id subnet-id instance-id interface-id region az-id sublocation-type sublocation-id action tcp-flags pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service traffic-path flow-direction log-status

The TypeScript projection list is the query allowlist and normalizer contract. Parsing requires exactly 29 tokens, version 5, bounded text, valid numeric ranges, valid IP literals, accepted action/status/direction values, a nonnegative ordered interval, configured source authority/index, and an opaque event fingerprint. Malformed, oversized, mismapped, out-of-window, or nonmatching rows increment rejected counts. The projection is tied to the AWS documented custom format; a producer that reorders or adds fields is unsupported until a new reviewed schema version is implemented.

AWS custom formats choose both field membership and order. Version is the highest version among fields included. The chosen profile includes the documented v5 packet service, direction, and traffic-path fields. AWS describes type values IPv4, IPv6, and EFA; missing values use a hyphen. The source retains account, Region, VPC, interface, and instance metadata exactly as producer facts and validates each available account, Region, and VPC value against the host mapping.

## Search and time

The query constrains source index, the dedicated sourcetype, and configured host authorities before splitting the record into projected columns. It tests the selected endpoint IP against srcaddr, dstaddr, pkt-srcaddr, and pkt-dstaddr separately. It also admits NODATA and SKIPDATA rows for capture-scope status display; these rows are never associated with a selected endpoint. Event fields are validated again by the normalizer.

AWS aggregates a flow over a maximum interval of 600 seconds by default or 60 seconds when configured; Nitro interfaces always use 60 seconds or less. The record start/end timestamps are Unix seconds and have up to 60 seconds of documented timestamp uncertainty. The shared loader dispatches from selection start minus 660 seconds through selection end plus 60 seconds. The query filters for record-interval overlap with the selected window extended by 60 seconds. Static sourcetype timestamp parsing reads token seven, start, so the event-time dispatch window can include any maximum-length aggregation that overlaps the selection.

Candidate input is capped at 10,001 rows so 10,001 explicitly signals the 10,000 input cap. The returned set is capped at 64 plus the common completion row. The common envelope reports input count, input cap, returned count, and oversized rows. Rows are sorted only after the candidate cap. A cap prevents a completeness claim and does not place a bound on Splunk scan cost.

No aggregation occurs in the source adapter. Packets and bytes stay on each record; there is no directional merge, duplicate suppression, or sum across ENIs or subscriptions. Index time, event time, source index, host authority, and event fingerprint remain on each observation.

## Identity and semantics

The verified observer mapping joins a Splunk host to one operator-attested routing scope, AWS account, Region, and VPC. Event metadata that is present must agree. The mapping separates overlapping private IP ranges between routing scopes. It does not prove publisher identity, provide access control, or prove that the opposite packet address belongs to the observed VPC.

Interface addresses and packet-level addresses remain separate. They can differ for NAT, secondary IPs, EKS pod networking, or other intermediaries. The adapter records exactly which address field matched the selected IP.

Action and status are different concepts. ACCEPT/REJECT describe the recorded network policy action and do not prove application outcome or identify a specific rejection rule. OK describes logging status. NODATA and SKIPDATA are capture-scope status, not selected-endpoint absence. AWS Flow Logs are best effort, can be delayed, and omit documented traffic classes.

ENI and instance IDs remain producer-reported values with the observation interval. Current ENI attachment or tag state is not used for historical attribution. IP-only identity history can associate a selected IP with an entity over time but cannot prove which ENI owned that IP. Optional owner attribution would require a separately qualified, time-valid binding with account, Region, VPC, ENI, IP, resource kind, resource ID, and half-open validity interval. The interval must cover the record with accepted timestamp uncertainty; missing or conflicting bindings leave attribution unavailable.

All returned records use context-only attribution in the initial implementation. No Flow Logs record creates a dependency edge or augments application graph counters.

## Operator qualification

The source-specific operator guide contains the exact AWS custom log-format string and Splunk timestamp stanza. Qualification is target-specific and must verify raw field order, data source and delivery mode, source host mapping, metadata match, parsing tier, timestamp behavior, permissions, search quotas, cancellation, caps, and measured scan cost. A fixed-schema fixture and unit tests validate the adapter contract but do not qualify a live AWS or Splunk deployment.

Primary references: AWS [Flow log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html), [record examples](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html), [limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html), and [CreateFlowLogs API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateFlowLogs.html).
