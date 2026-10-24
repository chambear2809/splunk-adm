# AWS VPC Flow Logs evidence

**Status:** optional, on-demand supplemental evidence. This guide does not establish production readiness and does not configure or mutate AWS resources. Read the [source design](../CLOUD_FLOW_EVIDENCE_DESIGN.md) before selecting the source.

Atlas can inspect records that have already been delivered to Splunk for a selected endpoint address, verified routing scope and bounded time window. Flow evidence is independent of the application graph: it does not create graph edges, change traffic counters, or prove a service dependency, successful application request, workload owner, or packet route.

## Supported producer contract

The initial adapter accepts only the AWS custom VPC Flow Logs record below, with the dedicated Splunk sourcetype **aws:vpcflow:v5** and the exact 29 fields in the exact order shown. It does not support AWS default version 2, Transit Gateway Flow Logs, Parquet, arbitrary custom field order, extra fields, or producer-normalized JSON.

Configure the custom flow log format using the AWS field identifiers in this order:

    version srcaddr dstaddr srcport dstport protocol start end type packets bytes account-id vpc-id subnet-id instance-id interface-id region az-id sublocation-type sublocation-id action tcp-flags pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service traffic-path flow-direction log-status

The corresponding CreateFlowLogs API value is:

    ${version} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${start} ${end} ${type} ${packets} ${bytes} ${account-id} ${vpc-id} ${subnet-id} ${instance-id} ${interface-id} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${action} ${tcp-flags} ${pkt-srcaddr} ${pkt-dstaddr} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${traffic-path} ${flow-direction} ${log-status}

AWS custom formats choose both field membership and order. The record version reports the highest field version included; it does not independently prove that every expected v5 field is present. The adapter therefore checks all 29 positions, requires version 5, and rejects unsupported records. See AWS [flow log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html), its [custom v5 examples](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html), and the [CreateFlowLogs API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateFlowLogs.html).

### Splunk timestamp parsing

Install the app's sourcetype stanza on the Splunk parsing tier that receives these events. The supported parser is intended to read the seventh token, start, as Unix seconds:

    SHOULD_LINEMERGE = false
    TIME_PREFIX = ^(?:\S+\s+){6}
    TIME_FORMAT = %s
    MAX_TIMESTAMP_LOOKAHEAD = 10

Confirm the effective configuration and observed event timestamps on the target before setting the source's schema-qualified flag. A local search-head-only props setting is insufficient when event parsing occurs on indexers or heavy forwarders. Direct HEC input may assign receipt time instead of applying this props stanza; the lab qualification therefore supplies HEC `time` explicitly and does not qualify props-based timestamp extraction. The ingestion path must assign `_time` from the producer `start` value (within one second), either through effective parsing-tier configuration or an explicit HEC event-time field. Atlas projects numeric `_time` as `event_time_epoch` and rejects records where it is missing or disagrees with producer `start`. Missing or incorrect event time can place records outside dispatch bounds before normalization, so verify the effective ingestion path with time-separated samples.

## Authority, account, and routing scope

Configure an administrator-verified observer mapping for each Splunk host that indexes these records:

- observer kind is **aws_vpc_flow**;
- observer is the exact, canonical lowercase Splunk host value used by the source search;
- routing scope is the selected, operator-defined network scope;
- mapping status is exactly **verified**;
- account ID, AWS Region, and VPC ID are explicit and valid for that host.

The shared source selector must name only reviewed lowercase index names. Select the dedicated source and schema qualification only after checking the mapping, target sourcetype, field order, parsing tier, timestamps, and viewer access. A host/index mapping is operator attestation; it is not cryptographic proof of the AWS publisher or an authorization boundary. Every Atlas viewer with access to this source can see its configured records.

Only an **active, schema-qualified** source dispatches a search. A staged source remains staged and is not queried; an active source without schema qualification fails closed.

For each event, if account ID, Region, or VPC ID is present, it must match the selected host mapping. AWS can emit **unknown** for the account of an AWS-service-created interface and **-** for fields that do not apply or cannot be computed; those values are retained as missing identity rather than used to identify an account or VPC. A capture-status record with missing metadata remains capture-scope evidence. It cannot be used to infer that the selected IP was absent.

Overlapping private addresses are separated by the selected routing scope and verified source authority. The query checks all four address fields but keeps them distinct: srcaddr and dstaddr describe the interface-aware view, while pkt-srcaddr and pkt-dstaddr are packet-level address fields. NAT, secondary addresses, EKS pod addresses, client-IP preservation, proxies, and service-managed interfaces can cause these values to differ. The selected address is reported with the field that matched; Atlas does not substitute a packet address for an interface address.

The account, Region, and VPC fields describe the interface being observed, not necessarily the VPC or resource that owns the opposite packet address. Do not use a private IP, source index, Region alone, or a matching packet address to claim the remote endpoint's resource identity.

## Time, action, status, and counters

Each record represents a flow over an aggregation interval on a network interface. AWS allows a maximum interval of 60 or 600 seconds; interfaces attached to Nitro instances always use 60 seconds or less. The start and end values are Unix seconds, and AWS documents up to 60 seconds of timestamp uncertainty around packet receipt/transmission. Atlas dispatches with up to 660 seconds of lookback (600-second interval plus 60-second timestamp uncertainty) and 60 seconds of future allowance, then checks interval overlap with the selected window using the same timestamp tolerance. The query returns source records; it does not merge or sum records.

The packets and bytes fields are counters from one record. Opposite directions, different ENIs, multiple subscriptions, re-deliveries, and overlapping flow-log resources can produce distinct or duplicate observations. Atlas presents each record separately and never sums these values into a connection total.

- **ACCEPT** means traffic was accepted at the recorded network policy point. It does not prove that a remote application received or completed a request.
- **REJECT** means traffic was rejected. The flow record does not necessarily identify which rule caused the result; packets received after a connection closed can also be rejected.
- **OK** is the flow logging status, not application success.
- **NODATA** indicates no network traffic to or from the observed interface during that aggregation interval.
- **SKIPDATA** indicates that one or more records were skipped during the interval, possibly due to AWS internal capacity or error.

NODATA and SKIPDATA records are displayed only as capture-status rows. They are not matched to the selected endpoint and must never be interpreted as endpoint absence or a complete coverage statement. AWS delivery is best effort: typical publication is about five minutes for CloudWatch Logs and ten minutes for Amazon S3, and can take longer. A quiet result, missing record, or NODATA status does not prove that no packet traversed the environment.

Flow Logs do not capture every IP traffic class. AWS documents exclusions including Amazon-provided DNS traffic, DHCP, instance metadata and time service traffic, ARP, the default VPC router address, and other cases in its [Flow Logs limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html). Confirm that the traffic of interest is actually observable before drawing conclusions from an empty result.

## Historical resource attribution

The record's interface ID and instance ID are displayed as AWS producer facts tied to that record interval. Instance ID can be **-** for requester-managed interfaces, and interface ID can be **-** for some regional NAT gateway flows. These fields do not establish that an IP or ENI belonged to a resource outside that record.

Atlas does not query today's AWS ENI attachment, IP assignment, or tags and apply them to historical flow records. Current state can be different from the state when the flow occurred. The existing IP identity history, when available, can associate an IP with a scope-specific entity for an interval; it does not prove an ENI-to-resource relationship.

An optional future owner attribution requires an independently qualified historical binding with the complete dimensions **(account, Region, VPC, ENI, IP, resource kind, resource ID, valid_from, valid_to)**. The interval must cover the flow record's full start/end interval plus accepted time uncertainty. If the binding is missing, stale, ambiguous, or overlaps another resource, owner attribution stays unavailable. That binding feed is not part of this initial adapter.

## Query bounds and qualification

The adapter searches only configured indexes, the dedicated sourcetype, mapped hosts, selected addresses across all four address fields, and capture-scope NODATA/SKIPDATA records. It transports only the fixed 29 projected values and source metadata, never arbitrary raw payload. A request is limited to 10,000 candidate records plus one overflow sentinel and at most 64 returned records. Input overflow, output caps, oversized rows, rejected records, Splunk warnings, source errors, or configuration changes remain explicit. A display cap does not bound indexer scan cost.

Before selecting AWS VPC Flow Logs, retain sanitized samples for ACCEPT, REJECT, NODATA, and SKIPDATA where available; IPv4 and IPv6; differing interface and packet addresses; missing fields; and all configured account/Region/VPC authorities. Verify:

1. the exact dedicated sourcetype, one-line event handling, 29-token field count and positions;
2. start parsing on the correct tier, observed event/index times, ingestion delay, and search-window overlap;
3. unique verified host/account/Region/VPC mappings, including missing and unknown event metadata;
4. viewer index permissions, Splunk search quotas, cancellation and completion handling, and measured scan cost;
5. that status-only records stay capture-scope, ACCEPT does not become an application-success claim, counters are not aggregated, and no result changes the graph or traffic counters.

The schema-qualified setting is a reviewed operator claim about the exact target feed, not a feature detector. Keep the source unqualified until these checks pass. This guide authorizes no AWS API calls, source creation, IAM changes, credentials, or index mutations. Manage AWS collection and Splunk ingestion through the normal, separately reviewed operations process.
