# Splunk Stream NetFlow Dependency Map: Initial Research

## Goal and working hypothesis

Build a time-aware graph of communicating network entities, then resolve those entities to services and applications using authoritative context. NetFlow/IPFIX provides useful flow-level evidence—endpoints, ports, protocol, time, and traffic volume—but does not by itself reliably identify the business application or process responsible for a connection. Application identity will depend on network and application context, supplied by suitable TAs, lookups, or other inventory sources.

The pilot now covers both VMs and Kubernetes, with OTel/Splunk Observability, AppDynamics, and the requested Cisco networking/security products as candidate context sources. See [telemetry correlation design](TELEMETRY_CORRELATION_DESIGN.md) and [the downloaded TA package findings](TA_PACKAGE_ANALYSIS.md).

## What Splunk Stream can provide

Splunk documents Stream as able to ingest NetFlow v5/v9, IPFIX, sFlow v5, and jFlow over UDP. A Stream Forwarder or Independent Stream Forwarder listens on a configured IP and port in `streamfwd.conf`; the Stream UI then configures a NetFlow metadata stream. The documented search sourcetype is `stream:netflow`. Stream uses flow start/end fields to set event time and end time when they are present. See [ingest NetFlow and IPFIX](https://help.splunk.com/en/splunk-enterprise/collect-stream-data/install-and-configure-splunk-stream/8.1/configure-your-splunk-stream-installation/use-splunk-stream-to-ingest-netflow-and-ipfix-data) and [Stream search and timestamp behavior](https://help.splunk.com/en/splunk-cloud-platform/collect-stream-data/install-and-configure-splunk-stream/8.0/reference/splunk-stream-search-syntax).

Inspection of Wire Data 8.1.6 shows an important timing detail: its common `source::stream:*` parsing stanza selects `endtime` for Splunk `_time`, while `timestamp` is the start. Preserve the explicit flow interval for identity and trace correlation and verify this behavior in the deployed configuration.

Capacity is a first-order design question. Splunk recommends Independent Stream Forwarder for scaling flow ingestion and says the Stream Forwarder path using `Splunk_TA_stream_wire_data` is for low-bandwidth or aggregated NetFlow capture because of limited ingestion capability. Estimate exporter rate, sampling, number of sensors, event size, and index volume before selecting a collector design.

Stream has separate packages and roles: `splunk_app_stream` provides search-head UI and dashboards; `Splunk_TA_stream` runs collection on forwarders; `Splunk_TA_stream_wire_data` supplies search/index knowledge objects. Confirm the target deployment and current Stream version before installation. See [Stream package roles](https://help.splunk.com/en/splunk-cloud-platform/collect-stream-data/install-and-configure-splunk-stream/8.0/introduction/splunk-stream-installation-package-overview).

## How TAs can help

TAs can define inputs and source types, parse vendor-specific fields, normalize field names, add lookups, and map source types to CIM. Splunk notes that add-on CIM mappings and dashboards depend on assigning the expected source type. First inventory which TAs are already installed, what events they cover, where their knowledge objects run, and whether they provide usable flow and asset fields. See [Splunk add-ons and CIM](https://help.splunk.com/en/supported-add-ons/about-the-splunk-supported-add-ons) and [CIM Network Traffic field mapping](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.0/field-mappings/network-traffic-field-mapping).

For a first graph, normalize source/destination IP and port, transport, event start/end, bytes/packets, exporter/device, and direction into consistent fields (ideally the CIM Network Traffic data model). Enrich those endpoints with maintained sources such as CMDB or IPAM ownership, DNS, subnet/zone, cloud or virtual network metadata, NAT mappings, load balancer pools, and a service/application catalog. Track enrichment provenance and confidence; stale or ambiguous IP-to-service mappings should not silently become certain application dependencies.

One Splunkbase result named “Technology Add-on for NetFlow” is a NetFlow Logic product and documents NetFlow Optimizer as a requirement; it is not a generic standalone receiver. Treat it as a separate product option, not as an assumed built-in Splunk TA. See [its Splunkbase listing](https://splunkbase.splunk.com/app/1838).

## Candidate data path

1. Choose one or more exporters and a bounded network segment with known applications.
2. Send flow records to a Stream collector at an appropriate network vantage point; confirm protocol version, UDP reachability, sampling, exporter templates, and load.
3. Configure the Stream NetFlow metadata stream and confirm raw flow fields, event timestamps, and `sourcetype=stream:netflow`.
4. Apply TA parsing and CIM normalization, then enrich endpoint identities from approved inventory data.
5. Aggregate flows into directional edges between resolved entities over useful time windows. Preserve raw endpoint-level evidence and represent unresolved endpoints as IP/subnet nodes.
6. Visualize the resulting graph with a dashboard or other approved Splunk visualization. The inspected Stream App 8.1.6 Flow Visualization queries `source=stream:Splunk_IP` for an IPv4 heatmap; application mapping needs searches that use NetFlow and the resolved application/workload records. See [package evidence](TA_PACKAGE_ANALYSIS.md).

Do not combine Stream-observed traffic and exported NetFlow into one edge total until duplicate observation and directional semantics are understood. NetFlow sampling, NAT, asymmetric routing, exporters reporting both directions, and ephemeral addresses can distort counts or identity unless modeled explicitly.

## Pilot checks and open questions

- What Splunk Enterprise or Cloud version, Stream version, deployment topology, and license are in use?
- Which NetFlow/IPFIX versions and exporters are present? What are their flow rates, sampling settings, and template behavior?
- Which network segments and applications can provide a representative, low-risk pilot? Where can Stream collectors receive their UDP exports?
- Which TAs are already installed, and which provide flow parsing, CIM mapping, DNS, network inventory, cloud metadata, or application context?
- What authoritative CMDB/IPAM/service ownership sources exist, and how often do IP ownership and NAT mappings change?
- What does “dependency” mean for the initial map: observed endpoint communication, service-to-service calls, or application-to-application relationships?

For the pilot, measure event completeness, timestamp accuracy, flow duplication, sampled-flow behavior, unresolved identity rate, enrichment freshness, ingestion volume, and collector drops. Validate known dependencies with application and network owners before treating the map as authoritative.
