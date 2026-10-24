# Envoy proxy evidence design

## Contract

The supplemental source ID is `proxy_envoy`. The proposed event contract is
`application_atlas.envoy_http_access.v1`, transported as
`atlas:proxy:envoy_access`. It is based on Envoy's versioned v1.40.0
documentation for access-log operators and `typed_json_format`; it is not a
claim that any deployed Envoy release or ingestion pipeline has been
qualified. Operators must retain the actual binary version and sample
qualification evidence.

This first adapter targets Envoy request logs. Existing Hubble translated-tuple
and L7 handoff evidence remains in the graph's separate client-handoff path;
the Envoy adapter does not reinterpret or merge it. The FTD translation gap
remains open: FTD NAT connection records and generic load-balancer access logs
are unsupported until their original/translated tuple, connection identity and
scope semantics are qualified in a separate source contract.

Each event is one HCM `DownstreamEnd` HTTP stream log. It includes:

- The request's `STREAM_ID` as a display/reference value only.
- `START_TIME(%s.%3f)` and `DURATION` with the explicit duration basis
  “request start to last byte out.”
- Physical downstream direct peer and listener address/port operators.
- Upstream local address and the selected upstream remote address/port.
- The raw configured cluster name, route, response code/flags, and attempt
  count as separate fields.
- A fixed schema ID, routing authority, and observer ID supplied as configured
  environment values. The observer ID must equal the Splunk `host` field and
  map uniquely to the selected scope.

The event deliberately excludes XFF. Ordinary downstream remote address
operators can reflect an address inferred from XFF or Proxy Protocol, whereas
the direct remote operators identify Envoy's physical adjacent peer. The
upstream remote IP is the only source for `selectedBackend`; the cluster name
is not backend membership. No request is joined to other events by stream ID,
tuple, timestamp, or shared proxy identity.

## Query and normalization

`buildProxySearch(config, selection)` validates the selected source, schema
qualification, literal indexes, exact observer authorities, and a unique
verified `envoy_proxy` mapping to `selection.scope`. The SPL filters by those
indexes and hosts, exact sourcetype/schema/log type/routing authority, and the
selected endpoint address on either the downstream direct peer or upstream
remote leg. It uses a bounded 24-hour pre-window lookback, then checks that the
request interval overlaps the selected time interval.

The query projects only the declared event fields through `json_object`,
retains index, host, event/index time and indexer bucket/offset fingerprint,
and adds numeric `event_time_epoch=tonumber(_time)` for strict normalization
even when Splunk's REST response serializes `_time` as ISO text. It then marks
raw events over 1 MiB oversized, limits input to 10,001 rows (10,000 plus
overflow sentinel), and returns at most 64 records plus one exact completion
row. The common supplemental loader validates the completion envelope and
search warnings before calling `normalizeProxyEvidence`.

`normalizeProxyEvidence(rows, selection, config)` rejects records with an
unknown schema/log type, missing or mismatched observer/scope, unconfigured
index, invalid event fingerprint, unparsed timestamp, `_time` disagreement,
out-of-window request, invalid direct peer, or no exact match to a selected
endpoint on the allowed legs. It accepts a record with a missing stream ID. It
keeps a missing upstream address as unknown, never substitutes `UPSTREAM_CLUSTER`
or a configured membership list, and records retry limitations. The output
contains no arbitrary raw event data. It requires the numeric SPL projection of
indexed `_time` and checks it against Envoy `start_time`, regardless of how the
REST layer serialized the `_time` field.

The generic loader invalidates source qualification if the settings fingerprint
changes during capture. The panel suppresses any association claim when the
source schema is unqualified, the configuration changes, or input is capped.
The optional search is user-triggered and uses shared job admission,
cancellation, and completion checks.

## UI and interpretation

`ProxyEvidenceInspection` is the central integration entry point. It accepts a
selection, search client, and optional configuration client; it does not search
on mount. `ProxyEvidencePanel` is result-only. It labels the downstream peer,
listener, selected upstream, cluster, request duration, status, observer, and
stream ID without merging the two transport legs. It reports caps, source
qualification, configuration change, and source coverage.

The output is supplemental request evidence, not packet proof, original-client
identity, a complete proxy inventory, or evidence that the configured route
pool's other members were selected. Long-running requests that began more than
24 hours before the selected window are outside the bounded start lookback.
Requests with no usable upstream remote IP have no selected backend in the
output.

## Qualification boundary

The TypeScript normalizer and fixtures prove contract handling for synthetic
events. The disposable lab acceptance test submits to
`/services/collector/event` with HEC `time` from synthetic Envoy `start_time`,
then checks indexed time and the numeric epoch alias returned alongside
REST-formatted `_time`. That test path does not exercise the app's parsing-tier
`props.conf` stanza, so it does not qualify timestamp extraction. Neither test
qualifies Envoy deployment configuration, logger uniqueness, collector
duplication, source permissions, index scan cost, production timestamp parsing,
or deployed field availability. A source becomes usable only after a target
operator checks the exact release/config/sample and Atlas's selected index,
host, scope mapping, production `_time` behavior, caps, and failure cases. See
the [operator setup guide](operators/proxy-evidence.md).
