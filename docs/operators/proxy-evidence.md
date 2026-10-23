# Envoy proxy evidence setup

Application Atlas can inspect selected Envoy HTTP access logs as supplemental
request evidence. This feed is off until an administrator selects the source,
verifies its observer-to-scope mapping, and qualifies the exact schema and
timestamp behavior. The feature does not make proxy logs a replacement for
network flow observations.

## Producer contract

The Atlas contract is `application_atlas.envoy_http_access.v1` with sourcetype
`atlas:proxy:envoy_access`. It is designed against the version-tagged Envoy
v1.40.0 access-log documentation. That documentation validates the operator
names and configuration shape; it does not qualify a deployed Envoy binary or
log pipeline. Record the actual producer release and inspect a sanitized event
from the target before enabling the source.

The producer example follows Envoy's [v1.40.0 access logging guide](https://www.envoyproxy.io/docs/envoy/v1.40.0/configuration/observability/access_log/usage), [substitution formatter reference](https://www.envoyproxy.io/docs/envoy/v1.40.0/configuration/advanced/substitution_formatter), and [v3 access-log filter reference](https://www.envoyproxy.io/docs/envoy/v1.40.0/api-v3/config/accesslog/v3/accesslog.proto). The timestamp example follows Splunk Enterprise 9.2's [timestamp recognition reference](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.2/configure-timestamps/configure-timestamp-recognition).

Configure one HTTP Connection Manager access logger with a JSON event for each
`DownstreamEnd` stream. The following is the relevant fragment; place it in the
HTTP Connection Manager configuration and adapt the logger sink to the
deployment's collector:

```yaml
access_log:
  - name: envoy.access_loggers.stdout
    filter:
      log_type_filter:
        types: [DownstreamEnd]
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
      log_format:
        typed_json_format:
          schema: "%ENVIRONMENT(ATLAS_ENVOY_SCHEMA)%"
          routing_authority: "%ENVIRONMENT(ATLAS_ENVOY_ROUTING_AUTHORITY)%"
          observer_id: "%ENVIRONMENT(ATLAS_ENVOY_OBSERVER_ID)%"
          access_log_type: "%ACCESS_LOG_TYPE%"
          stream_id: "%STREAM_ID%"
          start_time: "%START_TIME(%s.%3f)%"
          duration_ms: "%DURATION%"
          downstream_direct_remote_ip: "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT%"
          downstream_direct_remote_port: "%DOWNSTREAM_DIRECT_REMOTE_PORT%"
          downstream_direct_local_ip: "%DOWNSTREAM_DIRECT_LOCAL_ADDRESS_WITHOUT_PORT%"
          downstream_direct_local_port: "%DOWNSTREAM_DIRECT_LOCAL_PORT%"
          upstream_local_ip: "%UPSTREAM_LOCAL_ADDRESS_WITHOUT_PORT%"
          upstream_local_port: "%UPSTREAM_LOCAL_PORT%"
          upstream_remote_ip: "%UPSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
          upstream_remote_port: "%UPSTREAM_REMOTE_PORT%"
          upstream_cluster: "%UPSTREAM_CLUSTER_RAW%"
          route_name: "%ROUTE_NAME%"
          response_code: "%RESPONSE_CODE%"
          response_flags: "%RESPONSE_FLAGS%"
          upstream_attempt_count: "%UPSTREAM_REQUEST_ATTEMPT_COUNT%"
```

Set these process environment values as fixed deployment configuration:

- `ATLAS_ENVOY_SCHEMA=application_atlas.envoy_http_access.v1`
- `ATLAS_ENVOY_ROUTING_AUTHORITY=<the exact Atlas routing scope>`
- `ATLAS_ENVOY_OBSERVER_ID=<the exact Splunk host value for this observer>`

The observer must be dedicated to the configured routing scope for this
contract. A shared Envoy serving several unrelated routing scopes cannot use a
process-wide authority value to assert per-request scope. Do not derive the
scope from XFF, a private address, a route name, or cluster membership. Configure
per-request trusted scope metadata and qualify a revised schema before using a
multi-scope observer.

The direct downstream remote operators describe the physical adjacent peer,
even if Envoy also infers a remote address from Proxy Protocol or XFF. The direct
local operators describe the physical listener. Atlas uses neither ordinary
`DOWNSTREAM_REMOTE_*` operators nor any XFF field. The upstream remote address
is the selected endpoint for this exchange; the cluster field is a routing pool
name, not a list of backend members. An absent or non-IP upstream address leaves
the selected backend unknown. Retry count is retained, but candidate endpoints
are not reconstructed.

All keys in Envoy's `typed_json_format` map to substitution operators. The
`schema` and scope/observer values therefore use environment substitution
operators rather than static YAML strings. Envoy renders `%DURATION%`,
`%RESPONSE_CODE%`, and `%UPSTREAM_REQUEST_ATTEMPT_COUNT%` as typed JSON numbers;
`%START_TIME(%s.%3f)%` is a string containing epoch seconds and milliseconds.
Unset typed values are JSON `null`; the normalizer treats absent stream IDs and
upstream endpoints as unavailable values, not as reasons to invent one.

## Splunk ingestion

Set `TIME_FORMAT` on the parsing tier that assigns event timestamps to this
sourcetype so `_time` reflects Envoy `start_time`. For Splunk Enterprise 9.2,
the documented format for epoch seconds and three fractional digits is
`%s.%3N` (Splunk's `%3N` differs from Envoy's `%3f`):

```ini
[atlas:proxy:envoy_access]
TIME_PREFIX = "start_time"\s*:\s*"
TIME_FORMAT = %s.%3N
MAX_TIMESTAMP_LOOKAHEAD = 20
```

The prefix must end immediately before the timestamp digits. Verify this on
the actual parsing tier and confirm returned `_time` agrees with the JSON
`start_time` within one second. Atlas rejects records whose indexed event time
does not agree. A wrong `_time` parser can also make Splunk's event-time window
omit records before Atlas can inspect them.

## Atlas configuration and qualification

Set the literal index selector through `adm_index_proxy_envoy`. Map the exact
Splunk `host` value and observer kind `envoy_proxy` to the approved routing
scope with `mapping_status=verified`. The producer's `observer_id` must match
that `host` value exactly. Set `adm_proxy_envoy_schema_qualified=1` only after
reviewing representative sanitized events and the checks below. A missing,
duplicate, stale, or conflicting mapping leaves the source unavailable.

Before selection, verify:

1. The deployed Envoy version, HCM logger configuration, and collector output.
2. One and only one `DownstreamEnd` event per test request, with no duplicate
   ingestion from another logger or collector path.
3. The exact schema value, source `host`, `observer_id`, routing authority,
   source index, and sourcetype.
4. IPv4/IPv6 downstream direct peers, physical listener addresses, successful
   upstream selection, no-upstream failures, retries, missing stream IDs, and
   any internal/non-IP upstream address form.
5. `_time` parsing, event delay, clock behavior, and the target's index and
   Splunk search-resource bounds.
6. Search behavior for access denied, missing indexes, malformed events,
   oversized events, quiet feeds, warnings, caps, cancellation, and a
   configuration change during capture.

The query scans the selected source indexes and exact mapped hosts, requires
the schema, scope, observer, and `DownstreamEnd` type, and matches only the
selected endpoint against the direct downstream peer or Envoy's upstream remote
IP. Its event-time predicate requires the request interval to overlap the
selected interval. It looks back at most 24 hours for requests that started
before the selected window; longer-running streams that began earlier are
outside this bounded capture. Search results include at most 10,000 matching
input events plus an overflow sentinel and at most 64 projected records. A
completion row must account for the transported rows exactly. Warnings or a
missing/invalid completion envelope make the source unavailable.

The projection includes only declared fields and never exports arbitrary
`_raw`, request headers, or payloads. Keep sanitized qualification samples in
approved internal storage; do not add customer data, credentials, tokens, or
full request payloads to this repository.

## Reading the evidence

Treat every record as one observed HTTP stream at one Envoy observer. The
downstream direct peer and listener and the upstream local and selected remote
are distinct connection legs. NAT, another proxy, or a shared gateway can make
the adjacent peer differ from the original workload. Atlas does not bridge
those legs with tuple/time coincidence, stream ID, or XFF, and it does not infer
backend membership from the configured cluster name. A `DownstreamEnd` record
does not prove that a request traversed every network hop or that a response
was delivered to the original client.

An empty result means no qualifying records were returned within the configured
indexes, observers, schema, time range, permissions, and caps. It does not prove
that no traffic passed through a proxy. A capped or changed configuration
suppresses any source-to-selection association; the rows remain labelled as
context only.
