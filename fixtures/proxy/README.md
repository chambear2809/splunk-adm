# Envoy proxy evidence fixture

`envoy-v1.40-http-access.json` is a sanitized synthetic event for the proposed
`application_atlas.envoy_http_access.v1` contract. All IP addresses use the
documentation ranges from RFC 5737. It models one HTTP `DownstreamEnd` event,
keeps both direct transport legs, and identifies the selected upstream only
from `upstream_remote_ip` and `upstream_remote_port`.

The event is a test fixture, not a representative sample from a deployed Envoy
release. A production source remains unqualified until an operator captures and
checks the exact configured event schema, timestamp extraction, host mapping,
access-log filter, and observed Envoy release.
