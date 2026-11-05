# Qualified native network observations

`admqualified mode=graph` can add native Hubble and NetFlow observations beside
qualified OTel service calls. The existing finite pod-IP ownership manifests and
raw span qualification remain mandatory. Catalog behavior is unchanged.

Enable the `[network]` stanza of `adm_identity.conf` only after registering exact
`profiles_json` source authorities. Each profile has `id`, `kind`, `index`,
`source`, `sourcetype`, `scope`, and `cluster`. Hubble additionally requires an
explicit `observers` allowlist and `owner_scope` matching the identity profile.
NetFlow requires `exporter_ip`, `netflow_version`, and
`observation_domain_present`; `observation_domain_id` is required when present.
Absent domain and domain zero are distinct authorities. Without `owner_scope`,
NetFlow addresses cannot be joined to pod ownership.

Optional `frontends_json` registers configured frontend intent with `address`,
`scope`, `service`, `environment`, `cluster`, `namespace`, `valid_from`, and
`valid_to`. Its explicit validity interval must be at most one hour. The scope
must have a registered NetFlow exporter. This relates an observed address to the
selected service context; it proves neither backend selection nor translation.

The reader searches complete native source families per window of at most 300
seconds, with a 50,000-record limit per source query. Longer graph windows (up to
8 days) are read as independent 300-second slices, each qualified exactly as a
short window, then unioned by qualified node ID. With
[qualified summaries](../DATA_LAYER.md#qualified-graph-summaries) every
summarized slice contributes (exact totals) and only the newest unsummarized
minutes are read raw. Without them, up to 6 slices are read (all of them up to
30 minutes; otherwise evenly spaced, including the newest). Graph metadata
(`window_slices`, `window_slices_read`, `read_coverage`) and a warning state how
much of the window was read; counts describe the slices read. A slice without complete
evidence or without the selected service contributes nothing; a truncated slice
fails the graph. It rejects
incomplete searches and conflicting copies of the same indexed record. A pod
join requires unique, non-host-network ownership covering the complete native
observation interval. A service association at the event time requires explicit
qualified span containment; selected-window `runs_on` grouping does not extend
that containment into continuous ownership.

The reference ownership publisher leaves conservative gaps during checkpoint audits
and re-anchoring. A recent native record can reach Splunk before a complete
closed ownership interval is available, or fall outside every certified interval.
Such records remain unattributed. Shortening a polling interval does not establish
ownership during an audit; validate the receiver configuration and interval
semantics before changing its cadence.

Hubble/NetFlow edges use `traffic_observation`, preserving exported tuple
orientation, observer, per-record fingerprint, direction, verdict and reply
status. Source filters retain the associated workload context. These edges do
not establish a traced call, physical path, or NAT relationship. Counts describe
indexed observations, not unique connections. Exporter counters remain raw,
per-observer, and nonauthoritative; they are not summed across sensors.

Repeated tuples with the same ownership and observer context share graph edges;
each edge retains at most 64 individual observations with their original ports
and fingerprints. Port filters select those observations and update the displayed
record count. The graph retains its 2,000-edge limit. If qualified native records
cannot fit, metadata reports their omission and a partial-graph warning; a
displayed subset must not be treated as a complete traffic inventory.

Validation covers temporal boundaries, ambiguous ownership/service identity,
source attestation, malformed JSON, replay conflicts, protocol/clock parsing,
complete search paging, and Python-to-frontend graph compatibility. Live release
validation must additionally confirm the exact package build, enabled local
profile, real tuple records, qualified graph output, and displayed source-filter
behavior. Retain the prior package and local configuration snapshots for rollback.

## Portable activation sequence

The shipped defaults are inert: identity, native profiles, ACI polling, and ACI
bindings are disabled and contain placeholders. Replace every identity
placeholder with exact cluster, environment, scope, producer, source, and
namespace values, then verify complete interval and span schemas before enabling
the profile. Do not ship deployment authority or lab-specific values.

Only after identity qualification should `[network] enabled = true` be set in a
local `adm_identity.conf`, with exact Hubble/NetFlow source profiles and
observer/exporter authorities. ACI polling is a separate opt-in profile and
binding set. It provides quarantined, source-qualified inventory and exit-context
candidates; it does not prove packet traversal, switch-path selection, or
physical forwarding.

The app ships consumers, protocol validation, and graph presentation. It does
not ship a turnkey ownership publisher, Kubernetes watch publisher, APIC poll
runner, or private-lab producer. Those external producers/runners must be
qualified, permissioned, and operated separately before local profiles are
enabled.

The shipped catalog and graph wrappers retain the legacy readers. To opt in to
qualified readers after validating producers and profiles, put only these
definition overrides in `local/macros.conf`:

```ini
[adm_application_catalog_read]
definition = admqualified mode=catalog

[adm_application_graph_read(4)]
definition = admqualified mode=graph service="$service$" environment="$environment$" cluster="$cluster$" namespace="$namespace$"

# Optional, with qualified summaries: progressive map load (summaries first).
[adm_application_graph_read(5)]
definition = admqualified mode=graph service="$service$" environment="$environment$" cluster="$cluster$" namespace="$namespace$" tail="$tail$"
```

Splunk merges these overrides with the shipped arguments, strict validation,
error message, and `iseval = 0`. Retain those settings. These wrappers select
the qualified commands without bypassing caller search permissions or
administrator-owned configuration ACLs. Remove the two local overrides to
restore the legacy readers; do not modify the packaged defaults.
