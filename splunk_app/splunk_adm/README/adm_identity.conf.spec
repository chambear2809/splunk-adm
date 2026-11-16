# adm_identity.conf profile for the admqualified generating command.
# Disabled by default; administrators must provide an attested profile and
# enable it only after the identity producer and source indexes are qualified.
[profile]
enabled = false
cluster = <cluster>
environment = <environment>
scope = <scope>
producer_id = <producer-id>
interval_source = <interval-source>
span_source = <span-source>
interval_index = adm_identity_intervals
span_index = adm_identity_spans
interval_sourcetype = adm:pod_ip_interval:v2
span_sourcetype = otel:traces
namespaces = <comma-separated namespaces>
# Graph windows over 300 seconds are read as independent 300-second slices
# (at most 6 without summaries). slice_workers (1-6, default 2) reads that many slices at once;
# each holds one nested search, so keep it below the caller's srchJobsQuota.
slice_workers = <integer>

# Native observations remain opt-in. Profiles must attest exact source families,
# observer/domain authorities and their scopes; no wildcard or default scope.
# Frontends are bounded configured intent, never historical NAT/backend proof.
[network]
enabled = false
profiles_json = []
frontends_json = []

# Qualified graph summaries. When enabled, ADM - Qualified graph rollup writes
# one qualified summary per closed 300-second slice to the index, and graph
# windows over 300 seconds read summaries (exact totals) plus the newest
# unsummarized minutes raw.
[summary]
enabled = <bool>
index = <index name, default adm_summary_v2>
# Accepted indexing delay after a slice ends, in seconds (0-90, default 90).
# ADM - Qualified graph rollup summarizes the slice that ended two minutes
# before it runs, less a 30-second visibility margin, so larger values are
# rejected. Re-run older ranges with a larger horizon through
# adm_qualified_rollup(<seconds>) (0-86400).
lateness = <integer>
