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

# Native observations remain opt-in. Profiles must attest exact source families,
# observer/domain authorities and their scopes; no wildcard or default scope.
# Frontends are bounded configured intent, never historical NAT/backend proof.
[network]
enabled = false
profiles_json = []
frontends_json = []
