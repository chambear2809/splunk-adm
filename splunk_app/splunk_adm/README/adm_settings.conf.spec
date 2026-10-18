# Deployment-settings persistence topology attestation.
# See docs/DEPLOYMENT_HEALTH.md before enabling writes.

[persistence]

write_mode = disabled | single_namespace | qualified_shc
* Defaults to disabled.
* single_namespace requires one standalone search-head KV Store namespace.
* qualified_shc requires coordinated installation and qualified multi-member
  shared KV Store persistence. Independent search heads behind an LB are excluded.

platform = unqualified | enterprise
* Defaults to unqualified.
* enterprise attests the reviewed deployment platform. Splunk Cloud writes are
  unqualified and must remain disabled pending actual target qualification.
