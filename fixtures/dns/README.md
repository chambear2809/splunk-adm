# DNS adapter fixtures

These fixtures are synthetic and explicitly unqualified. The Stream field
names and list semantics are grounded in the locally inspected Stream App 8.1.6
`default/streams/dns` definition. The Hubble envelope and L7 field names follow
the Cilium flow JSON shape; the local Enterprise Hubble sample contains no DNS
L7 event and does not qualify the DNS schema. Neither fixture is a captured DNS
event. Stream's independent `host_addr` and `ttl` arrays intentionally do not
express per-answer relationships; Hubble's scalar TTL remains RRset context.
