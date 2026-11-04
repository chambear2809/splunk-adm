# Administrator-controlled bindings for quarantined ACI v2 poll context.
# Disabled by default. No command reads these settings until reviewed integration.
# Each binding must repeat the exact authenticated server-side poll profile's index,
# host, authority, fabric, scope, apic_host and apic_pin. tenant_dn and vrf_dn are
# exact APIC DNs; address_realm and revision are administrator assertions, not
# derived from names or addresses. valid_from and valid_to are finite Unix seconds;
# validity must enclose the full capture, with an exclusive upper bound. Overlapping
# intervals for the same tenant/VRF or the same address realm are invalid.
# Configuration is not an access-control boundary: restrict writes independently.
[bindings]
enabled = false

[binding:<administrator-assigned-id>]
enabled = false
index = <trusted-index>
host = <trusted-heavy-forwarder>
authority = <apic-authority>
fabric = <fabric>
scope = <scope>
apic_host = <apic-address>
apic_pin = <lowercase-sha256>
tenant_dn = <exact-tenant-dn>
vrf_dn = <exact-vrf-dn>
address_realm = <operator-attested-address-realm>
revision = <immutable-binding-revision>
valid_from = <unix-seconds>
valid_to = <unix-seconds-exclusive>
