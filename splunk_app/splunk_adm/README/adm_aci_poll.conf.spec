# Quarantined current-context reader. Only administrators may configure bindings.
# Enable only after producer, index writer controls, delivery and times qualify.
# No workload ownership, routing domain, historical attachment or traversal is implied.
[profile]
enabled = false
index = <index>
host = <trusted-heavy-forwarder-host>
authority = <apic-authority>
fabric = <fabric>
scope = <scope>
apic_host = <apic-address>
apic_pin = <lowercase-64-character-sha256>
# Explicit poll version; absent means 1. Version 2 searches only adm:aci_poll:v2.
poll_version = 1
