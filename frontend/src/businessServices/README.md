# Business-service imports

`previewBusinessServiceImport(json)` validates a whole JSON batch and returns
`claims`, row-indexed `errors`, and a bounded list of `conflicts` plus the full
`conflictCount`. Any invalid row rejects the batch. Claims remain imported
assertions, and an overlapping ownership or criticality disagreement remains a
conflict. Conflict checking covers the supplied batch only; the persistence
layer must compare against existing claims and enforce revisions atomically.

```json
{
  "schema_version": 1,
  "authority": "cmdb-east",
  "snapshot_id": "export-2026-11-16",
  "snapshot_at": "2026-11-16T12:00:00Z",
  "records": [
    {
      "record_id": "payment-checkout",
      "revision": 1,
      "service_id": "payments",
      "service_name": "Payments",
      "member_kind": "service",
      "member_id": "cluster-a/shop/checkout",
      "scope": "east",
      "team_id": "team-commerce",
      "team_name": "Commerce",
      "criticality": "critical",
      "validity_basis": "source_interval",
      "valid_from": "2026-11-01T00:00:00Z",
      "valid_to": null,
      "runbook": {
        "label": "Payments runbook",
        "url": "https://docs.example.org/payments"
      }
    }
  ]
}
```

`member_kind` is `service`, `workload`, or `asset`; its `member_id` is a
source-stable identifier. Syntax validation cannot prove identity stability;
the consumer must resolve it against a qualified source and scope rather than
treating an IP, display name, or this string alone as a graph node ID. A `snapshot_current` claim omits `valid_from` and `valid_to` and
only applies at the manifest snapshot. An interval has an inclusive start and
exclusive end; an open interval is observed only through the snapshot time.
Reference URLs require HTTPS and cannot contain credentials, query, or fragment.
The preview displays them as text; a downstream interface must separately apply
its approved navigation policy before making links.

`BusinessServiceImport` previews and optionally saves one complete validated batch
in browser-local storage after an explicit user action. This storage is not shared,
durable collaboration; the entire supplied JSON is stored and users must choose
only data appropriate for their browser. The save replaces the previous batch.
`onLocalChange` reports save and clear outcomes. `readLocalImport` validates
again on read and distinguishes empty, unavailable, uncertain, and ready; callers
must not interpret unavailable or uncertain as absence. Browser storage does not
provide source entitlement or server-side authorization.

`OwnershipAnnotations` accepts validated claims, explicitly source-qualified
resolved graph members, and a point or half-open interval in epoch seconds.
Consumers must only provide members after a qualified identity resolution, not
match names or IPs. The annotation preserves uncertainty, source provenance,
conflicts, and current-only limits; business criticality does not alter technical
priority. It creates no graph edges. Imported assertions are not verified facts.
This module has no vendor adapter or shared persistence.

Version 1 remains a claims-only manifest. Version 2 adds an optional `bindings`
array to the same manifest. Each entry is a separate,
imported assertion linking an exact claim identity to a qualified technical
service identity. Its `record_id` and `revision` identify the binding; the
manifest supplies the binding authority, snapshot ID and snapshot time. The
claim authority may differ from both binding and native authorities.

```json
{
  "record_id": "binding-1",
  "revision": 1,
  "claim": {
    "authority": "cmdb-east",
    "record_id": "membership-1",
    "revision": 2,
    "scope": "business-east",
    "member_kind": "service",
    "member_id": "business-member-1"
  },
  "target": {
    "kind": "service",
    "authority": "native-producer",
    "scope": "cluster-east",
    "config_revision": "config-v1",
    "key": {
      "service": "orders/api",
      "environment": "prod",
      "cluster": "cluster-a",
      "namespace": "shop"
    }
  },
  "validity_basis": "source_interval",
  "valid_from": "2026-01-05T00:00:00Z",
  "valid_to": null,
  "proof_reference": "mapping-ticket-123"
}
```

`proof_reference` is a non-secret identifier displayed as text, not a URL or
authorization. Do not put tokens, passwords, or personal data in the import.
The preview retains duplicate and overlapping binding conflicts. Importing or
storing a binding does not establish that its assertion is true and does not
grant access to its source.

`resolveBusinessOwnership(claims, bindings, nativeIdentities, time)` compares
the explicit tuple with caller-supplied, currently authorized `qualified_v2`
native identities. The caller must construct those identities from a trusted
qualified reader, never from the import. Source authority, scope and config
revision must match exactly; an unavailable or stale native context remains
unresolved. Coverage intersects claim validity, binding validity, source
snapshot times, and the native observation window. Conflicts remain visible;
no network edges, counters, severity or technical priority are created or
changed. A pod UID or IP address is not a substitute for a stable service
tuple. Version 2 currently targets only qualified services; other member kinds
can remain claims but require an explicit binding to such a service.

The integrated `OwnershipEvidence` boundary is opened explicitly from catalog,
Map, incident and Impact/maintenance views. It consumes `identityContext` emitted
by the qualified raw reader: schema 1 / `qualified_v2`, producer authority,
routing scope, configuration SHA-256 and exact absolute observation window.
Explicit `attr_service`, environment, cluster and namespace supply native tuples;
labels and concatenated IDs are never parsed. Complete contiguous raw slices may
retain matching provenance. Legacy KV catalogs, old/summary-only graphs and
IP/app-name Impact endpoints do not become qualified merely by opening this UI.
Missing, malformed, mixed or stale context stays unresolved; a failed/denied map
refresh or replaced source connection suppresses native references and export.
The provenance does not establish continuous identity lifetime, complete source
collection or authorization for a future read.

To prepare a v2 binding, explicitly open ownership, consent to download native
references, and copy the exact authority/scope/configuration and four-tuple into
the separate import assertion. The reference document contains native technical
references only; it does not embed imported teams, criticality, proof references,
runbooks or escalation details. A browser import remains local and unverified.
