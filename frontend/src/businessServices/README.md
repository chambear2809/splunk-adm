# Business-service import v1

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
