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

`BusinessServiceImport` renders the local preview. `onPreview` receives the
result after validation and `undefined` after edits so a consumer cannot apply
an old preview. No save or apply control is exposed until an independently
validated, authorized server endpoint exists. This module does not supply
persistence, source entitlement checks, cross-import conflict resolution,
service annotations, or a vendor adapter.
