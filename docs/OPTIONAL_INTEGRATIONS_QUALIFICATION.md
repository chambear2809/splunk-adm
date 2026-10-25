# Optional integrations qualification

Task baseline: `b8f05490f3df8352ff88f9b803ca39d7df3a14d5`.
This record is in progress. It is not approval to enable an integration.

| Workstream | Implementation | Offline tests | Installed Splunk | Real source / processor |
| --- | --- | --- | --- | --- |
| Observability health delivery and detector events | In progress | Pending final candidate | Pending final candidate | Not available; unqualified |
| AppDynamics current inventory and backend candidates | In progress | Pending final candidate | Pending final candidate | Not available; unqualified |
| Edge Processor / Ingest Processor v1 templates | In progress | Pending final artifacts | Pending direct/golden comparison | Not available; unqualified |

All sources are optional, unselected and schema-unqualified by default. Real
Observability realm/MMS/detector-origin coverage, Controller-version behavior,
and Edge/Ingest Processor runtime behavior require the source-specific operator
procedures. Offline fixture checks do not execute a processor. Installed direct
and golden events can prove Atlas facts survive the expected representation;
they cannot prove that an unavailable processor produces that representation.

The final evidence packet is retained under ignored
`dist/integrations-qualification/`, with source/package hashes, exact commands,
agent metadata and the task resource ledger. The actual baseline archive is
retained there for genuine upgrade tests. A skipped PR lab job is not runtime
evidence. Final review and merge require this record to identify the completed
checks and their exact candidate/package bindings.

Requested settings were changed explicitly by the user: coordinator
GPT-6.1 Sol/High; workers GPT-6 Luna/Max; final independent reviewer
GPT-6 Astra/Medium. Session metadata confirms those settings. The replaced
Astra/Max agent performed release preflight only and did not approve features.
No shared agent configuration was changed.
