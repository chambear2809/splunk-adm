# ITSI export and CMDB reconciliation

**Applications > ITSI export and CMDB reconciliation** compares the conversations Atlas observed in one routing scope with CMDB records, and prepares ITSI import files. It is read-only:

- Atlas never runs `itsiimportobjects`, never calls ITSI or CMDB APIs, and never writes to a lookup, KV Store collection or index for this feature.
- Every search runs as the signed-in reader with their own Splunk permissions.
- Exports are CSV files for an operator to review and import.

The workspace loads from the optional history asset only when the disclosure is opened. If that asset is missing or fails verification, the section reports that it is unavailable, and the rest of the Applications page keeps working.

## Sources

| Source | What it supplies | Required |
| --- | --- | --- |
| Conversation summaries (`adm_index_summary`, traffic contract v1) | Observed client/server IP, server port, transport, first/last seen, temporal endpoint identity (`adm_resolve`), and service attribution through `adm_service_workload` | Yes |
| [Asset history](asset-history.md) (`adm:asset_history`) | Per-IP CMDB/IPAM asset records with validity intervals | For "Not in CMDB" |
| CMDB relationship lookup (operator CSV, below) | CMDB relationships between endpoints | For relationship reconciliation |
| Business-service import v2 (browser-local) | Business-service parents for ITSI | Optional |

The asset-history reader uses the same qualification as endpoint investigations: an `active`, schema-qualified asset-history source, and a verified `asset_authority` observer mapping for each configured authority in the scope.

### ServiceNow

Atlas does not read the Splunk Add-on for ServiceNow directly. The add-on documents the `snow:cmdb_ci` (legacy `snow:cmdb_ci_list`) and `snow:cmdb_rel_ci` sourcetypes ([data types](https://splunk.github.io/splunk-add-on-for-servicenow/Datatypes/)), and `sys_id` / `sys_updated_on` as the default input ID and time fields ([inputs](https://splunk.github.io/splunk-add-on-for-servicenow/Configureinputs/)). It does not document the relationship columns (`parent`, `child`, `type`) or a CI IP column, so Atlas cannot ground a reader for them. `adm_index_snow` remains incident context only.

To reconcile ServiceNow CIs:

- Export the CIs through [asset history](asset-history.md), for example with `asset_id` = CI `sys_id`.
- Export the relationships into the CSV lookup below, resolving each parent and child CI to the IPs your team has qualified.

## CMDB relationship lookup

The source is inert until you configure it. Two macros control it:

- `adm_cmdb_relationship_rows` returns no rows by default.
- `adm_cmdb_relationships_schema_qualified` is `0` by default. While it is 0, the workspace shows relationships as **Not configured**, even if the lookup returns rows.

To configure the lookup:

1. Create a CSV lookup with exactly one row per directed client-to-server relationship and these columns:

   | Column | Meaning |
   | --- | --- |
   | `authority` | Lowercase CMDB authority literal (`[A-Za-z0-9][A-Za-z0-9._:/@-]*`) |
   | `relationship_id` | Stable ID, unique per authority (for example the `cmdb_rel_ci` `sys_id`). Duplicate IDs are rejected. |
   | `scope` | Atlas routing scope of both IPs |
   | `client_ip`, `server_ip` | Literal IPv4/IPv6 addresses of the dependent (client) and the provider (server) |
   | `server_port`, `transport` | Optional. When set, matching requires that port and transport (`tcp`, `udp`, …). |
   | `relationship_type` | Optional display text, for example ServiceNow `Depends on::Used by` |
   | `client_ci`, `server_ci` | Optional CI display names (never used for matching) |
   | `snapshot_at` | Optional Unix seconds of the export |

2. Share the lookup with the roles that use Atlas, read-only.
3. Override `adm_cmdb_relationship_rows` locally with `inputlookup <your lookup>`. Don't start the definition with a pipe.
4. Validate the direction, scope mapping and refresh cadence, then set `adm_cmdb_relationships_schema_qualified` to `1`. Don't set `iseval`.

The search reads at most 5,000 rows. A larger lookup is reported as incomplete.

## Reconciliation semantics

Run a reconciliation by choosing a routing scope, a window (last 1, 7, 14 or 30 days, aligned to the minute), and **Run reconciliation**.

**Endpoints** (every IP seen in an observed conversation):

| Status | Meaning |
| --- | --- |
| Matched | An asset-history record that overlaps the window, or a relationship-lookup row, names this scoped IP. |
| Not in CMDB | Seen talking in the window, and no record exists. Shown only when asset history is complete for the scope and window, and the relationship lookup is complete or not configured. |
| Conflicting CMDB records | Different asset IDs, or a revision conflict, claim the IP. |
| External (no CMDB expected) | A public address with no Atlas identity. |
| CMDB coverage unknown | Asset history is not configured, unavailable or incomplete, so a missing record is not conclusive. |

**Relationships:**

| Status | Meaning |
| --- | --- |
| Matched | A relationship-lookup row matches an observed conversation (scoped IPs, plus port and transport when the row sets them). |
| Not observed in window | No matching conversation was collected in the window. **This never means the relationship was removed or is absent.** The row reports endpoint coverage (`both`, `client_only`, `server_only`, `neither`). `neither` usually means the endpoints are outside collection coverage. |
| Observed, not in CMDB | Observed traffic with no lookup row. Shown only when the lookup is complete. |
| Observation coverage unknown | Observed traffic is incomplete (capped, malformed or missing its completion row), so absence of a match is not conclusive. |

Matching uses only scoped IPs, ports and transport. Names, hostnames and display labels are never matched.

Each source reports Complete, Incomplete, Unavailable or Not configured, with reasons and counts. Endpoint and relationship tables can be filtered by status and by text matching IPs, Atlas identity, asset IDs or CMDB relationship IDs. **Download CSV** exports the filtered rows. The table displays the first 200 rows, but the CSV export includes every filtered row.

## ITSI export

The export is built from the same run:

- **Services.** Every catalog service (`service (environment/cluster/namespace)`) is exported. A dependency is created only when the client and server sides of an observed conversation each have exactly one retained `adm_service_workload` binding. Unbound, ambiguous, VM and external peers create no service dependency.
- **Business services.** Parents come only from the v2 business-service import saved in this browser. A binding counts only when it resolves against a catalog row that carries qualified identity provenance, is not conflicting, and has known coverage in the window. Each parent depends on its resolved member services.
- **Entities.** VMs, endpoints and Kubernetes nodes that have one resolved Atlas identity, titled `name-or-ip (scope)`, with an `ip` alias. Pods are not exported, because their IPs churn. At most 5,000 entities.

Columns follow ITSI's CSV and search import fields:

- Services: `service_title`, `service_description`, `services_depends_on`. Each dependency is a comma-separated list of service titles, which maps to *Services* / `service_dependents`.
- Entities: `entity_title`, `entity_description`, `ip`. `atlas_scope` and `atlas_identity_kind` are informational; map them as info fields or ignore them.

Sources:

- [ITSI 4.21 bulk import (CSV)](https://docs.splunk.com/Documentation/ITSI/4.21.0/SI/BulkImportServices)
- [ITSI 5.0 import services from a search](https://help.splunk.com/en/splunk-it-service-intelligence/splunk-it-service-intelligence/visualize-and-assess-service-health/5.0/create-services/import-services-from-a-search-in-itsi)
- [ITSI 4.19 `inputs.conf` `itsi_csv_import`](https://help.splunk.com/en/splunk-it-service-intelligence/splunk-it-service-intelligence/administer/4.19/configuration-file-reference/inputs.conf)
- [Entity import from search](https://docs.splunk.com/Documentation/ITSI/latest/Entity/ImportSearch)

Titles are never rewritten. A title is excluded, and listed under **Excluded from export**, if it:

- contains `,` `;` `|` `^` a tab, `"` or a control character;
- starts with `=` `+` `-` or `@`;
- has leading or trailing spaces;
- is longer than 255 characters;
- or collides with another title.

The export also excludes:

- Business-service groups whose resolved claims disagree on the name.
- Members that are not exported services.

### Cycles and batches

ITSI rejects `services_depends_on` cycles. Atlas breaks them deterministically:

1. Titles are visited in sorted order with a depth-first search.
2. Each back edge closes a cycle and is removed.
3. Every removed edge is listed with its cycle, and can be downloaded with **Removed cycle edges** (`atlas-itsi-removed-cycle-edges-*.csv`).

Review the removed edges before importing; they are real observed dependencies.

Services are written children-first and split into batches of 200, 250 or 300 services (default 250). Each batch depends only on services in the same or an earlier batch. Import the batches in order, and the entities file after the services, or first if your KPIs use entity filtering.

When observed traffic is incomplete, identity resolution is incomplete, or the catalog shows a warning, service and entity downloads stay disabled until you acknowledge that the export is partial.

### Importing

Use either path:

- **Import from CSV.** Use ITSI's Import from CSV workflow, mapping `service_title` to the service title column and `services_depends_on` to the dependent services column.
- **Import from search.** Upload the CSV as a lookup, then use Import from search with `| inputlookup <file>`.

Atlas never runs `itsiimportobjects`. `adm_itsi_import_objects` stays inert (`| makeresults | where 1=0`). If you replace it locally, keep it bounded and schedule it only after reviewing a batch.

## Limits

- One routing scope per run.
- Observed relationships: at most 5,000 grouped rows, most recent first.
- Asset history: 10,000-row scan and 5,000 records.
- Relationship lookup: 5,000 rows.
- Caps are reported as incomplete, never as complete.
- Only traffic contract v1 conversation summaries are read. Traffic contract v2 observations are not yet included.
- Business parents require the qualified catalog identity contract. Legacy catalog rows never act as native identities.
- Collection coverage defines what can be observed. Short windows miss periodic jobs; choose a window longer than the dependency's cadence.
