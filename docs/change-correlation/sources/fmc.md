# FMC and FTD evidence

## Current boundary

Cisco Security Cloud Add-on for Splunk 3.7.2 remains the default package for
FMC policy polling, FTD eStreamer, and the related firewall inputs. Its
defaults assign:

- **sbg_sfw_api_input** to **cisco:sfw:policy**, index **cisco_sfw_api**, interval
  300 seconds;
- **sbg_fw_estreamer_input** to **cisco:sfw:estreamer**, index **cisco_secure_fw**,
  interval 600 seconds.

These are package defaults, not an instruction to enable or change an input.
No vendor archive or delete permission was changed.

The native policy-detail, audit, access-rule, and deployment adapters fail
closed with **unsupported_source_schema**. No raw FMC payload is interpreted.
The existing **fmc/audit_record** projection still supports an explicitly
normalized contract-v1 audit collection through
**normalize_fmc_audit_export**; this path does not parse or qualify an FMC
response. The fixture
**fixtures/change-correlation/fmc/normalized_audit_contract_v1.json** is
synthetic normalized contract input, not an FMC response or source sample.
Its exported evidence retains **normalized_export_only** and
**native_sample_unqualified**.

## TA 3.7.2 policy collection findings

Static review of the immutable Cisco Security Cloud 3.7.2 package
(**research/extracted/cisco-security-cloud_372/CiscoSecurityCloud/bin/CiscoSecurityCloud/fmc_api/collect_events.py**)
establishes this collection flow:

1. For access, intrusion, and file policies, the collector uses the
   **accesspolicies**, **intrusionpolicies**, and **filepolicies** resource paths.
2. It calls the delete search for each category before issuing its list and
   detail GET requests. The delete filter uses the static category labels
   **AccessPolicy**, **intrusionpolicy**, and **FilePolicy**.
3. The list loop reads **items** and each item's **id** to build a detail URL.
   It follows **paging.next[0]** until no next page is returned.
4. For each successful detail GET, it writes the entire response JSON,
   unchanged, to the configured index, source, and **cisco:sfw:policy**
   sourcetype.

This proves that the collector reads a list item's **id** and uses it in a
detail-request path. It does not prove that the detail response contains a
particular id, name, type, revision, timestamp, or any specific nested field.
The three category labels are used in the pre-fetch deletion query; the
collector does not attach a category to the detail event itself. The reviewed
package contains no policy response sample, policy-specific props.conf schema,
or policy saved search that establishes those fields.

The delete-before-fetch ordering creates a history gap: a failed or incomplete
refresh can remove the previous searchable policy state before replacement
records have been collected. The collector does not emit a collection receipt,
capture identifier, start/end bounds, page count, permission fingerprint, or
successful-completion marker. The smi.Event call does not set an event time.
Splunk's modular-input protocol uses data arrival time when the input omits the
event time, so _time is receipt time, not the FMC policy observation time or a
polling-window boundary. A cisco:sfw:policy search therefore cannot claim a
complete policy inventory, removals, or bounded policy-change times.

## Append-only preservation boundary

A scheduled Splunk search that copies the current policy events can race the
TA's delete-before-fetch sequence and cannot establish that it captured every
policy in one successful poll. It must not be presented as immutable history.

Splunk's CLONE_SOURCETYPE creates a near-exact duplicate event, then applies
the transform to that copy. That is not a safe archive by itself: this TA
writes full policy-detail JSON, and no field-level detail schema or safe
allowlist has been established. This change ships no clone or ingest-time
configuration. Before an index-time projection is considered, a versioned
policy schema must be reviewed and the target Splunk release must demonstrate
that the entire cloned _raw is rebuilt from only allowlisted fields. No raw
policy-detail clone is acceptable.

A future native policy capture needs a separately qualified read-only per-poll
export boundary outside the TA's delete visibility, or an independently
supported exporter. It must retain:

- FMC/FTD release, TA version, authority/domain, and policy category;
- stable capture ID, started/completed/received timestamps, page counts,
  completion status, and permission fingerprint;
- the list-page policy IDs paired with the corresponding detail records;
- a sanitized, version-matched TA detail sample for each supported policy
  category, preserving field names and types while removing credentials,
  URLs, and sensitive policy values;
- the exact native fields and units proposed for the safe flattened allowlist.

Until then, do not compare successive TA refreshes as complete snapshots or
claim rule-level changes, removals, policy evaluation, deployment success, or
FTD verdicts from FMC policy objects. FMC audit edits and deployment outcomes
remain separate evidence families. Access-rule IDs change when rules are
repositioned, so no stable child-rule lineage is assumed. The project's FTD
same-event/V2 evidence work is independent of FMC policy history; eStreamer,
syslog verdicts, and same-event translated tuples are not inferred from policy
objects or joined through NAT backend state.

## FMC audit and deployment API boundary

Cisco's FMC 7.7.0 REST Quick Start Guide, updated February 17, 2025, documents
the auditrecords/configchanges, accessrules, and jobhistories routes and
request pagination/filter parameters. The reviewed route sections do not
establish the native response field mappings needed for event IDs, timestamps
and units, actors, safe audit values, rule order/fields, or per-device
deployment results. Cisco also documents that an access-rule ID changes when
the rule is repositioned.

Cisco says the on-prem API Explorer resides on the FMC and that its OpenAPI
JSON specification is downloaded after signing into that FMC. No
version-matched on-prem OpenAPI export or sanitized API response was available
for this implementation. A cdFMC schema or another FMC release is not a
substitute for on-prem evidence.

Provide the exact on-prem FMC/FTD release, version-matched FMC API Explorer
specification, and sanitized audit/configchange and deployment responses to
enable those families. Rule snapshots additionally need a sanitized
GETALL accessrules result that preserves list ordering and identity behavior
across reorder, rename, deletion, and pagination.

## Primary references

- [FMC 7.7.0 REST API, Objects in the REST API](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770/Objects_In_The_REST_API.html)
- [FMC 7.7.0 REST API, About the API Explorer](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770/About_The_API_Explorer.html)
- [Splunk Enterprise 10.6 transforms.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/transforms.conf)
- [Splunk modular-input timestamp behavior](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.2/modular-inputs/set-up-streaming)
