# Cisco ACI source adapter

## Scope and evidence

`adapt_aci_audits` in `tools/change_correlation/adapters/aci.py` is a pure,
offline normalizer for the `aaaModLR` user-audit class. It accepts either the
reviewed flattened attributes emitted by Cisco DC Networking App for Splunk
1.2.2 or an APIC REST `imdata` object with `aaaModLR.attributes`. It performs
no network calls, credential access, polling, or collection. The only vendor
package inspected was the static Cisco DC Networking App 1.2.2 extract recorded
as `aci_nxos_nd` in `research/package-manifest.json`; its archive SHA-256 is
`9e2b8534b4c0ddfd5750d3d5924e07ba6d4cf689300164bed041f5cfadb08497`. The vendor
code was read as data and was not executed.

The package's `[cisco_nexus_aci://classInfo_aaaModLR]` stanza requests
`aaaModLR faultRecord eventRecord`, runs every 300 seconds, and is disabled by
default. The `aaaModLR` collector path sends it through the large-result paging
code and emits the selected object's attributes with `apic_host`, `actual_host`
and `component`. This verifies a package collection path; it does not qualify a
live APIC version, permissions, retention window, event completeness, or
sanitized source sample.

The native audit field names below come from Cisco's APIC audit-log examples.
Those examples are documentation examples, not inspected product output. The
APIC release deployed at any target site remains unknown. The cited APIC 6.2(x)
documentation supports class semantics and retention behavior but does not
establish that a particular site's controller is 6.2(x). [Cisco's APIC
Release Notes 6.0(9)](https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/6x/release-notes/cisco-apic-release-notes-609.html)
include a documentation-shaped `aaaModLR` record with the source field names
and an offset-qualified, millisecond `created` timestamp used here. This is a
versioned vendor example, not inspected APIC output. [Cisco's APIC accounting
guide](https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/6x/basic-configuration/cisco-apic-basic-configuration-guide-62x/user-access-authentication-and-accounting-62x/accounting.html)
defines `aaaModLR` as an audit object tracking changes and describes FIFO shard
retention with no default export policy. [Cisco's audit example](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/all/faults/guide/b_APIC_Faults_Errors/b_IFC_Faults_Errors_chapter_010.html)
shows the native fields and distinguishes an audit record from other event
classes. [Cisco's APIC monitoring guide](https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/6x/aci-fundamentals/cisco-aci-fundamentals-62x/monitoring-62x.html)
describes record retention, page-order limitations, and release 6.0(1) audit
backups that have different native `id` values.

## Input and normalized mapping

The caller supplies receipt metadata, including the exact APIC version, fabric
partition and scope, collection interval, received time, page counts, status,
permission fingerprint, and authority. Complete receipts must satisfy the
shared collection contract. A flattened TA record must identify
`component=aaaModLR` and carry `apic_host` equal to the authority host; the TA's
`actual_host` can be a cluster member and is not used to create another
authority. A REST `imdata` record carries no controller host, so its authority
must come from the caller's receipt metadata.

| Native field | Normalized value | Handling |
| --- | --- | --- |
| `id` | `object_id` | Native audit-record identity, kept separate from the affected managed object. |
| `created` | `event_at` | Parsed only as offset-qualified ISO-8601 source time. No fallback to Splunk `_time` or TA ingestion time. |
| `user` | `actor` | Explicit native actor; missing actor remains unknown. |
| `affected` | `fields.affected_dn` | Affected managed-object DN, never used as event identity. |
| `code` | `fields.event_code` | Bounded text from the documented native attribute. |
| `ind` | `fields.operation` | Native operation indicator, without inferred effect. |
| `trig` | `fields.trigger` | Native trigger attribute. |
| `txId` | `fields.transaction_id` | Native transaction identifier retained as text. |

Each normalized object has `kind=audit`, `revision=null`,
`effective_at=null`, and `observed_at` equal to collection `received_at`. The
adapter does not infer a deployment or effective time, parse change details, or
convert audit events into object snapshots. Missing `affected` stays missing;
the audit record's own `dn` is not a substitute.

Only the listed source attributes are read. `changeSet`, `descr`, `sessionId`,
URLs, secrets, arbitrary `before`/`after` payloads, `_raw`, and all other native
attributes are omitted without recursive inspection. `deletions_authoritative`
is always false, so an absent audit record never implies that an object was
deleted. The source is an audit log, not evidence that an edit was successfully
deployed or became effective.

## Completeness and identity limits

The adapter preserves each native `id` as received. Cisco documents that APIC
6.0(1) and later can return backup copies of audit records with distinct IDs;
this adapter does not collapse them into a synthetic event identity. The TA's
per-page ID deduplication is not an assertion that the APIC's retained log is a
complete event archive. APIC shard FIFO retention, changing permissions,
concurrent writes, source release, page behavior, and fabric-wide scope remain
collection gates. A partial page set must be labelled partial; the shared
contract rejects `status=complete` when the receipt's page counts are
incomplete. Even a contract-valid complete receipt describes only the declared
collection, not full APIC history.

The `aci.user_audit` feature remains sample- and permission-gated. This adapter
and its synthetic tests exercise a documentation-shaped mapping only; they do
not move `sanitized_source_sample`, installed tests, demo, or live qualification
to a verified state. An exact controller version, effective principal and
fabric permissions, sanitized readback, retention coverage, and page behavior
are still required.

## Track B policy snapshots

The coordinator admitted three separate Track B projection families to the
shared registry. Their qualification remains `normalized_export_only` with
`native_sample_unqualified=true`. `adapt_aci_policy_snapshots` accepts these
families only; they are separate from `aaa_mod_lr` and do not imply packet
evaluation or successful deployment. It accepts APIC class records or the
documented parent/child `imdata` tree shape. A caller must provide the exact
controller release and complete collection metadata. Policy object identity
uses native `dn`; a parent DN is included only when the native parent object is
present in the input tree. It does not split or reconstruct DN paths.

1. **Filter entry** (`filter_entry_snapshot`): one `vzEntry` object per native
   entry DN, with parent filter DN from the containing `vzFilter` node and
   fields `object_class`, `name`, `parent_dn`, `ether_type`, `protocol`,
   `source_from_port`, `source_to_port`, `destination_from_port`, and
   `destination_to_port`. Keep port values as text because Cisco's examples
   allow named values as well as numeric values. Independent entry IDs make
   input/page ordering irrelevant.
2. **Contract subject and filter reference** (`contract_subject_snapshot`):
   one `vzSubj` object and one `vzRsSubjFiltAtt` object per native DN. Fields
   are `object_class`, `name`, `parent_dn`, `reverse_filter_ports`,
   `provider_match_type`, `target_dn`, and `filter_name`. Preserve
   `revFltPorts` and `provmatchT` as source text on the subject. Preserve a
   relation's `tDn` only when APIC supplies it; retain `tnVzFilterName` as a
   label and never reconstruct a cross-tenant target DN from that label.
   Unreviewed subject children, including graph and label constructs, fail
   closed instead of producing a complete-looking receipt.
3. **EPG contract attachment** (`epg_contract_attachment_snapshot`): one
   `fvRsCons` or `fvRsProv` object per native DN, preserving its source class,
   fields `object_class`, `name`, `parent_dn`, `role`, `target_dn`,
   `contract_name`, and `match_label`. `tnVzBrCPName` stays a contract label;
   native `tDn` is retained when present. A `match_label` is recorded only when exactly one
   supported label child is supplied; multiple labels fail closed because the
   scalar projection cannot represent them losslessly. Known sibling relations
   such as `fvRsBd`, `fvRsDomAtt`, and `fvRsPathAtt` are outside this family and
   are ignored; unrecognized classes or error objects fail closed.

The exact versioned schema citation used for the policy attributes is Cisco's
[APIC REST API Configuration Guide, Release 4.1(x)](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/4-x/rest-api-config/Cisco-APIC-REST-API-Configuration-Guide-411/Cisco-APIC-REST-API-Configuration-Guide-411_chapter_01010.html).
It documents filter entries and their scalar fields, contract subjects and
filter references, and EPG provider/consumer relations. A specific target
controller's version-matched schema and sanitized capture are still required
before any family is source-qualified. Keep reference edges and object
identity; do not resolve missing references or turn a snapshot into a policy
decision. ESG, taboo, service graph, `vzAny`, preferred-group enforcement,
rule evaluation, and effective deployment semantics remain unsupported.

An unknown native class, APIC error object, malformed relationship, incomplete
page set marked complete, or unrepresentable multi-label attachment cannot
produce a valid complete receipt. Partial page counts must be recorded as
partial; the collection contract rejects complete receipts with missing pages.
For configuration snapshots, deletion authority remains an explicit caller
attestation under the collection contract; it must not be enabled when the
enumeration is partial or a source error occurred.

### Source capability IDs

| Feature ID | Adapter disposition |
| --- | --- |
| `aci.user_audit` | Offline mapping and documentation-shaped synthetic tests exist. Sanitized sample, permission coverage, installed test, demo, and live-qualification gates remain blocked. |
| `aci.contract_filter_entries` | Mapped to `filter_entry_snapshot`, which is normalized-export-only and native-sample-unqualified. |
| `aci.contract_relations` | Mapped to `contract_subject_snapshot` and `epg_contract_attachment_snapshot`, both normalized-export-only and native-sample-unqualified. |
| `aci.preferred_group_enforcement` | No effective enforcement or policy-evaluation claim is made. |
| `aci.unsupported_policy_constructs` | ESG, taboo, service graph, and `vzAny` remain unsupported. |

The ACI rows in the shared capability register remain owned by the coordinator;
this source adapter does not promote their qualification stages.
