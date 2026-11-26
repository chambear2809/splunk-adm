# Ecosystem traffic evidence (firewalls, load balancers, cloud flow logs)

**Status:** optional, on-demand supplemental evidence. **Unqualified**: implemented and tested against TA-grounded synthetic fixtures only. No source has been validated against a live device or cloud account, a live add-on install or a real ingestion path. Every index selector ships as `index=unconfigured_optional` and every schema flag ships as `0`, so nothing is searched until an administrator completes the steps below.

Atlas reads traffic logs that the vendor add-ons already index. It ships no inputs, contacts no device or cloud API and writes nothing back.

| Source id | Producer | Sourcetype | Index macro | Schema flag | Observer kind |
| --- | --- | --- | --- | --- | --- |
| `pan_traffic` | Splunk_TA_paloalto 6.x (PAN-OS syslog) | `pan:traffic` | `adm_index_pan` | `adm_pan_traffic_schema_qualified` | `pan_firewall` |
| `fortigate_traffic` | Fortinet FortiGate Add-on (FortiOS syslog) | `fgt_traffic` (add-on 1.5.x and earlier), `fortigate_traffic` (1.6.x and later) | `adm_index_fortigate` | `adm_fortigate_traffic_schema_qualified` | `fortigate_firewall` |
| `f5_ltm_http` | Splunk Add-on for F5 BIG-IP, LTM HSL iRules | `f5:bigip:ltm:http:irule`, `f5:bigip:ltm:lb:failed:irule` (SC4S: `f5:bigip:ltm:failed:irule`) | `adm_index_f5` | `adm_f5_ltm_irule_schema_qualified` | `f5_bigip` |
| `aws_elb_access` | Splunk Add-on for AWS, ELB access logs (ALB; NLB TLS) | `aws:elb:accesslogs` | `adm_index_aws` | `adm_aws_elb_access_schema_qualified` | `aws_elb` |
| `azure_vnet_flow` | Splunk Add-on for Microsoft Cloud Services 6.1.0+ (VNet flow logs) | `mscs:vnet:flow`, `mscs:storage:blob:json` | `adm_index_azure` | `adm_azure_vnet_flow_schema_qualified` | `azure_vnet_flow` |
| `gcp_vpc_flow` | Splunk Add-on for Google Cloud Platform (VPC Flow Logs via Pub/Sub) | `google:gcp:compute:vpc_flows` | `adm_index_gcp` | `adm_gcp_vpc_flow_schema_qualified` | `gcp_vpc_flow` |

Field provenance, versions and source URLs are in [fixtures/raw/FIELDS.md](../fixtures/raw/FIELDS.md#ecosystem-firewall-traffic-not-generated-by-gen_raw_fixturespy) and [the load balancer and flow log section](../fixtures/raw/FIELDS.md#ecosystem-load-balancer-and-cloud-flow-logs-not-generated-by-gen_raw_fixturespy).

## What a firewall record means

- One record is one traffic log line from one firewall: the reported 5-tuple, the firewall's policy decision, same-event NAT translation, the log time and the reported counters.
- **Allow / deny** is the decision of that firewall only. PAN `allow` is allow; PAN `deny`, `drop`, `reset-both`, `reset-client` and `reset-server` are deny. FortiGate `accept`, `close` and `timeout` are allow (a session the policy permitted); `deny` is deny. FortiGate `start`, `client-rst`, `server-rst`, `ip-conn` and `dns` are shown with their vendor action and counted as "decision not reported": a reset does not say whether policy allowed the session. Any other action is rejected, not guessed.
- **NAT** stays NAT. PAN `src_translated_ip`/`dest_translated_ip` (and ports) and FortiOS `transip`/`transport` (SNAT) and `tranip`/`tranport` (DNAT), with `trandisp`, are displayed as same-event translation evidence beside the reported tuple. A translated address is never used as an endpoint identity and the two tuples are not shown as separate hops or legs. `0.0.0.0`, `::` and port `0` in a translated column are treated as "not reported".
- Records are never joined across firewalls and never summed with other sensors.

## What a load balancer record means

One record is one request (F5 iRule, ALB) or one TLS connection (NLB) at one load balancer. Atlas shows its **client-side leg** and **server-side leg** as two separate observed legs from that one record. It never merges them into one flow, and it never treats a balancer-owned address as an endpoint.

| Record | Client-side leg | Server-side leg | Not grounded |
| --- | --- | --- | --- |
| F5 `Splunk-iRule-HTTP` | client `src_ip` (route domain `%n` kept) → virtual server address `vip` with port from `http_host` | balancer source → pool member `node`:`node_port`, pool from `virtual_server` | client port; the server-side source (SNAT pool, automap self IP or preserved client) is not logged, so it is shown as "not reported" |
| F5 `Splunk-iRule-LB_FAILED` | as above | none: load balancing failed, no pool member connection | — |
| ALB request | `client:port` → load balancer node (`ip_address`, field 34) | balancer source → `target:port`; `-` is "not forwarded" with `error_reason` / actions | listener port; the address the ALB uses toward the target; field 34 is absent in older logs |
| NLB TLS (version 3.0) | `client:port` → `destination:port` (listener or endpoint) | none: NLB access logs report no target | target, server-side source; NLB logs cover TLS listeners only |

- **Outcome** is the balancer's: forwarded with the server status, LB_FAILED, not forwarded (ALB `-` target, WAF, fixed-response, redirect), or the TLS verify status. It is not a firewall allow or deny, and Atlas does not derive one.
- **Counters** are labelled with their basis: F5 `Content-Length` headers, ALB bytes including headers, NLB decrypted bytes.
- **Matching.** A selected address can match the client source, the balancer-owned client destination or the server destination. A match only on the balancer address is marked `selected_address_matched_balancer_address_only`.
- **Time.** F5 iRule times have no zone. As with PAN, Atlas requires `_time` minus the naive time to be a whole 15-minute multiple within ±14 hours, with a residual of −2 to +120 s and the same offset for request and response. It shows the inferred offset. ALB times are ISO 8601 UTC. NLB times without a zone are read as UTC (an inference). `_time` must fall within the logged request (±1 s); this is also an inference.
- **Rejected values.** URI, query, User-Agent, cookie, user, referrer and TLS client certificate fields are never projected. F5 records whose quote count differs from the iRule's are rejected, so a `"` injected into a header cannot shift fields. Classic ELB and NLB log versions other than 3.0 are rejected.

## What a cloud flow log record means

- **GCP.** One VPC Flow Logs entry from one reporter (`SRC`, `DEST`, `SRC_GATEWAY`, `DEST_GATEWAY`) for one aggregation interval.
  - The decision is **deny** only when `disposition` is `DROPPED` (with `drop_reason`). Every other entry is "decision not reported": Google does not state an allow.
  - `nat_ip` / `nat_port` are accepted only with reporter `SRC` and are shown as Cloud NAT translation evidence.
  - Counters are sampled estimates.
  - Instance, project and VPC annotations are shown as labelled context, never as identity.
  - Both the add-on's Pub/Sub `data` wrapper and a bare LogEntry are accepted. Each event must be exactly one of the two.
- **Azure.** One flow tuple from one VNet flow log record at one captured interface.
  - The tuple's state `D` is **deny** under the named rule. `B`, `C` and `E` are **allow** under the rule, which may be a platform rule.
  - Encryption statuses `NX_SW_NOT_READY`, `NX_NOT_ACCEPTED` and `NX_NOT_SUPPORTED` are deny, because Microsoft documents that they drop the packet.
  - Version 5 source NAT (Private Link SNAT) is translation evidence.
  - Counters are deltas since the previous tuple.
  - Tuple width must be 13 for `flowLogVersion` 4 and 16 for version 5. This pairing comes from Microsoft's samples.
  - Tuple time must be within one hour before, and at most 60 s after, the record time.
  - The add-on's event boundary is not documented. Atlas accepts one record per event, either bare or as a one-element `records` array, and rejects arrays with more elements rather than guessing.
- Neither cloud reports an endpoint identity. A match on the translated address is marked `selected_address_matched_translated_field`.
- `_time` must be no earlier than the record time (−1 s) and no more than one hour after it. This is an inference; the add-ons do not document it.

## Map, dependency and blocked-flow features

Records are **context only**. The panels appear in the scoped endpoint/service investigation that the map and dependency views open, beside the other optional sources. They do not create dependency edges, change graph counters or feed the map's blocked-flow edges; the deny count is labelled that way in the UI. Promoting firewall or flow log denies into blocked-flow edges, or load balancer legs into dependency edges, would need a cross-sensor identity and deduplication contract with the core traffic summary, which does not exist yet.

## Search contract

Each inspection is explicit (a button press in the investigation) and runs as the caller:

1. Configuration recheck: the source must be active, the index macro reviewed (not `unconfigured_optional`), the schema flag `1`, and at least one verified `adm_observer_scope` mapping of the source's observer kind for the selected scope. The search filters `host` to those mapped observers.
2. Window: `[selection start, selection end + 3600 s]` for every source, so session-end, response and delayed flow-log records written after the window are found. Longer sessions without a log in that range can be missed; this is shown as a limitation.
3. Projection: PAN uses the add-on's search-time fields (`[extract_traffic]`, `vendor_action`), so the add-on must be installed on the search head and its knowledge objects visible to the caller. FortiGate keys, F5 iRule keys and AWS access-log fields are extracted from `_raw` by Atlas with bounded, anchored `rex` in the documented order. GCP and Azure JSON paths are read with `spath`, and each Azure tuple is split by position after a bounded `mvexpand`. Only an allowlist of fields is returned; `_raw` is never returned.
4. Address match: `cidrmatch` against the reported and translated addresses, and for load balancers against the client, balancer and server-leg addresses (IPv4 and `::ffff:` forms). Rows whose required fields failed to parse are kept so they count as rejected rather than disappearing.
5. Caps: 10,001 input rows and 64 displayed records plus one completion row; 30 s server / 35 s client deadlines; shared two-job optional lease.

The browser normalizer fails closed. It rejects multivalue fields, unparsed or unsupported rows, unmapped hosts, wrong index or sourcetype, mismatched configuration fingerprints, records outside the window, rows that match no selected address, and time disagreement:

- **PAN**: Generated Time has no time zone. Atlas requires `_time` minus the naive Generated Time to be a whole multiple of 15 minutes within ±14 hours and displays the inferred offset. It does not prove the device's configured zone.
- **FortiGate**: `eventtime` must be 10 (seconds) or 19 (nanoseconds) digits and within 1 second of `_time`.

Input caps, rejected rows, warnings and configuration changes are shown as incomplete evidence. No visible records does not prove the traffic was absent or allowed: logging profiles, per-rule logging, log forwarding and caller permissions all limit coverage.

## Packaging

The adapters and panels live in `frontend/src/ecosystem/` and ship as an independently versioned optional asset (`pages/ecosystem.js`, `ecosystem.css`, `ecosystem-manifest.json`; 48 KiB gzip budget), built by `vite.ecosystem.config.ts` like the multicast and history assets. The main bundle carries only the loader, which fetches the asset when an investigation or the Health page renders a panel; loading it dispatches no search. `tools/check_release.py` requires the complete set once the main bundle registers it and verifies the version and hashes.

## Receipt check (Health)

Health has an on-demand **Check ecosystem receipt** panel; there is no background probe for optional sources. For each staged or active source it counts records indexed in the last 7 days (at most 10,001), how many the adapter's extraction can read (firewalls: required fields and a supported action; load balancers: the anchored line pattern; GCP: a VPC flow `logName`; Azure: one record of a supported version and category, without expanding tuples), how many come from mapped observers, the latest event and index times and the worst ingest lag. Results read as "receipt observed", "stale", "quality gaps", "unmapped hosts" or "no visible records". No visible records is described as not proof of a collection outage. The check runs as the caller and does not mark the source qualified.

## Operator steps

1. Install and configure the vendor add-on per the vendor's documentation (Splunk_TA_paloalto on search heads and parsing tier; Fortinet FortiGate Add-on; the F5 add-on's LTM HSL iRules attached to the virtual servers; the AWS add-on's ELB Access Logs input; the MSCS Storage Blob input for VNet flow logs; the GCP Pub/Sub input for a VPC Flow Logs sink). Confirm events arrive with the sourcetypes in the table above.
2. Set the source's `adm_index_*` macro to the reviewed lowercase index names (for example `index=pan` or `(index=fw_a OR index=fw_b)`).
3. Add one `adm_observer_scope` mapping per Splunk `host` value: the observer kind from the table, observer equal to the exact lowercase `host`, the routing scope, and status `verified`. For F5 this is the BIG-IP as seen by the syslog input. For AWS, Azure and GCP the `host` is normally the collecting forwarder, so the mapping attests the collection input and scope, not the cloud resource.
4. Select the source in deployment settings as staged or active. Investigations query only an active, schema-qualified source; the Health receipt check also runs for staged and active sources that are not yet schema-qualified, so it can be used for step 5.
5. Run **Check ecosystem receipt** on Health, then compare a few known sessions between the vendor console and the Atlas panel: allow, deny, SNAT and DNAT for firewalls; a forwarded request, an LB_FAILED or 5xx and the F5 inferred offset for load balancers; a dropped or denied flow and a NAT flow for cloud flow logs.
6. Only after that comparison, set the schema flag to `1`. Without it the source fails closed.

## Qualification still required

- Live PAN-OS and FortiOS emission through the deployment's actual syslog/SC4S path and add-on version (field order, `vendor_action`, quoting, `eventtime` precision, `devid`/`host` mapping, virtual systems and VDOMs).
- Time zone behaviour on PAN devices not logging in UTC.
- Scale: firewalls generate far more traffic logs than the 10,001-row cap; the cap is reported, but useful windows need measurement on real volumes.
- PAN-OS 10.x/11.x fields beyond the 6.2.0 TA list are ignored; FortiOS 6.x without `eventtime` is rejected.
- F5: the deployed iRule must be the add-on's unmodified iRule. A customised iRule changes the key order and fails closed. The syslog input's header handling, and the SC4S versus add-on sourcetype, must be confirmed.
- AWS: the S3 input's line splitting and `_time` assignment, the presence of field 34 on the deployment's log version, and NLB time zone behaviour.
- Azure: the MSCS event boundary for `mscs:vnet:flow` (one record per event is assumed), version 4 versus 5 tuple widths on real logs, `spath` behaviour on deep arrays, and `mvexpand` memory limits on large records.
- GCP: the sink's Pub/Sub message shape, sampling and aggregation settings, and `_time` assignment.
- None of the new SPL (`rex`, `spath`, `mvexpand`) has run on a live search head. Only the JavaScript emulation in the unit tests has exercised it.

## Tests

- `frontend/src/ecosystem/firewallTrafficEvidence.test.tsx`: search contract, refusals, window, PAN and FortiOS mapping, NAT, time rules and rejections over the fixture `_raw` text, loader and rendered view.
- `frontend/src/ecosystem/loadBalancerEvidence.test.tsx`: F5, ALB and NLB extraction over the fixture `_raw` text, separate client- and server-side legs, not-reported sources, the F5 zone inference, header-injection and legacy-field handling, loader and rendered view.
- `frontend/src/ecosystem/cloudFlowLogEvidence.test.tsx`: GCP and Azure shapes, reporter and NAT rules, drop and deny mapping, tuple widths and times, multi-record rejection, loader and rendered view.
- `frontend/src/ecosystem/ecosystemReceipt.test.tsx`: receipt search, statuses, inconsistent rows, not-selected and unreadable configuration, panels dispatch nothing on render.
- `frontend/src/ecosystem/EcosystemLazyEvidence.test.ts`: optional asset host registration, versioned same-origin URLs, mixed-version rejection and retry.
- `tests/test_release.py` (`*ecosystem*`): complete-set, tampering, mixed-version and budget checks for the optional asset.
- `frontend/src/data/evidenceConfig.test.ts`: index macros, schema flags and observer kinds resolve.
- `tests/test_ecosystem_fixtures.py`: fixture determinism; PAN field order and actions; FortiOS, F5, AWS, Azure and GCP key allowlists; shipped-disabled macros; registry entries.
