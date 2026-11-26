# Ecosystem TAs Atlas can search

Application Atlas does not ship `inputs.conf` or a custom collector. It searches indexes that existing Splunkbase TAs, Splunk Stream, Splunk Connect for SNMP, syslog (SC4S), and the Splunk Distribution of OpenTelemetry Collector already populate. Point the matching `adm_index_*` macros in Setup at those indexes; leave a macro on `index=unconfigured_optional` until the TA is installed and writing.

| Producer | Splunkbase | Sourcetype | Macro | Atlas use |
| --- | --- | --- | --- | --- |
| Splunk Stream | Stream app / TA | `stream:netflow` | `adm_index_netflow` | Observed conversations |
| Splunk Stream | Stream app / TA | `stream:tcp` | `adm_index_stream_tcp` | TCP RTT, retransmits, resets |
| Splunk Connect for SNMP | SC4SNMP | `sc4snmp:event` | `adm_index_snmp` | IF-MIB names and optional capacity |
| Splunk OTel Collector | Helm chart | `otel:traces` | `adm_index_traces` | Service calls |
| Splunk OTel Collector | Helm chart | `kube:object:pods` | `adm_index_k8s` | Pod identity |
| Hubble via OTel | file log | `cilium:hubble:flow` | `adm_index_hubble` | Pod flows |
| F5 BIG-IP TA | 2680 | `f5:bigip:ltm:http:irule` / `f5:bigip:ltm:lb:failed:irule` | `adm_index_f5` | Optional client→VIP and pool member request legs (unqualified) |
| HAProxy TA | 3135 | `haproxy:http` | `adm_index_haproxy` | Proxy legs |
| AWS TA | 1876 | `aws:elb:accesslogs` | `adm_index_aws` | Optional ALB/NLB access legs (unqualified) |
| AWS TA | 1876 | `aws:vpcflow:v5` | `adm_index_aws_vpc_flow` | VPC flow evidence |
| MSCS (Azure) | 3110 | `mscs:vnet:flow` / `mscs:storage:blob:json` | `adm_index_azure` | Optional Azure **VNet** flow log evidence, not retired NSG flow logs (unqualified) |
| GCP TA | 3088 | `google:gcp:compute:vpc_flows` | `adm_index_gcp` | Optional VPC flow log evidence (unqualified) |
| Palo Alto TA | PAN-OS | `pan:traffic` | `adm_index_pan` | Optional firewall traffic evidence (unqualified) |
| FortiGate TA | Fortinet | `fgt_traffic` / `fortigate_traffic` | `adm_index_fortigate` | Optional firewall traffic evidence (unqualified) |
| VMware TA | VMware | `vmware:inv:vm` | `adm_index_vmware_inv` | Inventory / move-group |
| ServiceNow TA | 1928 | `snow:incident`, `snow:change_request` | `adm_index_snow` | Incident context; change windows for [Verify change](change-verification.md) via `adm_change_request_window` (not authorization or approval) |

## Firewall traffic evidence (PAN-OS, FortiGate)

`adm_index_pan` and `adm_index_fortigate` feed the optional `pan_traffic` and `fortigate_traffic` sources. They are **unqualified**: tested only against TA-grounded synthetic fixtures, not live firewalls. Each needs its index macro, verified `adm_observer_scope` mappings with observer kind `pan_firewall` or `fortigate_firewall` (observer = exact lowercase Splunk `host`), source selection in deployment settings, and its schema flag (`adm_pan_traffic_schema_qualified`, `adm_fortigate_traffic_schema_qualified`, both `0` by default). Records appear only in the scoped endpoint/service investigation as context: allow/deny is that firewall's decision and NAT is shown as same-event translation, and they add no dependency edges or blocked-flow edges. Health has an on-demand **Check ecosystem receipt** panel. PAN fields come from Splunk_TA_paloalto search-time extraction, so install the add-on on the search head. FortiGate add-on 1.6.x and later uses sourcetype `fortigate_traffic`; Atlas accepts both. See [the design](../ECOSYSTEM_TRAFFIC_EVIDENCE_DESIGN.md) for meaning, limits and qualification steps.

## Load balancer and cloud flow log evidence (F5, AWS ALB/NLB, Azure, GCP)

`adm_index_f5`, `adm_index_aws`, `adm_index_azure` and `adm_index_gcp` feed the optional `f5_ltm_http`, `aws_elb_access`, `azure_vnet_flow` and `gcp_vpc_flow` sources. They are **unqualified** in the same way as the firewall sources and follow the same steps.

Each source needs:

- its index macro;
- verified `adm_observer_scope` mappings with observer kind `f5_bigip`, `aws_elb`, `azure_vnet_flow` or `gcp_vpc_flow` (observer = exact lowercase Splunk `host`, which for the cloud add-ons is normally the collecting forwarder);
- source selection in deployment settings;
- its schema flag: `adm_f5_ltm_irule_schema_qualified`, `adm_aws_elb_access_schema_qualified`, `adm_azure_vnet_flow_schema_qualified` or `adm_gcp_vpc_flow_schema_qualified`. All four ship as `0`.

What each source contributes:

- **F5.** Only the add-on's unmodified LTM HSL iRules are read. Atlas shows the client→virtual server leg and the pool member leg of each request separately. The server-side source (SNAT pool or automap) is not in the iRule, so it is shown as not reported.
- **AWS.** ALB requests show client→load balancer node and target separately. NLB access logs exist only for TLS listeners and report no target.
- **Azure.** Each event must carry exactly one VNet flow log record. The MSCS add-on's event boundary is not documented, so wider events are rejected.
- **GCP.** Entries reach Splunk through a Pub/Sub sink. Only `DROPPED` entries carry a decision.
- **All four.** Balancer and NAT addresses are never used as endpoint identity, and records add no dependency or blocked-flow edges.

See [the design](../ECOSYSTEM_TRAFFIC_EVIDENCE_DESIGN.md) for what each leg means, what is not grounded and the qualification steps.

AWS VPC flow logs are a separate optional source ([aws-vpc-flow-evidence](aws-vpc-flow-evidence.md)). The HAProxy macro above is still declared only; nothing in Atlas searches it yet.

Webhook alerts `ADM - Newly blocked production dependency`, `ADM - Redundancy loss`, `ADM - Unexpected new dependency`, and `ADM - Telemetry blindness` ship **disabled** (`enableSched = 0`, `action.webhook = 0`). Enable them only after the summary and NetFlow macros are populated and a webhook URL is set. They use Splunk's built-in webhook action; Atlas does not add `alert.execute.cmd`.

ITSI import (`adm_itsi_import_objects`) and IF-MIB capacity (`adm_ifmib_capacity`) macros are inert until an operator replaces them with a bounded local search. Do not emit `services_depends_on` cycles; batch ITSI services at 200–300. Applications > ITSI export and CMDB reconciliation downloads cycle-broken, batched ITSI CSV drafts and never writes to ITSI; see [itsi-cmdb](itsi-cmdb.md). Atlas does not read ServiceNow CMDB sourcetypes directly.
