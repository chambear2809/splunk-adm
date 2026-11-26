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
| F5 BIG-IP TA | 2680 | `f5:bigip:syslog` | `adm_index_f5` | VIP / pool member legs |
| HAProxy TA | 3135 | `haproxy:http` | `adm_index_haproxy` | Proxy legs |
| AWS TA | 1876 | `aws:elb:accesslogs` | `adm_index_aws` | ALB/NLB legs |
| AWS TA | 1876 | `aws:vpcflow:v5` | `adm_index_aws_vpc_flow` | VPC flow evidence |
| MSCS (Azure) | 3110 | `mscs:storage:blob:json` | `adm_index_azure` | Azure **VNet** flow logs (not retired NSG flow logs) |
| GCP TA | 3088 | `google:gcp:pubsub:message` | `adm_index_gcp` | VPC flow logs |
| Palo Alto TA | PAN-OS | `pan:traffic` | `adm_index_pan` | NGFW traffic |
| FortiGate TA | Fortinet | `fgt_traffic` | `adm_index_fortigate` | NGFW traffic |
| VMware TA | VMware | `vmware:inv:vm` | `adm_index_vmware_inv` | Inventory / move-group |
| ServiceNow TA | 1928 | `snow:incident` | `adm_index_snow` | Incident context (not authorization) |

Webhook alerts `ADM - Newly blocked production dependency`, `ADM - Redundancy loss`, `ADM - Unexpected new dependency`, and `ADM - Telemetry blindness` ship **disabled** (`enableSched = 0`, `action.webhook = 0`). Enable them only after the summary and NetFlow macros are populated and a webhook URL is set. They use Splunk's built-in webhook action; Atlas does not add `alert.execute.cmd`.

ITSI import (`adm_itsi_import_objects`) and IF-MIB capacity (`adm_ifmib_capacity`) macros are inert until an operator replaces them with a bounded local search. Do not emit `services_depends_on` cycles; batch ITSI services at 200–300.
