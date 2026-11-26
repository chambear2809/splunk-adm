"""Splunkbase / OTel / Stream / syslog / SNMP contracts Atlas may search.

Atlas ships no inputs.conf and no custom collector. Every row below is already
indexed by a documented producer. Macros stay unconfigured until an operator
points them at the TA's index.
"""

# (id, producer, transport, sourcetype, role)
ECOSYSTEM = (
    (
        "stream_netflow",
        "Splunk Stream",
        "netflow/ipfix",
        "stream:netflow",
        "flow evidence",
    ),
    (
        "stream_tcp",
        "Splunk Stream",
        "wire/pcap",
        "stream:tcp",
        "TCP RTT / handshake",
    ),
    (
        "sc4snmp",
        "Splunk Connect for SNMP",
        "snmp",
        "sc4snmp:event",
        "IF-MIB capacity",
    ),
    (
        "otel_traces",
        "Splunk Distribution of OpenTelemetry Collector",
        "otlp/hec",
        "otel:traces",
        "service calls",
    ),
    (
        "otel_k8s",
        "Splunk Distribution of OpenTelemetry Collector",
        "k8sobjects",
        "kube:object:pods",
        "pod identity",
    ),
    (
        "hubble",
        "Cilium Hubble via OTel Collector",
        "hec",
        "cilium:hubble:flow",
        "pod flows",
    ),
    (
        "f5",
        "Splunk Add-on for F5 BIG-IP (2680)",
        "syslog/sc4s",
        "f5:bigip:syslog",
        "LTM virtual/pool legs",
    ),
    (
        "haproxy",
        "Splunk Add-on for HAProxy (3135)",
        "syslog/file",
        "haproxy:http",
        "proxy legs",
    ),
    (
        "aws_alb",
        "Splunk Add-on for Amazon Web Services (1876)",
        "aws ta / firehose",
        "aws:elb:accesslogs",
        "ALB/NLB legs",
    ),
    (
        "aws_vpc_flow",
        "Splunk Add-on for Amazon Web Services (1876)",
        "aws ta / firehose",
        "aws:vpcflow:v5",
        "VPC flow evidence",
    ),
    (
        "azure_vnet",
        "Splunk Add-on for Microsoft Cloud Services (3110)",
        "mscs / data manager",
        "mscs:storage:blob:json",
        "VNet flow logs",
    ),
    (
        "gcp_vpc",
        "Splunk Add-on for Google Cloud Platform (3088)",
        "pubsub",
        "google:gcp:pubsub:message",
        "VPC flow logs",
    ),
    (
        "pan_traffic",
        "Splunk Add-on for Palo Alto Networks",
        "syslog/sc4s",
        "pan:traffic",
        "NGFW traffic",
    ),
    (
        "fortigate",
        "Splunk Add-on for Fortinet FortiGate",
        "syslog/sc4s",
        "fgt_traffic",
        "NGFW traffic",
    ),
    (
        "vmware",
        "Splunk Add-on for VMware",
        "vcenter ta",
        "vmware:inv:vm",
        "vMotion / VM inventory",
    ),
    (
        "intersight",
        "Cisco Intersight Add-on for Splunk",
        "intersight ta",
        "cisco:intersight",
        "server / move-group inventory",
    ),
    (
        "snow",
        "Splunk Add-on for ServiceNow (1928)",
        "snow ta",
        "snow:incident",
        "incident / change context",
    ),
    (
        "itsi",
        "Splunk IT Service Intelligence",
        "itsiimportobjects",
        "itsi_import_objects",
        "service entities",
    ),
)


def sourcetype_for(source_id):
    for row in ECOSYSTEM:
        if row[0] == source_id:
            return row[3]
    raise KeyError(source_id)


def producer_for(source_id):
    for row in ECOSYSTEM:
        if row[0] == source_id:
            return row[1]
    raise KeyError(source_id)
