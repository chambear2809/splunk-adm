/** Search-time contracts for Splunkbase TAs, Stream, syslog and SNMP. */

export interface TaSource {
  id: string;
  producer: string;
  splunkbaseId?: number;
  transport: "netflow" | "snmp" | "syslog" | "otel" | "ta" | "wire";
  sourcetype: string;
  indexMacro: string;
  role: string;
}

export const TA_SOURCES: TaSource[] = [
  {
    id: "stream_netflow",
    producer: "Splunk Stream",
    transport: "netflow",
    sourcetype: "stream:netflow",
    indexMacro: "adm_index_netflow",
    role: "flow evidence",
  },
  {
    id: "stream_tcp",
    producer: "Splunk Stream",
    transport: "wire",
    sourcetype: "stream:tcp",
    indexMacro: "adm_index_stream_tcp",
    role: "TCP RTT",
  },
  {
    id: "sc4snmp",
    producer: "Splunk Connect for SNMP",
    transport: "snmp",
    sourcetype: "sc4snmp:event",
    indexMacro: "adm_index_snmp",
    role: "IF-MIB capacity",
  },
  {
    id: "otel_traces",
    producer: "Splunk Distribution of OpenTelemetry Collector",
    transport: "otel",
    sourcetype: "otel:traces",
    indexMacro: "adm_index_traces",
    role: "service calls",
  },
  {
    id: "f5",
    producer: "Splunk Add-on for F5 BIG-IP",
    splunkbaseId: 2680,
    transport: "syslog",
    sourcetype: "f5:bigip:syslog",
    indexMacro: "adm_index_f5",
    role: "LTM virtual/pool legs",
  },
  {
    id: "haproxy",
    producer: "Splunk Add-on for HAProxy",
    splunkbaseId: 3135,
    transport: "syslog",
    sourcetype: "haproxy:http",
    indexMacro: "adm_index_haproxy",
    role: "proxy legs",
  },
  {
    id: "aws_alb",
    producer: "Splunk Add-on for Amazon Web Services",
    splunkbaseId: 1876,
    transport: "ta",
    sourcetype: "aws:elb:accesslogs",
    indexMacro: "adm_index_aws",
    role: "ALB/NLB legs",
  },
  {
    id: "azure_vnet",
    producer: "Splunk Add-on for Microsoft Cloud Services",
    splunkbaseId: 3110,
    transport: "ta",
    sourcetype: "mscs:storage:blob:json",
    indexMacro: "adm_index_azure",
    role: "VNet flow logs",
  },
  {
    id: "gcp_vpc",
    producer: "Splunk Add-on for Google Cloud Platform",
    splunkbaseId: 3088,
    transport: "ta",
    sourcetype: "google:gcp:pubsub:message",
    indexMacro: "adm_index_gcp",
    role: "VPC flow logs",
  },
  {
    id: "pan_traffic",
    producer: "Splunk Add-on for Palo Alto Networks",
    transport: "syslog",
    sourcetype: "pan:traffic",
    indexMacro: "adm_index_pan",
    role: "NGFW traffic",
  },
  {
    id: "fortigate",
    producer: "Splunk Add-on for Fortinet FortiGate",
    transport: "syslog",
    sourcetype: "fgt_traffic",
    indexMacro: "adm_index_fortigate",
    role: "NGFW traffic",
  },
  {
    id: "vmware",
    producer: "Splunk Add-on for VMware",
    transport: "ta",
    sourcetype: "vmware:inv:vm",
    indexMacro: "adm_index_vmware_inv",
    role: "vMotion inventory",
  },
  {
    id: "snow",
    producer: "Splunk Add-on for ServiceNow",
    splunkbaseId: 1928,
    transport: "ta",
    sourcetype: "snow:incident",
    indexMacro: "adm_index_snow",
    role: "incident context",
  },
];

export function taSearch(source: TaSource, bound = 64): string {
  return `| \` ${source.indexMacro} \` sourcetype="${source.sourcetype}" | head ${bound}`
    .replace(/` /g, "`")
    .replace(/ `/, "`");
}

export function lbLegFields(sourceId: string): string[] {
  if (sourceId === "f5")
    return ["virtual_name", "pool_name", "client_ip", "dest_ip", "dest_port"];
  if (sourceId === "haproxy")
    return ["frontend_name", "backend_name", "client_ip", "server"];
  if (sourceId === "aws_alb")
    return ["elb", "client:port", "target:port", "request"];
  return [];
}
