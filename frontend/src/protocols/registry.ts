import {
  sourceForLens,
  type LensProfileValidator,
  type ProtocolLensId,
  type ProtocolLensRegistration,
} from "./shared/contract";
import { validateTcpTlsExtra } from "./lenses/tcp_tls/validate";
import { validateDnsOpsExtra } from "./lenses/dns_ops/validate";
import { validateRoutingExtra } from "./lenses/routing/validate";
import { validateL2ControlExtra } from "./lenses/l2_control/validate";
import { validateInterfaceHealthExtra } from "./lenses/interface_health/validate";

/**
 * Central registry of all 13 protocol workbenches.
 * Wave 0 populates metadata and validators; Waves 1–4 add lens implementations
 * and Wave 5 wires every lens's lazy loader and summary runner.
 */
export const PROTOCOL_LENSES: readonly ProtocolLensRegistration[] = [
  {
    id: "tcp_tls",
    source: sourceForLens("tcp_tls"),
    title: "TCP Health & TLS",
    shortTitle: "TCP & TLS",
    category: "transport",
    summary:
      "Client vs server RTT, retransmits, resets, and TLS certificate posture.",
    sources: ["stream:tcp", "stream:netflow"],
    streamIds: ["tcp"],
    operatorDoc: "protocol-tcp-tls.md",
    validateExtra: validateTcpTlsExtra,
    summarize: async (client, request, configuration, signal) => {
      const { summarizeTcpTls } = await import("./lenses/tcp_tls/adapter");
      return summarizeTcpTls(client, request, configuration, signal, {
        profileValidators: registeredProfileValidators(),
      });
    },
    loadComponent: async () =>
      (await import("./lenses/tcp_tls/TcpTlsLensPage")).TcpTlsLensPage,
  },
  {
    id: "dns_ops",
    source: sourceForLens("dns_ops"),
    title: "DNS Operations",
    shortTitle: "DNS Ops",
    category: "control_plane",
    summary:
      "Resolver errors, latency, answer churn, and search-suffix amplification.",
    sources: ["stream:dns", "cilium:hubble:flow"],
    streamIds: ["dns"],
    operatorDoc: "protocol-dns-ops.md",
    validateExtra: validateDnsOpsExtra,
    summarize: async (client, request, configuration, signal) => {
      const { summarizeDnsOps } = await import("./lenses/dns_ops/adapter");
      return summarizeDnsOps(client, request, configuration, signal, {
        profileValidators: registeredProfileValidators(),
      });
    },
    loadComponent: async () =>
      (await import("./lenses/dns_ops/DnsOpsLensPage")).DnsOpsLensPage,
  },
  {
    id: "routing",
    source: sourceForLens("routing"),
    title: "Routing Control Plane",
    shortTitle: "Routing",
    category: "control_plane",
    summary: "BGP, OSPF, IS-IS, and BFD peers, flaps, and flow asymmetry.",
    sources: [
      "cisco:dc:nexus9k:dme",
      "cisco:ios",
      "cisco:dc:nexus9k:syslog",
      "stream:netflow",
    ],
    streamIds: [],
    operatorDoc: "protocol-routing.md",
    validateExtra: validateRoutingExtra,
    summarize: async (client, request, configuration, signal) => {
      const { summarizeRouting } = await import("./lenses/routing/adapter");
      return summarizeRouting(client, request, configuration, signal, {
        profileValidators: registeredProfileValidators(),
      });
    },
    loadComponent: async () =>
      (await import("./lenses/routing/RoutingLensPage")).RoutingLensPage,
  },
  {
    id: "l2_control",
    source: sourceForLens("l2_control"),
    title: "L2 Control Plane",
    shortTitle: "L2 Control",
    category: "control_plane",
    summary:
      "DHCP DORA health, STP root and port state, and port-channel members.",
    sources: [
      "stream:dhcp",
      "stream:arp",
      "cisco:dc:nexus9k:dme",
      "cisco:ios",
      "cisco:dc:nexus9k:syslog",
    ],
    streamIds: ["dhcp", "arp"],
    operatorDoc: "protocol-l2-control.md",
    validateExtra: validateL2ControlExtra,
    summarize: async (client, request, configuration, signal) => {
      const { summarizeL2Control } =
        await import("./lenses/l2_control/adapter");
      return summarizeL2Control(client, request, configuration, signal, {
        profileValidators: registeredProfileValidators(),
      });
    },
    loadComponent: async () =>
      (await import("./lenses/l2_control/L2ControlLensPage")).L2ControlLensPage,
  },
  {
    id: "interface_health",
    source: sourceForLens("interface_health"),
    title: "Interface & Link Health",
    shortTitle: "Interfaces",
    category: "fabric_qos",
    summary: "Utilization, errors, discards, and ETHPORT link flap timelines.",
    sources: [
      "cisco:dc:nexus9k:dme",
      "cisco:dc:nd:*",
      "cisco:ios",
      "cisco:dc:nexus9k:syslog",
    ],
    streamIds: [],
    operatorDoc: "protocol-interface-health.md",
    validateExtra: validateInterfaceHealthExtra,
    summarize: async (client, request, configuration, signal) => {
      const { summarizeInterfaceHealth } =
        await import("./lenses/interface_health/adapter");
      return summarizeInterfaceHealth(client, request, configuration, signal, {
        profileValidators: registeredProfileValidators(),
      });
    },
    loadComponent: async () =>
      (await import("./lenses/interface_health/InterfaceHealthLensPage"))
        .InterfaceHealthLensPage,
  },
  {
    id: "qos_icmp",
    source: sourceForLens("qos_icmp"),
    title: "QoS/DSCP & ICMP",
    shortTitle: "QoS & ICMP",
    category: "fabric_qos",
    summary:
      "DSCP remarking across exporters, PMTUD candidates, and fabric drops.",
    sources: ["stream:netflow", "stream:icmp", "cisco:dc:nd:*"],
    streamIds: ["icmp"],
    operatorDoc: "protocol-qos-icmp.md",
  },
  {
    id: "enterprise_l7",
    source: sourceForLens("enterprise_l7"),
    title: "Enterprise L7",
    shortTitle: "Enterprise L7",
    category: "application",
    summary: "SMB, NFS, LDAP, RADIUS, and VoIP SIP/RTP quality posture.",
    sources: [
      "stream:smb",
      "stream:nfs",
      "stream:ldap",
      "stream:radius",
      "stream:sip",
      "stream:rtp",
    ],
    streamIds: ["smb", "nfs", "ldap", "radius", "sip", "rtp", "rtcp"],
    operatorDoc: "protocol-enterprise-l7.md",
  },
  {
    id: "drops",
    source: sourceForLens("drops"),
    title: "Blocked Traffic & Drops",
    shortTitle: "Drops",
    category: "fabric_qos",
    summary:
      "Source-native denies across ACI, FTD, Hubble, ND, and firewall logs.",
    sources: [
      "cisco:sfw:estreamer",
      "cilium:hubble:flow",
      "cisco:dc:nd:*",
      "cisco:dc:aci:*",
    ],
    streamIds: [],
    operatorDoc: "protocol-drops.md",
  },
  {
    id: "endpoint_mobility",
    source: sourceForLens("endpoint_mobility"),
    title: "Endpoint Mobility & ARP",
    shortTitle: "Mobility",
    category: "control_plane",
    summary:
      "MAC/IP moves, duplicate IP conflicts, ARP spikes, and port flaps.",
    sources: ["stream:arp", "cisco:dc:nd:*", "cisco:dc:nexus9k:dme"],
    streamIds: ["arp"],
    operatorDoc: "protocol-endpoint-mobility.md",
  },
  {
    id: "app_transactions",
    source: sourceForLens("app_transactions"),
    title: "HTTP & DB Transactions",
    shortTitle: "HTTP & DB",
    category: "application",
    summary:
      "Rate, errors, and p95 latency per HTTP and SQL server without query text.",
    sources: [
      "stream:http",
      "stream:mysql",
      "stream:postgres",
      "stream:tds",
      "stream:tns",
    ],
    streamIds: ["http", "mysql", "postgres", "tds", "tns"],
    operatorDoc: "protocol-app-transactions.md",
  },
  {
    id: "state_events",
    source: sourceForLens("state_events"),
    title: "State-Change Timeline",
    shortTitle: "State Events",
    category: "operations",
    summary: "Link, BGP, OSPF, BFD, STP, PIM, and HSRP/VRRP state transitions.",
    sources: [
      "cisco:ios",
      "cisco:dc:nexus9k:syslog",
      "cisco:aci",
      "cisco:dc:aci:syslog",
    ],
    streamIds: [],
    operatorDoc: "protocol-state-events.md",
  },
  {
    id: "mgmt_plane",
    source: sourceForLens("mgmt_plane"),
    title: "Management-Plane Hygiene",
    shortTitle: "Mgmt Plane",
    category: "operations",
    summary: "SNMPv1/v2c, cleartext Telnet/FTP/TFTP, and syslog receipt gaps.",
    sources: [
      "stream:snmp",
      "stream:ftp",
      "stream:netflow",
      "cisco:ios",
      "cisco:dc:nexus9k:syslog",
    ],
    streamIds: ["snmp", "ftp"],
    operatorDoc: "protocol-mgmt-plane.md",
  },
  {
    id: "lb_health",
    source: sourceForLens("lb_health"),
    title: "Load Balancer Pool Health",
    shortTitle: "LB Health",
    category: "application",
    summary: "VIP and pool-member failures across F5, ALB, and NLB.",
    sources: [
      "f5:bigip:ltm:http:irule",
      "aws:alb:accesslogs",
      "aws:nlb:accesslogs",
    ],
    streamIds: [],
    operatorDoc: "protocol-lb-health.md",
  },
];

export function lensById(
  id: ProtocolLensId,
): ProtocolLensRegistration | undefined {
  return PROTOCOL_LENSES.find((lens) => lens.id === id);
}

export function registeredProfileValidators(): Partial<
  Record<ProtocolLensId, LensProfileValidator>
> {
  const map: Partial<Record<ProtocolLensId, LensProfileValidator>> = {};
  for (const lens of PROTOCOL_LENSES) {
    if (lens.validateExtra) map[lens.id] = lens.validateExtra;
  }
  return map;
}
