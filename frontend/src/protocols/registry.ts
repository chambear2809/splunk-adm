import type { ComponentType } from "react";
import {
  sourceForLens,
  type LensProfileValidator,
  type ProtocolLensComponentProps,
  type ProtocolLensId,
  type ProtocolLensRegistration,
  type ProtocolLensSummaryRunner,
} from "./shared/contract";
import { loadProtocolLensBundle } from "./shared/loader";
import { validateTcpTlsExtra } from "./lenses/tcp_tls/validate";
import { validateDnsOpsExtra } from "./lenses/dns_ops/validate";
import { validateRoutingExtra } from "./lenses/routing/validate";
import { validateL2ControlExtra } from "./lenses/l2_control/validate";
import { validateInterfaceHealthExtra } from "./lenses/interface_health/validate";
import { validateQosIcmpExtra } from "./lenses/qos_icmp/validate";
import { validateEnterpriseL7Extra } from "./lenses/enterprise_l7/validate";
import { validateDropsExtra } from "./lenses/drops/validate";
import { validateEndpointMobilityExtra } from "./lenses/endpoint_mobility/validate";

/**
 * Builds Splunk-aware lazy loaders for a lens.
 * - In packaged Splunk builds (`__ADM_SPLUNK_BUILD__`), loads the per-lens
 *   optional IIFE asset (`pages/protocol-<id>.js`), so Vite dead-code-eliminates
 *   every lens page and adapter from `protocols-core.js`.
 * - In Vite dev/preview and Vitest (`!__ADM_SPLUNK_BUILD__`), imports the lens
 *   modules directly.
 */
function makeSplunkLensLoaders(
  id: ProtocolLensId,
): Pick<ProtocolLensRegistration, "loadComponent" | "summarize"> {
  return {
    summarize: async (client, request, configuration, signal) => {
      const bundle = await loadProtocolLensBundle(id);
      if (!bundle.summarize) {
        throw new Error(
          `Protocol lens "${id}" does not export a summary runner.`,
        );
      }
      return bundle.summarize(client, request, configuration, signal, {
        profileValidators: registeredProfileValidators(),
      });
    },
    loadComponent: async () => {
      const bundle = await loadProtocolLensBundle(id);
      return bundle.LensPage;
    },
  };
}

function makeDevLensLoaders(
  loadDevPage: () => Promise<ComponentType<ProtocolLensComponentProps>>,
  loadDevSummarize: () => Promise<ProtocolLensSummaryRunner>,
): Pick<ProtocolLensRegistration, "loadComponent" | "summarize"> {
  return {
    summarize: async (client, request, configuration, signal) => {
      const fn = await loadDevSummarize();
      return fn(client, request, configuration, signal);
    },
    loadComponent: loadDevPage,
  };
}

/**
 * Central registry of all 13 protocol workbenches.
 * Wave 0 populates metadata and validators; Waves 1–4 add lens implementations
 * and per-lens optional bundles (`pages/protocol-<lens>.js`).
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
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("tcp_tls")
      : makeDevLensLoaders(
          async () =>
            (await import("./lenses/tcp_tls/TcpTlsLensPage")).TcpTlsLensPage,
          async () => {
            const { summarizeTcpTls } =
              await import("./lenses/tcp_tls/adapter");
            return (client, request, configuration, signal) =>
              summarizeTcpTls(client, request, configuration, signal, {
                profileValidators: registeredProfileValidators(),
              });
          },
        )),
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
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("dns_ops")
      : makeDevLensLoaders(
          async () =>
            (await import("./lenses/dns_ops/DnsOpsLensPage")).DnsOpsLensPage,
          async () => {
            const { summarizeDnsOps } =
              await import("./lenses/dns_ops/adapter");
            return (client, request, configuration, signal) =>
              summarizeDnsOps(client, request, configuration, signal, {
                profileValidators: registeredProfileValidators(),
              });
          },
        )),
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
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("routing")
      : makeDevLensLoaders(
          async () =>
            (await import("./lenses/routing/RoutingLensPage")).RoutingLensPage,
          async () => {
            const { summarizeRouting } =
              await import("./lenses/routing/adapter");
            return (client, request, configuration, signal) =>
              summarizeRouting(client, request, configuration, signal, {
                profileValidators: registeredProfileValidators(),
              });
          },
        )),
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
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("l2_control")
      : makeDevLensLoaders(
          async () =>
            (await import("./lenses/l2_control/L2ControlLensPage"))
              .L2ControlLensPage,
          async () => {
            const { summarizeL2Control } =
              await import("./lenses/l2_control/adapter");
            return (client, request, configuration, signal) =>
              summarizeL2Control(client, request, configuration, signal, {
                profileValidators: registeredProfileValidators(),
              });
          },
        )),
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
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("interface_health")
      : makeDevLensLoaders(
          async () =>
            (await import("./lenses/interface_health/InterfaceHealthLensPage"))
              .InterfaceHealthLensPage,
          async () => {
            const { summarizeInterfaceHealth } =
              await import("./lenses/interface_health/adapter");
            return (client, request, configuration, signal) =>
              summarizeInterfaceHealth(client, request, configuration, signal, {
                profileValidators: registeredProfileValidators(),
              });
          },
        )),
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
    validateExtra: validateQosIcmpExtra,
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("qos_icmp")
      : makeDevLensLoaders(
          async () =>
            (await import("./lenses/qos_icmp/QosIcmpLensPage")).QosIcmpLensPage,
          async () => {
            const { summarizeQosIcmp } =
              await import("./lenses/qos_icmp/adapter");
            return (client, request, configuration, signal) =>
              summarizeQosIcmp(client, request, configuration, signal, {
                profileValidators: registeredProfileValidators(),
              });
          },
        )),
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
      "stream:rtcp",
    ],
    streamIds: ["smb", "nfs", "ldap", "radius", "sip", "rtp", "rtcp"],
    operatorDoc: "protocol-enterprise-l7.md",
    validateExtra: validateEnterpriseL7Extra,
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("enterprise_l7")
      : makeDevLensLoaders(
          async () =>
            (await import("./lenses/enterprise_l7/EnterpriseL7LensPage"))
              .EnterpriseL7LensPage,
          async () => {
            const { summarizeEnterpriseL7 } =
              await import("./lenses/enterprise_l7/adapter");
            return (client, request, configuration, signal) =>
              summarizeEnterpriseL7(client, request, configuration, signal, {
                profileValidators: registeredProfileValidators(),
              });
          },
        )),
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
    validateExtra: validateDropsExtra,
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("drops")
      : makeDevLensLoaders(
          async () =>
            (await import("./lenses/drops/DropsLensPage")).DropsLensPage,
          async () => {
            const { summarizeDrops } = await import("./lenses/drops/adapter");
            return (client, request, configuration, signal) =>
              summarizeDrops(client, request, configuration, signal, {
                profileValidators: registeredProfileValidators(),
              });
          },
        )),
  },
  {
    id: "endpoint_mobility",
    source: sourceForLens("endpoint_mobility"),
    title: "Endpoint Mobility & ARP",
    shortTitle: "Mobility",
    category: "control_plane",
    summary:
      "MAC/IP moves, duplicate IP conflicts, ARP spikes, and port flaps.",
    sources: [
      "stream:arp",
      "cisco:dc:nd:*",
      "cisco:dc:aci:*",
      "cisco:dc:nexus9k:dme",
      "cisco:ios",
      "cisco:dc:nexus9k:syslog",
    ],
    streamIds: ["arp"],
    operatorDoc: "protocol-endpoint-mobility.md",
    validateExtra: validateEndpointMobilityExtra,
    ...(__ADM_SPLUNK_BUILD__
      ? makeSplunkLensLoaders("endpoint_mobility")
      : makeDevLensLoaders(
          async () =>
            (
              await import("./lenses/endpoint_mobility/EndpointMobilityLensPage")
            ).EndpointMobilityLensPage,
          async () => {
            const { summarizeEndpointMobility } =
              await import("./lenses/endpoint_mobility/adapter");
            return (client, request, configuration, signal) =>
              summarizeEndpointMobility(
                client,
                request,
                configuration,
                signal,
                {
                  profileValidators: registeredProfileValidators(),
                },
              );
          },
        )),
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
