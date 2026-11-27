import { pageURL } from "../app/urlState";
import type { ProtocolLensId } from "./shared/contract";

export interface ProtocolDrillInLink {
  lens: ProtocolLensId | "multicast";
  label: string;
  href: string;
}

/** Keep drill-in link construction self-contained so `atlas.js` never imports protocol workbench modules. */
const PROTOCOL_VERSION = "1";
const MAX_WINDOW_SECONDS = 3600;
const SELECTOR_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;
const RESERVED_SCOPE_RE = /^(unmapped|unknown|reserved|none)(:|$)/i;
const IP_LITERAL_RE =
  /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:]*:[0-9A-Fa-f]{0,4})$/;

function isValidEpoch(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= 253402300799
  );
}

function clampProtocolWindow(
  earliest?: number,
  latest?: number,
  now = Math.floor(Date.now() / 1000),
): { earliest: number; latest: number } | undefined {
  if (!isValidEpoch(earliest) || !isValidEpoch(latest)) return undefined;
  const clampedLatest = Math.min(latest, now);
  if (clampedLatest <= 0) return undefined;
  const clampedEarliest = Math.max(
    1,
    Math.min(earliest, clampedLatest - 60),
    clampedLatest - MAX_WINDOW_SECONDS,
  );
  if (clampedEarliest >= clampedLatest) return undefined;
  return { earliest: clampedEarliest, latest: clampedLatest };
}

function safeScope(value?: string): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  return SELECTOR_RE.test(trimmed) && !RESERVED_SCOPE_RE.test(trimmed)
    ? trimmed
    : undefined;
}

function safeSelector(value?: string): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  return SELECTOR_RE.test(trimmed) ? trimmed : undefined;
}

function safeIpSelector(value?: string): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  return IP_LITERAL_RE.test(trimmed) && SELECTOR_RE.test(trimmed)
    ? trimmed
    : undefined;
}

/**
 * Builds a validated `/app/splunk_adm/protocols` drill-in URL that clamps
 * wider windows to the protocol workbench 1-hour UTC bound and silently drops
 * unvalidated selectors rather than throwing during render.
 */
export function safeProtocolHref(options: {
  lens: ProtocolLensId;
  scope?: string;
  earliest?: number;
  latest?: number;
  src?: string;
  dst?: string;
  device?: string;
  pathname?: string;
  now?: number;
}): string {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const scope = safeScope(options.scope);
  const win = clampProtocolWindow(options.earliest, options.latest, now);
  const src = safeSelector(options.src);
  const dst = safeSelector(options.dst);
  const device = safeSelector(options.device);
  const params = new URLSearchParams();
  params.set("p_v", PROTOCOL_VERSION);
  params.set("p_lens", options.lens);
  if (scope) params.set("p_scope", scope);
  if (win) {
    params.set("p_earliest", String(win.earliest));
    params.set("p_latest", String(win.latest));
  }
  if (src) params.set("p_src", src);
  if (dst) params.set("p_dst", dst);
  if (device) params.set("p_device", device);
  return pageURL("protocols", params, options.pathname);
}

/** Map edge inspector drill-ins: TCP/TLS, QoS, Drops, App Transactions, LB Health. */
export function mapEdgeProtocolLinks(options: {
  srcIp?: string;
  dstIp?: string;
  scope?: string;
  earliest?: number;
  latest?: number;
  pathname?: string;
  now?: number;
}): ProtocolDrillInLink[] {
  const src = safeIpSelector(options.srcIp);
  const dst = safeIpSelector(options.dstIp);
  const entries: readonly { lens: ProtocolLensId; label: string }[] = [
    { lens: "tcp_tls", label: "TCP & TLS" },
    { lens: "qos_icmp", label: "QoS & ICMP" },
    { lens: "drops", label: "Drops" },
    { lens: "app_transactions", label: "HTTP & DB" },
    { lens: "lb_health", label: "LB Health" },
  ];
  return entries.map(({ lens, label }) => ({
    lens,
    label,
    href: safeProtocolHref({
      lens,
      scope: options.scope,
      earliest: options.earliest,
      latest: options.latest,
      src,
      dst,
      pathname: options.pathname,
      now: options.now,
    }),
  }));
}

/** Device page drill-ins: Routing, L2 Control, Interfaces, State Events, Mgmt Plane, Multicast. */
export function deviceProtocolLinks(options: {
  device?: string;
  scope?: string;
  earliest?: number;
  latest?: number;
  pathname?: string;
  now?: number;
}): ProtocolDrillInLink[] {
  const entries: readonly { lens: ProtocolLensId; label: string }[] = [
    { lens: "routing", label: "Routing" },
    { lens: "l2_control", label: "L2 Control" },
    { lens: "interface_health", label: "Interfaces" },
    { lens: "state_events", label: "State Events" },
    { lens: "mgmt_plane", label: "Mgmt Plane" },
  ];
  return [
    ...entries.map(({ lens, label }) => ({
      lens,
      label,
      href: safeProtocolHref({
        lens,
        scope: options.scope,
        earliest: options.earliest,
        latest: options.latest,
        device: options.device,
        pathname: options.pathname,
        now: options.now,
      }),
    })),
    {
      lens: "multicast",
      label: "Multicast",
      href: pageURL("multicast", new URLSearchParams(), options.pathname),
    },
  ];
}

/** Endpoint page drill-ins: TCP/TLS, DNS Ops, Mobility, QoS & ICMP. */
export function endpointProtocolLinks(options: {
  address?: string;
  scope?: string;
  earliest?: number;
  latest?: number;
  pathname?: string;
  now?: number;
}): ProtocolDrillInLink[] {
  const src = safeIpSelector(options.address);
  const entries: readonly { lens: ProtocolLensId; label: string }[] = [
    { lens: "tcp_tls", label: "TCP & TLS" },
    { lens: "dns_ops", label: "DNS Ops" },
    { lens: "endpoint_mobility", label: "Mobility" },
    { lens: "qos_icmp", label: "QoS & ICMP" },
  ];
  return entries.map(({ lens, label }) => ({
    lens,
    label,
    href: safeProtocolHref({
      lens,
      scope: options.scope,
      earliest: options.earliest,
      latest: options.latest,
      src,
      pathname: options.pathname,
      now: options.now,
    }),
  }));
}
