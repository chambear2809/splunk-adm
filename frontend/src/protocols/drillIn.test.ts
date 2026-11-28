import { describe, expect, it } from "vitest";
import {
  deviceProtocolLinks,
  endpointProtocolLinks,
  mapEdgeProtocolLinks,
  safeProtocolHref,
} from "./drillIn";
import { parseProtocolLink } from "./inputs";

const NOW = 1800000000;

describe("protocol drill-in helpers", () => {
  it("builds valid Map edge drill-in links that round-trip through parseProtocolLink", () => {
    const links = mapEdgeProtocolLinks({
      srcIp: "10.10.20.11",
      dstIp: "10.10.30.10",
      scope: "prod:dc1",
      earliest: NOW - 7200, // 2h window -> clamped to 1h
      latest: NOW,
      pathname: "/en-US/app/splunk_adm/map",
      now: NOW,
    });
    expect(links.map((l) => l.lens)).toEqual([
      "tcp_tls",
      "qos_icmp",
      "drops",
      "app_transactions",
      "lb_health",
    ]);
    for (const link of links) {
      const url = new URL(link.href, "https://splunk.local");
      expect(url.pathname).toBe("/en-US/app/splunk_adm/protocols");
      const parsed = parseProtocolLink(url.searchParams, NOW);
      expect(parsed.lens).toBe(link.lens);
      expect(parsed.scope).toBe("prod:dc1");
      expect(parsed.earliest).toBe(NOW - 3600);
      expect(parsed.latest).toBe(NOW);
      expect(parsed.filter?.src).toBe("10.10.20.11");
      expect(parsed.filter?.dst).toBe("10.10.30.10");
    }
  });

  it("builds Device drill-in links including Multicast and preserves device selector", () => {
    const links = deviceProtocolLinks({
      device: "leaf1.pseudo.co",
      earliest: NOW - 900,
      latest: NOW,
      pathname: "/app/splunk_adm/device",
      now: NOW,
    });
    expect(links.map((l) => l.lens)).toEqual([
      "routing",
      "l2_control",
      "interface_health",
      "state_events",
      "mgmt_plane",
      "multicast",
    ]);
    const routingUrl = new URL(links[0].href, "https://splunk.local");
    const parsed = parseProtocolLink(routingUrl.searchParams, NOW);
    expect(parsed.filter?.device).toBe("leaf1.pseudo.co");
    expect(links[5].href).toBe("/app/splunk_adm/multicast");
  });

  it("builds Endpoint drill-in links for TCP/TLS, DNS, Mobility, and ICMP", () => {
    const links = endpointProtocolLinks({
      address: "10.10.20.42",
      scope: "prod:dc1",
      earliest: NOW - 600,
      latest: NOW,
      pathname: "/app/splunk_adm/endpoints",
      now: NOW,
    });
    expect(links.map((l) => l.lens)).toEqual([
      "tcp_tls",
      "dns_ops",
      "endpoint_mobility",
      "qos_icmp",
    ]);
    const parsed = parseProtocolLink(
      new URL(links[1].href, "https://splunk.local").searchParams,
      NOW,
    );
    expect(parsed.lens).toBe("dns_ops");
    expect(parsed.filter?.src).toBe("10.10.20.42");
  });

  it("drops invalid selectors and never throws", () => {
    const href = safeProtocolHref({
      lens: "tcp_tls",
      scope: "unmapped:bad",
      src: "not a valid selector; | delete",
      earliest: -10,
      latest: NOW + 999999,
      pathname: "/app/splunk_adm/map",
      now: NOW,
    });
    const parsed = parseProtocolLink(
      new URL(href, "https://splunk.local").searchParams,
      NOW,
    );
    expect(parsed.lens).toBe("tcp_tls");
    expect(parsed.scope).toBeUndefined();
    expect(parsed.filter).toBeUndefined();
  });
});
