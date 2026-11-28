import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../data/searchClient";
import { applyProtocolParamPatch, ProtocolsPage } from "./ProtocolsPage";
import { protocolLink } from "./inputs";
import { PROTOCOL_LENSES } from "./registry";

describe("ProtocolsPage hub landing", () => {
  it("renders Multicast standalone card and all 13 protocol lens cards without auto-searching", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <ProtocolsPage client={client} live={false} theme="light" />,
    );
    expect(html).toContain("Multicast / IGMP");
    for (const lens of PROTOCOL_LENSES) {
      expect(html).toContain(`protocol-card-${lens.id}`);
    }
    expect(search).not.toHaveBeenCalled();
  });

  it("renders live hub without issuing any SPL search during initial mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <ProtocolsPage client={client} live={true} theme="light" />,
    );
    expect(html).toContain("Protocols");
    expect(search).not.toHaveBeenCalled();
  });

  it("clears filter params from URL state and sanitizes malformed Focus pivot filters", () => {
    const win = { earliest: 1800000000 - 900, latest: 1800000000 };
    const withFilter = applyProtocolParamPatch(
      { lens: "tcp_tls", scope: "dc1", view: "overview" },
      "tcp_tls",
      "dc1",
      win,
      {
        filter: {
          src: "10.0.0.1",
          dst: "10.0.0.2",
          port: "443",
          bidirectional: true,
        },
      },
    );
    expect(withFilter.filter).toEqual({
      src: "10.0.0.1",
      dst: "10.0.0.2",
      port: "443",
      bidirectional: true,
    });

    const cleared = applyProtocolParamPatch(withFilter, "tcp_tls", "dc1", win, {
      filter: undefined,
    });
    expect(cleared.filter).toBeUndefined();
    const qs = protocolLink(cleared, 1800000000);
    expect(qs.has("p_src")).toBe(false);
    expect(qs.has("p_dst")).toBe(false);
    expect(qs.has("p_port")).toBe(false);
    expect(qs.has("p_bidir")).toBe(false);

    const sanitized = applyProtocolParamPatch(
      cleared,
      "interface_health",
      "dc1",
      win,
      {
        filter: {
          device: "leaf1.dc1",
          iface: "eth1/1|bad",
        },
      },
    );
    expect(sanitized.filter).toEqual({ device: "leaf1.dc1" });
  });
});
