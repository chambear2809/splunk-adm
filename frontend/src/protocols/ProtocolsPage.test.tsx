import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../data/searchClient";
import { ProtocolsPage } from "./ProtocolsPage";
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
});
