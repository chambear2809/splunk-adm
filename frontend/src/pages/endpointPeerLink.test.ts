import { describe, expect, it } from "vitest";
import { peerEndpointUrl } from "./endpointPeerLink";

const path = "/en-US/app/splunk_adm/endpoints";
const selection = { scope: "dc1", start: 1000, end: 2000 };

describe("peerEndpointUrl", () => {
  it("builds the peer URL from the validated selection", () => {
    const url = peerEndpointUrl(selection, "10.0.0.2", path);
    const params = new URLSearchParams(url.split("?")[1]);
    expect(url.startsWith(`${path}?`)).toBe(true);
    expect(params.get("endpoint_ip")).toBe("10.0.0.2");
    expect(params.get("endpoint_scope")).toBe("dc1");
    expect(params.get("endpoint_start")).toBe("1000");
    expect(params.get("endpoint_end")).toBe("2000");
  });

  it("does not depend on any live form state", () => {
    expect(() => peerEndpointUrl(selection, "10.0.0.3", path)).not.toThrow();
  });
});
