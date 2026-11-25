import { describe, expect, it } from "vitest";
import { pageFromPath, pageURL, SECTION_OF } from "../app/urlState";
import fixture from "../../../fixtures/multicast/profiles.json";
import {
  multicastLink,
  parseMulticastLink,
  parseMulticastView,
  parseProfile,
  parseProfiles,
  parseScopeLink,
  scopeLink,
} from "./inputs";

const request = {
  version: 1,
  scope: "lab:media",
  group: "239.1.2.3",
  sender: "192.0.2.20",
  earliest: 1795283857,
  latest: 1795284157,
} as const;

describe("multicast investigation inputs", () => {
  it("round trips scoped absolute inputs through the standalone localized route", () => {
    const link = pageURL(
      "multicast",
      multicastLink(request),
      "/en-US/app/splunk_adm/map",
    );
    const url = new URL(link, "https://example.test");
    expect(pageFromPath(url.pathname)).toBe("multicast");
    expect(SECTION_OF.multicast).toBe("multicast");
    expect(parseMulticastLink(url.searchParams)).toEqual(request);
    expect(
      parseMulticastLink(new URLSearchParams("namespace=shop")),
    ).toBeUndefined();
  });

  it.each([
    ["mc_v", "2"],
    ["mc_scope", "unmapped:lab"],
    ["mc_scope", 'lab" | delete'],
    ["mc_scope", "lab\n"],
    ["mc_group", "239.1.2.999"],
    ["mc_group", "239.01.2.3"],
    ["mc_group", "2001:db8::20"],
    ["mc_sender", "0.0.0.0"],
    ["mc_sender", "239.1.2.4"],
    ["mc_sender", "192.0.2.20\n"],
    ["mc_earliest", "-1h"],
    ["mc_latest", "1795290000"],
    ["mc_latest", "1795283856"],
  ])("rejects invalid %s=%s", (key, value) => {
    const params = multicastLink(request);
    params.set(key, value);
    expect(() => parseMulticastLink(params)).toThrow();
  });

  it("rejects repeated or unexpected multicast selectors", () => {
    const repeated = multicastLink(request);
    repeated.append("mc_group", request.group);
    expect(() => parseMulticastLink(repeated)).toThrow();
    const unknown = multicastLink(request);
    unknown.set("mc_index", "other");
    expect(() => parseMulticastLink(unknown)).toThrow();
  });

  it("allows disabled and independent source profiles", () => {
    expect(parseProfiles(undefined)).toEqual([]);
    expect(parseProfiles({ version: 1, profiles: [] })).toEqual([]);
    expect(parseProfiles(fixture)).toHaveLength(2);
  });

  it("accepts Stream's absolute PCAP capture selector and rejects SPL syntax", () => {
    const igmp = fixture.profiles[0];
    const captureInterface = "/opt/splunk/capture/igmp.pcap";
    expect(parseProfile({ ...igmp, captureInterface })).toMatchObject({
      captureInterface,
    });
    expect(() =>
      parseProfile({ ...igmp, captureInterface: '/opt/capture" OR true()' }),
    ).toThrow(/Invalid IGMP capture/);
  });

  it("limits the Stream ingress counter fields to attested ingress profiles", () => {
    const flow = { ...fixture.profiles[1], direction: "ingress" };
    expect(
      parseProfile({ ...flow, counterFields: "stream-ingress" }),
    ).toMatchObject({
      counterFields: "stream-ingress",
    });
    expect(() =>
      parseProfile({
        ...flow,
        direction: "egress",
        counterFields: "stream-ingress",
      }),
    ).toThrow(/counter profile/);
    expect(() => parseProfile({ ...flow, counterFields: "arbitrary" })).toThrow(
      /counter profile/,
    );
  });

  it("rejects overlapping mappings for the same capture or exporter domain", () => {
    const [igmp, flow] = fixture.profiles;
    for (const first of [igmp, flow])
      expect(() =>
        parseProfiles({
          version: 1,
          profiles: [
            first,
            { ...first, id: "other", scope: "other", index: "other" },
          ],
        }),
      ).toThrow(/ambiguous/);
    expect(
      parseProfiles({
        version: 1,
        profiles: [
          igmp,
          { ...igmp, id: "other", scope: "other", captureInterface: "eth1" },
        ],
      }),
    ).toHaveLength(2);
  });

  it("rejects an endpoint reporter also identified as a proxy", () => {
    expect(() =>
      parseProfiles({
        version: 1,
        profiles: [
          { ...fixture.profiles[0], endpointReporters: ["192.0.2.1"] },
        ],
      }),
    ).toThrow();
  });

  it("round-trips scope link and view", () => {
    const window = {
      version: 1,
      scope: request.scope,
      earliest: request.earliest,
      latest: request.latest,
    } as const;
    for (const view of ["overview", "matrix", "topology"] as const) {
      const params = scopeLink(window, view);
      expect(params.get("mc_view")).toBe(view);
      expect(params.has("mc_group")).toBe(false);
      expect(parseScopeLink(params)).toEqual(window);
      expect(parseMulticastView(params)).toBe(view);
    }
    expect(parseMulticastView(new URLSearchParams())).toBe("overview");
    expect(
      parseScopeLink(new URLSearchParams("namespace=shop")),
    ).toBeUndefined();
    const group = multicastLink(request);
    group.set("mc_view", "topology");
    expect(parseMulticastLink(group)).toEqual(request);
    expect(parseScopeLink(group)).toEqual(window);
  });

  it("rejects unknown mc_view", () => {
    const params = multicastLink(request);
    params.set("mc_view", "graph");
    expect(() => parseMulticastView(params)).toThrow(
      "The multicast link contains unsupported parameters.",
    );
    expect(() => parseMulticastLink(params)).toThrow(
      "The multicast link contains unsupported parameters.",
    );
    expect(() => parseScopeLink(params)).toThrow(
      "The multicast link contains unsupported parameters.",
    );
    const repeated = multicastLink(request);
    repeated.append("mc_view", "matrix");
    repeated.append("mc_view", "matrix");
    expect(() => parseMulticastView(repeated)).toThrow();
  });

  it("group link still requires mc_group", () => {
    const params = scopeLink(
      {
        version: 1,
        scope: request.scope,
        earliest: request.earliest,
        latest: request.latest,
      },
      "overview",
    );
    expect(() => parseMulticastLink(params)).toThrow(/multicast group/);
  });
});
