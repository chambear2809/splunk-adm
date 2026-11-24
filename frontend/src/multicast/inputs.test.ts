import { describe, expect, it } from "vitest";
import { pageFromPath, pageURL, SECTION_OF } from "../app/urlState";
import fixture from "../../../fixtures/multicast/profiles.json";
import { multicastLink, parseMulticastLink, parseProfiles } from "./inputs";

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
});
