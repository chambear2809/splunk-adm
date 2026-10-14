import { describe, expect, it } from "vitest";
import { pageFromPath, pageURL, parseUrlState, stateParams } from "./urlState";
describe("Atlas deep links", () => {
  it("round trips the complete map state", () => {
    const state = parseUrlState(
      new URLSearchParams(
        "service=payments&environment=prod&cluster=cluster-a&namespace=shop&earliest=1770000000&latest=1770003600&mode=live&tab=services&q=checkout",
      ),
    );
    expect(parseUrlState(stateParams(state))).toEqual(state);
  });
  it.each([
    "service=foo%22%29%7Cdelete",
    "namespace=bad%0Aname",
    "earliest=-1h%7Cdelete",
    "earliest=-xx%2B1h",
    "earliest=-%7C%7C%2B1h",
    "latest=now%60",
    "earliest=20&latest=10",
    "mode=other",
    "tab=other",
    "q=%00",
    "scenario=other",
  ])("rejects unsafe or invalid state %s", (query) => {
    expect(() => parseUrlState(new URLSearchParams(query))).toThrow();
  });
  it("retains safe relative bounds until the signed-in timezone is known", () => {
    const state = parseUrlState(
      new URLSearchParams("earliest=1791943200&latest=@d&mode=live"),
    );
    expect(parseUrlState(stateParams(state))).toEqual(state);
  });
  it("defaults to live inside Splunk and demo outside", () => {
    expect(parseUrlState(new URLSearchParams(), true).mode).toBe("live");
    expect(parseUrlState(new URLSearchParams()).mode).toBe("demo");
  });
  it("allows only implemented views including legacy redirect", () => {
    expect(pageFromPath("/en-US/app/splunk_adm/applications")).toBe(
      "applications",
    );
    expect(pageFromPath("/splunk/en-US/app/splunk_adm/map")).toBe("map");
    expect(pageFromPath("/app/splunk_adm/dependency_map")).toBe(
      "dependency_map",
    );
    expect(() => pageFromPath("/en-US/app/other/map")).toThrow();
    expect(() => pageFromPath("/en-US/app/splunk_adm/unknown")).toThrow();
  });
  it("preserves localized host paths and safely encodes query strings", () => {
    expect(
      pageURL(
        "map",
        new URLSearchParams({ q: "a&b" }),
        "/en-US/app/splunk_adm/applications",
      ),
    ).toBe("/en-US/app/splunk_adm/map?q=a%26b");
  });
});
