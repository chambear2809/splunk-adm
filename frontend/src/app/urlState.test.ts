import { describe, expect, it } from "vitest";
import {
  pageFromPath,
  pageURL,
  parseUrlState,
  recoverUrlState,
  stateParams,
} from "./urlState";
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
  it.each(["catalyst-aci", "meraki-nxos"])(
    "round trips the %s synthetic networking demo",
    (scenario) => {
      const state = parseUrlState(
        new URLSearchParams(`mode=demo&scenario=${scenario}`),
      );
      expect(parseUrlState(stateParams(state)).scenario).toBe(scenario);
    },
  );
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

it("leaves missing live scope empty instead of selecting the demo", () => {
  for (const params of [
    new URLSearchParams(),
    new URLSearchParams("mode=live"),
  ]) {
    expect(parseUrlState(params, true).args).toEqual({
      environment: "",
      cluster: "",
      namespace: "",
      service: "",
    });
  }
  expect(parseUrlState(new URLSearchParams()).args.service).toBe("frontend");
});

it("recovers invalid deep links while preserving valid scope and strict stored-state validation", () => {
  const { state, notice } = recoverUrlState(
    new URLSearchParams(
      "mode=live&service=api&namespace=bad%7Cdelete&earliest=20&latest=10&tab=no&q=%00",
    ),
    true,
  );
  expect(state.args.service).toBe("api");
  expect(state.args.namespace).toBe("");
  expect(state.earliest).toBe("-1h");
  expect(state.latest).toBe("now");
  expect(state.tab).toBe("network");
  expect(state.query).toBe("");
  expect(notice).toContain("link parameters");
  expect(() =>
    parseUrlState(new URLSearchParams("namespace=bad%7Cdelete")),
  ).toThrow();
  expect(recoverUrlState(new URLSearchParams()).notice).toBeUndefined();
});

it("retains query strings in browsers without URLSearchParams.size", () => {
  const descriptor = Object.getOwnPropertyDescriptor(
    URLSearchParams.prototype,
    "size",
  );
  Reflect.deleteProperty(URLSearchParams.prototype, "size");
  try {
    expect(
      pageURL(
        "map",
        new URLSearchParams("namespace=shop"),
        "/app/splunk_adm/map",
      ),
    ).toBe("/app/splunk_adm/map?namespace=shop");
    expect(pageURL("map", new URLSearchParams(), "/app/splunk_adm/map")).toBe(
      "/app/splunk_adm/map",
    );
  } finally {
    if (descriptor)
      Object.defineProperty(URLSearchParams.prototype, "size", descriptor);
  }
});
