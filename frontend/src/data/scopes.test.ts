import { describe, expect, it } from "vitest";
import { cascadeScope, parseScopes, scopeValues } from "./scopes";
const args = {
  environment: "prod",
  cluster: "a",
  namespace: "shop",
  service: "frontend",
};
const rows = parseScopes([
  { ...args, last_seen: "100", pods: "2" },
  { ...args, service: "checkout", last_seen: "90", pods: "1" },
  { ...args, environment: "other", cluster: "b", last_seen: "100", pods: "3" },
  { ...args, environment: "", last_seen: "100", pods: "1" },
]);
describe("scope options", () => {
  it("retains invalid dimensions for disabled explanations", () =>
    expect(scopeValues(rows, args, "environment")).toEqual([
      "",
      "other",
      "prod",
    ]));
  it("filters each dimension by its parents", () => {
    expect(scopeValues(rows, args, "cluster")).toEqual(["a"]);
    expect(scopeValues(rows, args, "service")).toEqual([
      "checkout",
      "frontend",
    ]);
  });
  it("clears every descendant when a parent changes", () =>
    expect(cascadeScope(args, "cluster", "b")).toEqual({
      ...args,
      cluster: "b",
      namespace: "",
      service: "",
    }));
  it("does not clear parents when changing service", () =>
    expect(cascadeScope(args, "service", "checkout")).toEqual({
      ...args,
      service: "checkout",
    }));
  it("rejects malformed rows instead of manufacturing options", () => {
    expect(() =>
      parseScopes([{ ...args, pods: "bad", last_seen: "100" }]),
    ).toThrow();
    expect(() =>
      parseScopes([
        { ...args, namespace: undefined, pods: "1", last_seen: "100" },
      ]),
    ).toThrow();
  });
});
