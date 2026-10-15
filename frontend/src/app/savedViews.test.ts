import { describe, expect, it } from "vitest";
import { savedViewsFor } from "./savedViews";
import type { UrlState } from "./urlState";

const state: UrlState = {
  args: {
    service: "frontend",
    environment: "demo",
    cluster: "demo-cluster",
    namespace: "shop",
  },
  earliest: "-1h",
  latest: "now",
  mode: "demo",
  scenario: "aci",
  tab: "network",
  query: "",
};
const storage = () => {
  const values = new Map<string, string>();
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  } as unknown as Storage;
};
describe("saved views", () => {
  it("keeps users separate and validates stored state", () => {
    const target = storage();
    const alice = savedViewsFor("alice", target);
    alice.save("Demo", state);
    expect(savedViewsFor("alice", target).read()).toHaveLength(1);
    expect(savedViewsFor("bob", target).read()).toEqual([]);
    target.setItem(
      "splunk_adm:alice:views:v1",
      JSON.stringify([{ id: "bad", name: "bad", state: { mode: "live" } }]),
    );
    expect(alice.read()).toEqual([]);
  });
  it("does not create an anonymous bucket and reports storage failures", () => {
    const anonymous = savedViewsFor(undefined, storage());
    expect(anonymous.enabled).toBe(false);
    expect(() => anonymous.save("x", state)).toThrow("Sign in");
    const denied = savedViewsFor("alice", {
      setItem: () => {
        throw new Error("denied");
      },
      getItem: () => null,
    } as unknown as Storage);
    expect(() => denied.save("x", state)).toThrow("could not be stored");
  });
  it("rejects empty and oversized names", () => {
    const store = savedViewsFor("alice", storage());
    expect(() => store.save(" ", state)).toThrow();
    expect(() => store.save("x".repeat(81), state)).toThrow();
  });
});

it("reports unavailable storage when the browser denies the storage getter", () => {
  const descriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    "localStorage",
  );
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    get() {
      throw new Error("SecurityError");
    },
  });
  try {
    const store = savedViewsFor("alice");
    expect(store.read()).toEqual([]);
    expect(() => store.save("Demo", state)).toThrow(
      "Browser storage is unavailable.",
    );
    expect(() => store.remove("missing")).toThrow(
      "Browser storage is unavailable.",
    );
  } finally {
    if (descriptor)
      Object.defineProperty(globalThis, "localStorage", descriptor);
    else Reflect.deleteProperty(globalThis, "localStorage");
  }
});
