import { describe, expect, it, vi } from "vitest";
import { mapPreferences, prefsFor } from "./prefs";

describe("map preferences", () => {
  it("validates stored defaults", () => {
    expect(mapPreferences({})).toEqual({
      persona: "network",
      view: "network",
      mergeFrontends: true,
    });
    expect(
      mapPreferences({ persona: "application", mergeFrontends: false }).view,
    ).toBe("services");
    expect(
      mapPreferences({ persona: "admin", mergeFrontends: "false" }),
    ).toEqual(mapPreferences({}));
  });
  it("keeps users separate and tolerates denied or corrupt storage", () => {
    const values = new Map<string, string>();
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
    } as unknown as Storage;
    prefsFor("alice", storage).write({ persona: "application" });
    expect(prefsFor("alice", storage).read()).toEqual({
      persona: "application",
    });
    expect(prefsFor("bob", storage).read()).toEqual({});
    values.forEach((_, key) => values.set(key, "not json"));
    expect(prefsFor("alice", storage).read()).toEqual({});
    const denied = {
      getItem: vi.fn(() => {
        throw new Error("denied");
      }),
      setItem: vi.fn(() => {
        throw new Error("denied");
      }),
    } as unknown as Storage;
    expect(prefsFor("alice", denied).read()).toEqual({});
    expect(() => prefsFor("alice", denied).write({})).not.toThrow();
  });
});
