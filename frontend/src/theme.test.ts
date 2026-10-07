import { describe, expect, it } from "vitest";
import { detectTheme } from "./theme";

const el = (attrs: Record<string, string> = {}, classes: string[] = []) =>
  ({
    getAttribute: (name: string) => attrs[name] ?? null,
    classList: classes,
  }) as unknown as HTMLElement;
const env = (
  opts: {
    splunk?: string;
    html?: HTMLElement;
    body?: HTMLElement;
    osDark?: boolean;
  } = {},
) => ({
  win: {
    __splunk_page_theme__: opts.splunk,
    matchMedia: ((q: string) => ({
      matches: !!opts.osDark && q.includes("dark"),
    })) as unknown as Window["matchMedia"],
  },
  doc: { documentElement: opts.html ?? el(), body: opts.body ?? el() },
});

describe("detectTheme", () => {
  it("uses Splunk's page theme first", () => {
    expect(detectTheme(env({ splunk: "dark" }), true)).toBe("dark");
    expect(detectTheme(env({ splunk: "light", osDark: true }), false)).toBe(
      "light",
    );
  });
  it("reads explicit theme markers on html or body", () => {
    expect(detectTheme(env({ html: el({ "data-theme": "dark" }) }), true)).toBe(
      "dark",
    );
    expect(
      detectTheme(env({ body: el({}, ["dashboard-theme-dark"]) }), true),
    ).toBe("dark");
  });
  it("ignores the OS preference inside Splunk but honours it standalone", () => {
    expect(detectTheme(env({ osDark: true }), true)).toBe("light");
    expect(detectTheme(env({ osDark: true }), false)).toBe("dark");
    expect(detectTheme(env(), false)).toBe("light");
  });
  it("ignores unknown theme values", () => {
    expect(detectTheme(env({ splunk: "enterprise" }), true)).toBe("light");
  });
});
