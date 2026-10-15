import { afterEach, describe, expect, it, vi } from "vitest";
import { exportBounds, serializeMapSvg } from "./exportMap";

const escapeXml = (value: string) =>
  value.replace(/&/g, "&amp;").replace(/"/g, "&quot;");

function fakeSvg() {
  const cloneAttrs = new Map<string, string>();
  const root = {
    removeAttribute: vi.fn((name: string) => cloneAttrs.delete(name)),
  };
  const childAttrs = new Map<string, string>();
  const cloneChild = {
    setAttribute: vi.fn((name: string, value: string) =>
      childAttrs.set(name, value),
    ),
    getAttribute: vi.fn((name: string) => childAttrs.get(name) ?? null),
  };
  const clone = {
    setAttribute: vi.fn((name: string, value: string) =>
      cloneAttrs.set(name, value),
    ),
    getAttribute: vi.fn((name: string) => cloneAttrs.get(name) ?? null),
    querySelectorAll: vi.fn(() => [cloneChild]),
    querySelector: vi.fn(() => root),
    insertBefore: vi.fn(),
    firstChild: null,
  };
  const child = {};
  const source = {
    viewBox: { baseVal: { x: 0, y: 0, width: 100, height: 80 } },
    clientWidth: 100,
    clientHeight: 80,
    dataset: { exportWidth: "200", exportHeight: "100" },
    getBBox: vi.fn(() => ({ x: 0, y: 0, width: 100, height: 80 })),
    cloneNode: vi.fn(() => clone),
    querySelectorAll: vi.fn(() => [child]),
    closest: vi.fn(() => ({ kind: "page" })),
  } as unknown as SVGSVGElement;
  const serializer = {
    serializeToString: vi.fn(() => {
      const style = cloneAttrs.get("style") ?? "";
      return `<svg viewBox="${escapeXml(cloneAttrs.get("viewBox") ?? "")}" style="${escapeXml(style)}"/>`;
    }),
  };
  vi.stubGlobal("document", {
    createElementNS: vi.fn(() => ({ setAttribute: vi.fn() })),
  });
  vi.stubGlobal("XMLSerializer", function XMLSerializer() {
    return serializer;
  });
  vi.stubGlobal("getComputedStyle", (element: unknown) => ({
    getPropertyValue: (property: string) =>
      element === source
        ? property === "--adm-page"
          ? "#101820"
          : "red & blue"
        : property === "--adm-page"
          ? ""
          : "",
  }));
  return { source, clone, cloneAttrs, root, serializer };
}

afterEach(() => vi.unstubAllGlobals());

describe("map export", () => {
  it("expands the viewBox to include complete diagram bounds", () => {
    expect(
      exportBounds(
        { x: 0, y: 0, width: 100, height: 80 },
        { x: -10, y: 5, width: 130, height: 100 },
      ),
    ).toEqual({ x: -10, y: 0, width: 130, height: 105 });
  });
  it("keeps a valid viewBox when layout measurement is unavailable", () => {
    expect(exportBounds({ x: 2, y: 3, width: 50, height: 40 })).toEqual({
      x: 2,
      y: 3,
      width: 50,
      height: 40,
    });
    expect(exportBounds({ x: 0, y: 0, width: 0, height: 0 })).toEqual({
      x: 0,
      y: 0,
      width: 1,
      height: 1,
    });
  });

  it("serializes complete diagram bounds, theme background, styles, and unpans root", () => {
    const { source, clone, cloneAttrs, root, serializer } = fakeSvg();
    const result = serializeMapSvg(source);
    expect(result.width).toBe(232);
    expect(result.height).toBe(132);
    expect(cloneAttrs.get("viewBox")).toBe("-16 -16 232 132");
    expect(cloneAttrs.get("width")).toBe("232");
    expect(cloneAttrs.get("height")).toBe("132");
    expect(cloneAttrs.get("xmlns")).toBe("http://www.w3.org/2000/svg");
    expect(root.removeAttribute).toHaveBeenCalledWith("transform");
    expect(clone.insertBefore).toHaveBeenCalled();
    expect(serializer.serializeToString).toHaveBeenCalledWith(clone);
    expect(result.svg).toContain("&amp;");
    expect(result.svg).toContain("-16 -16 232 132");
  });

  it("uses measured content bounds when export dimensions are absent", () => {
    const fixture = fakeSvg();
    const source = fixture.source as unknown as {
      dataset: Record<string, string>;
      getBBox: () => unknown;
    };
    source.dataset = {};
    source.getBBox = vi.fn(() => ({
      x: -8,
      y: 4,
      width: 140,
      height: 90,
    })) as unknown as () => DOMRect;
    const result = serializeMapSvg(fixture.source);
    expect(result.width).toBe(140);
    expect(result.height).toBe(94);
    expect(fixture.cloneAttrs.get("viewBox")).toBe("-8 0 140 94");
    expect(fixture.root.removeAttribute).not.toHaveBeenCalled();
  });
});
