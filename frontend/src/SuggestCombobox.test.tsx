import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  EndpointCombobox,
  SuggestCombobox,
  comboboxKey,
  endpointStatus,
  filterSuggestOptions,
} from "./SuggestCombobox";

const closed = { open: false, active: -1 };

describe("comboboxKey", () => {
  it("opens and moves through options with the arrow keys, wrapping", () => {
    expect(comboboxKey(closed, "ArrowDown", 3)).toEqual({
      open: true,
      active: 0,
      preventDefault: true,
    });
    expect(comboboxKey({ open: true, active: 0 }, "ArrowDown", 3).active).toBe(
      1,
    );
    expect(comboboxKey({ open: true, active: 2 }, "ArrowDown", 3).active).toBe(
      0,
    );
    expect(comboboxKey(closed, "ArrowUp", 3).active).toBe(2);
    expect(comboboxKey({ open: true, active: 0 }, "ArrowUp", 3).active).toBe(2);
    expect(comboboxKey({ open: true, active: 2 }, "ArrowUp", 3).active).toBe(1);
    expect(comboboxKey(closed, "ArrowDown", 0)).toEqual({
      open: true,
      active: -1,
      preventDefault: true,
    });
  });

  it("selects the active option on Enter and otherwise lets the form submit", () => {
    expect(comboboxKey({ open: true, active: 1 }, "Enter", 3)).toEqual({
      open: false,
      active: -1,
      select: 1,
      preventDefault: true,
    });
    expect(comboboxKey({ open: true, active: -1 }, "Enter", 3)).toEqual({
      open: true,
      active: -1,
      preventDefault: false,
    });
    expect(comboboxKey(closed, "Enter", 3).preventDefault).toBe(false);
    expect(comboboxKey({ open: true, active: 5 }, "Enter", 3).select).toBe(
      undefined,
    );
  });

  it("closes on Escape and Tab without trapping focus", () => {
    expect(comboboxKey({ open: true, active: 1 }, "Escape", 3)).toEqual({
      open: false,
      active: -1,
      preventDefault: true,
    });
    expect(comboboxKey(closed, "Escape", 3).preventDefault).toBe(false);
    expect(comboboxKey({ open: true, active: 1 }, "Tab", 3)).toEqual({
      open: false,
      active: -1,
      preventDefault: false,
    });
    expect(comboboxKey({ open: true, active: 1 }, "a", 3)).toEqual({
      open: true,
      active: 1,
      preventDefault: false,
    });
  });
});

describe("SuggestCombobox", () => {
  it("renders an APG list-autocomplete combobox wired to its listbox", () => {
    const html = renderToStaticMarkup(
      <SuggestCombobox
        aria-label="Trace source"
        value=""
        onChange={() => undefined}
        options={[{ value: "10.0.0.5", label: "web-0" }]}
      />,
    );
    expect(html).toContain('role="combobox"');
    expect(html).toContain('aria-autocomplete="list"');
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain('autoComplete="off"');
    const controls = /aria-controls="([^"]+)"/.exec(html)?.[1];
    expect(controls).toBeTruthy();
    expect(html).toContain(`<ul id="${controls}" role="listbox"`);
    expect(html).toContain('aria-label="Suggestions"');
    expect(html.match(/Trace source/g)).toHaveLength(1);
    expect(html).not.toContain("<datalist");
  });

  it("filters page-local options by value or label, capped", () => {
    const options = [
      { value: "leaf-101", label: "10.1.0.1" },
      { value: "spine-1", label: "10.1.0.9" },
      { value: "fw-a" },
    ];
    expect(filterSuggestOptions(options, "10.1.0.9")).toEqual([options[1]]);
    expect(filterSuggestOptions(options, "LEAF")).toEqual([options[0]]);
    expect(filterSuggestOptions(options, "")).toHaveLength(3);
    expect(filterSuggestOptions(options, "fw-a")).toEqual([]);
    expect(
      filterSuggestOptions(
        Array.from({ length: 50 }, (_, i) => ({ value: `d${i}` })),
        "d",
      ),
    ).toHaveLength(20);
  });

  it("explains when scope suggestions start and when to keep typing", () => {
    const idle = { status: "idle" } as const;
    expect(endpointStatus(idle, "10.4", "fabric-a", false)).toBeUndefined();
    expect(endpointStatus(idle, "10.4", "", true)).toMatch(/routing scope/);
    expect(endpointStatus(idle, "10", "fabric-a", true)).toMatch(/3\+/);
    expect(
      endpointStatus({ status: "loading" }, "10.4", "fabric-a", true),
    ).toMatch(/Searching/);
    expect(
      endpointStatus(
        { status: "ready", suggestions: [], truncated: true },
        "10.4",
        "fabric-a",
        true,
      ),
    ).toMatch(/keep typing/);
    expect(
      endpointStatus(
        { status: "ready", suggestions: [], truncated: false },
        "10.4",
        "fabric-a",
        true,
      ),
    ).toMatch(/No identity matches/);
  });

  it("issues no search while rendering an endpoint field", () => {
    let searched = false;
    const client = {
      search: () => {
        searched = true;
        return Promise.reject(new Error("unexpected"));
      },
    };
    const html = renderToStaticMarkup(
      <EndpointCombobox
        aria-label="IP address"
        value="10.4.0.1"
        onChange={() => undefined}
        scope="fabric-a"
        client={client}
        live
        required
      />,
    );
    expect(searched).toBe(false);
    expect(html).toContain('role="combobox"');
    expect(html).toContain("required");
  });
});
