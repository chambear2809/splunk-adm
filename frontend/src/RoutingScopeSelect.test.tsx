import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { RoutingScopeSelect } from "./RoutingScopeSelect";
import {
  SCOPE_FILTER_THRESHOLD,
  type RoutingScopeState,
} from "./data/routingScopes";

const render = (
  state: RoutingScopeState,
  value = "",
  props: Partial<Parameters<typeof RoutingScopeSelect>[0]> = {},
) =>
  renderToStaticMarkup(
    <RoutingScopeSelect
      showLabel
      value={value}
      onChange={() => {}}
      state={state}
      onRetry={() => {}}
      {...props}
    />,
  );
const ready = (...scopes: string[]): RoutingScopeState => ({
  status: "ready",
  options: scopes.map((scope) => ({ scope, observers: 1, verified: false })),
});

describe("RoutingScopeSelect", () => {
  it("shows a labelled, busy select while scopes load", () => {
    const html = render({ status: "loading" });
    expect(html).toMatch(/<label for="[^"]+-scope">Routing scope<\/label>/);
    expect(html).toContain('aria-busy="true"');
    expect(html).toContain("Loading scopes…");
    expect(html).toContain("disabled");
  });

  it("keeps a linked scope selectable while the list loads", () => {
    const html = render({ status: "loading" }, "fabric-a");
    expect(html).not.toContain("disabled");
    expect(html).toContain('<option value="fabric-a" selected="">fabric-a');
  });

  it("lists loaded scopes in a native select", () => {
    const html = render(ready("dmz", "fabric-a"), "dmz");
    expect(html).toContain("Choose a routing scope");
    expect(html).toContain('<option value="dmz" selected="">dmz</option>');
    expect(html).toContain('<option value="fabric-a">fabric-a</option>');
    expect(html).not.toContain("not in mapped list");
  });

  it("explains the empty state and points administrators to Setup", () => {
    const html = render(ready());
    expect(html).toContain("No mapped routing scopes yet");
    expect(html).toContain("Map observers in Setup");
    expect(html).toMatch(/href="[^"]*setup/);
  });

  it("marks a deep-linked scope that is not mapped instead of dropping it", () => {
    const html = render(ready("fabric-a"), "old-scope");
    expect(html).toContain(
      '<option value="old-scope" selected="">old-scope (not in mapped list)</option>',
    );
    expect(html).toContain("not in the mapped scope list");
  });

  it("falls back to manual entry with a retry when the list fails", () => {
    const html = render({ status: "error", error: "HTTP 503" }, "fabric-a");
    expect(html).toContain('<input id="');
    expect(html).toContain('value="fabric-a"');
    expect(html).toContain("Routing scope list unavailable");
    expect(html).toContain("Retry scope list");
  });

  it("adds a local filter only when there are many scopes", () => {
    const few = render(ready("a", "b"));
    expect(few).not.toContain('type="search"');
    const many = render(
      ready(
        ...Array.from(
          { length: SCOPE_FILTER_THRESHOLD + 1 },
          (_, i) => `scope-${i}`,
        ),
      ),
    );
    expect(many).toContain('type="search"');
    expect(many).toContain(`Filter ${SCOPE_FILTER_THRESHOLD + 1} scopes`);
  });

  it("renders one bare control in compact toolbars", () => {
    const html = render(ready("a", "b"), "", { compact: true });
    expect(html.startsWith("<select")).toBe(true);
    expect(html).not.toContain("<label");
    const text = render({ status: "idle" }, "", { compact: true });
    expect(text).toMatch(/^<input[^>]*placeholder="Routing scope"/);
  });
});
