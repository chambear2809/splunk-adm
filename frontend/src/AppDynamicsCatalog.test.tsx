import { expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ControllerPath } from "./AppDynamicsCatalog";

it("makes missing device evidence explicit without claiming traversal", () => {
  const html = renderToStaticMarkup(<ControllerPath />);
  expect(html).toContain("Unknown");
  expect(html).toContain("ACI evidence is quarantined");
  expect(html).not.toContain("observed traversal");
});
