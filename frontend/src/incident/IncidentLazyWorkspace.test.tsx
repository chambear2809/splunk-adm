import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { demoGraph } from "../provider";
import {
  IncidentLazyWorkspace,
  loadIncidentWorkspace,
} from "./IncidentLazyWorkspace";
import { IncidentWorkspace } from "./IncidentWorkspace";

describe("IncidentLazyWorkspace", () => {
  it("announces loading before the workspace is available", () => {
    const html = renderToStaticMarkup(
      <IncidentLazyWorkspace
        incident={demoGraph()}
        loadWindow={() => Promise.reject(new Error("unused"))}
      />,
    );
    expect(html).toBe('<p role="status">Opening investigation…</p>');
  });

  it("imports the workspace module directly outside the Splunk build", async () => {
    await expect(loadIncidentWorkspace()).resolves.toBe(IncidentWorkspace);
  });
});
