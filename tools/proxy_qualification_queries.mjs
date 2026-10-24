#!/usr/bin/env node
/** Emit the exact frontend-generated Envoy SPL used by disposable-lab qualification. */
import { createServer } from "vite";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
let input;
try {
  input = JSON.parse(
    await new Promise((resolveInput, reject) => {
      let text = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => {
        text += chunk;
      });
      process.stdin.on("end", () => resolveInput(text));
      process.stdin.on("error", reject);
    }),
  );
} catch {
  process.stderr.write("Invalid qualification input.\n");
  process.exit(2);
}

const vite = await createServer({
  configFile: false,
  root,
  define: { __ADM_SPLUNK_BUILD__: "false" },
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true },
});
try {
  const proxy = await vite.ssrLoadModule("/frontend/src/data/proxyEvidence.ts");
  const searches = input.selections.map((selection) => {
    const window = proxy.proxySearchWindow(selection, input.config);
    return {
      selectionId: selection.selectionId,
      search: proxy.buildProxySearch(input.config, selection),
      earliest: window.start,
      latest: window.end,
    };
  });
  process.stdout.write(`${JSON.stringify({ searches })}\n`);
} catch (error) {
  process.stderr.write(
    `Builder rejected qualification input: ${error instanceof Error ? error.message : "unknown error"}\n`,
  );
  process.exitCode = 2;
} finally {
  await vite.close();
}
