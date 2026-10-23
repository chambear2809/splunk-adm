#!/usr/bin/env node
/** Emit or normalize using the exact frontend AWS VPC Flow Logs contract. */
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
  const cloudFlow = await vite.ssrLoadModule(
    "/frontend/src/data/cloudFlowEvidence.ts",
  );
  const result = {
    search: cloudFlow.buildCloudFlowSearch(input.config, input.selection),
    window: cloudFlow.cloudFlowSearchWindow(input.selection),
    ...(Array.isArray(input.rows)
      ? {
          normalized: cloudFlow.normalizeCloudFlowEvidence(
            input.rows,
            input.selection,
            input.config,
          ),
        }
      : {}),
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(
    `Builder rejected qualification input: ${error instanceof Error ? error.message : "unknown error"}\n`,
  );
  process.exitCode = 2;
} finally {
  await vite.close();
}
