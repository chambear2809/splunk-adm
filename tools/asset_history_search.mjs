#!/usr/bin/env node
/** Invoke the frontend's validated asset-history SPL builder for lab checks. */

import { createServer } from "vite";

const MAX_INPUT = 1024 * 1024;
let input = "";
for await (const chunk of process.stdin) {
  input += chunk;
  if (Buffer.byteLength(input, "utf8") > MAX_INPUT) {
    process.stderr.write("asset-history search request exceeds 1 MiB\n");
    process.exitCode = 2;
    process.exit();
  }
}

let payload;
try {
  payload = JSON.parse(input);
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("request must be an object");
} catch (error) {
  process.stderr.write(`invalid request: ${error.message}\n`);
  process.exitCode = 2;
  process.exit();
}

const server = await createServer({
  configFile: new URL("../vite.config.ts", import.meta.url).pathname,
  server: { middlewareMode: true },
  appType: "custom",
  logLevel: "silent",
});
try {
  const module = await server.ssrLoadModule("/src/data/inventoryEvidence.ts");
  if (payload.mode === "normalize") {
    process.stdout.write(
      JSON.stringify(
        module.normalizeAssetHistoryEvidence(
          payload.rows,
          payload.selection,
          payload.config,
        ),
      ),
    );
  } else {
    process.stdout.write(
      module.buildAssetHistorySearch(payload.config, payload.selection),
    );
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
} finally {
  await server.close();
}
