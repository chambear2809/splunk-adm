#!/usr/bin/env node
/** Emit or normalize using Atlas's exact ThousandEyes evidence contract. */
import { resolve } from "node:path";
import { createServer } from "vite";

const MAX_INPUT_BYTES = 1024 * 1024;
const root = resolve(import.meta.dirname, "..");
let payload;
try {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
    if (Buffer.byteLength(input, "utf8") > MAX_INPUT_BYTES)
      throw new Error("input_limit");
  }
  payload = JSON.parse(input);
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    !["build", "normalize"].includes(payload.mode) ||
    !payload.configuration ||
    typeof payload.configuration !== "object" ||
    Array.isArray(payload.configuration) ||
    !payload.selection ||
    typeof payload.selection !== "object" ||
    Array.isArray(payload.selection) ||
    (payload.mode === "normalize" && !Array.isArray(payload.rows))
  )
    throw new Error("invalid_request");
} catch {
  process.stderr.write("Invalid ThousandEyes qualification input.\n");
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
  const evidence = await vite.ssrLoadModule(
    "/frontend/src/data/thousandEyesEvidence.ts",
  );
  const result =
    payload.mode === "build"
      ? {
          search: evidence.buildThousandEyesSearch(
            payload.configuration,
            payload.selection,
          ),
        }
      : evidence.normalizeThousandEyesEvidence(
          payload.rows,
          payload.selection,
          payload.configuration,
        );
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch {
  process.stderr.write("ThousandEyes qualification request was rejected.\n");
  process.exitCode = 2;
} finally {
  await vite.close();
}
