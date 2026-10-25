#!/usr/bin/env node
/** Emit or normalize using the exact frontend AppDynamics evidence contract. */
import { createServer } from "vite";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
let input;
try {
  let text = "";
  for await (const chunk of process.stdin) {
    text += chunk;
    if (text.length > 16 * 1024 * 1024) throw new Error("input_limit");
  }
  input = JSON.parse(text);
} catch {
  process.stderr.write("Invalid AppDynamics qualification input.\n");
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
  const appdynamics = await vite.ssrLoadModule(
    "/frontend/src/data/appdynamicsEvidence.ts",
  );
  const supplemental = await vite.ssrLoadModule(
    "/frontend/src/data/supplementalEvidence.ts",
  );
  const window = appdynamics.appDynamicsSearchWindow(
    input.selection,
    input.config,
  );
  const result = {
    search: appdynamics.buildAppDynamicsSearch(input.config, input.selection),
    window,
    ...(Array.isArray(input.rows)
      ? (() => {
          const envelope = supplemental.parseSupplementalEnvelope(input.rows);
          return {
            envelope: {
              inputCount: envelope.inputCount,
              inputCapped: envelope.inputCapped,
              outputCapped: envelope.outputCapped,
              sourceScanCount: envelope.sourceScanCount,
              sourceScanCapped: envelope.sourceScanCapped,
              sourceScanInvalidCount: envelope.sourceScanInvalidCount,
            },
            normalized: appdynamics.normalizeAppDynamicsEvidence(
              envelope.rows,
              input.selection,
              input.config,
            ),
          };
        })()
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
