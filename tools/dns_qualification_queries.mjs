#!/usr/bin/env node
/** Emit the exact frontend-generated SPL used by disposable-lab qualification. */
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
  const dns = await vite.ssrLoadModule("/frontend/src/data/dnsEvidence.ts");
  const endpoint = await vite.ssrLoadModule(
    "/frontend/src/data/endpointInvestigation.ts",
  );
  if (input.endpointResults) {
    const { selection, configuration, conversation, observation } =
      input.endpointResults;
    const result = await endpoint.runEndpointInvestigation(
      {
        async search({ search }) {
          const indexes = configuration.summaryIndexes
            .map((index) => `index=${index}`)
            .join(" OR ");
          if (search === endpoint.buildEndpointSearch(selection, indexes))
            return { rows: conversation, warnings: [], errors: [] };
          if (
            search ===
            endpoint.buildEndpointObservationSearch(selection, indexes)
          )
            return { rows: observation, warnings: [], errors: [] };
          throw new Error("Unexpected Endpoint qualification search.");
        },
      },
      { read: async () => configuration },
      selection,
      new AbortController().signal,
    );
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else {
    const selection = input.selection;
    const result = {
      dns: input.dns.map((config) => ({
        source: config.source,
        search: dns.buildDnsSearch(config, selection),
      })),
      endpoint: input.endpoint.map(
        ({ selection: endpointSelection, indexes }) => ({
          contract: endpointSelection.trafficContract,
          conversation: endpoint.buildEndpointSearch(
            endpointSelection,
            indexes.map((index) => `index=${index}`).join(" OR "),
          ),
          observation:
            endpointSelection.trafficContract === 2
              ? endpoint.buildEndpointObservationSearch(
                  endpointSelection,
                  indexes.map((index) => `index=${index}`).join(" OR "),
                )
              : null,
        }),
      ),
    };
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }
} catch (error) {
  process.stderr.write(
    `Builder rejected qualification input: ${error instanceof Error ? error.message : "unknown error"}\n`,
  );
  process.exitCode = 2;
} finally {
  await vite.close();
}
