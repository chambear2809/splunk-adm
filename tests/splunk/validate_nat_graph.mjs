import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "../..");
const require = createRequire(resolve(repositoryRoot, "package.json"));
const vitePath = require.resolve("vite");
const { createServer } = await import(pathToFileURL(vitePath).href);
const { cases } = JSON.parse(readFileSync(0, "utf8"));
const server = await createServer({
  configFile: resolve(repositoryRoot, "vite.config.ts"),
  server: { middlewareMode: true },
  appType: "custom",
});

try {
  const { rowsToGraph } = await server.ssrLoadModule("/src/rows.ts");
  const graphs = cases.map(({ rows, args }) => rowsToGraph(rows, args));
  process.stdout.write(JSON.stringify(graphs));
} finally {
  await server.close();
}
