import { readFileSync } from "node:fs";
import { defineConfig } from "vite";
const captures = new Set([
  "demo-catalog.json",
  "demo-find.json",
  "demo-networking-catalog.json",
  "demo-networking-find.json",
  "demo-networking-scopes.json",
]);
export default defineConfig({
  root: "frontend",
  define: { __ADM_SPLUNK_BUILD__: "false" },
  base: "./",
  plugins: [
    {
      name: "atlas-catalog-demo-captures",
      configureServer(server) {
        server.middlewares.use((request, response, next) => {
          const path = new URL(request.url ?? "/", "http://localhost").pathname;
          const name = path.replace(/^\/fixtures\//, "");
          if (!path.startsWith("/fixtures/") || !captures.has(name))
            return next();
          try {
            response.setHeader("Content-Type", "application/json");
            response.end(
              readFileSync(new URL(`./fixtures/${name}`, import.meta.url)),
            );
          } catch {
            response.statusCode = 404;
            response.end("Capture unavailable");
          }
        });
      },
      generateBundle() {
        for (const name of captures)
          this.emitFile({
            type: "asset",
            fileName: `fixtures/${name}`,
            source: readFileSync(
              new URL(`./fixtures/${name}`, import.meta.url),
            ),
          });
      },
    },
  ],
  build: { outDir: "../dist/preview", emptyOutDir: true },
});
