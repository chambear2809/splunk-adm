import { readFileSync } from "node:fs";
import { defineConfig } from "vite";

export default defineConfig({
  // The preview routes are served by middleware, and the lifecycle harness has
  // its own React entry. Scan them all before serving concurrent browser tests
  // so a later route cannot invalidate dependency URLs or reload active pages.
  optimizeDeps: {
    entries: [
      "frontend/src/main.tsx",
      "tests/browser/harness.tsx",
      "tests/browser/map-lifecycle-harness.tsx",
      "tests/browser/dns-evidence-harness.tsx",
      "tests/browser/o11y-health-harness.tsx",
      "tests/browser/map-service-health-harness.tsx",
    ],
  },
  plugins: [
    {
      name: "atlas-preview-host",
      configureServer(server) {
        const html = readFileSync(
          new URL("../../frontend/index.html", import.meta.url),
          "utf8",
        ).replace("/src/main.tsx", "/frontend/src/main.tsx");
        server.middlewares.use((request, response, next) => {
          const path = new URL(request.url ?? "/", "http://local").pathname;
          if (
            ![
              "/applications",
              "/endpoints",
              "/map",
              "/data_health",
              "/setup",
              "/help",
            ].includes(path)
          )
            return next();
          response.setHeader("Content-Type", "text/html");
          void server
            .transformIndexHtml(request.url ?? path, html)
            .then((transformed) => response.end(transformed))
            .catch(next);
        });
      },
    },
  ],
  root: ".",
  cacheDir: "node_modules/.vite-browser",
  define: { __ADM_SPLUNK_BUILD__: "false" },
  resolve: { preserveSymlinks: true },
});
