import { readFileSync } from "node:fs";
import { defineConfig } from "vite";

export default defineConfig({
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
