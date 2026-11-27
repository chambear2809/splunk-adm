import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { adminAssetVersion, adminHostModule } from "./vite.admin.shared";

const MAX_GZIP_BYTES = 48 * 1024;

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_ADMIN_ASSET_VERSION__: JSON.stringify(adminAssetVersion()),
  },
  plugins: [
    {
      name: "admin-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        const js = bundle["pages/admin.js"];
        const css = bundle["admin.css"];
        if (!js || js.type !== "chunk" || !css || css.type !== "asset")
          throw new Error("Admin page assets were not generated.");
        if (gzipSync(js.code, { level: 9 }).length > MAX_GZIP_BYTES)
          throw new Error(
            "Admin page optional asset exceeds its 48 KiB gzip budget.",
          );
        this.emitFile({
          type: "asset",
          fileName: "admin-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: adminAssetVersion(),
              javascriptSha256: createHash("sha256")
                .update(js.code)
                .digest("hex"),
              cssSha256: createHash("sha256").update(css.source).digest("hex"),
            }) + "\n",
        });
      },
    },
  ],
  build: {
    outDir: "splunk_app/splunk_adm/appserver/static",
    emptyOutDir: false,
    target: "es2022",
    sourcemap: false,
    lib: {
      entry: resolve("frontend/src/admin/admin-entry.tsx"),
      name: "ApplicationAtlasAdmin",
      formats: ["iife"],
      fileName: () => "pages/admin.js",
      cssFileName: "admin",
    },
    rolldownOptions: {
      external: (id) => adminHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasAdminHost.${adminHostModule(id)}`,
      },
    },
  },
});
