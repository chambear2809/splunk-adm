import { defineConfig } from "vite";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import {
  migrationAssetVersion,
  migrationHostModule,
} from "./vite.migration.shared";

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_MIGRATION_ASSET_VERSION__: JSON.stringify(migrationAssetVersion()),
  },
  plugins: [
    {
      name: "migration-optional-asset-budget",
      enforce: "post",
      generateBundle(_options, bundle) {
        const js = bundle["pages/migration.js"];
        const css = bundle["migration.css"];
        if (!js || js.type !== "chunk" || !css || css.type !== "asset")
          throw new Error("Migration planner assets were not generated.");
        if (gzipSync(js.code, { level: 9 }).length > 48 * 1024)
          throw new Error(
            "Migration planner optional asset exceeds its 48 KiB gzip budget.",
          );
        this.emitFile({
          type: "asset",
          fileName: "migration-manifest.json",
          source:
            JSON.stringify({
              schemaVersion: 1,
              assetVersion: migrationAssetVersion(),
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
      entry: resolve("frontend/src/migration/migration-entry.ts"),
      name: "ApplicationAtlasMigration",
      formats: ["iife"],
      fileName: () => "pages/migration.js",
      cssFileName: "migration",
    },
    rolldownOptions: {
      external: (id) => migrationHostModule(id) !== undefined,
      output: {
        intro: "var define;",
        globals: (id) => `__AtlasMigrationHost.${migrationHostModule(id)}`,
      },
    },
  },
});
