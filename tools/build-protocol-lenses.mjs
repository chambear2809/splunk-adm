import { build } from "vite";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { resolve } from "node:path";
import {
  IMPLEMENTED_PROTOCOL_LENSES,
  protocolLensAssetVersion,
  protocolLensExternalGlobal,
} from "./protocol-lenses.mjs";

const MAX_LENS_GZIP_BYTES = 64 * 1024;

for (const lens of IMPLEMENTED_PROTOCOL_LENSES) {
  const version = protocolLensAssetVersion(lens.id);
  const virtualId = `virtual:protocol-lens-entry:${lens.id}`;
  const resolvedVirtualId = `\0${virtualId}`;
  const indexPath = resolve(
    `frontend/src/protocols/lenses/${lens.id}/index.ts`,
  );

  await build({
    configFile: false,
    logLevel: "warn",
    define: {
      "process.env.NODE_ENV": JSON.stringify("production"),
      __ADM_SPLUNK_BUILD__: "true",
      __ADM_PROTOCOL_LENS_ASSET_VERSION__: JSON.stringify(version),
    },
    plugins: [
      {
        name: `protocol-lens-entry-${lens.id}`,
        enforce: "pre",
        resolveId(id) {
          if (id === virtualId || id.endsWith(virtualId)) {
            return resolvedVirtualId;
          }
          return null;
        },
        load(id) {
          if (id !== resolvedVirtualId) return null;
          return [
            `import { ${lens.pageExport} as LensPage, ${lens.summarizeExport} as summarize } from ${JSON.stringify(indexPath)};`,
            `const assetVersion = __ADM_PROTOCOL_LENS_ASSET_VERSION__;`,
            `const rt = globalThis;`,
            `const reg = rt.ApplicationAtlasProtocolLenses ?? (rt.ApplicationAtlasProtocolLenses = {});`,
            `reg[${JSON.stringify(lens.id)}] = Object.freeze({ assetVersion, LensPage, summarize });`,
            `export { assetVersion, LensPage, summarize };`,
          ].join("\n");
        },
      },
      {
        name: `protocol-lens-budget-${lens.id}`,
        enforce: "post",
        generateBundle(_options, bundle) {
          const js = bundle[`pages/protocol-${lens.id}.js`];
          if (!js || js.type !== "chunk") {
            throw new Error(
              `Protocol lens "${lens.id}" asset was not generated.`,
            );
          }
          const gzipBytes = gzipSync(js.code, { level: 9 }).length;
          if (gzipBytes > MAX_LENS_GZIP_BYTES) {
            throw new Error(
              `Protocol lens "${lens.id}" exceeds its 64 KiB gzip budget (${gzipBytes} bytes).`,
            );
          }
          this.emitFile({
            type: "asset",
            fileName: `protocol-${lens.id}-manifest.json`,
            source:
              JSON.stringify({
                schemaVersion: 1,
                lens: lens.id,
                assetVersion: version,
                javascriptSha256: createHash("sha256")
                  .update(js.code)
                  .digest("hex"),
              }) + "\n",
          });
          console.log(
            `pages/protocol-${lens.id}.js  ${(js.code.length / 1024).toFixed(2)} kB | gzip: ${(gzipBytes / 1024).toFixed(2)} kB`,
          );
        },
      },
    ],
    build: {
      outDir: "splunk_app/splunk_adm/appserver/static",
      emptyOutDir: false,
      target: "es2022",
      sourcemap: false,
      lib: {
        entry: virtualId,
        name: `ApplicationAtlasProtocolLens_${lens.id}`,
        formats: ["iife"],
        fileName: () => `pages/protocol-${lens.id}.js`,
      },
      rolldownOptions: {
        external: (id) => protocolLensExternalGlobal(id) !== undefined,
        output: {
          intro: "var define;",
          globals: (id) => protocolLensExternalGlobal(id) ?? id,
        },
      },
    },
  });
}
