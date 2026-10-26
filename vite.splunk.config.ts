import { defineConfig, type Plugin } from "vite";
import { basename, isAbsolute, resolve } from "node:path";
import { gzipSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { thousandEyesAssetVersion } from "./vite.thousandeyes.shared";

// Mirrors tools/check_release.py's 670 KiB release gate.
const SPLUNK_BUNDLE_CEILING_GZIP = 670 * 1024;
type AtlasBundleAsset = {
  type: string;
  fileName: string;
  code?: string;
  modules?: Record<
    string,
    { renderedLength?: number; originalLength?: number }
  >;
};

/**
 * Keep bundle headroom visible without adding a runtime dependency or a
 * generated report to the packaged app. Rollup's rendered module lengths are
 * source-attribution data; gzip totals are computed from the final asset.
 */
function atlasBundleContributionReport(): Plugin {
  const moduleName = (id: string) => {
    const normalized = id.replaceAll("\\", "/");
    const root = process.cwd().replaceAll("\\", "/");
    const dependency = normalized.lastIndexOf("/node_modules/");
    if (dependency >= 0) return normalized.slice(dependency + 1);
    if (normalized.startsWith(`${root}/`))
      return normalized.slice(root.length + 1);
    if (normalized.startsWith("\0"))
      return `virtual:${basename(normalized.slice(1))}`;
    if (isAbsolute(normalized) || /^[A-Za-z]:\//.test(normalized))
      return `external:${basename(normalized)}`;
    return normalized;
  };
  return {
    name: "atlas-bundle-contribution-report",
    generateBundle(
      _options: unknown,
      bundle: Record<string, AtlasBundleAsset>,
    ) {
      const chunks = Object.values(bundle).filter(
        (asset) => asset.type === "chunk",
      );
      const reports = chunks.map((chunk) => {
        const source = typeof chunk.code === "string" ? chunk.code : "";
        const modules = Object.entries(chunk.modules ?? {})
          .map(([id, info]) => ({
            id: moduleName(id),
            bytes: info.renderedLength ?? info.originalLength ?? 0,
          }))
          .sort((a, b) => b.bytes - a.bytes);
        return {
          fileName: chunk.fileName,
          bytes: Buffer.byteLength(source),
          gzipBytes: gzipSync(source, { level: 9 }).byteLength,
          modules,
        };
      });
      const gzipBytes = reports.reduce(
        (sum, report) => sum + report.gzipBytes,
        0,
      );
      const eagerThousandEyes = reports
        .flatMap((entry) => entry.modules)
        .filter(
          (module) =>
            module.bytes > 0 &&
            /\/(ThousandEyesEvidencePanel|thousandEyesAdapters|thousandEyesEvidence|thousandEyesAttribution)\.tsx?$/.test(
              module.id,
            ),
        );
      if (eagerThousandEyes.length)
        throw new Error(
          "ThousandEyes investigation code must remain outside the initial Atlas bundle.",
        );
      const report = {
        generatedBy: "atlas-bundle-contribution-report",
        ceilingGzipBytes: SPLUNK_BUNDLE_CEILING_GZIP,
        gzipBytes,
        headroomGzipBytes: SPLUNK_BUNDLE_CEILING_GZIP - gzipBytes,
        chunks: reports,
      };
      mkdirSync(resolve("dist"), { recursive: true });
      writeFileSync(
        resolve("dist/atlas-bundle-report.json"),
        `${JSON.stringify(report, null, 2)}\n`,
        "utf8",
      );
    },
  };
}

export default defineConfig({
  plugins: [atlasBundleContributionReport()],
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __ADM_SPLUNK_BUILD__: "true",
    __ADM_TE_ASSET_VERSION__: JSON.stringify(thousandEyesAssetVersion()),
  },
  build: {
    outDir: "splunk_app/splunk_adm/appserver/static",
    emptyOutDir: true,
    lib: {
      entry: resolve("frontend/src/main.tsx"),
      name: "ApplicationAtlas",
      formats: ["iife"],
      fileName: () => "pages/atlas.js",
      cssFileName: "adm",
    },
    sourcemap: false,
    target: "es2022",
    rolldownOptions: {
      // Simple XML pages expose RequireJS's global define. Shadow it inside the
      // IIFE so UMD dependencies (lodash) take their CommonJS path instead of
      // emitting an anonymous define() and overwriting the page's window._.
      output: { intro: "var define;" },
    },
  },
});
