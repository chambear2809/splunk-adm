import {
  access,
  chmod,
  cp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import {
  assertPackableTree,
  copyPackableFile,
} from "./package-tree-safety.mjs";

const root = new URL("../", import.meta.url);
process.chdir(fileURLToPath(root));
const app = "splunk_app/splunk_adm";
// Deployment-local state and development artifacts never ship; check_release.py
// enforces the same set on the finished archive.
const excludedFromStage = (source) => {
  const path = source.replaceAll("\\", "/");
  return (
    /(^|\/)(\.DS_Store|\._.*|docs|local|local\.meta|\.git|node_modules|__pycache__|.*\.py[co])$/i.test(
      path,
    ) || /^\/appserver\/static\/demo(?:\/|$)/i.test(path)
  );
};
await assertPackableTree(app, { excluded: excludedFromStage });
await access(`${app}/appserver/static/adm.css`);
await access(`${app}/appserver/static/pages/atlas.js`);
for (const file of ["pages/history.js", "history.css", "history-manifest.json"])
  await access(`${app}/appserver/static/${file}`);
await access(`${app}/default/data/ui/views/map.xml`);

const { version } = JSON.parse(await readFile("package.json", "utf8"));
const appConf = await readFile(`${app}/default/app.conf`, "utf8");
const stanzas = {};
let current = "default";
for (const line of appConf.split(/\r?\n/)) {
  const header = line.match(/^\s*\[([^\]]*)\]\s*$/);
  if (header) current = header[1];
  const setting = line.match(/^\s*([^#\s=]+)\s*=\s*(.*?)\s*$/);
  if (setting) (stanzas[current] ??= {})[setting[1]] = setting[2];
}
if (stanzas.install)
  throw new Error("app.conf must not declare [install]; packaging adds it.");
for (const stanza of ["id", "launcher"])
  if (stanzas[stanza]?.version !== version)
    throw new Error(
      `app.conf [${stanza}] version ${stanzas[stanza]?.version} does not match package.json ${version}`,
    );

const stageRoot = "dist/stage";
const stage = `${stageRoot}/splunk_adm`;
await rm(stageRoot, { recursive: true, force: true });
await mkdir(stageRoot, { recursive: true });
await cp(app, stage, {
  recursive: true,
  filter: (source) => !excludedFromStage(source.slice(app.length)),
});
// The endpoint validates against the same source registry as the frontend.
await copyPackableFile(
  "config/deployment-health.json",
  `${stage}/bin/adm_settings_registry.json`,
);
await mkdir(`${stage}/docs`, { recursive: true });
await copyPackableFile("docs/DATA_LAYER.md", `${stage}/docs/DATA_LAYER.md`);
await copyPackableFile(
  "docs/DEPLOYMENT_HEALTH.md",
  `${stage}/docs/DEPLOYMENT_HEALTH.md`,
);
await copyPackableFile("docs/RECOVERY.md", `${stage}/docs/RECOVERY.md`);
await copyPackableFile(
  "docs/RETENTION_MAINTENANCE.md",
  `${stage}/docs/RETENTION_MAINTENANCE.md`,
);
await copyPackableFile(
  "docs/DNS_EVIDENCE_QUALIFICATION.md",
  `${stage}/docs/DNS_EVIDENCE_QUALIFICATION.md`,
);
await copyPackableFile(
  "docs/DNS_EVIDENCE_SCENARIOS.md",
  `${stage}/docs/DNS_EVIDENCE_SCENARIOS.md`,
);
await copyPackableFile(
  "docs/DNS_EVIDENCE_DESIGN.md",
  `${stage}/docs/DNS_EVIDENCE_DESIGN.md`,
);
await copyPackableFile(
  "docs/VSPHERE_SWITCH_DESIGN.md",
  `${stage}/docs/VSPHERE_SWITCH_DESIGN.md`,
);
await copyPackableFile(
  "docs/DNS_INGESTION_RESEARCH.md",
  `${stage}/docs/DNS_INGESTION_RESEARCH.md`,
);
await mkdir(`${stage}/docs/operators`, { recursive: true });
await copyPackableFile(
  "docs/operators/dns-evidence.md",
  `${stage}/docs/operators/dns-evidence.md`,
);
await copyPackableFile(
  "docs/operators/multicast.md",
  `${stage}/docs/operators/multicast.md`,
);
await copyPackableFile(
  "docs/multicast-source-qualification.md",
  `${stage}/docs/multicast-source-qualification.md`,
);

await copyPackableFile(
  "docs/LATE_CATALYST_RECEIPTS.md",
  `${stage}/docs/LATE_CATALYST_RECEIPTS.md`,
);
await copyPackableFile("docs/UPGRADES.md", `${stage}/docs/UPGRADES.md`);
await copyPackableFile(
  "docs/CONNECTED_JOURNEYS.md",
  `${stage}/docs/CONNECTED_JOURNEYS.md`,
);
for (const file of [
  "DEPENDENCY_BASELINES.md",
  "DEPENDENCY_WATCH_EXECUTION.md",
  "BASELINE_SOURCE_PROVIDER.md",
  "CASE_REQUEST_SUPERVISION.md",
  "CASE_SOURCE_QUALIFICATION.md",
  "INCIDENT_SOURCE_ASSOCIATIONS.md",
  "BACKUP_RESTORE.md",
  "TASK_LABS.md",
  "INVESTIGATION_RECORDS.md",
  "FEATURE_SOURCE_OBSERVATIONS.md",
  "FEATURE_FOUNDATIONS.md",
  "FEATURE_DELIVERY.md",
  "FEATURE_QUALIFICATION.json",
])
  await copyPackableFile(`docs/${file}`, `${stage}/docs/${file}`);
for (const file of ["THOUSANDEYES_DESIGN.md", "THOUSANDEYES_OPERATIONS.md"])
  await copyPackableFile(`docs/${file}`, `${stage}/docs/${file}`);
await copyPackableFile(
  "docs/operators/thousandeyes.md",
  `${stage}/docs/operators/thousandeyes.md`,
);
await mkdir(`${stage}/docs/research`, { recursive: true });
for (const file of [
  "thousandeyes.md",
  "thousandeyes-capabilities.md",
  "thousandeyes-operating-constraints.md",
])
  await copyPackableFile(
    `docs/research/${file}`,
    `${stage}/docs/research/${file}`,
  );
await copyPackableFile(
  "docs/CISCO_CONTRACT_MIGRATION.md",
  `${stage}/docs/CISCO_CONTRACT_MIGRATION.md`,
);
await copyPackableFile(
  "docs/CISCO_NETWORKING_QUALIFICATION.md",
  `${stage}/docs/CISCO_NETWORKING_QUALIFICATION.md`,
);
await mkdir(`${stage}/docs/operators`, { recursive: true });
await copyPackableFile(
  "docs/operators/cisco-enterprise-networking.md",
  `${stage}/docs/operators/cisco-enterprise-networking.md`,
);
await copyPackableFile(
  "docs/operators/qualified-native-network.md",
  `${stage}/docs/operators/qualified-native-network.md`,
);
await copyPackableFile("LICENSE", `${stage}/LICENSE`);
await copyPackableFile("NOTICE", `${stage}/NOTICE`);

// The bundle embeds production dependencies; ship their license texts with it.
// Include packages with deep JS entry points even when there is no root main.
// Type-only packages never reach the bundle.
const depDirs = execFileSync("npm", [
  "ls",
  "--omit=dev",
  "--all",
  "--parseable",
])
  .toString()
  .trim()
  .split("\n")
  .slice(1);
const notices = new Map();
// These npm distributions omit their upstream MIT license text. Keep the
// verified text locally rather than dropping a dependency's required notice.
const licenseFallbacks = JSON.parse(
  await readFile("tools/licenses/provenance.json", "utf8"),
);
for (const dir of depDirs) {
  const pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
  const files = await readdir(dir);
  const runtime =
    pkg.main ||
    pkg.module ||
    pkg.exports ||
    files.some((file) => /\.[cm]?js$/.test(file));
  const key = `${pkg.name}@${pkg.version}`;
  if (notices.has(key) || !runtime) continue;
  const licenseFile = files.find((f) =>
    /^(licen[cs]e|copying)([.-]|$)/i.test(f),
  );
  const fallback = licenseFallbacks[key];
  if (!licenseFile && !fallback)
    throw new Error(`${key} has no license file to include in notices`);
  const licensePath = licenseFile
    ? join(dir, licenseFile)
    : join("tools/licenses", fallback.file);
  const text = await readFile(licensePath, "utf8");
  if (!licenseFile) {
    const sha = createHash("sha256").update(text).digest("hex");
    if (sha !== fallback.sha256 || pkg.license !== "MIT")
      throw new Error(`License provenance mismatch for ${key}`);
  }
  notices.set(
    key,
    `${pkg.name} ${pkg.version} (${pkg.license})\n\n${text.trim()}\n`,
  );
}
await writeFile(
  `${stage}/THIRD_PARTY_NOTICES.txt`,
  "Third-party software bundled in appserver/static/pages/atlas.js\n\n" +
    [...notices.keys()]
      .sort()
      .map((name) => notices.get(name))
      .join(`\n${"-".repeat(72)}\n\n`),
);

// Splunk Web caches appserver/static by build number; bump it on every package.
const rawEpoch = process.env.SOURCE_DATE_EPOCH;
const epoch =
  rawEpoch !== undefined ? Number(rawEpoch) : Math.floor(Date.now() / 1000);
const build = Math.floor(epoch);
if (rawEpoch === "" || !Number.isSafeInteger(build) || build < 1) {
  throw new Error(`Invalid SOURCE_DATE_EPOCH build number: ${rawEpoch}`);
}
await writeFile(
  `${stage}/default/app.conf`,
  `[install]\nbuild = ${build}\n${appConf}`,
);

async function normalizeModes(dir) {
  await chmod(dir, 0o755);
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile())) {
      throw new Error(`Refusing linked or non-regular staged input: ${path}`);
    }
    if (entry.isDirectory()) await normalizeModes(path);
    else await chmod(path, 0o644);
  }
}
await normalizeModes(stage);

const bsd = execFileSync("tar", ["--version"]).toString().includes("bsdtar");
const ownership = bsd
  ? ["--uid", "0", "--gid", "0", "--uname", "splunk", "--gname", "splunk"]
  : ["--owner=0", "--group=0", "--numeric-owner"];
const filename = `splunk_adm-${version}.tar.gz`;
const archive = `dist/${filename}`;
execFileSync(
  "tar",
  [
    "-czf",
    archive,
    "--no-xattrs",
    ...ownership,
    "--exclude",
    ".DS_Store",
    "-C",
    stageRoot,
    "splunk_adm",
  ],
  { stdio: "inherit", env: { ...process.env, COPYFILE_DISABLE: "1" } },
);
const sha = createHash("sha256")
  .update(await readFile(archive))
  .digest("hex");
await writeFile(`${archive}.sha256`, `${sha}  ${filename}\n`);
console.log(`Created ${archive} (build ${build})\nSHA256 ${sha}`);
