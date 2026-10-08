import {
  access,
  chmod,
  copyFile,
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

const root = new URL("../", import.meta.url);
process.chdir(fileURLToPath(root));
const app = "splunk_app/splunk_adm";
await access(`${app}/appserver/static/adm.bundle.js`);
await access(`${app}/appserver/static/adm.css`);

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
  filter: (source) => !/(^|\/)(\.DS_Store|\._.*|docs)$/.test(source),
});
await mkdir(`${stage}/docs`, { recursive: true });
await copyFile("docs/DATA_LAYER.md", `${stage}/docs/DATA_LAYER.md`);
await copyFile("LICENSE", `${stage}/LICENSE`);
await copyFile("NOTICE", `${stage}/NOTICE`);

// The bundle embeds production dependencies; ship their license texts with it.
// Type-only packages (no runtime entry point) never reach the bundle.
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
for (const dir of depDirs) {
  const pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
  const files = await readdir(dir);
  const runtime =
    pkg.main || pkg.module || pkg.exports || files.includes("index.js");
  if (notices.has(pkg.name) || !runtime) continue;
  const licenseFile = files.find((f) => /^(licen[cs]e|copying)(\.|$)/i.test(f));
  if (!licenseFile)
    throw new Error(`${pkg.name} has no license file to include in notices`);
  const text = await readFile(join(dir, licenseFile), "utf8");
  notices.set(
    pkg.name,
    `${pkg.name} ${pkg.version} (${pkg.license})\n\n${text.trim()}\n`,
  );
}
await writeFile(
  `${stage}/THIRD_PARTY_NOTICES.txt`,
  "Third-party software bundled in appserver/static/adm.bundle.js\n\n" +
    [...notices.keys()]
      .sort()
      .map((name) => notices.get(name))
      .join(`\n${"-".repeat(72)}\n\n`),
);

// Splunk Web caches appserver/static by build number; bump it on every package.
const epoch = Number(process.env.SOURCE_DATE_EPOCH ?? Date.now() / 1000);
const build = Math.floor(epoch);
await writeFile(
  `${stage}/default/app.conf`,
  `[install]\nbuild = ${build}\n${appConf}`,
);

async function normalizeModes(dir) {
  await chmod(dir, 0o755);
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) await normalizeModes(path);
    else await chmod(path, 0o644);
  }
}
await normalizeModes(stage);

const filename = `splunk_adm-${version}.tar.gz`;
const archive = `dist/${filename}`;
const bsd = execFileSync("tar", ["--version"]).toString().includes("bsdtar");
const ownership = bsd
  ? ["--uid", "0", "--gid", "0", "--uname", "splunk", "--gname", "splunk"]
  : ["--owner=0", "--group=0", "--numeric-owner"];
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
