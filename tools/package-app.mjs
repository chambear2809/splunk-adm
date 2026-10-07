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
