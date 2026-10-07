import { mkdir, access, writeFile, copyFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
const root = new URL("../", import.meta.url);
process.chdir(fileURLToPath(root));
await access("splunk_app/splunk_adm/appserver/static/adm.bundle.js");
await access("splunk_app/splunk_adm/appserver/static/adm.css");
await mkdir("dist", { recursive: true });
await writeFile(
  "splunk_app/splunk_adm/README.md",
  "# Application Atlas\n\nReact dependency mapping pilot targeting Splunk 10.6. Demo mode is synthetic.\nSee [pilot instructions](docs/PILOT.md) and [graph contract](docs/GRAPH_CONTRACT.md).\nOffline CLI and fixtures described there belong to the source repository, not this installed app.\nNo indexes, collectors, or HEC inputs are automatically provisioned.\n",
);
await mkdir("splunk_app/splunk_adm/docs", { recursive: true });
for (const name of ["GRAPH_CONTRACT.md", "PILOT.md", "TA_PACKAGE_ANALYSIS.md"])
  await copyFile(`docs/${name}`, `splunk_app/splunk_adm/docs/${name}`);
const archive = "dist/splunk_adm-0.1.0.tar.gz";
execFileSync("tar", ["-czf", archive, "-C", "splunk_app", "splunk_adm"], {
  stdio: "inherit",
});
const sha = createHash("sha256")
  .update(await readFile(archive))
  .digest("hex");
await writeFile(`${archive}.sha256`, `${sha}  splunk_adm-0.1.0.tar.gz\n`);
console.log(`Created ${archive}\nSHA256 ${sha}`);
