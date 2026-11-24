import { copyFile, lstat, readdir, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";

/** Extra package inputs such as documentation must also be regular files. */
export async function copyPackableFile(source, target) {
  if (
    !(await lstat(source)).isFile() ||
    (await realpath(source)) !== resolve(source)
  )
    throw new Error(`Refusing linked or non-regular package input: ${source}`);
  await copyFile(source, target);
}

/**
 * Verify that every source entry that would be copied into a package is a
 * regular file or directory.  This must run before cp() and mode
 * normalization: both operations can follow a symlink and mutate or expose
 * a path outside the staging tree.
 */
export async function assertPackableTree(
  root,
  { excluded = () => false } = {},
) {
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory()) {
    throw new Error(`Refusing linked or non-regular package input: ${root}`);
  }

  async function walk(directory, relative = "") {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const childRelative = `${relative}/${entry.name}`;
      if (excluded(childRelative)) continue;
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile())) {
        throw new Error(
          `Refusing linked or non-regular package input: ${path}`,
        );
      }
      if (entry.isDirectory()) await walk(path, childRelative);
    }
  }

  await walk(root);
}
