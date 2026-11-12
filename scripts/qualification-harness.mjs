import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

export const execute = promisify(execFile);

export const INSTALL_ARGUMENTS = [
  "install",
  "--ignore-scripts",
  "--no-package-lock",
  "--no-audit",
  "--no-fund",
];

export async function packPlugin(repoRoot, packRoot) {
  const packed = await execute("npm", [
    "pack",
    "--json",
    "--pack-destination",
    packRoot,
  ], { cwd: repoRoot });
  const manifests = JSON.parse(packed.stdout);
  assert.equal(manifests.length, 1);
  return {
    manifest: manifests[0],
    tarball: path.join(packRoot, manifests[0].filename),
  };
}

export async function installPackedPlugin(
  { manifest, tarball },
  consumerRoot,
  peers = [],
) {
  await writeFile(
    path.join(consumerRoot, "package.json"),
    JSON.stringify({ name: "opencode-firewall-plugin-consumer", private: true }),
  );
  await execute("npm", [...INSTALL_ARGUMENTS, tarball, ...peers], {
    cwd: consumerRoot,
  });
  return path.join(consumerRoot, "node_modules", ...manifest.name.split("/"));
}

export async function makeEnvironment(root) {
  const home = path.join(root, "home");
  const directories = {
    HOME: home,
    XDG_CONFIG_HOME: path.join(root, "xdg", "config"),
    XDG_CACHE_HOME: path.join(root, "xdg", "cache"),
    XDG_DATA_HOME: path.join(root, "xdg", "data"),
    XDG_STATE_HOME: path.join(root, "xdg", "state"),
    TMPDIR: path.join(root, "tmp"),
  };
  await Promise.all(
    Object.values(directories).map((directory) =>
      mkdir(directory, { recursive: true, mode: 0o700 }),
    ),
  );
  return {
    values: {
      ...directories,
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      SHELL: "/bin/sh",
      TERM: "xterm-256color",
      COLORTERM: "truecolor",
      LANG: "en_US.UTF-8",
      LC_ALL: "en_US.UTF-8",
    },
  };
}
