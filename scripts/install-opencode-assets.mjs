#!/usr/bin/env node
import { copyFile, mkdir, readdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = path.join(repoRoot, "opencode");
const configRoot = process.env.OPENCODE_CONFIG_DIR
  ? path.resolve(process.env.OPENCODE_CONFIG_DIR)
  : path.join(os.homedir(), ".config", "opencode");

const assetRoots = ["skills", "commands"];

async function copyTree(relativeRoot) {
  const sourceDir = path.join(sourceRoot, relativeRoot);
  const entries = await readdir(sourceDir, { recursive: true, withFileTypes: true });
  const copied = [];

  for (const entry of entries) {
    if (!entry.isFile()) {
      continue;
    }

    const relativePath = path.join(entry.parentPath ?? sourceDir, entry.name).slice(sourceDir.length + 1);
    const sourcePath = path.join(sourceDir, relativePath);
    const targetPath = path.join(configRoot, relativeRoot, relativePath);
    await mkdir(path.dirname(targetPath), { recursive: true });
    await copyFile(sourcePath, targetPath);
    copied.push(path.join(relativeRoot, relativePath));
  }

  return copied;
}

async function main() {
  const copied = [];
  for (const assetRoot of assetRoots) {
    copied.push(...await copyTree(assetRoot));
  }

  process.stdout.write([
    `Installed OpenCode assets into ${configRoot}:`,
    ...copied.map((asset) => `- ${asset}`),
    "",
  ].join("\n"));
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
