import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const PINNED_REVISION = "810c0eba1a7348036f8bdf61e6632d0c36c6876c";
const execute = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = path.join(
  repoRoot,
  "test",
  "fixtures",
  "opencode-v1.19.5",
  "sources.json",
);
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
assert.equal(manifest.revision, PINNED_REVISION);
const ts = createRequire(path.join(repoRoot, "package.json"))("typescript");

const sources = {};
for (const file of [manifest.license, ...manifest.files]) {
  const response = await fetch(file.url, { signal: AbortSignal.timeout(30_000) });
  assert.equal(response.ok, true, `${file.path}: HTTP ${response.status}`);
  const source = await response.text();
  assert.equal(
    createHash("sha256").update(source).digest("hex"),
    file.sha256,
    `${file.path}: pinned source hash`,
  );
  sources[file.path] = source;
}
assert.match(sources.LICENSE, /^MIT License\n/u);

function originalFunctions(file, names) {
  const sourceFile = ts.createSourceFile(
    file,
    sources[file],
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const found = new Map();
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name && names.includes(node.name.text)) {
      assert.equal(found.has(node.name.text), false, `duplicate ${node.name.text}`);
      found.set(node.name.text, node.getText(sourceFile));
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return names.map((name) => {
    assert.ok(found.has(name), `missing original ${name}`);
    return found.get(name);
  }).join("\n");
}

// Function bodies come unchanged from the SHA-verified official source. The
// harness supplies only their imported helpers and erases TypeScript syntax.
const sourceContract = [
  'import path,{resolve as pathResolve,win32,relative,isAbsolute,sep} from "node:path";',
  'import {realpathSync} from "node:fs";',
  'import {fileURLToPath,pathToFileURL} from "node:url";',
  originalFunctions("packages/tui/src/util/record.ts", ["isRecord"]),
  originalFunctions("packages/opencode/src/util/filesystem.ts", [
    "isEnoent",
    "normalizePath",
    "windowsPath",
    "resolve",
  ]),
  originalFunctions("packages/core/src/fs-util.ts", ["contains"]),
  "const Filesystem={resolve,contains};",
  originalFunctions("packages/opencode/src/plugin/shared.ts", [
    "resolveExportPath",
    "extractExportValue",
    "packageMain",
    "resolvePackageFile",
    "resolvePackagePath",
    "resolvePackageEntrypoint",
    "readPluginId",
    "readV1Plugin",
    "resolvePluginId",
  ]),
  originalFunctions("packages/opencode/src/plugin/index.ts", [
    "isServerPlugin",
    "getServerPlugin",
    "getLegacyPlugins",
    "applyPlugin",
  ]),
  "export {resolvePackageEntrypoint,readV1Plugin,readPluginId,applyPlugin};",
].join("\n");
const compiledContract = ts.transpileModule(sourceContract, {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
  },
}).outputText;
const native = await import(
  `data:text/javascript;base64,${Buffer.from(compiledContract).toString("base64")}`
);

const scratch = await mkdtemp(path.join(tmpdir(), "silmaril-opencode-v1-contract-"));
try {
  const packDirectory = path.join(scratch, "pack");
  const isolatedHome = path.join(scratch, "home");
  await mkdir(packDirectory);
  await mkdir(isolatedHome);
  const packed = JSON.parse((await execute("npm", [
    "pack",
    "--ignore-scripts",
    "--json",
    "--pack-destination",
    scratch,
  ], { cwd: repoRoot })).stdout);
  assert.equal(packed.length, 1);
  const tarball = path.join(scratch, packed[0].filename);
  await execute("tar", ["-xzf", tarball, "-C", packDirectory]);
  await symlink(
    path.join(repoRoot, "node_modules"),
    path.join(scratch, "node_modules"),
    "dir",
  );

  // Resolve the private temporary path before the pinned containment helper
  // compares package and entry paths.
  const directory = await realpath(path.join(packDirectory, "package"));
  const packageJson = JSON.parse(await readFile(path.join(directory, "package.json"), "utf8"));
  assert.equal(packageJson.peerDependencies["@opencode-ai/plugin"], ">=1.18.22");
  const descriptor = {
    dir: directory,
    pkg: packageJson.name,
    json: packageJson,
  };
  const entry = native.resolvePackageEntrypoint(
    packageJson.name,
    "server",
    descriptor,
  );

  const assertions = [];
  assert.equal(entry, pathToFileURL(path.join(directory, "dist/server.js")).href);
  assert.notEqual(entry, pathToFileURL(path.join(directory, packageJson.main)).href);
  assertions.push("original export selector preferred ./server over main");

  Object.assign(process.env, {
    HOME: isolatedHome,
    XDG_CONFIG_HOME: path.join(isolatedHome, ".config"),
    XDG_CACHE_HOME: path.join(isolatedHome, ".cache"),
    XDG_DATA_HOME: path.join(isolatedHome, ".local", "share"),
  });
  const mod = await import(entry);
  assert.deepEqual(Object.keys(mod), ["default"]);
  assert.equal(
    native.readV1Plugin(mod, packageJson.name, "server", "detect"),
    mod.default,
  );
  assert.equal(
    native.readPluginId(mod.default.id, packageJson.name),
    "silmaril-firewall",
  );
  assertions.push("original readV1Plugin accepted dual definition");

  const hooks = [];
  await native.applyPlugin({
    mod,
    spec: entry,
    source: "file",
    target: entry,
    pkg: descriptor,
    options: {},
  }, oldPluginInput(directory), hooks);
  assert.equal(hooks.length, 1);
  for (const name of [
    "chat.message",
    "tool.execute.before",
    "tool.execute.after",
    "experimental.text.complete",
  ]) {
    assert.equal(typeof hooks[0][name], "function", name);
  }
  assertions.push("original applyPlugin initialized packed server once and returned four legacy hooks");

  assert.throws(
    () => native.readV1Plugin(
      { default: { id: "v2-only", setup() {} } },
      "fixture",
      "server",
      "detect",
    ),
    /server/u,
  );
  assertions.push("v2-only definition rejected");
  assert.throws(
    () => native.readV1Plugin(
      { default: { id: "bad", server: 1 } },
      "fixture",
      "server",
      "detect",
    ),
    /invalid server/u,
  );
  assertions.push("non-function server rejected");
  assert.throws(
    () => native.resolvePackageEntrypoint("escape", "server", {
      ...descriptor,
      json: { exports: { "./server": "../../escape.js" } },
    }),
    /outside plugin directory/u,
  );
  assertions.push("escaping server export rejected");

  assert.equal(assertions.length, 6);
  console.log(
    `ok - pinned OpenCode 1.19.5 original loader contract consumed packed artifact (${assertions.length} assertions)`,
  );
  console.log(
    "scope - original entrypoint/validator/consumer functions; not a full CLI turn or dispatcher",
  );
} finally {
  await rm(scratch, { recursive: true, force: true });
}

function oldPluginInput(directory) {
  return {
    client: {
      app: { async log() {} },
      session: {
        async get() {
          return { data: undefined };
        },
        async messages() {
          return { data: [] };
        },
      },
    },
    project: { id: "project-v1", name: "Project" },
    directory,
    worktree: directory,
    experimental_workspace: { register() {} },
    serverUrl: new URL("http://127.0.0.1:4096"),
    $: () => {},
  };
}
