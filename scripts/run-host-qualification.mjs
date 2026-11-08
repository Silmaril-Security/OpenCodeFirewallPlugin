import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { Host } from "@opencode/plugin/host";
import { PluginPromise } from "@opencode/core/plugin/promise";
import { PluginHooks } from "@opencode/core/plugin/hooks";
import { Tool } from "@opencode/core/tool";
import { Permission } from "@opencode/core/permission";
import { LayerNode } from "@opencode/util/effect/layer-node";
import { Effect, Exit, Layer, Schema, Stream } from "effect";

const execute = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const qualificationRoot = await mkdtemp(path.join(repoRoot, ".host-qualification-"));
const packRoot = path.join(qualificationRoot, "pack");
const consumerRoot = path.join(qualificationRoot, "consumer");
const originalFetch = globalThis.fetch;

try {
  await mkdir(packRoot);
  await mkdir(consumerRoot);
  const isolatedHome = path.join(qualificationRoot, "home");
  await mkdir(isolatedHome);
  const hostEnv = {
    ...process.env,
    HOME: isolatedHome,
    XDG_CONFIG_HOME: path.join(isolatedHome, ".config"),
    XDG_CACHE_HOME: path.join(isolatedHome, ".cache"),
    XDG_DATA_HOME: path.join(isolatedHome, ".local", "share"),
  };
  const oldVersion = await execute(
    path.join(repoRoot, "node_modules", "opencode-ai", "bin", "opencode.exe"),
    ["--version"],
    { cwd: qualificationRoot, env: hostEnv },
  );
  assert.equal(oldVersion.stdout.trim(), "1.19.5");
  const newVersion = await execute(
    path.join(repoRoot, "node_modules", "@opencode", "cli", "bin", "opencode.exe"),
    ["--version"],
    { cwd: qualificationRoot, env: hostEnv },
  );
  assert.equal(newVersion.stdout.trim(), "opencode v2.2.6");
  const packed = await execute("npm", [
    "pack",
    "--json",
    "--pack-destination",
    packRoot,
  ], { cwd: repoRoot });
  const packResult = JSON.parse(packed.stdout);
  assert.equal(packResult.length, 1);
  const tarball = path.join(packRoot, packResult[0].filename);
  await writeFile(
    path.join(consumerRoot, "package.json"),
    JSON.stringify({ name: "opencode-firewall-host-qualification", private: true }),
  );
  await execute("npm", [
    "install",
    "--ignore-scripts",
    "--no-package-lock",
    "--no-audit",
    "--no-fund",
    tarball,
  ], { cwd: consumerRoot });

  const packageDirectory = path.join(
    consumerRoot,
    "node_modules",
    "@silmaril",
    "opencode-firewall-plugin",
  );
  const entries = Host.resolve({ directory: packageDirectory });
  assert.ok(entries.server?.endsWith("/dist/server.js"), entries.server);
  const loaded = await Host.load(entries.server);
  assert.deepEqual(Object.keys(loaded), ["default"]);
  assert.equal(loaded.default.id, "silmaril-firewall");
  assert.equal(typeof loaded.default.server, "function");
  assert.equal(typeof loaded.default.setup, "function");

  const oldHooks = await loaded.default.server(oldPluginInput(), {});
  assert.equal(typeof oldHooks["chat.message"], "function");
  assert.equal(typeof oldHooks["tool.execute.before"], "function");
  assert.equal(typeof oldHooks["experimental.text.complete"], "function");

  const packageJson = JSON.parse(
    await readFile(path.join(packageDirectory, "package.json"), "utf8"),
  );
  assert.equal(packageJson.exports["./server"].import, "./dist/server.js");
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.8.2");

  let requestBodies = [];
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body));
    requestBodies.push(body);
    const malicious = body.text.includes("BLOCK_BEFORE")
      || (body.hook === "tool_response" && body.text.includes("MALICIOUS_TOOL_RESULT"))
      || body.text.includes("MALICIOUS_PROMPT");
    return new Response(JSON.stringify({
      prediction: malicious ? "MALICIOUS" : "BENIGN",
      score: malicious ? 0.99 : 0.01,
      threshold: 0.5,
      primary_outcome: malicious ? "control_abuse" : "benign",
    }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  const counter = { value: 0 };
  await qualifyV2Runtime(loaded.default, counter);
  assert.ok(requestBodies.length >= 5);
  const toolRequest = requestBodies.find(
    (body) => body.tool_name === "github_create_issue",
  );
  assert.deepEqual(toolRequest.resource, {
    kind: "tool",
    id: "github_create_issue",
  });
  assert.equal(Object.hasOwn(toolRequest, "agent"), false);
  assert.equal(toolRequest.metadata.agent, "build");

  console.log("ok - packed server resolves and loads through OpenCode 2.2.6 Host");
  console.log("ok - supplemental OpenCode 1.19.5 binary version and retained server adapter initialize");
  console.log("ok - OpenCode 2.2.6 Promise adapter runs prompt and real Tool service hooks");
} finally {
  globalThis.fetch = originalFetch;
  await rm(qualificationRoot, { recursive: true, force: true });
}

async function qualifyV2Runtime(definition, counter) {
  const permission = {
    close: Effect.void,
    ask: () => Effect.succeed({ id: "permission-fixture", effect: "allow" }),
    assert: () => Effect.void,
    assertNotDenied: () => Effect.void,
    allows: () => Effect.succeed(true),
    reply: () => Effect.void,
    get: () => Effect.succeed(undefined),
    forSession: () => Effect.succeed([]),
    list: () => Effect.succeed([]),
  };
  const layer = LayerNode.compile(
    LayerNode.group([Tool.node, PluginHooks.node]),
    {
      replacements: [
        Permission.node.replace(
          Layer.succeed(Permission.Service, permission),
        ),
      ],
    },
  );

  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const hooks = yield* PluginHooks.Service;
        const tools = yield* Tool.Service;
        yield* tools.transform((editor) => {
          editor.namespace({
            name: "github",
            description: "Synthetic generic namespace for qualification.",
          });
          editor.add({
            name: "create_issue",
            options: { namespace: "github", codemode: false },
            description: "Increment a local counter and return fixture output.",
            input: Schema.Struct({ text: Schema.String }),
            output: Schema.Struct({ secret: Schema.String }),
            execute: ({ text }) =>
              Effect.sync(() => {
                counter.value += 1;
                return {
                  output: { secret: text },
                  content: text,
                  metadata: { private: text },
                };
              }),
          });
        });

        const host = makeHost(hooks, tools);
        const adapted = PluginPromise.fromPromise({
          id: definition.id,
          setup: definition.setup,
        });
        yield* adapted.effect(host);

        const prompt = {
          sessionID: "session-v2",
          messageID: "message-prompt",
          prompt: {
            text: "MALICIOUS_PROMPT",
            files: [{ uri: "file:///private" }],
            agents: [{ name: "unsafe-agent" }],
            skills: [{ id: "unsafe-skill" }],
          },
          metadata: { fixture: true },
          delivery: "queue",
        };
        yield* hooks.trigger("session", "prompt", prompt);
        assert.match(prompt.prompt.text, /blocked this prompt/u);
        assert.deepEqual(prompt.prompt.files, []);
        assert.deepEqual(prompt.prompt.agents, []);
        assert.deepEqual(prompt.prompt.skills, []);

        const snapshot = yield* tools.snapshot();
        const blockedBefore = yield* Effect.exit(snapshot.execute({
          sessionID: "session-v2",
          agent: "build",
          messageID: "message-before",
          call: {
            type: "tool-call",
            id: "call-before",
            name: "github_create_issue",
            input: { text: "BLOCK_BEFORE" },
          },
        }));
        assert.equal(Exit.isFailure(blockedBefore), true);
        assert.equal(counter.value, 0);

        const allowed = yield* snapshot.execute({
          sessionID: "session-v2",
          agent: "build",
          messageID: "message-allowed",
          call: {
            type: "tool-call",
            id: "call-allowed",
            name: "github_create_issue",
            input: { text: "allowed result" },
          },
        });
        assert.equal(counter.value, 1);
        assert.deepEqual(allowed.output, { secret: "allowed result" });

        const blockedAfter = yield* snapshot.execute({
          sessionID: "session-v2",
          agent: "build",
          messageID: "message-after",
          call: {
            type: "tool-call",
            id: "call-after",
            name: "github_create_issue",
            input: { text: "MALICIOUS_TOOL_RESULT" },
          },
        });
        assert.equal(counter.value, 2);
        const serialized = JSON.stringify(blockedAfter);
        assert.doesNotMatch(serialized, /MALICIOUS_TOOL_RESULT/u);
        assert.match(serialized, /blocked this tool result/u);
        assert.equal(typeof blockedAfter.output, "string");
      }).pipe(Effect.provide(layer)),
    ),
  );
}

function makeHost(hooks, tools) {
  const inert = inertDomain();
  const rpc = Object.assign(
    () => inert,
    {
      register: () => Effect.succeed({
        dispose: Effect.void,
        events: { emit: () => Effect.void },
      }),
    },
  );
  return {
    app: { name: "OpenCode", version: "2.2.6", channel: "stable" },
    location: {
      directory: "/tmp/opencode-firewall-qualification",
      project: {
        id: "project-v2",
        directory: "/tmp/opencode-firewall-qualification",
        canonical: "/tmp/opencode-firewall-qualification",
      },
    },
    options: {
      silmaril_api_key: "test-key",
      silmaril_api_url: "https://fixture.invalid/classify",
      mode: "block",
    },
    agent: inert,
    aisdk: inert,
    command: inert,
    credential: inert,
    event: { subscribe: () => Stream.empty },
    experimental: {
      terminal: inert,
      generate: inert,
      artifact: inert,
    },
    generate: inert,
    integration: inert,
    mcp: inert,
    model: inert,
    permission: inert,
    plugin: inert,
    provider: inert,
    reference: inert,
    rpc,
    session: {
      ...inert,
      hook: (name, callback, options) =>
        hooks.register("session", name, callback, options),
      instructions: {
        entry: inert,
      },
    },
    shell: inert,
    skill: inert,
    storage: inert,
    tool: {
      ...inert,
      hook: (name, callback) => hooks.register("tool", name, callback),
      list: () => tools.list(),
      transform: (callback) => tools.transform(callback),
      reload: () => tools.reload(),
    },
    vcs: inert,
    websearch: inert,
    worktree: inert,
  };
}

function inertDomain() {
  return new Proxy({}, {
    get() {
      return () => Effect.void;
    },
  });
}

function oldPluginInput() {
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
    project: {
      id: "project-v1",
      name: "Project",
    },
    directory: path.join(tmpdir(), "opencode-firewall-v1"),
    worktree: path.join(tmpdir(), "opencode-firewall-v1"),
    experimental_workspace: { register() {} },
    serverUrl: new URL("http://localhost:4096"),
    $: () => {},
  };
}
