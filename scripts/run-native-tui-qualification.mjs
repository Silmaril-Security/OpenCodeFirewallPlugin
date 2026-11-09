import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn as spawnPty } from "@lydell/node-pty";

const EXPECTED_VERSION = "opencode v2.2.6";
const COMMAND_TITLE = "Silmaril Firewall";
const SLASH_COMMAND = "/silmaril-firewall";
const TOAST_MESSAGE =
  "Blocked decisions are shown inline in the current session transcript.";
const RECEIPT_FILES = [
  "slash.raw",
  "slash.txt",
  "slash.json",
  "palette.raw",
  "palette.txt",
  "palette.json",
  "summary.json",
];
const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

const outputDirectory = parseOutput(process.argv.slice(2));
let receiptRoot;
let qualificationRoot;
let workspace;
let build;
let cliVersion;
let workspaceCleanup = { attempted: false, removed: false };
const sessions = [];
let fatalError;

try {
  receiptRoot = await prepareReceiptRoot(outputDirectory);
  build = buildCurrentDistribution();

  qualificationRoot = await mkdtemp(
    "/private/tmp/opencode-firewall-native-",
  );
  await chmod(qualificationRoot, 0o700);
  workspace = path.join(qualificationRoot, "workspace");
  await mkdir(workspace, { mode: 0o700 });

  const config = {
    plugin: [[packageURL(repoRoot), {}]],
  };
  await writeFile(
    path.join(workspace, "opencode.json"),
    `${JSON.stringify(config, null, 2)}\n`,
    { mode: 0o600 },
  );

  const cliPath = path.join(
    repoRoot,
    "node_modules",
    "@opencode",
    "cli",
    "bin",
    "opencode.exe",
  );
  const versionEnvironment = await makeEnvironment(
    path.join(qualificationRoot, "version"),
  );
  const versionResult = spawnSync(cliPath, ["--version"], {
    cwd: workspace,
    env: versionEnvironment.values,
    encoding: "utf8",
  });
  assert.equal(versionResult.status, 0, versionResult.stderr);
  cliVersion = versionResult.stdout.trim();
  assert.equal(cliVersion, EXPECTED_VERSION);

  sessions.push(
    await runSession({
      name: "slash",
      cliPath,
      receiptRoot,
      qualificationRoot,
      workspace,
      interact: async (terminal) => {
        terminal.record("typed slash completion");
        terminal.write(SLASH_COMMAND);
        await terminal.waitFor(
          "slash completion command title",
          (text) =>
            text.includes(SLASH_COMMAND) && text.includes(COMMAND_TITLE),
        );
        terminal.record("selected slash completion");
        terminal.write("\r");
      },
    }),
  );

  sessions.push(
    await runSession({
      name: "palette",
      cliPath,
      receiptRoot,
      qualificationRoot,
      workspace,
      interact: async (terminal) => {
        terminal.record("opened command palette");
        terminal.write("\x10");
        await terminal.waitFor(
          "command palette",
          (text) =>
            text.includes("Search commands") || text.includes("Commands"),
        );
        terminal.record("searched command palette");
        terminal.write(COMMAND_TITLE);
        await terminal.waitFor(
          "palette command title",
          (text) => text.includes(COMMAND_TITLE),
        );
        terminal.record("selected palette command");
        terminal.write("\r");
      },
    }),
  );
} catch (error) {
  fatalError = serializeError(error);
} finally {
  if (qualificationRoot) {
    workspaceCleanup.attempted = true;
    try {
      await rm(qualificationRoot, { recursive: true });
      workspaceCleanup.removed = true;
    } catch (error) {
      workspaceCleanup.error = serializeError(error);
    }
  }

  if (receiptRoot) {
    const summary = {
      schema: "silmaril.opencode-native-tui-qualification.v1",
      createdAt: new Date().toISOString(),
      repository: repoRoot,
      packageVersion: "0.4.9",
      cli: {
        path: path.join(
          repoRoot,
          "node_modules",
          "@opencode",
          "cli",
          "bin",
          "opencode.exe",
        ),
        version: cliVersion,
      },
      build,
      outputDirectory: receiptRoot,
      isolation: {
        qualificationRoot,
        workspace,
        workspaceOutsideUserHomeAncestors:
          typeof workspace === "string" &&
          workspace.startsWith("/private/tmp/"),
        completePackageDirectory: repoRoot,
        projectConfig: {
          key: "plugin",
          normalizedCliField: "plugins",
          value: [[packageURL(repoRoot), {}]],
        },
        childEnvironmentPolicy: "explicit allowlist",
        childEnvironmentKeys: environmentKeys(),
        inheritedCredentialAccountModelPromptHookKeys: [],
      },
      deactivation: {
        observed: false,
        manualRegistrationCleanup: false,
        gap:
          "OpenCode 2.2.6 documents host-owned layer removal but exposes no native observation for deactivation cleanup.",
      },
      sessions: sessions.map((session) => ({
        name: session.name,
        passed: session.passed,
        receipt: session.receipt,
      })),
      workspaceCleanup,
      fatalError,
      passed:
        !fatalError &&
        sessions.length === 2 &&
        sessions.every((session) => session.passed) &&
        workspaceCleanup.removed,
    };
    await writeExclusive(
      path.join(receiptRoot, "summary.json"),
      `${JSON.stringify(summary, null, 2)}\n`,
    );
    if (!summary.passed) process.exitCode = 1;
    else {
      console.log(`ok - native slash completion rendered the expected toast`);
      console.log(`ok - native command palette rendered the expected toast`);
      console.log(`ok - receipts: ${receiptRoot}`);
    }
  } else {
    process.exitCode = 1;
    if (fatalError) console.error(fatalError.message);
  }
}

async function runSession(input) {
  const startedAt = new Date().toISOString();
  const rawChunks = [];
  const actions = [];
  const knownProcesses = new Map();
  const environment = await makeEnvironment(
    path.join(input.qualificationRoot, input.name),
  );
  let pty;
  let exitEvent;
  let rootPgid;
  let signal;
  let fallbackSignals = [];
  let error;
  let tracking;

  const exitPromise = new Promise((resolve) => {
    pty = spawnPty(input.cliPath, ["--standalone"], {
      name: "xterm-256color",
      cols: 120,
      rows: 36,
      cwd: input.workspace,
      env: environment.values,
      encoding: null,
    });
    pty.onData((data) => {
      rawChunks.push(
        Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8"),
      );
    });
    pty.onExit((event) => {
      exitEvent = event;
      resolve(event);
    });
  });

  const track = () => {
    const snapshot = processSnapshot();
    const owned = ownedProcesses(snapshot, pty.pid, rootPgid);
    const root = snapshot.find((item) => item.pid === pty.pid);
    if (root && rootPgid === undefined) rootPgid = root.pgid;
    for (const item of owned) knownProcesses.set(item.pid, item);
    return owned;
  };
  tracking = setInterval(track, 100);
  track();

  const terminal = {
    write(data) {
      if (exitEvent) throw new Error("OpenCode exited before input was sent");
      pty.write(data);
    },
    record(action) {
      actions.push({
        at: new Date().toISOString(),
        action,
        bytesCaptured: rawLength(rawChunks),
      });
    },
    waitFor(label, predicate, timeoutMs = 20_000) {
      return waitForText(label, predicate, timeoutMs, rawChunks, () => exitEvent);
    },
  };

  try {
    await terminal.waitFor(
      "initial OpenCode TUI",
      (text) => text.includes("OpenCode") || text.length > 100,
    );
    await delay(2_500);
    await input.interact(terminal);
    await terminal.waitFor(
      "rendered Silmaril toast",
      (text) => containsRenderedText(text, TOAST_MESSAGE),
    );
    await delay(300);
  } catch (cause) {
    error = serializeError(cause);
  }

  const beforeSignal = track();
  try {
    signal = sendOwnedSignal(pty, rootPgid, "SIGINT");
    actions.push({
      at: new Date().toISOString(),
      action: "sent owned SIGINT",
      signal,
    });
  } catch (cause) {
    error ??= serializeError(cause);
  }

  if (!exitEvent) {
    const exited = await boundedExit(exitPromise, 5_000);
    if (!exited) {
      fallbackSignals = await forceCleanup(pty, rootPgid, knownProcesses);
      await boundedExit(exitPromise, 5_000);
    }
  }
  clearInterval(tracking);
  track();
  await delay(250);

  const afterExitSnapshot = processSnapshot();
  const remaining = afterExitSnapshot.filter((item) =>
    knownProcesses.has(item.pid),
  );
  if (remaining.length) {
    const finalFallback = await forceCleanup(
      pty,
      rootPgid,
      new Map(remaining.map((item) => [item.pid, item])),
    );
    fallbackSignals.push(...finalFallback);
    await delay(250);
  }
  const finalSnapshot = processSnapshot();
  const finalRemaining = finalSnapshot.filter((item) =>
    knownProcesses.has(item.pid),
  );

  const raw = Buffer.concat(rawChunks);
  const text = stripTerminal(raw.toString("utf8"));
  const rawPath = path.join(input.receiptRoot, `${input.name}.raw`);
  const textPath = path.join(input.receiptRoot, `${input.name}.txt`);
  const receiptPath = path.join(input.receiptRoot, `${input.name}.json`);
  const commandVisible =
    text.includes(COMMAND_TITLE) &&
    (input.name !== "slash" || text.includes(SLASH_COMMAND));
  const toastRendered = containsRenderedText(text, TOAST_MESSAGE);
  const cleanSigintExit =
    signal !== undefined &&
    fallbackSignals.length === 0 &&
    exitEvent !== undefined &&
    (exitEvent.exitCode === 0 ||
      exitEvent.exitCode === 130 ||
      exitEvent.signal === 2);
  const cleanupComplete = finalRemaining.length === 0;
  const passed =
    !error &&
    commandVisible &&
    toastRendered &&
    cleanSigintExit &&
    cleanupComplete;

  await writeExclusive(rawPath, raw);
  await writeExclusive(textPath, text);
  const receipt = {
    schema: "silmaril.opencode-native-tui-session.v1",
    name: input.name,
    startedAt,
    endedAt: new Date().toISOString(),
    passed,
    repository: repoRoot,
    completePackageDirectory: repoRoot,
    workspace: input.workspace,
    home: environment.values.HOME,
    xdg: {
      config: environment.values.XDG_CONFIG_HOME,
      cache: environment.values.XDG_CACHE_HOME,
      data: environment.values.XDG_DATA_HOME,
      state: environment.values.XDG_STATE_HOME,
    },
    environmentKeys: Object.keys(environment.values).sort(),
    config: {
      path: path.join(input.workspace, "opencode.json"),
      pluginTuple: [packageURL(repoRoot), {}],
      normalizedCliField: "plugins",
    },
    cli: {
      path: input.cliPath,
      version: EXPECTED_VERSION,
      args: ["--standalone"],
      pid: pty.pid,
      pgid: rootPgid,
      exit: exitEvent,
    },
    actions,
    evidence: {
      commandTitle: COMMAND_TITLE,
      slashCommand: input.name === "slash" ? SLASH_COMMAND : undefined,
      commandVisible,
      exactToastMessage: TOAST_MESSAGE,
      toastRendered,
      cleanSigintExit,
      cleanupComplete,
    },
    cleanup: {
      beforeSignal,
      signal,
      fallbackSignals,
      ownedProcessesObserved: [...knownProcesses.values()],
      remainingAfterCleanup: finalRemaining,
    },
    artifacts: {
      raw: rawPath,
      text: textPath,
      receipt: receiptPath,
      rawBytes: raw.length,
    },
    deactivationCleanupObserved: false,
    error,
  };
  await writeExclusive(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return { name: input.name, passed, receipt: receiptPath };
}

function buildCurrentDistribution() {
  const tsc = path.join(repoRoot, "node_modules", "typescript", "bin", "tsc");
  const result = spawnSync(process.execPath, [tsc, "-p", "tsconfig.json"], {
    cwd: repoRoot,
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      HOME: "/private/tmp",
      LANG: "en_US.UTF-8",
      LC_ALL: "en_US.UTF-8",
    },
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(
      `current distribution build failed (${result.status}): ${result.stderr}`,
    );
  }
  return {
    command: `${process.execPath} ${tsc} -p tsconfig.json`,
    exitCode: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

async function makeEnvironment(root) {
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

function environmentKeys() {
  return [
    "COLORTERM",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SHELL",
    "TERM",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
  ];
}

async function prepareReceiptRoot(requested) {
  if (!path.isAbsolute(requested)) {
    throw new Error("--output must be an absolute path");
  }
  await mkdir(requested, { recursive: true, mode: 0o700 });
  const resolvedOutput = await realpath(requested);
  const resolvedRepo = await realpath(repoRoot);
  const relative = path.relative(resolvedRepo, resolvedOutput);
  if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) {
    throw new Error("receipt output must be outside the tracked repository");
  }
  for (const file of RECEIPT_FILES) {
    const target = path.join(resolvedOutput, file);
    try {
      await access(target);
      throw new Error(`refusing to overwrite receipt: ${target}`);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  return resolvedOutput;
}

function parseOutput(args) {
  if (args.length !== 2 || args[0] !== "--output" || !args[1]) {
    throw new Error(
      "usage: npm run qualify:native -- --output /absolute/external/directory",
    );
  }
  return path.resolve(args[1]);
}

function packageURL(directory) {
  return pathToFileURL(`${directory}${path.sep}`).href;
}

async function waitForText(
  label,
  predicate,
  timeoutMs,
  chunks,
  getExit,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const text = stripTerminal(Buffer.concat(chunks).toString("utf8"));
    if (predicate(text)) return text;
    const exited = getExit();
    if (exited) {
      throw new Error(
        `OpenCode exited before ${label}: ${JSON.stringify(exited)}`,
      );
    }
    await delay(50);
  }
  throw new Error(`timed out waiting for ${label}`);
}

function stripTerminal(text) {
  return text
    .replace(/\u001B\][^\u0007]*(?:\u0007|\u001B\\)/gu, "")
    .replace(/\u001B[P^_X][\s\S]*?\u001B\\/gu, "")
    .replace(/\u001B\[[0-?]*[ -/]*[@-~]/gu, "")
    .replace(/\u001B[@-_]/gu, "")
    .replace(/\r/gu, "\n")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/gu, "");
}

function containsRenderedText(text, expected) {
  const pattern = expected
    .trim()
    .split(/\s+/u)
    .map(escapeRegExp)
    .join("[\\s\\u2500-\\u257F]*");
  return new RegExp(pattern, "u").test(text);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function processSnapshot() {
  const result = spawnSync(
    "/bin/ps",
    ["-axo", "pid=,ppid=,pgid=,command="],
    { encoding: "utf8" },
  );
  if (result.status !== 0) return [];
  return result.stdout
    .split("\n")
    .map((line) => {
      const match = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/u);
      if (!match) return;
      return {
        pid: Number(match[1]),
        ppid: Number(match[2]),
        pgid: Number(match[3]),
        command: match[4],
      };
    })
    .filter(Boolean);
}

function ownedProcesses(snapshot, rootPid, rootPgid) {
  const owned = new Set([rootPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const item of snapshot) {
      if (
        owned.has(item.pid) ||
        (!owned.has(item.ppid) && item.pgid !== rootPgid)
      ) {
        continue;
      }
      owned.add(item.pid);
      changed = true;
    }
  }
  return snapshot.filter((item) => owned.has(item.pid));
}

function sendOwnedSignal(pty, pgid, signal) {
  if (pgid === pty.pid) {
    process.kill(-pgid, signal);
    return { target: "process-group", id: pgid, signal };
  }
  pty.kill(signal);
  return { target: "pid", id: pty.pid, signal };
}

async function forceCleanup(pty, pgid, knownProcesses) {
  const sent = [];
  for (const signal of ["SIGTERM", "SIGKILL"]) {
    const snapshot = processSnapshot();
    const alive = snapshot.filter((item) => knownProcesses.has(item.pid));
    if (!alive.length) break;
    if (pgid === pty.pid && alive.some((item) => item.pgid === pgid)) {
      try {
        process.kill(-pgid, signal);
        sent.push({ target: "process-group", id: pgid, signal });
      } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    }
    for (const item of alive.filter((entry) => entry.pgid !== pgid)) {
      try {
        process.kill(item.pid, signal);
        sent.push({ target: "pid", id: item.pid, signal });
      } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    }
    await delay(signal === "SIGTERM" ? 2_000 : 250);
  }
  return sent;
}

async function boundedExit(exitPromise, timeoutMs) {
  return Promise.race([
    exitPromise.then(() => true),
    delay(timeoutMs).then(() => false),
  ]);
}

async function writeExclusive(file, data) {
  await writeFile(file, data, { flag: "wx", mode: 0o600 });
}

function rawLength(chunks) {
  return chunks.reduce((total, chunk) => total + chunk.length, 0);
}

function serializeError(error) {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }
  return { name: "Error", message: String(error) };
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
