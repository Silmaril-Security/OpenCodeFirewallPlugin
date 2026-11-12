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
import { makeEnvironment } from "./qualification-harness.mjs";

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

async function main(args) {
  const outputDirectory = parseOutput(args);
  let receiptRoot;
  let qualificationRoot;
  let workspace;
  let build;
  let cliVersion;
  const workspaceCleanup = { attempted: false, removed: false };
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
        resultRow: hasSlashResultRow,
        interact: async (terminal) => {
          terminal.record("typed slash completion");
          terminal.write(SLASH_COMMAND);
          await terminal.waitForResultRow(
            "slash completion result row",
            hasSlashResultRow,
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
        resultRow: hasPaletteResultRow,
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
          await terminal.waitForResultRow(
            "palette command result row",
            hasPaletteResultRow,
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
}

async function runSession(input) {
  const startedAt = new Date().toISOString();
  const rawChunks = [];
  const actions = [];
  const knownProcesses = new Map();
  const processObservation = {
    successful: true,
    finalAvailable: false,
    errors: [],
  };
  const environment = await makeEnvironment(
    path.join(input.qualificationRoot, input.name),
  );
  let pty;
  let exitEvent;
  let rootPgid;
  let signal;
  let fallbackSignals = [];
  let cleanupSignalErrors = [];
  let error;
  let tracking;
  let resultRowVisibleBeforeEnter = false;

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

  const recordObservationError = (stage, cause) => {
    processObservation.successful = false;
    if (!processObservation.errors.some((item) => item.stage === stage)) {
      const detail = {
        stage,
        ...processObservationEvidence(cause),
      };
      processObservation.errors.push(detail);
      error ??= {
        name: "ProcessObservationError",
        message: `process observation unavailable during ${stage}`,
        processObservation: detail,
      };
    }
  };
  const observe = (stage) => {
    try {
      const snapshot = processSnapshot();
      const root = snapshot.find((item) => item.pid === pty.pid);
      if (root && rootPgid === undefined) rootPgid = root.pgid;
      const owned = ownedProcesses(snapshot, pty.pid, rootPgid);
      for (const item of owned) knownProcesses.set(item.pid, item);
      return { snapshot, owned };
    } catch (cause) {
      recordObservationError(stage, cause);
      return null;
    }
  };
  tracking = setInterval(() => {
    observe("interval");
  }, 100);
  observe("initial");

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
    async waitForResultRow(label, predicate, timeoutMs = 20_000) {
      const text = await waitForText(
        label,
        predicate,
        timeoutMs,
        rawChunks,
        () => exitEvent,
      );
      resultRowVisibleBeforeEnter = predicate(text);
      actions.push({
        at: new Date().toISOString(),
        action: "observed strict result row before selection",
        bytesCaptured: rawLength(rawChunks),
      });
      return text;
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

  const beforeSignal = observe("before-sigint")?.owned ?? null;
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
      const fallback = await forceCleanup(
        pty,
        rootPgid,
        knownProcesses,
        (stage) => observe(stage)?.snapshot ?? null,
      );
      fallbackSignals = fallback.sent;
      cleanupSignalErrors = fallback.errors;
      await boundedExit(exitPromise, 5_000);
    }
  }
  clearInterval(tracking);
  observe("teardown-track");
  await delay(250);

  const afterExit = observe("post-sigint");
  const remaining = afterExit
    ? remainingOwnedProcesses(afterExit.snapshot, pty.pid, knownProcesses)
    : null;
  if (remaining === null || remaining.length) {
    const finalFallback = await forceCleanup(
      pty,
      rootPgid,
      knownProcesses,
      (stage) => observe(stage)?.snapshot ?? null,
    );
    fallbackSignals.push(...finalFallback.sent);
    cleanupSignalErrors.push(...finalFallback.errors);
    await delay(250);
  }
  const finalObservation = observe("final-verification");
  const finalRemaining = finalObservation
    ? remainingOwnedProcesses(
        finalObservation.snapshot,
        pty.pid,
        knownProcesses,
      )
    : null;
  processObservation.finalAvailable = finalRemaining !== null;

  const raw = Buffer.concat(rawChunks);
  const text = stripTerminal(raw.toString("utf8"));
  const rawPath = path.join(input.receiptRoot, `${input.name}.raw`);
  const textPath = path.join(input.receiptRoot, `${input.name}.txt`);
  const receiptPath = path.join(input.receiptRoot, `${input.name}.json`);
  const resultRowVisible =
    resultRowVisibleBeforeEnter && input.resultRow(text);
  const toastRendered = containsRenderedText(text, TOAST_MESSAGE);
  const cleanSigintExit =
    signal !== undefined &&
    fallbackSignals.length === 0 &&
    exitEvent !== undefined &&
    (exitEvent.exitCode === 0 ||
      exitEvent.exitCode === 130 ||
      exitEvent.signal === 2);
  const evaluation = evaluateSessionEvidence({
    interactionSucceeded: !error && cleanupSignalErrors.length === 0,
    resultRowVisible,
    toastRendered,
    cleanSigintExit,
    processObservationSucceeded: processObservation.successful,
    remainingAfterCleanup: finalRemaining,
  });

  await writeExclusive(rawPath, raw);
  await writeExclusive(textPath, text);
  const receipt = {
    schema: "silmaril.opencode-native-tui-session.v1",
    name: input.name,
    startedAt,
    endedAt: new Date().toISOString(),
    passed: evaluation.passed,
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
      resultRowVisible,
      commandVisible: resultRowVisible,
      exactToastMessage: TOAST_MESSAGE,
      toastRendered,
      cleanSigintExit,
      processObservationSucceeded: processObservation.successful,
      cleanupComplete: evaluation.cleanupComplete,
    },
    processObservation,
    cleanup: {
      beforeSignal,
      signal,
      fallbackSignals,
      signalErrors: cleanupSignalErrors,
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
  return { name: input.name, passed: evaluation.passed, receipt: receiptPath };
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

const PALETTE_RESULT_ROW =
  /Silmaril Firewall[ \t]{1,16}Silmaril Firewall[ \t]{1,64}Plugin(?=[ \t\n\r\u2500-\u257F]|$)/u;
const SLASH_RESULT_ROW =
  /\/silmaril-firewall[ \t]{1,64}Silmaril Firewall(?=[ \t\n\r\u2500-\u257F]|$)/u;

export function hasPaletteResultRow(text) {
  return PALETTE_RESULT_ROW.test(text);
}

export function hasSlashResultRow(text) {
  return SLASH_RESULT_ROW.test(text);
}

export class ProcessObservationError extends Error {
  constructor(kind, evidence) {
    super(`process observation unavailable: ${kind}`);
    this.name = "ProcessObservationError";
    this.processObservation = Object.freeze({ kind, ...evidence });
  }
}

export function processSnapshot(spawn = spawnSync) {
  let result;
  try {
    result = spawn(
      "/bin/ps",
      ["-axo", "pid=,ppid=,pgid=,command="],
      { encoding: "utf8" },
    );
  } catch {
    throw observationError("spawn-threw");
  }
  if (result?.error) {
    throw observationError("spawn-error", result);
  }
  if (result?.status === null || result?.status === undefined) {
    throw observationError("missing-status", result);
  }
  if (result.status !== 0) {
    throw observationError("nonzero-status", result);
  }

  const stdout = outputText(result.stdout);
  const processes = [];
  let malformedLines = 0;
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue;
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/u);
    if (!match) {
      malformedLines += 1;
      continue;
    }
    processes.push({
      pid: Number(match[1]),
      ppid: Number(match[2]),
      pgid: Number(match[3]),
      command: match[4],
    });
  }
  if (malformedLines > 0) {
    throw observationError("malformed-output", result, { malformedLines });
  }
  return processes;
}

function observationError(kind, result = {}, extra = {}) {
  return new ProcessObservationError(kind, {
    status:
      Number.isSafeInteger(result?.status) ? result.status : null,
    spawnError: Boolean(result?.error),
    stderr: redactedOutputMetadata(result?.stderr),
    ...extra,
  });
}

function redactedOutputMetadata(value) {
  const bytes = Buffer.byteLength(outputText(value), "utf8");
  const limit = 4096;
  return {
    present: bytes > 0,
    bytes: Math.min(bytes, limit),
    truncated: bytes > limit,
  };
}

function outputText(value) {
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  return typeof value === "string" ? value : "";
}

function processObservationEvidence(error) {
  if (error instanceof ProcessObservationError) {
    return error.processObservation;
  }
  return {
    kind: "unexpected-observer-error",
    status: null,
    spawnError: true,
    stderr: { present: false, bytes: 0, truncated: false },
  };
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

function remainingOwnedProcesses(snapshot, rootPid, knownProcesses) {
  return snapshot.filter(
    (item) => item.pid === rootPid || knownProcesses.has(item.pid),
  );
}

export function evaluateSessionEvidence(input) {
  const cleanupComplete =
    input.processObservationSucceeded === true &&
    Array.isArray(input.remainingAfterCleanup) &&
    input.remainingAfterCleanup.length === 0;
  return {
    cleanupComplete,
    passed:
      input.interactionSucceeded === true &&
      input.resultRowVisible === true &&
      input.toastRendered === true &&
      input.cleanSigintExit === true &&
      cleanupComplete,
  };
}

function sendOwnedSignal(pty, pgid, signal) {
  if (pgid === pty.pid) {
    process.kill(-pgid, signal);
    return { target: "process-group", id: pgid, signal };
  }
  pty.kill(signal);
  return { target: "pid", id: pty.pid, signal };
}

async function forceCleanup(pty, pgid, knownProcesses, observe) {
  const sent = [];
  const errors = [];
  for (const signal of ["SIGTERM", "SIGKILL"]) {
    const snapshot = observe(`fallback-${signal.toLowerCase()}`);
    const alive = snapshot
      ? remainingOwnedProcesses(snapshot, pty.pid, knownProcesses)
      : [
          { pid: pty.pid, pgid: pgid ?? pty.pid },
          ...knownProcesses.values(),
        ];
    if (snapshot && !alive.length) break;
    if (pgid === pty.pid) {
      try {
        process.kill(-pgid, signal);
        sent.push({ target: "process-group", id: pgid, signal });
      } catch (error) {
        if (error?.code !== "ESRCH") errors.push(serializeError(error));
      }
    } else {
      try {
        pty.kill(signal);
        sent.push({ target: "pid", id: pty.pid, signal });
      } catch (error) {
        if (error?.code !== "ESRCH") errors.push(serializeError(error));
      }
    }
    const targets = new Map(
      alive
        .filter((entry) => entry.pid !== pty.pid && entry.pgid !== pgid)
        .map((entry) => [entry.pid, entry]),
    );
    for (const item of targets.values()) {
      try {
        process.kill(item.pid, signal);
        sent.push({ target: "pid", id: item.pid, signal });
      } catch (error) {
        if (error?.code !== "ESRCH") errors.push(serializeError(error));
      }
    }
    await delay(signal === "SIGTERM" ? 2_000 : 250);
  }
  return { sent, errors };
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
  if (error instanceof ProcessObservationError) {
    return {
      name: error.name,
      message: error.message,
      processObservation: error.processObservation,
    };
  }
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

const entrypoint = process.argv[1] && path.resolve(process.argv[1]);
if (entrypoint === fileURLToPath(import.meta.url)) {
  await main(process.argv.slice(2));
}
