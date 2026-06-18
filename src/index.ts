import { spawn } from "node:child_process";
import { platform } from "node:os";
import type {
  Plugin,
  PluginInput,
  PluginModule,
  PluginOptions,
} from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";

const PLUGIN_ID = "opencode-firewall-plugin";
const PLUGIN_VERSION = "0.1.0";
const DEFAULT_CLASSIFY_TIMEOUT_MS = 2500;
const MIN_CLASSIFY_TIMEOUT_MS = 250;
const MAX_CLASSIFY_TIMEOUT_MS = 10000;
const DEFAULT_DEMO_BASE_URL = "https://app.silmaril.dev";

const HOOK_LABEL = {
  USER_INPUT: "user_input",
  TOOL_CALL: "tool_call",
  TOOL_RESPONSE: "tool_response",
  LLM_OUTPUT: "llm_output",
} as const;

type RuntimeConfig = {
  apiKey: string;
  apiUrl: string;
  timeoutMs: number;
  blockMalicious: boolean;
  debug: boolean;
};

type RuntimeSource = Record<string, unknown>;
type ClassificationResult = Record<string, unknown>;
type FirewallClient = {
  classify(text: string, options?: ClassifyOptions): Promise<ClassificationResult>;
};
type FirewallConstructor = new (options: {
  apiKey: string;
  apiUrl: string;
  timeoutMs: number;
}) => FirewallClient;
type ClassifyOptions = {
  hook?: string;
  toolName?: string;
  metadata?: Record<string, unknown>;
};
type FirewallSdk = {
  Firewall: FirewallConstructor;
};
type HookTarget = {
  hookEventName: string;
  hook: string;
  text: string;
  metadata: Record<string, unknown>;
  toolName?: string;
  callId?: string;
};
type CompactContext = {
  silmarilFirewall: Record<string, unknown>;
};
type ToolClassificationState = {
  toolCall?: CompactContext;
};
type DebugLogger = (event: string, fields?: Record<string, unknown>) => Promise<void>;

let sdkLoadPromise: Promise<FirewallSdk | undefined> | undefined;
let syntheticPartCounter = 0;

export const SilmarilFirewallPlugin: Plugin = async (input, options = {}) => {
  const toolClassifications = new Map<string, ToolClassificationState>();
  const logger = makeDebugLogger(input, options, process.env);

  return {
    tool: {
      silmaril_demo: tool({
        description: "Open or return the public Silmaril Firewall demo URL.",
        args: {
          route: tool.schema
            .enum(["setup", "playground"])
            .optional()
            .describe("Demo route to open. Defaults to setup."),
          open: tool.schema
            .boolean()
            .optional()
            .describe("Open the URL in the system browser."),
          base_url: tool.schema
            .string()
            .optional()
            .describe("Override the demo base URL for preview validation."),
        },
        async execute(args) {
          const route = args.route ?? "setup";
          const url = buildDemoUrl(args.base_url ?? process.env.SILMARIL_DEMO_BASE_URL, route);
          const opened = args.open ? openBrowser(url) : false;
          return {
            title: "Silmaril Firewall demo",
            output: JSON.stringify({ route, url, opened }, null, 2),
            metadata: { route, url, opened },
          };
        },
      }),
    },

    "chat.message": async (hookInput, output) => {
      const text = extractUserText(output.parts);
      const target: HookTarget = {
        hookEventName: "chat.message",
        hook: HOOK_LABEL.USER_INPUT,
        text,
        metadata: buildMetadata(input, "chat.message", {
          sessionID: hookInput.sessionID,
          messageID: hookInput.messageID ?? output.message.id,
          agent: hookInput.agent,
          modelProviderID: hookInput.model?.providerID,
          modelID: hookInput.model?.modelID,
          variant: hookInput.variant,
        }),
      };
      const result = await classifyTarget(target, options, process.env, logger);
      if (!result) return;

      if (isBlockingEnabled(options, process.env) && isMaliciousClassification(result)) {
        throw new SilmarilFirewallBlockedError(formatBlockReason(result));
      }

      output.parts.push(buildSyntheticContextPart(hookInput.sessionID, output.message.id, target, result));
    },

    "tool.execute.before": async (hookInput, output) => {
      const target: HookTarget = {
        hookEventName: "tool.execute.before",
        hook: HOOK_LABEL.TOOL_CALL,
        text: stableStringify(output.args),
        toolName: hookInput.tool,
        callId: hookInput.callID,
        metadata: buildMetadata(input, "tool.execute.before", {
          sessionID: hookInput.sessionID,
          callId: hookInput.callID,
          toolName: hookInput.tool,
        }),
      };
      const result = await classifyTarget(target, options, process.env, logger);
      if (!result) return;

      toolClassifications.set(cacheKey(hookInput.sessionID, hookInput.callID), {
        toolCall: buildCompactContext(target, result),
      });

      if (isBlockingEnabled(options, process.env) && isMaliciousClassification(result)) {
        throw new SilmarilFirewallBlockedError(formatBlockReason(result));
      }
    },

    "tool.execute.after": async (hookInput, output) => {
      const target: HookTarget = {
        hookEventName: "tool.execute.after",
        hook: HOOK_LABEL.TOOL_RESPONSE,
        text: output.output,
        toolName: hookInput.tool,
        callId: hookInput.callID,
        metadata: buildMetadata(input, "tool.execute.after", {
          sessionID: hookInput.sessionID,
          callId: hookInput.callID,
          toolName: hookInput.tool,
        }),
      };
      const result = await classifyTarget(target, options, process.env, logger);
      const key = cacheKey(hookInput.sessionID, hookInput.callID);
      const previous = toolClassifications.get(key);
      toolClassifications.delete(key);
      if (!result && !previous?.toolCall) return;

      const toolResponse = result ? buildCompactContext(target, result) : undefined;
      const combined = buildCombinedToolContext(previous?.toolCall, toolResponse);
      appendFirewallContext(output, combined);
    },

    "experimental.text.complete": async (hookInput, output) => {
      const target: HookTarget = {
        hookEventName: "experimental.text.complete",
        hook: HOOK_LABEL.LLM_OUTPUT,
        text: output.text,
        metadata: buildMetadata(input, "experimental.text.complete", {
          sessionID: hookInput.sessionID,
          messageID: hookInput.messageID,
          partID: hookInput.partID,
        }),
      };
      await classifyTarget(target, options, process.env, logger);
    },
  };
};

const pluginModule: PluginModule = {
  id: PLUGIN_ID,
  server: SilmarilFirewallPlugin,
};

export default pluginModule;

export class SilmarilFirewallBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SilmarilFirewallBlockedError";
  }
}

export function resolveRuntimeConfig(
  options: RuntimeSource = {},
  env: RuntimeSource = process.env,
): RuntimeConfig | undefined {
  const apiKey = readFirstString(options, ["silmaril_api_key"])
    ?? readFirstString(env, ["SILMARIL_API_KEY"]);
  const apiUrl = readFirstString(options, ["silmaril_api_url"])
    ?? readFirstString(env, ["SILMARIL_API_URL"]);

  if (!apiKey || !apiUrl) {
    return undefined;
  }

  return {
    apiKey,
    apiUrl,
    timeoutMs: readIntegerInRange(
      readFirstRaw(options, ["timeout_ms"])
        ?? readFirstRaw(env, ["SILMARIL_TIMEOUT_MS"]),
      MIN_CLASSIFY_TIMEOUT_MS,
      MAX_CLASSIFY_TIMEOUT_MS,
    ) ?? DEFAULT_CLASSIFY_TIMEOUT_MS,
    blockMalicious: readBoolean(
      readFirstRaw(options, ["block_malicious"])
        ?? readFirstRaw(env, ["SILMARIL_BLOCK_MALICIOUS"]),
    ) ?? false,
    debug: readBoolean(
      readFirstRaw(options, ["debug"])
        ?? readFirstRaw(env, ["SILMARIL_DEBUG"]),
    ) ?? false,
  };
}

export function buildMetadata(
  input: Pick<PluginInput, "project" | "directory" | "worktree">,
  hookEventName: string,
  fields: Record<string, unknown>,
): Record<string, unknown> {
  return omitUndefined({
    silmaril: {
      integration: PLUGIN_ID,
      version: PLUGIN_VERSION,
    },
    opencodeHookEvent: hookEventName,
    sessionId: readString(fields.sessionID),
    messageId: readString(fields.messageID),
    partId: readString(fields.partID),
    callId: readString(fields.callId),
    agent: readString(fields.agent),
    modelProviderId: readString(fields.modelProviderID),
    modelId: readString(fields.modelID),
    variant: readString(fields.variant),
    toolName: readString(fields.toolName),
    projectId: readString((input.project as Record<string, unknown> | undefined)?.id),
    projectName: readString((input.project as Record<string, unknown> | undefined)?.name),
    directory: readString(input.directory),
    worktree: readString(input.worktree),
  });
}

export function extractUserText(parts: unknown[]): string {
  return parts
    .map((part) => readRecord(part))
    .filter((part): part is Record<string, unknown> => part?.type === "text")
    .map((part) => readString(part.text))
    .filter((text): text is string => Boolean(text))
    .join("\n")
    .trim();
}

export function buildSyntheticContextPart(
  sessionID: string,
  messageID: string,
  target: HookTarget,
  result: ClassificationResult,
): {
  id: string;
  sessionID: string;
  messageID: string;
  type: "text";
  text: string;
  synthetic: boolean;
  time: { start: number };
  metadata: { silmarilFirewall: boolean };
} {
  return {
    id: nextSyntheticPartId(),
    sessionID,
    messageID,
    type: "text",
    text: formatContextObject(buildCompactContext(target, result)),
    synthetic: true,
    time: { start: Date.now() },
    metadata: {
      silmarilFirewall: true,
    },
  };
}

export function buildCompactContext(target: HookTarget, result: ClassificationResult): CompactContext {
  return {
    silmarilFirewall: omitUndefined({
      hook: target.hook,
      opencodeHookEvent: target.hookEventName,
      toolName: target.toolName,
      callId: target.callId,
      classification: summarizeClassification(result),
    }),
  };
}

export function buildCombinedToolContext(
  toolCall: CompactContext | undefined,
  toolResponse: CompactContext | undefined,
): CompactContext {
  return {
    silmarilFirewall: omitUndefined({
      toolCall: toolCall?.silmarilFirewall,
      toolResponse: toolResponse?.silmarilFirewall,
    }),
  };
}

export function appendFirewallContext(
  output: { output: string; metadata: unknown },
  context: CompactContext,
): void {
  const formatted = formatContextObject(context);
  output.output = output.output
    ? `${output.output}\n\n${formatted}`
    : formatted;
  output.metadata = {
    ...(readRecord(output.metadata) ?? {}),
    silmarilFirewall: context.silmarilFirewall,
  };
}

export function formatContextObject(context: CompactContext): string {
  return "Silmaril Firewall classification:\n```json\n"
    + JSON.stringify(context, null, 2)
    + "\n```";
}

export function summarizeClassification(result: ClassificationResult): Record<string, unknown> {
  return omitUndefined({
    prediction: result.prediction,
    score: result.score,
    threshold: result.threshold,
    primaryOutcome: result.primaryOutcome,
    outcomeScores: readRecord(result.outcomeScores) ?? {},
    detectorScores: readRecord(result.detectorScores) ?? {},
    detectorCounts: readRecord(result.detectorCounts) ?? {},
  });
}

export function buildLogSummary(target: HookTarget, result: ClassificationResult): Record<string, unknown> {
  return omitUndefined({
    hookEventName: target.hookEventName,
    hook: target.hook,
    toolName: target.toolName,
    callId: target.callId,
    prediction: result.prediction,
    score: result.score,
    threshold: result.threshold,
    primaryOutcome: result.primaryOutcome,
  });
}

export function isMaliciousClassification(result: ClassificationResult): boolean {
  const prediction = readString(result.prediction)?.toLowerCase();
  if (prediction === "malicious") {
    return true;
  }
  return typeof result.blocked === "boolean" ? result.blocked : false;
}

export function formatBlockReason(result: ClassificationResult): string {
  const summary = summarizeClassification(result);
  const parts = ["Silmaril Firewall classified this event as malicious"];
  const primaryOutcome = readString(summary.primaryOutcome);
  const score = readFiniteNumber(summary.score);
  const threshold = readFiniteNumber(summary.threshold);
  if (primaryOutcome) {
    parts.push(`primaryOutcome=${primaryOutcome}`);
  }
  if (score !== undefined) {
    parts.push(`score=${score}`);
  }
  if (threshold !== undefined) {
    parts.push(`threshold=${threshold}`);
  }
  return parts.join("; ");
}

export function stableStringify(value: unknown): string {
  if (value === undefined) {
    return "";
  }
  const seen = new WeakSet<object>();
  try {
    return JSON.stringify(sortForStableStringify(value, seen)) ?? "";
  } catch {
    return String(value ?? "");
  }
}

export function buildDemoUrl(
  baseUrl: string | undefined = DEFAULT_DEMO_BASE_URL,
  route: "setup" | "playground" = "setup",
): string {
  const rawBase = readString(baseUrl) ?? DEFAULT_DEMO_BASE_URL;
  const normalizedBase = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawBase)
    ? rawBase
    : `https://${rawBase}`;
  const parsed = new URL(normalizedBase);
  const path = route === "playground" ? "/demo/playground" : "/demo/setup-complete";
  return `${parsed.origin}${path}`;
}

export function openBrowser(url: string): boolean {
  const command = platform() === "darwin"
    ? "open"
    : platform() === "win32"
      ? "cmd"
      : "xdg-open";
  const args = platform() === "win32"
    ? ["/c", "start", "", url]
    : [url];
  try {
    const child = spawn(command, args, {
      detached: true,
      stdio: "ignore",
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

async function classifyTarget(
  target: HookTarget,
  options: PluginOptions,
  env: RuntimeSource,
  logger: DebugLogger,
): Promise<ClassificationResult | undefined> {
  const debugEnabled = isDebugEnabled(options, env);
  const config = resolveRuntimeConfig(options, env);
  if (!config) {
    await logger("missing_config");
    return undefined;
  }
  if (!target.text.trim()) {
    await logger("empty_text", { hookEventName: target.hookEventName, hook: target.hook });
    return undefined;
  }

  const sdk = await loadFirewallSdk();
  if (!sdk) {
    await logger("sdk_import_failure", { hookEventName: target.hookEventName, hook: target.hook });
    return undefined;
  }

  try {
    const firewall = new sdk.Firewall({
      apiKey: config.apiKey,
      apiUrl: config.apiUrl,
      timeoutMs: config.timeoutMs,
    });
    const result = await firewall.classify(target.text, {
      hook: target.hook,
      toolName: target.toolName,
      metadata: target.metadata,
    });
    if (debugEnabled) {
      await logger("classification_result", buildLogSummary(target, result));
    }
    return result;
  } catch (err) {
    await logger("classification_error", {
      hookEventName: target.hookEventName,
      hook: target.hook,
      toolName: target.toolName,
      callId: target.callId,
      errorName: err instanceof Error ? err.name : typeof err,
    });
    return undefined;
  }
}

function isBlockingEnabled(options: RuntimeSource, env: RuntimeSource): boolean {
  return resolveRuntimeConfig(options, env)?.blockMalicious ?? false;
}

function isDebugEnabled(options: RuntimeSource, env: RuntimeSource): boolean {
  return readBoolean(
    readFirstRaw(options, ["debug"])
      ?? readFirstRaw(env, ["SILMARIL_DEBUG"]),
  ) ?? false;
}

function makeDebugLogger(input: PluginInput, options: RuntimeSource, env: RuntimeSource): DebugLogger {
  return async (event, fields = {}) => {
    if (!isDebugEnabled(options, env)) {
      return;
    }
    try {
      await input.client.app.log({
        body: {
          service: PLUGIN_ID,
          level: "debug",
          message: event,
          extra: omitUndefined(fields),
        },
        query: {
          directory: input.directory,
        },
      });
    } catch {
      // Logging must not affect agent execution.
    }
  };
}

async function loadFirewallSdk(): Promise<FirewallSdk | undefined> {
  sdkLoadPromise ??= import("@silmaril-security/sdk")
    .then((module) => {
      const maybeFirewall = (module as Record<string, unknown>).Firewall;
      return typeof maybeFirewall === "function"
        ? { Firewall: maybeFirewall as FirewallConstructor }
        : undefined;
    })
    .catch(() => undefined);
  return sdkLoadPromise;
}

function readRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readFiniteNumber(value: unknown): number | undefined {
  const numberValue = typeof value === "string" && value.trim()
    ? Number(value)
    : value;
  return typeof numberValue === "number" && Number.isFinite(numberValue)
    ? numberValue
    : undefined;
}

function readIntegerInRange(value: unknown, min: number, max: number): number | undefined {
  const numberValue = readFiniteNumber(value);
  if (numberValue === undefined) {
    return undefined;
  }
  const integerValue = Math.trunc(numberValue);
  return integerValue >= min && integerValue <= max ? integerValue : undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return undefined;
}

function readFirstRaw(source: RuntimeSource, keys: readonly string[]): unknown {
  for (const key of keys) {
    const value = source[key];
    if (value !== undefined) {
      return value;
    }
  }
  return undefined;
}

function readFirstString(source: RuntimeSource, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = readString(source[key]);
    if (value) {
      return value;
    }
  }
  return undefined;
}

function sortForStableStringify(value: unknown, seen: WeakSet<object>): unknown {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    return "[Circular]";
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map((entry) => sortForStableStringify(entry, seen));
  }
  const record = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(record)
      .sort()
      .map((key) => [key, sortForStableStringify(record[key], seen)]),
  );
}

function omitUndefined<T extends Record<string, unknown>>(record: T): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(record).filter((entry) => entry[1] !== undefined),
  );
}

function nextSyntheticPartId(): string {
  syntheticPartCounter += 1;
  return `prt_silmaril_${Date.now().toString(36)}_${syntheticPartCounter.toString(36)}`;
}

function cacheKey(sessionID: string, callID: string): string {
  return `${sessionID}:${callID}`;
}

export const __testInternals = {
  resolveRuntimeConfig,
  buildMetadata,
  extractUserText,
  buildSyntheticContextPart,
  buildCompactContext,
  buildCombinedToolContext,
  appendFirewallContext,
  formatContextObject,
  summarizeClassification,
  buildLogSummary,
  isMaliciousClassification,
  formatBlockReason,
  stableStringify,
  buildDemoUrl,
};
