import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { platform } from "node:os";
import type {
  Plugin,
  PluginInput,
  PluginModule,
  PluginOptions,
} from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";
import {
  buildLocalProtectionEvent,
  emitLocalProtectionEvent,
  emitLocalProtectionEventBestEffort,
  flushLocalEvidenceWritesForTests,
  resolveLocalEventDirectory,
  type LocalProtectionEventInput,
} from "./local-evidence.js";

const PLUGIN_ID = "opencode-firewall-plugin";
const PLUGIN_VERSION = "0.3.1";
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
  endpointId?: string;
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
  requestId?: string;
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
type DebugLogger = (event: string, fields?: Record<string, unknown>) => Promise<void>;
type FirewallRuntime = {
  getClient(config: RuntimeConfig): Promise<FirewallClient | undefined>;
};

export const SilmarilFirewallPlugin: Plugin = async (input, options = {}) => {
  const logger = makeDebugLogger(input, options, process.env);
  const firewallRuntime = createFirewallRuntime();
  const childSessions = new Map<string, string>();
  const observedTraceSegments = new Map<string, Set<string>>();

  const observeTarget = async (target: HookTarget): Promise<void> => {
    const result = await classifyTarget(
      target,
      options,
      process.env,
      logger,
      firewallRuntime,
    );
    if (!result) return;
    emitOpenCodeLocalEvidence(
      target,
      result,
      options,
      process.env,
      "allowed",
      false,
    );
  };

  return {
    event: async ({ event }) => {
      const eventRecord = readRecord(event);
      const eventType = readString(eventRecord?.type);
      const properties = readRecord(eventRecord?.properties);
      if (!eventType || !properties) {
        return;
      }

      if (eventType === "session.created") {
        const session = readRecord(properties.info);
        const sessionID = readString(session?.id);
        const parentID = readString(session?.parentID);
        if (!sessionID || !parentID) {
          return;
        }
        childSessions.set(sessionID, parentID);
        const title = readString(session?.title);
        if (!title) {
          return;
        }
        await observeTarget({
          hookEventName: "subagent.start",
          hook: HOOK_LABEL.USER_INPUT,
          text: title,
          metadata: buildMetadata(input, "subagent.start", {
            sessionID,
            parentSessionID: parentID,
            traceSource: "session.created",
          }),
        });
        return;
      }

      if (eventType === "session.deleted") {
        const session = readRecord(properties.info);
        const sessionID = readString(session?.id);
        if (sessionID) {
          childSessions.delete(sessionID);
          observedTraceSegments.delete(sessionID);
        }
        return;
      }

      if (eventType !== "session.idle") {
        return;
      }
      const sessionID = readString(properties.sessionID);
      if (!sessionID) {
        return;
      }
      const parentID = await resolveParentSessionID(input, sessionID, childSessions);
      if (!parentID) {
        return;
      }
      const traceSegments = await readOpenCodeTraceSegments(input, sessionID);
      const observedForSession = observedTraceSegments.get(sessionID) ?? new Set<string>();
      observedTraceSegments.set(sessionID, observedForSession);
      for (const [traceIndex, segment] of traceSegments.entries()) {
        const identity = sha256(stableStringify({
          sessionID,
          messageID: segment.messageID,
          partID: segment.partID,
          traceIndex,
          source: segment.source,
          hook: segment.hook,
          contentHash: sha256(segment.text),
        }));
        if (observedForSession.has(identity)) {
          continue;
        }
        observedForSession.add(identity);
        const target: HookTarget = {
          hookEventName: "subagent.trace",
          hook: segment.hook,
          text: segment.text,
          toolName: segment.toolName,
          callId: segment.callId,
          metadata: buildMetadata(input, "subagent.trace", {
            sessionID,
            parentSessionID: parentID,
            messageID: segment.messageID,
            partID: segment.partID,
            traceIndex,
            traceSource: segment.source,
            traceRole: segment.role,
            toolName: segment.toolName,
            callId: segment.callId,
          }),
        };
        const result = await classifyTarget(
          target,
          options,
          process.env,
          logger,
          firewallRuntime,
        );
        if (!result) {
          observedForSession.delete(identity);
          continue;
        }
        emitOpenCodeLocalEvidence(
          target,
          result,
          options,
          process.env,
          "allowed",
          false,
        );
      }
    },

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
      const result = await classifyTarget(target, options, process.env, logger, firewallRuntime);
      if (!result) return;

      const blocked = isBlockingEnabled(options, process.env)
        && shouldBlockClassification(result);
      emitOpenCodeLocalEvidence(
        target,
        result,
        options,
        process.env,
        blocked ? "block_returned" : "allowed",
      );
      if (blocked) {
        throw new SilmarilFirewallBlockedError(formatBlockReason(result));
      }
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
      const result = await classifyTarget(target, options, process.env, logger, firewallRuntime);
      if (!result) return;
      const blocked = isBlockingEnabled(options, process.env)
        && shouldBlockClassification(result);
      emitOpenCodeLocalEvidence(
        target,
        result,
        options,
        process.env,
        blocked ? "block_returned" : "allowed",
      );
      if (blocked) {
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
      const result = await classifyTarget(target, options, process.env, logger, firewallRuntime);
      if (!result) return;
      const blocked = isBlockingEnabled(options, process.env)
        && shouldBlockClassification(result);
      emitOpenCodeLocalEvidence(
        target,
        result,
        options,
        process.env,
        blocked ? "content_replaced" : "allowed",
      );
      if (blocked) {
        const combined = buildCombinedToolContext(
          undefined,
          buildCompactContext(target, result),
        );
        replaceWithBlockedOutput(output, target, result, combined);
      }
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
      const result = await classifyTarget(target, options, process.env, logger, firewallRuntime);
      if (!result) return;
      const blocked = isBlockingEnabled(options, process.env)
        && shouldBlockClassification(result);
      emitOpenCodeLocalEvidence(
        target,
        result,
        options,
        process.env,
        blocked ? "content_replaced" : "allowed",
      );
      if (blocked) {
        output.text = buildBlockedReplacement(target, result);
      }
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
  const endpointId = readEndpointId(
    readFirstString(options, ["endpoint_id"])
      ?? readFirstString(env, ["SILMARIL_ENDPOINT_ID"]),
  );

  if (!apiKey || !apiUrl) {
    return undefined;
  }

  return {
    apiKey,
    apiUrl,
    ...(endpointId ? { endpointId } : {}),
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
    conversationId: readString(fields.sessionID),
    sessionId: readString(fields.sessionID),
    parentSessionId: readString(fields.parentSessionID),
    messageId: readString(fields.messageID),
    partId: readString(fields.partID),
    callId: readString(fields.callId),
    agent: readString(fields.agent),
    modelProviderId: readString(fields.modelProviderID),
    modelId: readString(fields.modelID),
    variant: readString(fields.variant),
    toolName: readString(fields.toolName),
    traceIndex: readFiniteNumber(fields.traceIndex),
    traceSource: readString(fields.traceSource),
    traceRole: readString(fields.traceRole),
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

export function buildCompactContext(target: HookTarget, result: ClassificationResult): CompactContext {
  return {
    silmarilFirewall: omitUndefined({
      hook: target.hook,
      opencodeHookEvent: target.hookEventName,
      toolName: target.toolName,
      callId: target.callId,
      risk: describeRisk(result),
      surface: describeSurface(target),
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

export function replaceWithBlockedOutput(
  output: { title?: string; output: string; metadata: unknown },
  target: HookTarget,
  result: ClassificationResult,
  context: CompactContext,
): void {
  output.title = "Silmaril Firewall blocked tool output";
  output.output = buildBlockedReplacement(target, result);
  output.metadata = {
    ...(readRecord(output.metadata) ?? {}),
    silmarilFirewall: {
      ...context.silmarilFirewall,
      blocked: true,
    },
  };
}

export function buildBlockedReplacement(target: HookTarget, result: ClassificationResult): string {
  return formatDecisionText(target, result, {
    title: "Silmaril Firewall blocked unsafe content",
    action: "The original content was withheld before downstream model consumption.",
  });
}

export function summarizeClassification(result: ClassificationResult): Record<string, unknown> {
  return omitUndefined({
    prediction: result.prediction,
    risk: describeRisk(result),
    blocked: shouldBlockClassification(result),
  });
}

export function buildLogSummary(target: HookTarget, result: ClassificationResult): Record<string, unknown> {
  return omitUndefined({
    hookEventName: target.hookEventName,
    hook: target.hook,
    toolName: target.toolName,
    callId: target.callId,
    prediction: result.prediction,
    score: readFiniteNumber(result.score),
    threshold: readFiniteNumber(result.threshold),
    primaryOutcome: readString(result.primaryOutcome) ?? readString(result.primary_outcome),
    risk: describeRisk(result),
    blocked: shouldBlockClassification(result),
  });
}

export function shouldBlockClassification(result: ClassificationResult): boolean {
  return result.prediction === "MALICIOUS";
}

/** @deprecated Use shouldBlockClassification. */
export const isMaliciousClassification = shouldBlockClassification;

export function formatBlockReason(result: ClassificationResult): string {
  return `Silmaril Firewall blocked this request: ${describeRisk(result)}. Continue without using the blocked content.`;
}

export function formatDecisionText(
  target: HookTarget,
  result: ClassificationResult,
  copy: { title: string; action: string },
): string {
  return [
    copy.title,
    "",
    `Surface: ${describeSurface(target)}`,
    `Risk: ${describeRisk(result)}`,
    `Action: ${copy.action}`,
    `Next step: ${describeNextStep(describeSurface(target))}`,
  ].join("\n");
}

function describeNextStep(surface: string): string {
  if (surface.startsWith("tool result")) {
    return "Do not use the withheld tool result. Retry with a safer tool, skip this step, or ask the user how to proceed.";
  }
  if (surface.startsWith("final assistant output")) {
    return "Do not send the withheld output. Continue with a safer response that avoids the flagged content.";
  }
  if (surface.startsWith("tool call")) {
    return "Choose a safer tool call or ask the user how to proceed before retrying.";
  }
  return "Ask the user to rephrase the request or remove sensitive instructions before continuing.";
}

function describeSurface(target: Pick<HookTarget, "hookEventName" | "toolName" | "callId">): string {
  const base = target.hookEventName === "experimental.text.complete"
    ? "final assistant output"
    : target.hookEventName === "tool.execute.after"
      ? "tool result"
      : target.hookEventName === "tool.execute.before"
        ? "tool call"
        : "user prompt";
  const tool = target.toolName ? ` (${target.toolName})` : "";
  const id = target.callId ? ` [${target.callId}]` : "";
  return `${base}${tool}${id}`;
}

function describeRisk(result: ClassificationResult): string {
  const outcome = readString(result.primaryOutcome) ?? readString(result.primary_outcome);
  if (!outcome) {
    return "Unsafe content";
  }
  switch (outcome.trim().toLowerCase()) {
    case "information_disclosure":
      return "Sensitive information disclosure";
    case "secret_exposure":
      return "Secret or credential exposure";
    case "control_abuse":
    case "prompt_injection":
      return "Unsafe agent control attempt";
    case "system_compromise":
      return "System compromise risk";
    case "service_disruption":
      return "Service disruption risk";
    case "benign":
      return shouldBlockClassification(result) ? "Unexpected classification conflict" : "No flagged risk";
    default:
      return outcome
        .replace(/[_-]+/g, " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());
  }
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

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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
  firewallRuntime: FirewallRuntime,
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

  const firewall = await firewallRuntime.getClient(config);
  if (!firewall) {
    await logger("sdk_import_failure", { hookEventName: target.hookEventName, hook: target.hook });
    return undefined;
  }

  try {
    const result = await firewall.classify(target.text, {
      hook: target.hook,
      toolName: target.toolName,
      metadata: withProvenance(target.metadata, config.endpointId),
      requestId: buildLogicalRequestId(target),
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

function emitOpenCodeLocalEvidence(
  target: HookTarget,
  result: ClassificationResult,
  options: RuntimeSource,
  env: RuntimeSource,
  nativeAction: LocalProtectionEventInput["nativeAction"],
  enforceable = true,
): void {
  const blocking = isBlockingEnabled(options, env);
  const malicious = shouldBlockClassification(result);
  emitLocalProtectionEventBestEffort({
    hook: localEvidenceHook(target.hookEventName),
    mode: blocking ? "block" : "shadow",
    rawText: target.text,
    requestIdentity: buildLogicalRequestId(target),
    sessionIdentity: readString(target.metadata.sessionId),
    toolName: target.toolName,
    classification: result,
    policyDecision: malicious
      ? blocking && enforceable
        ? "block"
        : "monitor"
      : "allow",
    nativeAction,
    pluginVersion: PLUGIN_VERSION,
  });
}

function localEvidenceHook(
  hookEventName: string,
): LocalProtectionEventInput["hook"] {
  switch (hookEventName) {
    case "chat.message":
      return "user_input";
    case "tool.execute.before":
      return "pre_tool";
    case "tool.execute.after":
      return "post_tool";
    case "experimental.text.complete":
      return "llm_output";
    case "subagent.start":
    case "subagent.trace":
      return "subagent";
    default:
      return "user_input";
  }
}

function isDebugEnabled(options: RuntimeSource, env: RuntimeSource): boolean {
  return readBoolean(
    readFirstRaw(options, ["debug"])
      ?? readFirstRaw(env, ["SILMARIL_DEBUG"]),
  ) ?? false;
}

type OpenCodeTraceSegment = {
  text: string;
  hook: string;
  source: string;
  messageID?: string;
  partID?: string;
  role?: string;
  toolName?: string;
  callId?: string;
};

async function resolveParentSessionID(
  input: PluginInput,
  sessionID: string,
  childSessions: Map<string, string>,
): Promise<string | undefined> {
  const cached = childSessions.get(sessionID);
  if (cached) {
    return cached;
  }
  try {
    const response = await input.client.session.get({
      path: { id: sessionID },
      query: { directory: input.directory },
    });
    const session = readRecord(response.data);
    const parentID = readString(session?.parentID);
    if (parentID) {
      childSessions.set(sessionID, parentID);
    }
    return parentID;
  } catch {
    return undefined;
  }
}

async function readOpenCodeTraceSegments(
  input: PluginInput,
  sessionID: string,
): Promise<OpenCodeTraceSegment[]> {
  let messages: unknown;
  try {
    const response = await input.client.session.messages({
      path: { id: sessionID },
      query: { directory: input.directory },
    });
    messages = response.data;
  } catch {
    return [];
  }
  if (!Array.isArray(messages)) {
    return [];
  }

  const segments: OpenCodeTraceSegment[] = [];
  for (const entry of messages) {
    const messageEntry = readRecord(entry);
    const info = readRecord(messageEntry?.info);
    const role = readString(info?.role);
    const messageID = readString(info?.id);
    const parts = Array.isArray(messageEntry?.parts) ? messageEntry.parts : [];
    for (const partValue of parts) {
      const part = readRecord(partValue);
      const partType = readString(part?.type);
      const partID = readString(part?.id);
      if (!part || !partType) {
        continue;
      }
      if (partType === "text") {
        const text = readString(part.text);
        if (text) {
          segments.push({
            text,
            hook: role === "assistant" ? HOOK_LABEL.LLM_OUTPUT : HOOK_LABEL.USER_INPUT,
            source: "text",
            messageID,
            partID,
            role,
          });
        }
        continue;
      }
      if (partType === "reasoning") {
        const text = readString(part.text);
        if (text) {
          segments.push({
            text,
            hook: HOOK_LABEL.LLM_OUTPUT,
            source: "reasoning",
            messageID,
            partID,
            role: "assistant",
          });
        }
        continue;
      }
      if (partType === "subtask") {
        const text = stableStringify(omitUndefined({
          prompt: part.prompt,
          description: part.description,
          agent: part.agent,
        }));
        if (text.trim() && text !== "{}") {
          segments.push({
            text,
            hook: HOOK_LABEL.USER_INPUT,
            source: "subtask",
            messageID,
            partID,
            role,
          });
        }
        continue;
      }
      if (partType !== "tool") {
        continue;
      }
      const state = readRecord(part.state);
      const toolName = readString(part.tool);
      const callId = readString(part.callID);
      const inputText = stableStringify(state?.input);
      if (inputText.trim()) {
        segments.push({
          text: inputText,
          hook: HOOK_LABEL.TOOL_CALL,
          source: "tool_input",
          messageID,
          partID,
          role,
          toolName,
          callId,
        });
      }
      const outputText = readString(state?.output) ?? readString(state?.error);
      if (outputText) {
        segments.push({
          text: outputText,
          hook: HOOK_LABEL.TOOL_RESPONSE,
          source: readString(state?.status) === "error" ? "tool_error" : "tool_output",
          messageID,
          partID,
          role,
          toolName,
          callId,
        });
      }
    }
  }
  return segments;
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

function createFirewallRuntime(): FirewallRuntime {
  let sdkLoadPromise: Promise<FirewallSdk | undefined> | undefined;
  let clientCache: { key: string; client: FirewallClient } | undefined;

  async function loadFirewallSdk(): Promise<FirewallSdk | undefined> {
    sdkLoadPromise ??= import("@silmaril-security/sdk")
      .then((module) => {
        const maybeFirewall = (module as Record<string, unknown>).Firewall;
        return typeof maybeFirewall === "function"
          ? { Firewall: maybeFirewall as FirewallConstructor }
          : undefined;
      })
      .catch(() => {
        sdkLoadPromise = undefined;
        return undefined;
      });
    const sdk = await sdkLoadPromise;
    if (!sdk) {
      sdkLoadPromise = undefined;
    }
    return sdk;
  }

  return {
    async getClient(config) {
      const key = stableStringify({
        apiKey: config.apiKey,
        apiUrl: config.apiUrl,
        timeoutMs: config.timeoutMs,
      });
      if (clientCache?.key === key) {
        return clientCache.client;
      }

      const sdk = await loadFirewallSdk();
      if (!sdk) {
        clientCache = undefined;
        return undefined;
      }

      const client = new sdk.Firewall({
        apiKey: config.apiKey,
        apiUrl: config.apiUrl,
        timeoutMs: config.timeoutMs,
      });
      clientCache = { key, client };
      return client;
    },
  };
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

export function withProvenance(
  metadata: Record<string, unknown>,
  endpointId?: string,
): Record<string, unknown> {
  const silmaril = readRecord(metadata.silmaril) ?? {};
  return {
    ...metadata,
    silmaril: {
      ...silmaril,
      provenance: omitUndefined({
        schema_version: 1,
        endpoint_id: endpointId,
        harness: "opencode",
      }),
    },
  };
}

function readEndpointId(value: string | undefined): string | undefined {
  return value && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
    ? value
    : undefined;
}

export function buildLogicalRequestId(target: HookTarget): string | undefined {
  const stableEventId = readString(target.metadata.callId)
    ?? readString(target.metadata.partId)
    ?? readString(target.metadata.messageId);
  if (!stableEventId) return undefined;
  const digest = createHash("sha256")
    .update(stableStringify({
      integration: PLUGIN_ID,
      hookEventName: target.hookEventName,
      hook: target.hook,
      conversationId: readString(target.metadata.conversationId),
      stableEventId,
      contentHash: createHash("sha256").update(target.text).digest("hex"),
    }))
    .digest("hex");
  return `${PLUGIN_ID}-${digest}`;
}

export const __testInternals = {
  resolveRuntimeConfig,
  buildMetadata,
  withProvenance,
  extractUserText,
  buildCompactContext,
  buildCombinedToolContext,
  replaceWithBlockedOutput,
  buildBlockedReplacement,
  formatDecisionText,
  summarizeClassification,
  buildLogSummary,
  shouldBlockClassification,
  isMaliciousClassification,
  formatBlockReason,
  stableStringify,
  buildLogicalRequestId,
  readOpenCodeTraceSegments,
  resolveParentSessionID,
  buildDemoUrl,
  buildLocalProtectionEvent,
  emitLocalProtectionEvent,
  flushLocalEvidenceWritesForTests,
  resolveLocalEventDirectory,
};
