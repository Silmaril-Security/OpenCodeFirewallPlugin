import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  rename,
  rm,
} from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

const EVENT_SCHEMA_VERSION = 1;
const MAX_EVENT_BYTES = 64 * 1024;
const RUNTIME_CHECK_MARKER = /\bsilmaril-runtime-check:([A-Za-z0-9-]{16,128})\b/;
const pendingWrites = new Set<Promise<void>>();

type ClassificationLike = Record<string, unknown>;

export type LocalProtectionEventInput = {
  hook: "user_input" | "pre_tool" | "post_tool" | "llm_output";
  mode: "block" | "shadow";
  rawText: string;
  requestIdentity?: string;
  sessionIdentity?: string;
  toolName?: string;
  classification: ClassificationLike;
  policyDecision: "allow" | "monitor" | "block";
  nativeAction: "allowed" | "block_returned" | "content_replaced";
  pluginVersion: string;
  occurredAt?: Date;
};

export type LocalProtectionEventV1 = {
  schemaVersion: 1;
  id: string;
  occurredAt: string;
  host: "openCode";
  hook: LocalProtectionEventInput["hook"];
  mode: LocalProtectionEventInput["mode"];
  requestFingerprint: string;
  sessionFingerprint?: string;
  toolDisplayName?: string;
  riskClass: string;
  attemptedConsequence: {
    category: string;
    summary: string;
  };
  prediction: "benign" | "malicious" | "unknown" | "unavailable";
  modelScore?: number;
  modelThreshold?: number;
  policyDecision: LocalProtectionEventInput["policyDecision"];
  nativeAction: LocalProtectionEventInput["nativeAction"];
  outcome: "not_observed";
  evidenceTruth: "plugin_reported" | "native_response_returned";
  evidenceCompleteness: "partial";
  provenance: {
    schemaVersion: 1;
    producer: "opencode-firewall-plugin";
    producerVersion: string;
    pluginVersion: string;
    policyVersion: "opencode-plugin-policy-v1";
    observedAt: string;
  };
};

type EmitOptions = {
  directory?: string;
  environment?: Record<string, string | undefined>;
  homeDirectory?: string;
};

const CONSEQUENCE_SUMMARIES: Record<string, string> = {
  credential_exposure: "A credential or secret could be exposed.",
  sensitive_data_exposure: "Sensitive data could be exposed.",
  code_execution: "The action could lead to unsafe code execution.",
  destructive_change: "The action could disrupt service or cause a destructive change.",
  external_communication: "The action could communicate with an external destination.",
  privilege_change: "The action could change privileges.",
  unsafe_agent_control: "The action could take unsafe control of an AI agent.",
  other: "The action could cause an unsafe consequence.",
  unknown: "No specific harmful consequence was identified by the plugin.",
};

export function buildLocalProtectionEvent(
  input: LocalProtectionEventInput,
): LocalProtectionEventV1 {
  const occurredAt = (input.occurredAt ?? new Date()).toISOString();
  const prediction = normalizePrediction(input.classification.prediction);
  const riskClass = consequenceCategory(input.classification, prediction);
  const runtimeMarker = input.rawText.match(RUNTIME_CHECK_MARKER)?.[0];
  const requestFingerprint = runtimeMarker
    ? sha256(runtimeMarker)
    : fingerprint([
      "opencode-firewall-plugin",
      input.hook,
      input.requestIdentity ?? "",
      sha256(input.rawText),
    ]);
  const sessionFingerprint = input.sessionIdentity
    ? fingerprint(["openCode", input.sessionIdentity])
    : undefined;
  const id = stableID("protection-event", [
    "openCode",
    input.hook,
    requestFingerprint,
    sessionFingerprint ?? "",
    input.mode,
    input.policyDecision,
    input.nativeAction,
    input.requestIdentity ? "" : occurredAt,
  ]);
  const modelScore = unitInterval(input.classification.score);
  const modelThreshold = unitInterval(input.classification.threshold);

  return omitUndefined({
    schemaVersion: EVENT_SCHEMA_VERSION,
    id,
    occurredAt,
    host: "openCode",
    hook: input.hook,
    mode: input.mode,
    requestFingerprint,
    sessionFingerprint,
    toolDisplayName: safeToolName(input.toolName),
    riskClass,
    attemptedConsequence: {
      category: riskClass,
      summary: CONSEQUENCE_SUMMARIES[riskClass] ?? CONSEQUENCE_SUMMARIES.unknown,
    },
    prediction,
    modelScore,
    modelThreshold,
    policyDecision: input.policyDecision,
    nativeAction: input.nativeAction,
    outcome: "not_observed",
    evidenceTruth: input.nativeAction === "block_returned"
        || input.nativeAction === "content_replaced"
      ? "native_response_returned"
      : "plugin_reported",
    evidenceCompleteness: "partial",
    provenance: {
      schemaVersion: 1,
      producer: "opencode-firewall-plugin",
      producerVersion: bounded(input.pluginVersion, 128),
      pluginVersion: bounded(input.pluginVersion, 128),
      policyVersion: "opencode-plugin-policy-v1",
      observedAt: occurredAt,
    },
  }) as LocalProtectionEventV1;
}

export function emitLocalProtectionEventBestEffort(
  input: LocalProtectionEventInput,
  options: EmitOptions = {},
): void {
  const pending = emitLocalProtectionEvent(input, options)
    .then(() => undefined)
    .catch(() => {
      // Evidence is best-effort and must never affect native enforcement.
    })
    .finally(() => {
      pendingWrites.delete(pending);
    });
  pendingWrites.add(pending);
}

export async function flushLocalEvidenceWritesForTests(): Promise<void> {
  await Promise.all([...pendingWrites]);
}

export async function emitLocalProtectionEvent(
  input: LocalProtectionEventInput,
  options: EmitOptions = {},
): Promise<string> {
  const event = buildLocalProtectionEvent(input);
  const encoded = Buffer.from(`${JSON.stringify(event)}\n`, "utf8");
  if (encoded.byteLength > MAX_EVENT_BYTES) {
    throw new Error("Local protection event exceeds the bounded event size.");
  }

  const directory = options.directory
    ?? resolveLocalEventDirectory(
      options.environment ?? process.env,
      options.homeDirectory ?? homedir(),
    );
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryStat = await lstat(directory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error("Local evidence directory must be a real directory.");
  }
  await chmod(directory, 0o700);

  const eventDigest = sha256(event.id);
  const destination = path.join(directory, `event-${eventDigest}.json`);
  const temporary = path.join(
    directory,
    `.event-${eventDigest}.${process.pid}.${randomUUID()}.tmp`,
  );
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(encoded);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
    await chmod(destination, 0o600);
    return destination;
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

export function resolveLocalEventDirectory(
  environment: Record<string, string | undefined> = process.env,
  homeDirectory = homedir(),
): string {
  const incoming = environment.SILMARIL_LOCAL_EVENT_DIR?.trim();
  if (incoming) return incoming;
  const root = environment.SILMARIL_EVIDENCE_ROOT?.trim();
  if (root) return path.join(root, "incoming");
  return path.join(
    homeDirectory,
    "Library",
    "Application Support",
    "Silmaril",
    "Evidence",
    "incoming",
  );
}

function normalizePrediction(
  value: unknown,
): LocalProtectionEventV1["prediction"] {
  if (value === "MALICIOUS") return "malicious";
  if (value === "BENIGN") return "benign";
  if (value === undefined || value === null) return "unavailable";
  return "unknown";
}

function consequenceCategory(
  classification: ClassificationLike,
  prediction: LocalProtectionEventV1["prediction"],
): string {
  const raw = typeof classification.primaryOutcome === "string"
    ? classification.primaryOutcome
    : typeof classification.primary_outcome === "string"
      ? classification.primary_outcome
      : undefined;
  switch (raw?.trim().toLowerCase()) {
    case "secret_exposure":
      return "credential_exposure";
    case "information_disclosure":
      return "sensitive_data_exposure";
    case "system_compromise":
      return "code_execution";
    case "service_disruption":
      return "destructive_change";
    case "external_communication":
      return "external_communication";
    case "privilege_change":
      return "privilege_change";
    case "control_abuse":
    case "prompt_injection":
      return "unsafe_agent_control";
    case "benign":
    case undefined:
      return prediction === "malicious" ? "other" : "unknown";
    default:
      return prediction === "malicious" ? "other" : "unknown";
  }
}

function safeToolName(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed || trimmed.length > 64) return undefined;
  if (!/^[A-Za-z][A-Za-z0-9._/-]*$/.test(trimmed)) return "redacted_tool";
  if (/(secret|token|credential|password|api[_-]?key)/i.test(trimmed)) {
    return "redacted_tool";
  }
  return trimmed;
}

function bounded(value: string, maximum: number): string {
  return value
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .trim()
    .slice(0, maximum);
}

function unitInterval(value: unknown): number | undefined {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= 0
    && value <= 1
    ? value
    : undefined;
}

function fingerprint(components: string[]): string {
  return `sha256:${sha256(frame(components))}`;
}

function stableID(namespace: string, components: string[]): string {
  return `${namespace}:${sha256(frame([namespace, ...components]))}`;
}

function frame(components: string[]): string {
  return components
    .map((component) => `${Buffer.byteLength(component, "utf8")}:${component}`)
    .join("|");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function omitUndefined<T extends Record<string, unknown>>(record: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(record).filter(([, value]) => value !== undefined),
  ) as Partial<T>;
}
