#!/usr/bin/env node
import { spawn } from "node:child_process";
import { platform } from "node:os";

const DEFAULT_DEMO_BASE_URL = "https://app.silmaril.dev";

function readArgs(argv) {
  const args = {
    open: false,
    json: false,
    route: "setup",
    baseUrl: process.env.SILMARIL_DEMO_BASE_URL || DEFAULT_DEMO_BASE_URL,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--open") {
      args.open = true;
      continue;
    }
    if (arg === "--json") {
      args.json = true;
      continue;
    }
    if (arg === "--playground") {
      args.route = "playground";
      continue;
    }
    if (arg === "--route") {
      const value = argv[index + 1];
      if (value !== "setup" && value !== "playground") {
        throw new Error("--route must be setup or playground");
      }
      args.route = value;
      index += 1;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return args;
}

export function buildDemoUrl(baseUrl = DEFAULT_DEMO_BASE_URL, route = "setup") {
  const rawBase = String(baseUrl || DEFAULT_DEMO_BASE_URL).trim() || DEFAULT_DEMO_BASE_URL;
  const normalizedBase = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawBase)
    ? rawBase
    : `https://${rawBase}`;
  const parsed = new URL(normalizedBase);
  const path = route === "playground" ? "/demo/playground" : "/demo/setup-complete";
  return `${parsed.origin}${path}`;
}

export function openBrowser(url) {
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

function printHelp() {
  process.stdout.write([
    "Usage: node scripts/open-playground.mjs [--open] [--json] [--route <setup|playground>]",
    "",
    "Environment:",
    "  SILMARIL_DEMO_BASE_URL  Override https://app.silmaril.dev for preview validation.",
    "",
  ].join("\n"));
}

async function main() {
  const args = readArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const url = buildDemoUrl(args.baseUrl, args.route);
  const opened = args.open ? openBrowser(url) : false;
  const payload = { route: args.route, url, opened };

  if (args.json) {
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    return;
  }

  process.stdout.write(`${url}\n`);
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  main().catch((err) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
