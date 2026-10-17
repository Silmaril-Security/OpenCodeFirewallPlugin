import type { spawn } from "node:child_process";

export function openBrowser(url: string, options?: {
  spawnImpl?: typeof spawn;
  platformName?: NodeJS.Platform;
  timeoutMs?: number;
}): Promise<boolean>;
