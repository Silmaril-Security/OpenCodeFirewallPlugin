import { spawn } from "node:child_process";
import { platform } from "node:os";

/** Report a successful opener exit; an error or unconfirmed launch is false. */
export function openBrowser(url, {
  spawnImpl = spawn,
  platformName = platform(),
  timeoutMs = 5000,
} = {}) {
  const command = platformName === "darwin"
    ? "open"
    : platformName === "win32"
      ? "cmd"
      : "xdg-open";
  const args = platformName === "win32"
    ? ["/c", "start", "", url]
    : [url];

  return new Promise((resolve) => {
    let settled = false;
    const finish = (opened) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(opened);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    try {
      const child = spawnImpl(command, args, {
        detached: true,
        stdio: "ignore",
      });
      // Keep the error listener even after the deadline so a late error is safe.
      child.once("error", () => finish(false));
      child.once("close", (code) => finish(code === 0));
      child.unref();
    } catch {
      finish(false);
    }
  });
}
