import { openBrowser } from "../scripts/open-browser.mjs";

const DEFAULT_DEMO_BASE_URL = "https://app.silmaril.dev";

export type DemoRoute = "setup" | "playground";
export type BrowserOpener = (url: string) => Promise<boolean>;

export { openBrowser };

export function buildDemoUrl(
  baseUrl: string | undefined = DEFAULT_DEMO_BASE_URL,
  route: DemoRoute = "setup",
): string {
  const rawBase = typeof baseUrl === "string" && baseUrl.trim()
    ? baseUrl.trim()
    : DEFAULT_DEMO_BASE_URL;
  const normalizedBase = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawBase)
    ? rawBase
    : `https://${rawBase}`;
  const parsed = new URL(normalizedBase);
  const path = route === "playground" ? "/demo/playground" : "/demo/setup-complete";
  return `${parsed.origin}${path}`;
}
