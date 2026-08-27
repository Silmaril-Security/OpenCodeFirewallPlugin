# OpenCode Firewall Plugin

Silmaril Firewall native visibility hooks for opencode.

This plugin classifies opencode lifecycle events with Silmaril Firewall. Shadow is silent, Warn preserves content and adds one bounded warning at supported same-turn context surfaces, and Block throws at pre-execution boundaries or replaces malicious output at mutable post-execution boundaries.

Silmaril is an AI application firewall that protects agent execution. It evaluates intent, application context, tool calls, and accumulated execution state together before harmful outcomes materialize.

## Source Availability

This repository is intended to be public, but it is not OSI-licensed yet. Until a license is selected, the package is marked `UNLICENSED`, `private=true`, and npm publishing is blocked by `prepublishOnly`.

## Install

For local development, build this package and register the built plugin with opencode:

```sh
npm install
npm run build
```

Then add the plugin to `opencode.json`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "file:///absolute/path/to/OpenCodeFirewallPlugin/dist/index.js",
      {
        "silmaril_api_url": "https://...",
        "silmaril_api_key": "...",
        "endpoint_id": "2b64e603-f82a-4aec-9524-9736472dc80a",
        "timeout_ms": 2500,
        "mode": "warn",
        "debug": false
      }
    ]
  ]
}
```

Install the OpenCode-visible skill and slash command into your global OpenCode config:

```sh
npm run install:opencode-assets
```

This installs:

- `~/.config/opencode/skills/silmaril-demo/SKILL.md`
- `~/.config/opencode/commands/silmaril-demo.md`

Use environment variables instead of committed config values when possible:

```sh
export SILMARIL_API_URL="https://..."
export SILMARIL_API_KEY="..."
export SILMARIL_ENDPOINT_ID="2b64e603-f82a-4aec-9524-9736472dc80a"
export SILMARIL_TIMEOUT_MS="2500"
export SILMARIL_BLOCK_MALICIOUS="false"
export SILMARIL_DEBUG="false"
```

## Configure

Runtime configuration is resolved in this order:

1. opencode plugin tuple options: `silmaril_api_key`, `silmaril_api_url`, `endpoint_id`, `timeout_ms`, `block_malicious`, and `debug`.
2. Process environment variables: `SILMARIL_API_KEY`, `SILMARIL_API_URL`, `SILMARIL_ENDPOINT_ID`, `SILMARIL_TIMEOUT_MS`, `SILMARIL_BLOCK_MALICIOUS`, and `SILMARIL_DEBUG`.

If either API key or API URL is missing, the plugin exits hooks without output. `timeout_ms` defaults to `2500` and accepts values from `250` through `10000`. Omit `mode` to use the backend, or set `shadow`, `warn`, or `block`; explicit mode wins over legacy `block_malicious`. Classifier failures, SDK import failures, malformed payloads, empty extracted text, and timeouts fail open without adding context.

Every classifier request carries plugin-owned `metadata.silmaril.provenance`. If the app-provided canonical UUID v4 is absent, the plugin continues with harness-only provenance.

Set `debug=true` or `SILMARIL_DEBUG=true` to write compact diagnostic summaries through `client.app.log()`. Debug logs omit raw prompts, tool inputs, tool outputs, and assistant text.

The package also exposes a TUI entrypoint at `dist/tui.js` / `@silmaril/opencode-firewall-plugin/tui`. It registers a native status command that points users to inline blocked-decision feedback in the current session transcript, while enforcement remains in the server plugin.

## Demo

The plugin exposes a `silmaril_demo` tool that returns the public Firewall demo URL and can optionally open it with the system browser. It never places API keys in URLs, logs, or tool output.

OpenCode does not discover skills from plugin package directories. The packaged OpenCode assets install a visible `silmaril-demo` skill and `/silmaril-demo` command into the OpenCode config directory. After running `npm run install:opencode-assets`, start a new OpenCode session and use:

```text
/silmaril-demo
/silmaril-demo playground
```

You can also run the launcher directly:

```sh
node scripts/open-playground.mjs
node scripts/open-playground.mjs --open
node scripts/open-playground.mjs --route playground --json
```

For preview validation, set `SILMARIL_DEMO_BASE_URL`:

```sh
SILMARIL_DEMO_BASE_URL="http://localhost:3001" node scripts/open-playground.mjs
```

## Event Mapping

| opencode hook | Classified text | Firewall hook | Default behavior | Optional enforcement |
| --- | --- | --- | --- | --- |
| `chat.message` | concatenated user text parts | `user_input` | silent | block malicious user message |
| `tool.execute.before` | stable-serialized tool args | `tool_call` | silent | block malicious tool call |
| `tool.execute.after` | tool output string | `tool_response` | exact pass-through | replace malicious output before model reuse |
| `experimental.text.complete` | assistant text | `llm_output` | exact pass-through | replace malicious output before delivery |
| `session.created` for a child | child-session title | `user_input` | observe-only | none |

opencode does not expose direct `Stop` or `SubagentStop` parity hooks. Assistant
output classification is implemented through `experimental.text.complete`.
Child sessions created by the `task` tool use the same normal hook surface under
their own `sessionID`. The plugin observes `session.created` only for the current
child lifecycle payload and never fetches session messages at `session.idle`.
Every native event produces at most one classification, while the Firewall
sequence cache owns conversation state from the incremental hook stream.

Only `prediction === "MALICIOUS"` is enforceable. Scores, thresholds, outcomes,
missing predictions, and unknown predictions remain diagnostic. Each OpenCode
`sessionID` is sent as the exact conversation identity, so child sessions retain
independent sequences. Stable message, part, and call identifiers produce
content-sensitive request IDs for retry idempotency; events without one use the
SDK-generated ID.

## Local Evidence

Every successful classification emits one bounded `LocalProtectionEventV1`
file under `~/Library/Application Support/Silmaril/Evidence/incoming`. Files
are written privately through an atomic temporary rename. They contain opaque
request and session fingerprints, the policy decision, native host action, and
version provenance. They never contain the prompt, tool arguments, tool
output, assistant text, API key, or classifier URL.

Set `SILMARIL_LOCAL_EVENT_DIR` to override the incoming directory for testing.
Evidence failures are fail-open and never alter OpenCode enforcement. Plugins
report native block responses, but only the Silmaril app can independently
verify that a consequence was prevented.

## Development

```sh
npm install
npm run typecheck
npm test
npm run build
npm pack --dry-run
```

The package pins `@silmaril-security/sdk` to `0.6.0` so backend-selected mode
is preserved, and develops against
`@opencode-ai/plugin@1.18.4`. Unit tests stub the SDK and cover config loading,
opencode event mapping, shadow behavior, optional enforcement across supported
boundaries, fail-open behavior, no raw payload leakage, demo launcher behavior,
and dependency invariants.

## References

- [Silmaril docs](https://www.silmaril.dev/docs)
- [opencode plugin docs](https://opencode.ai/docs/plugins/)
- [opencode config docs](https://opencode.ai/docs/config/)
