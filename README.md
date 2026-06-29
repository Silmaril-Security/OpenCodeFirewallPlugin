# OpenCode Firewall Plugin

Silmaril Firewall context hooks for opencode.

This plugin classifies opencode lifecycle events with Silmaril Firewall. It defaults to fail-open shadow/pass-through mode, adds compact classification context where opencode supports it, and blocks malicious content at every supported enforcement boundary when `block_malicious=true`.

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
        "timeout_ms": 2500,
        "block_malicious": false,
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
export SILMARIL_TIMEOUT_MS="2500"
export SILMARIL_BLOCK_MALICIOUS="false"
export SILMARIL_DEBUG="false"
```

## Configure

Runtime configuration is resolved in this order:

1. opencode plugin tuple options: `silmaril_api_key`, `silmaril_api_url`, `timeout_ms`, `block_malicious`, and `debug`.
2. Process environment variables: `SILMARIL_API_KEY`, `SILMARIL_API_URL`, `SILMARIL_TIMEOUT_MS`, `SILMARIL_BLOCK_MALICIOUS`, and `SILMARIL_DEBUG`.

If either API key or API URL is missing, the plugin exits hooks without output. `timeout_ms` defaults to `2500` and accepts values from `250` through `10000`. `block_malicious` defaults to `false`; set it to `true` only when you want malicious user-message, tool-call, tool-output, and final assistant-output classifications to block where opencode exposes an enforcement surface. Classifier failures, SDK import failures, malformed payloads, empty extracted text, and timeouts fail open.

Set `debug=true` or `SILMARIL_DEBUG=true` to write compact diagnostic summaries through `client.app.log()`. Debug logs omit raw prompts, tool inputs, tool outputs, and assistant text.

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
| `chat.message` | concatenated user text parts | `user_input` | append synthetic context part | block malicious user message |
| `tool.execute.before` | stable-serialized tool args | `tool_call` | classify and cache compact summary | block malicious tool call |
| `tool.execute.after` | tool output string | `tool_response` | append compact tool-call/tool-response summary | replace malicious tool output |
| `experimental.text.complete` | assistant text | `llm_output` | telemetry only | replace malicious final assistant output |

opencode does not expose direct `Stop` or `SubagentStop` parity hooks. Assistant output classification is implemented through `experimental.text.complete`.

## Context Output

Model-visible context uses a compact JSON object and never includes raw classified text:

```json
{
  "silmarilFirewall": {
    "hook": "tool_call",
    "opencodeHookEvent": "tool.execute.before",
    "toolName": "bash",
    "callId": "call_123",
    "classification": {
      "prediction": "MALICIOUS",
      "score": 0.92,
      "threshold": 0.5,
      "primaryOutcome": "prompt_injection",
      "outcomeScores": {},
      "detectorScores": {},
      "detectorCounts": {}
    }
  }
}
```

`classification` includes the compact Silmaril summary fields used by opencode: `prediction`, `score`, `threshold`, `primaryOutcome`, `outcomeScores`, `detectorScores`, and `detectorCounts`. Missing score maps serialize as empty objects.

When optional blocking is enabled, post-execution hooks replace malicious tool or assistant output with a safe Silmaril Firewall summary. The replacement includes hook metadata, score, threshold, and primary outcome, but never includes the original tool output or assistant text.

## Development

```sh
npm install
npm run typecheck
npm test
npm run build
npm pack --dry-run
```

The package pins `@silmaril-security/sdk` to `0.4.2`. Unit tests stub the SDK and cover config loading, opencode event mapping, shadow behavior, optional enforcement across supported boundaries, fail-open behavior, no raw payload leakage, demo launcher behavior, and the SDK version invariant.

## References

- [Silmaril docs](https://www.silmaril.dev/docs)
- [opencode plugin docs](https://opencode.ai/docs/plugins/)
- [opencode config docs](https://opencode.ai/docs/config/)
