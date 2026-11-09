# OpenCode Firewall Plugin

Silmaril Firewall native visibility hooks with an OpenCode 1 minimum of
1.18.22, a retained V1 loader qualification at 1.19.5, and current V2
qualification at 2.2.6.

This plugin classifies OpenCode lifecycle events with Silmaril Firewall. The
package exposes one lazy `./server` entry: OpenCode 1 uses its `id/server`
definition, while OpenCode 2 uses its `id/setup` Promise API definition.
Loading either generation does not eagerly load the other generation's API.

Silmaril is an AI application firewall that protects agent execution. It evaluates intent, application context, tool calls, and accumulated execution state together before harmful outcomes materialize.

## Source Availability

This repository is intended to be public, but it is not OSI-licensed yet. Until a license is selected, the package is marked `UNLICENSED`, `private=true`, and npm publishing is blocked by `prepublishOnly`.

## Release Status

Version 0.4.8 is the current source candidate and has not been published.
Version 0.4.7 remains available as the
[`v0.4.7` GitHub release](https://github.com/Silmaril-Security/OpenCodeFirewallPlugin/releases/tag/v0.4.7).
That historical artifact remains at immutable Git ref `refs/tags/v0.4.7`,
resolving to commit `90fcd559d9bd02de218a47af9e7ac302044ce95f`.
The package remains private and `UNLICENSED`, with npm publishing blocked.
Check out the exact published Git ref:

```sh
git clone https://github.com/Silmaril-Security/OpenCodeFirewallPlugin.git
cd OpenCodeFirewallPlugin
git checkout --detach refs/tags/v0.4.7
npm ci
npm run build
```

Git source archives do not include the generated `dist` distribution, so they
likewise require `npm ci` followed by `npm run build`.

## Install

For OpenCode 2.2.6 local development, build the complete package directory:

```sh
npm ci
npm run build
```

Then add that directory to `opencode.json`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "file:///absolute/path/to/OpenCodeFirewallPlugin",
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

OpenCode 2 local paths are package directories, not individual distribution
files. From the directory's `package.json`, the 2.2.6 host resolves both the
`./server` and `./tui` exports. A managed or locally installed copy must
therefore retain the complete package payload, including `package.json`,
`dist/`, `opencode/`, and the packaged asset installer. Pointing configuration
at `dist/server.js` loads only one file and does not provide the TUI or assets.

For retained OpenCode 1, use the complete package as a package/directory
plugin so its loader selects the `./server` export; the `dist/index.js` root
remains the V1 async plugin API for existing programmatic consumers. The
supported V1 floor is 1.18.22 because earlier hosts include the affected
server-upgrade line. The pinned legacy loader qualification runs at 1.19.5;
it does not claim full-turn qualification for every version in that range.
OpenCode hosts below 1.18.22 must be rejected rather than admitted in
standalone or managed compatibility metadata.

Install the OpenCode-visible skill and slash command into your global OpenCode config:

```sh
npm run install:opencode-assets
```

This installs:

- `~/.config/opencode/skills/silmaril-demo/SKILL.md`
- `~/.config/opencode/commands/silmaril-demo.md`

`OPENCODE_CONFIG_DIR` overrides the default `~/.config/opencode` directory.

Use environment variables instead of committed config values when possible:

```sh
export SILMARIL_API_URL="https://..."
export SILMARIL_API_KEY="..."
export SILMARIL_ENDPOINT_ID="2b64e603-f82a-4aec-9524-9736472dc80a"
export SILMARIL_TIMEOUT_MS="2500"
export SILMARIL_MODE="warn"
export SILMARIL_DEBUG="false"
```

## Configure

For each setting, the opencode plugin tuple option wins over the matching environment variable:

1. Plugin options: `silmaril_api_key`, `silmaril_api_url`, `endpoint_id`, `timeout_ms`, `mode`, `block_malicious`, and `debug`.
2. Environment variables: `SILMARIL_API_KEY`, `SILMARIL_API_URL`, `SILMARIL_ENDPOINT_ID`, `SILMARIL_TIMEOUT_MS`, `SILMARIL_MODE`, `SILMARIL_BLOCK_MALICIOUS`, and `SILMARIL_DEBUG`.

If either API key or API URL is missing, hooks return without classifying or changing content. `timeout_ms` defaults to `2500`. Values are truncated to integers and kept only from `250` through `10000`; any other value uses that default.

Set `mode` or `SILMARIL_MODE` to `shadow`, `warn`, or `block`. Any other string is ignored. A recognized mode wins over legacy `block_malicious` / `SILMARIL_BLOCK_MALICIOUS`. When mode is omitted, boolean `true` or the case-insensitive strings `true`, `yes`, `on`, and `1` select `block`. Boolean `false` or the strings `false`, `no`, `off`, and `0` select `shadow`. Any other legacy value is treated as unset. Legacy `false` does not defer to the backend. Omit both to use the classifier response mode, or `shadow` when the response has no mode. An unrecognized plugin `mode` does not fall through to `SILMARIL_MODE`; legacy `block_malicious` is still considered, and if that is also unset the same classifier-or-shadow rule applies. `endpoint_id` is kept only when it is a canonical lowercase UUID v4; otherwise provenance omits it and still sends harness `opencode`.

Classifier failures, SDK import failures, malformed payloads, empty extracted text, and timeouts fail open without adding context.

Every classifier request carries plugin-owned `metadata.silmaril.provenance` with harness `opencode`. A missing or invalid `endpoint_id` is omitted from that object.

Set `debug=true` or `SILMARIL_DEBUG=true` to write compact diagnostic summaries. OpenCode 1 uses `client.app.log()`. OpenCode 2.2.6 exposes only app name, version, and channel on its Promise context, so v2 writes bounded JSON diagnostics synchronously to stderr and does not call an invented host logging extension. Diagnostics identify missing configuration, SDK loading, client initialization, classification failures, and compact classification outcomes. They omit API keys, API URLs, exception messages, raw prompts, tool inputs, tool outputs, metadata payloads, and assistant text.

The package also exposes a TUI entrypoint through its `./tui` package export.
It registers the `silmaril.firewall.status` palette command and
`/silmaril-firewall`, which show a native toast explaining that blocked
decisions appear inline in the current session transcript. The official pinned
2.2.6 types specify that the host removes keymap layers when a plugin
deactivates; local qualification does not execute that host lifecycle.
Enforcement stays in the server plugin.

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

With no local `mode` and no legacy `block_malicious`, the classifier response mode selects the column below. If that response mode is missing or unrecognized, behavior matches Shadow. Warn and Block apply when the model prediction is exactly `MALICIOUS` or `governance.action` is exactly `block`.

| OpenCode generation and hook | Classified text | Firewall hook | Shadow | Warn | Block |
| --- | --- | --- | --- | --- | --- |
| 1.19.5 `chat.message` | concatenated user text parts | `user_input` | silent | append one bounded warning | reject before the turn continues |
| 2.2.6 `session.prompt` | native prompt text | `user_input` | silent | append one bounded warning | replace text, files, agents, and skills with an inert notice |
| 1.19.5/2.2.6 tool before | stable-serialized native input | `tool_call` | silent | unchanged | reject before execution; OpenCode 2 converts the fixed rejection to native `Tool.Error` |
| 1.19.5 tool after | output string | `tool_response` | exact pass-through | append one bounded warning | replace output before model reuse |
| 2.2.6 tool after (completed only) | content and structured output | `tool_response` | exact pass-through | append one bounded content warning | replace both content and structured output before model reuse |
| 1.19.5 `experimental.text.complete` | assistant text | `llm_output` | exact pass-through | unchanged | replace output before delivery |
| child `session.created` with a title | child-session title | `user_input` | observe-only | observe-only | observe-only |

OpenCode 2.2.6 has no Promise API equivalent of
`experimental.text.complete`, so v2 final assistant output is not classified or
blocked. The OpenCode 1 final-output path remains supported; this is an
explicit capability gap, not parity.

Child sessions use normal prompt and tool hooks under their own `sessionID`.
OpenCode 2 records `session.created` parent correlation even when its optional
title is absent, and closes the event iterator when the plugin unloads. Neither
adapter reconstructs child history at idle.
Every native event produces at most one classification, while the Firewall
sequence cache owns conversation state from the incremental hook stream.

The policy candidate is `prediction === "MALICIOUS"` or
`governance.action === "block"`. Unknown or malformed governance actions do not
block. Governance-only denials retain the model's original `BENIGN` prediction
in logs and local evidence. Scores, thresholds, outcomes, missing predictions,
and unknown predictions remain diagnostic. Each OpenCode
`sessionID` is sent as the exact conversation identity, so child sessions retain
independent sequences. Stable message, part, and call identifiers produce
content-sensitive request IDs for retry idempotency; events without one use the
SDK-generated ID.

Tool requests use SDK 0.8.2 typed governance resources. OpenCode 2 maps the
native effective tool ID to `{ kind: "tool", id }`. Its public Promise context
does not expose independent MCP registry authority, and tool namespaces are
generic and normalized, so the plugin never invents an `mcp_tool` parent from
a namespace. OpenCode agent names remain metadata attribution only and are not
sent as an authenticated governance principal.

## Local Evidence

Every successful classification emits one bounded `LocalProtectionEventV1`
file under `~/Library/Application Support/Silmaril/Evidence/incoming`. Files
are written privately through an atomic temporary rename. They contain opaque
request and session fingerprints, the policy decision, native host action, and
version provenance. They never contain the prompt, tool arguments, tool
output, assistant text, API key, or classifier URL.

Set `SILMARIL_LOCAL_EVENT_DIR` to override the incoming directory. If that is unset or blank and `SILMARIL_EVIDENCE_ROOT` is set, the directory is `<root>/incoming`.
Evidence failures are fail-open and never alter OpenCode enforcement. Plugins
report native block responses, but only the Silmaril app can independently
verify that a consequence was prevented.

## Development

Requires Node.js 22 or newer.

```sh
npm ci
npm run typecheck
npm test
npm run build
npm pack --dry-run
```

The package pins `@silmaril-security/sdk` to `0.8.2`, requires retained
`@opencode-ai/plugin` hosts to be at least 1.18.22, develops against
`opencode-ai` and `@opencode-ai/plugin` 1.19.5, and qualifies the actual
`@opencode/cli`, `@opencode/plugin`, `@opencode/core`, and `@opencode/util`
2.2.6 packages. `effect` is a peer dependency and a development dependency.
As required by OpenCode's plugin packaging contract, bundlers must keep
`effect`, `effect/*`, and `@opencode/plugin` entry points external so the
plugin receives the host runtime instance.

Tests call the real SDK against a local fetch capture, inspect the complete
packed payload, and load both the package's server and TUI exports through
OpenCode 2.2.6's published `Host.resolve`/`Host.load`. They run the official
Promise adapter, verify `silmaril_demo` in the native tool registry, execute
both that tool and a local counter tool through the real OpenCode 2 tool
service, and invoke the TUI's palette/slash command against the pinned
keymap/toast contract. The TUI qualification is deterministic and
non-interactive: the actual pinned host resolves and loads the module, while a
synthetic callback context verifies the layer factory, command registration,
and toast invocation. It does not exercise host deactivation or claim an
interactive terminal render. For OpenCode 1.19.5, the test fetches five official
source files and the MIT license at pinned revision
`810c0eba1a7348036f8bdf61e6632d0c36c6876c`, verifies their SHA-256 hashes,
AST-extracts the original entrypoint, validator, and consumer functions
unchanged, erases only TypeScript syntax, and runs them against the current
packed artifact. This proves the retained loader function contract, not a full
1.19.5 CLI turn or dispatcher. Tests use no model or paid inference.

## References

- [Silmaril docs](https://www.silmaril.dev/docs)
- [opencode plugin docs](https://opencode.ai/docs/plugins/)
- [opencode config docs](https://opencode.ai/docs/config/)

Current classify responses omit mode. Without an explicit or legacy local
setting, this plugin falls back to Shadow. Set Warn or Block explicitly; the
SDK pin does not establish backend-selected enforcement.
