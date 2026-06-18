---
name: silmaril-demo
description: Open and guide the hosted Silmaril Firewall demo for OpenCode plugin setup and live playground classification.
---

# Silmaril Demo

Use this skill when the user asks to open, test, or walk through the Silmaril Firewall demo from OpenCode.

## Quick Start

Prefer the `silmaril_demo` tool exposed by the OpenCode Firewall Plugin:

```json
{
  "route": "setup",
  "open": true
}
```

The tool returns or opens `https://app.silmaril.dev/demo/setup-complete` by default. It does not start any local service and does not add credentials to the URL.

To open the playground directly, call the same tool with:

```json
{
  "route": "playground",
  "open": true
}
```

For preview validation, pass `base_url` or set `SILMARIL_DEMO_BASE_URL`.

## Demo Flow

1. Open the setup-complete page and confirm the plugin-ready state.
2. Fill the demo API configuration from the plugin config if the page asks for it.
3. Continue to the playground.
4. Select a benign Silmaril eval sample and classify it.
5. Select a blocking sample and classify it.
6. Show user input, tool call, tool response, and LLM output examples where useful.
7. Reset the playground before handing control back to the user.

## Constraints

- Do not print the Silmaril API key in chat, command output, URLs, logs, or navigation.
- Do not start a local proxy or demo service.
- Do not place credentials in the demo URL.
- Only enter credentials into the hosted demo setup fields as part of a user-authorized setup flow.
