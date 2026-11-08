# Release notes

## 0.4.6 (unreleased)

The package now exposes a lazy dual-generation `./server` entry. It retains
the OpenCode 1.19.5 async plugin and adds native OpenCode 2.2.6 Promise hooks
for prompt replacement, before-tool rejection, completed tool-result
replacement, and child-session correlation. OpenCode 2.2.6 does not expose a
final-output Promise hook, so final assistant output protection remains an
OpenCode 1 capability.

Host qualification now runs the original OpenCode 1.19.5 entrypoint,
validator, and consumer functions extracted unchanged from SHA-verified
official source at pinned revision
`810c0eba1a7348036f8bdf61e6632d0c36c6876c` against the packed package. Its
scope is the retained loader contract, not a full old CLI turn or dispatcher.

The Silmaril SDK is pinned to 0.8.2. Tool classifications send the native
effective tool ID as a typed `tool` governance resource. Generic OpenCode
namespaces are not treated as proof of an MCP server parent, while OpenCode
agent identity remains metadata attribution only.

The demo browser launcher returns `opened: false` when an opener is missing, exits unsuccessfully, or does not confirm success within five seconds. It handles asynchronous spawn errors, including errors after the deadline, without terminating the host. The corrected helper is already on main but is absent from GitHub release v0.4.5.

The package and runtime provenance identify version 0.4.6. Publishing requires a separate authorized GitHub release. The package remains private and unlicensed; npm publishing remains blocked.
