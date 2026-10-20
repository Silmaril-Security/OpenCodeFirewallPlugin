# Release notes

## 0.4.6 (unreleased)

The demo browser launcher returns `opened: false` when an opener is missing, exits unsuccessfully, or does not confirm success within five seconds. It handles asynchronous spawn errors, including errors after the deadline, without terminating the host. The corrected helper is already on main but is absent from GitHub release v0.4.5.

The package and runtime provenance identify version 0.4.6. Publishing requires a separate authorized GitHub release. The package remains private and unlicensed; npm publishing remains blocked.
