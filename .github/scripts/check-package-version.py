"""Require a release version increase for changes to package inputs."""

import json
import re
import subprocess
import sys


MANIFEST = "package.json"
PACKAGE_INPUTS = (
    "src",
    "dist",
    "examples",
    "opencode",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    ".npmignore",
    ".gitattributes",
    "scripts/install-opencode-assets.mjs",
    "scripts/open-browser.mjs",
    "scripts/open-browser.d.mts",
    "scripts/open-playground.mjs",
    "scripts/archive-customer-release.py",
    "scripts/block-publish.mjs",
)


def version_at(revision):
    manifest = subprocess.check_output(
        ["git", "show", f"{revision}:{MANIFEST}"], text=True
    )
    value = json.loads(manifest)["version"]
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}", value):
        raise ValueError(f"Expected a stable release version in {MANIFEST}, got {value!r}")
    return tuple(map(int, value.split(".")))


def main(base, candidate):
    diff = subprocess.run(
        ["git", "diff", "--quiet", "--no-renames", base, candidate, "--", *PACKAGE_INPUTS]
    )
    if diff.returncode == 0:
        print("Package inputs are unchanged.")
        return
    if diff.returncode != 1:
        diff.check_returncode()
    if version_at(candidate) <= version_at(base):
        raise SystemExit(f"Package inputs changed. Increase the version in {MANIFEST} in this PR.")
    print("Package version increased.")


if __name__ == "__main__":
    main(*sys.argv[1:])
