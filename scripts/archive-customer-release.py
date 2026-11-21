#!/usr/bin/env python3
"""Freeze the exact source commit together with its compiled package exports."""
import json
from pathlib import Path
import subprocess
import sys


def archive(commit, destination):
    if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != commit:
        raise ValueError("Build checkout and release commit disagree")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], check=True)
    manifest = json.loads(Path("package.json").read_text())
    for entry in [manifest["main"], *(info["import"] for info in manifest["exports"].values())]:
        if not entry.startswith("./dist/") or ".." in Path(entry).parts or not Path(entry).is_file():
            raise ValueError("Build is missing an exported runtime file")
    args = ["git", "archive", "--format=tar.gz", "--output=" + destination]
    tracked = set(subprocess.check_output(["git", "ls-files", "-z", "dist"]).decode().split("\0"))
    for file in sorted(Path("dist").rglob("*")):
        if file.is_symlink():
            raise ValueError("Unexpected symlink in compiled runtime")
        if file.is_file() and str(file) not in tracked:
            args.extend([f"--prefix=source/{file.parent}/", f"--add-file={file}"])
    subprocess.run([*args, "--prefix=source/", commit], check=True)


if __name__ == "__main__":
    archive(*sys.argv[1:])
