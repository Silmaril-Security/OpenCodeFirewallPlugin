"""Exercise the PR version check against real base and candidate commits."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CHECK = Path(__file__).with_name("check-package-version.py").resolve()


class PackageVersionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Version check")
        self.git("config", "user.email", "version@example.invalid")
        self.git("config", "commit.gpgSign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        self.manifest = self.repo / "package.json"
        self.set_version("0.4.9")
        (self.repo / "src").mkdir()
        self.runtime = self.repo / "src" / "index.ts"
        self.runtime.write_text("export const enabled = true;\n")
        self.commit()

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "Version check fixture")

    def set_version(self, version):
        self.manifest.write_text(json.dumps({"version": version}) + "\n")

    def assert_gate(self, should_pass):
        self.commit()
        result = subprocess.run(
            [sys.executable, CHECK, "HEAD^", "HEAD"],
            cwd=self.repo, capture_output=True, text=True,
        )
        if should_pass:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Increase the version", result.stderr)

    def test_package_change_without_bump(self):
        self.runtime.write_text("export const enabled = false;\n")
        self.assert_gate(False)

    def test_lower_version(self):
        self.set_version("0.4.8")
        self.assert_gate(False)

    def test_numeric_patch_order(self):
        self.set_version("0.4.10")
        self.assert_gate(True)

    def test_move_out_of_package_counts_as_removal(self):
        (self.repo / "test").mkdir()
        self.runtime.rename(self.repo / "test" / "example.ts")
        self.assert_gate(False)

    def test_only_test_changed(self):
        (self.repo / "test").mkdir()
        (self.repo / "test" / "example.ts").write_text("export {};\n")
        self.assert_gate(True)


if __name__ == "__main__":
    unittest.main()
