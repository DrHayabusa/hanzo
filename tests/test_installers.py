"""Installer regressions with local Git fixtures and fake package managers only."""
from __future__ import annotations

import contextlib
import importlib.metadata
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
import doctor
import sync_integrations as sync


class SourceLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "Fixture")
        (self.repo / "README").write_text("fixture\n")
        self.git("add", "README")
        self.git("commit", "-qm", "fixture")
        self.git("remote", "add", "origin", "https://github.com/example/source.git")
        self.item = {"directory": "source", "url": "https://github.com/example/source.git",
                     "revision": self.git("rev-parse", "HEAD"), "profile": "core"}

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True, stderr=subprocess.DEVNULL).strip()

    def test_existing_clean_locked_checkout_is_pinned(self):
        self.assertEqual(sync.sync_one(self.item, self.root, True)["status"], "pinned")

    def test_matching_head_with_dirty_content_is_not_accepted(self):
        (self.repo / "README").write_text("user edit\n")
        with self.assertRaisesRegex(ValueError, "local changes"):
            sync.sync_one(self.item, self.root)
        self.assertEqual((self.repo / "README").read_text(), "user edit\n")

    def test_untracked_user_file_is_preserved(self):
        (self.repo / "user-file").write_text("keep")
        with self.assertRaisesRegex(ValueError, "local changes"):
            sync.sync_one(self.item, self.root)

    def test_unexpected_remote_is_not_modified(self):
        self.git("remote", "set-url", "origin", "https://github.com/example/other.git")
        with self.assertRaisesRegex(ValueError, "Unexpected source"):
            sync.sync_one(self.item, self.root)

    def test_check_only_does_not_clone_fetch_or_checkout(self):
        with patch.object(sync, "git") as git:
            self.assertEqual(sync.sync_one({**self.item, "directory": "missing"}, self.root, True)["status"], "missing")
        git.assert_not_called()
        self.assertFalse((self.root / "missing").exists())

    def test_check_only_reports_wrong_revision(self):
        changed = {**self.item, "revision": "a" * 40}
        self.assertEqual(sync.sync_one(changed, self.root, True)["status"], "revision_mismatch")
        self.assertEqual(self.git("rev-parse", "HEAD"), self.item["revision"])

    def test_symlink_checkout_is_rejected(self):
        (self.root / "alias").symlink_to(self.repo)
        with self.assertRaisesRegex(ValueError, "symlink"):
            sync.sync_one({**self.item, "directory": "alias"}, self.root)

    def test_manifest_rejects_path_traversal_unpinned_refs_and_credentials(self):
        manifest = self.root / "lock.json"
        for key, value in (("directory", "../escape"), ("revision", "main"),
                           ("url", "https://secret@github.com/example/source.git"), ("profile", "unknown")):
            manifest.write_text(json.dumps({"schema": 1, "repositories": [{**self.item, key: value}]}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                sync.load_manifest(manifest)

    def test_release_manifest_is_valid(self):
        rows = sync.load_manifest(PROJECT / "integrations.lock.json")
        self.assertGreaterEqual(len(rows), 8)
        self.assertEqual(sum(row["profile"] == "core" for row in rows), 2)

    def test_failed_sync_is_nonzero_without_leaking_git_output(self):
        with patch.object(sync, "load_manifest", return_value=[self.item]), \
             patch.object(sync, "sync_one", side_effect=subprocess.CalledProcessError(1, ["git"], stderr="SECRET")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            status = sync.main(["--check", "--json"])
        self.assertEqual(status, 1)
        self.assertFalse(json.loads(output.getvalue())["passed"])
        self.assertNotIn("SECRET", output.getvalue())


class DoctorTests(unittest.TestCase):
    def test_missing_sources_have_no_network_or_write_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            shutil.copyfile(PROJECT / "integrations.lock.json", project / "integrations.lock.json")
            with patch.dict(os.environ, {"GROQ_API_KEY": "secret-provider", "HANZO_SPLUNK_HEC_TOKEN": "secret-hec"}, clear=True), \
                 patch.object(doctor.subprocess, "run") as run:
                report = doctor.inventory(project)
            run.assert_not_called()
            self.assertFalse((project / ".integrations").exists())
            self.assertFalse(report["core_inventory_ready"])
            self.assertTrue(report["configuration"]["cloud_credentials_present"]["GROQ_API_KEY"])
            self.assertNotIn("secret-provider", json.dumps(report))
            self.assertNotIn("secret-hec", json.dumps(report))
            self.assertTrue(all(not row["runtime_verified"] for row in report["sources"]))

    def test_strict_exit_status_reflects_inventory(self):
        with patch.object(doctor, "inventory", return_value={"core_inventory_ready": False}), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(doctor.main(["--json", "--strict"]), 1)
            self.assertEqual(doctor.main(["--json"]), 0)

    def test_missing_python_dependencies_are_actionable(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(importlib.metadata, "version", side_effect=importlib.metadata.PackageNotFoundError):
            report = doctor.inventory(Path(directory))
        self.assertTrue(any("requirements-core.txt" in issue for issue in report["problems"]))


class KaliInstallerTests(unittest.TestCase):
    """All apt/sudo/dpkg invocations resolve to fixtures. No installs occur."""
    FAKE = '''#!/usr/bin/env python3
import os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
root = pathlib.Path(os.environ["HANZO_TEST_ROOT"])
if name == "uname":
    print("Linux")
elif name == "sudo":
    sys.exit(subprocess.call(sys.argv[1:]))
elif name == "dpkg-query":
    package = sys.argv[-1]
    if package != os.environ.get("HANZO_TEST_MISSING", ""):
        print("install ok installed", end="")
    else:
        sys.exit(1)
elif name == "apt-get":
    with (root / "calls").open("a") as log:
        log.write(" ".join(sys.argv[1:]) + "\\n")
    if sys.argv[1] == "update" and os.environ.get("HANZO_TEST_UPDATE_FAIL"):
        sys.exit(1)
    if sys.argv[1] == "install" and os.environ.get("HANZO_TEST_INSTALL_FAIL"):
        sys.exit(1)
'''

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        self.script = self.root / "scripts/install_kali_arsenal.sh"
        shutil.copyfile(PROJECT / "scripts/install_kali_arsenal.sh", self.script)
        self.bin = self.root / "fake-bin"
        self.bin.mkdir()
        for command in ("uname", "sudo", "apt-get", "dpkg-query"):
            path = self.bin / command
            path.write_text(self.FAKE)
            path.chmod(0o755)
        self.environment = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "HANZO_TEST_ROOT": str(self.root)}

    def run_installer(self, *args, **env):
        return subprocess.run(["bash", str(self.script), *args], env={**self.environment, **env}, capture_output=True, text=True, timeout=30)

    def test_dry_run_has_no_install_or_report_writes(self):
        result = self.run_installer("--core", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nmap", result.stdout)
        self.assertFalse((self.root / "calls").exists())
        self.assertFalse((self.root / ".hanzo-data").exists())

    def test_failed_metadata_refresh_stops_before_install(self):
        result = self.run_installer(HANZO_TEST_UPDATE_FAIL="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual((self.root / "calls").read_text(), "update\n")
        self.assertIn("no packages installed", result.stdout)

    def test_package_failure_is_nonzero_with_retained_log(self):
        result = self.run_installer(HANZO_TEST_MISSING="nmap", HANZO_TEST_INSTALL_FAIL="1")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("1 packages failed", result.stdout)
        self.assertEqual(len(list((self.root / ".hanzo-data").glob("arsenal-install.*/nmap.log"))), 1)

    def test_package_success_without_dpkg_verification_is_failure(self):
        result = self.run_installer(HANZO_TEST_MISSING="nmap")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAILED VERIFICATION", result.stdout)

    def test_already_installed_packages_pass_without_reinstall(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "calls").read_text(), "update\n")

    def test_unknown_argument_rejected(self):
        self.assertEqual(self.run_installer("--unknown").returncode, 2)

    def test_shell_files_are_syntax_valid(self):
        for name in ("setup_kali.sh", "install_integrations.sh", "install_kali_arsenal.sh"):
            result = subprocess.run(["bash", "-n", str(PROJECT / "scripts" / name)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
