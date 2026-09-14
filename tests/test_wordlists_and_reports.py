import json
import os
import tempfile
import unittest
from pathlib import Path

import wordlists
from hanzo_store import HanzoStore
from hexstrike_server import app


class WordlistDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        (self.project / "wordlists" / "Discovery" / "Web-Content").mkdir(parents=True)
        (self.project / "wordlists" / "Discovery" / "DNS").mkdir(parents=True)
        self.web = self.project / "wordlists" / "Discovery" / "Web-Content" / "common.txt"
        self.web.write_text("admin\nlogin\nbackup\n" * 4, encoding="utf-8")
        self.dns = self.project / "wordlists" / "Discovery" / "DNS" / "subdomains.txt"
        self.dns.write_text("www\nmail\napi\n" * 4, encoding="utf-8")
        (self.project / "wordlists" / "notes.md").write_text("not a wordlist", encoding="utf-8")
        (self.project / "wordlists" / "empty.txt").write_text("", encoding="utf-8")
        self.addCleanup(self.temporary.cleanup)

    def discover(self):
        return wordlists.discover(self.project, use_cache=False)

    def test_only_real_readable_wordlists_are_listed(self):
        catalog = self.discover()
        paths = {item["path"] for group in catalog["groups"] for item in group["wordlists"]}
        self.assertEqual(paths, {str(self.web), str(self.dns)})
        self.assertTrue(catalog["installed"])

    def test_empty_and_non_wordlist_files_are_skipped(self):
        paths = {item["name"] for group in self.discover()["groups"] for item in group["wordlists"]}
        self.assertNotIn("notes.md", paths)
        self.assertNotIn("empty.txt", paths)

    def test_groups_use_the_path_relative_to_its_root(self):
        groups = {group["id"] for group in self.discover()["groups"]}
        self.assertEqual(groups, {"web", "dns"})

    def test_absolute_host_layout_never_decides_the_group(self):
        # A project under /Users must not push every list into the usernames group.
        self.assertEqual(wordlists.classify("Discovery/Web-Content/common.txt")[0], "web")
        self.assertEqual(wordlists.classify("/Users/someone/lists/Discovery/DNS/x.txt")[0], "dns")

    def test_missing_wordlists_are_reported_honestly(self):
        empty = Path(self.temporary.name) / "no-lists"
        empty.mkdir()
        catalog = wordlists.discover(empty, use_cache=False)
        self.assertEqual(catalog["count"], 0)
        self.assertFalse(catalog["installed"])
        self.assertIn("No wordlist was found", catalog["message"])
        self.assertIn("SecLists", catalog["install_hint"])

    def test_extra_roots_come_from_the_environment(self):
        extra = Path(self.temporary.name) / "extra"
        extra.mkdir()
        (extra / "custom.txt").write_text("alpha\nbeta\n", encoding="utf-8")
        os.environ["HANZO_WORDLIST_DIRS"] = str(extra)
        self.addCleanup(os.environ.pop, "HANZO_WORDLIST_DIRS", None)
        names = {item["name"] for group in self.discover()["groups"] for item in group["wordlists"]}
        self.assertIn("custom.txt", names)

    def test_resolve_accepts_a_real_file_and_rejects_the_rest(self):
        self.assertTrue(wordlists.resolve(str(self.web))["readable"])
        missing = wordlists.resolve(str(self.project / "nope.txt"))
        self.assertFalse(missing["exists"])
        self.assertIn("does not exist", missing["error"])
        directory = wordlists.resolve(str(self.project))
        self.assertFalse(directory["readable"])
        self.assertIn("directory", directory["error"])
        self.assertIn("required", wordlists.resolve("")["error"])


class WordlistRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_catalog_route_returns_groups(self):
        response = self.client.get("/api/arsenal/wordlists")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("groups", payload)
        self.assertIn("installed", payload)

    def test_resolve_route_rejects_a_missing_path(self):
        response = self.client.post("/api/arsenal/wordlists/resolve",
                                    json={"path": "/definitely/not/here.txt"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["readable"])


class ReportDeletionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        os.environ["HANZO_DB_PATH"] = str(Path(self.temporary.name) / "hanzo.db")
        self.addCleanup(os.environ.pop, "HANZO_DB_PATH", None)
        self.store = HanzoStore(Path(self.temporary.name))

    def add(self, count=3):
        return [self.store.record(f"host{index}", "command", "completed", True, {"index": index})
                for index in range(count)]

    def test_delete_removes_exactly_one_run(self):
        identifiers = self.add()
        self.assertTrue(self.store.delete(identifiers[1]))
        remaining = {run["id"] for run in self.store.recent(50)}
        self.assertEqual(remaining, {identifiers[0], identifiers[2]})

    def test_deleting_an_unknown_or_blank_id_changes_nothing(self):
        self.add()
        self.assertFalse(self.store.delete("not-a-real-id"))
        self.assertFalse(self.store.delete(""))
        self.assertEqual(self.store.count(), 3)

    def test_delete_many_reports_the_number_removed(self):
        identifiers = self.add(4)
        self.assertEqual(self.store.delete_many(identifiers[:2]), 2)
        self.assertEqual(self.store.count(), 2)

    def test_purge_keeps_the_newest_runs(self):
        self.add(5)
        outcome = self.store.purge(keep_latest=2)
        self.assertEqual(outcome["deleted"], 3)
        self.assertEqual(outcome["remaining"], 2)
        self.assertEqual(self.store.count(), 2)

    def test_purge_without_a_rule_deletes_nothing(self):
        self.add(3)
        outcome = self.store.purge()
        self.assertEqual(outcome["deleted"], 0)
        self.assertEqual(self.store.count(), 3)
        self.assertIn("Nothing deleted", outcome["message"])

    def test_purge_by_age_leaves_recent_runs(self):
        self.add(2)
        self.assertEqual(self.store.purge(older_than_days=1)["deleted"], 0)
        self.assertEqual(self.store.count(), 2)

    def test_negative_retention_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.purge(keep_latest=-1)
        with self.assertRaises(ValueError):
            self.store.purge(older_than_days=-5)

    def test_vacuum_after_deletion_keeps_the_database_usable(self):
        identifiers = self.add(2)
        self.store.delete(identifiers[0])
        self.store.vacuum()
        self.assertEqual(self.store.count(), 1)


if __name__ == "__main__":
    unittest.main()
