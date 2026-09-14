import shlex
import unittest
from unittest.mock import patch

import hexstrike_server
from hexstrike_server import app

SPACED = "/Volumes/shuaibs/Shahid project/hanzo/wordlists/common.txt"


class PathQuotingTests(unittest.TestCase):
    """Adapters build shell strings for shell=True.

    An unquoted path containing a space splits into separate arguments, so the
    tool reads the wrong file or fails. These guard the quoting that prevents it.
    """

    def setUp(self):
        self.client = app.test_client()

    def run_tool(self, route, payload):
        captured = {}

        result = {"success": True, "return_code": 0, "stdout": "", "stderr": ""}

        def capture_plain(command, *args, **kwargs):
            captured["command"] = command
            return result

        def capture_recovery(tool_name, command, *args, **kwargs):
            # execute_command_with_recovery takes the tool name first.
            captured["command"] = command
            return result

        with patch.object(hexstrike_server, "execute_command", side_effect=capture_plain), \
             patch.object(hexstrike_server, "execute_command_with_recovery", side_effect=capture_recovery):
            response = self.client.post(route, json=payload)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return captured.get("command", "")

    def assert_path_survives_shlex(self, command, path):
        self.assertIn(path, command)
        self.assertIn(path, shlex.split(command),
                      f"path was split by the shell in: {command}")

    def test_gobuster_wordlist_with_spaces_stays_one_argument(self):
        command = self.run_tool("/api/tools/gobuster",
                                {"url": "http://127.0.0.1:5099", "mode": "dir", "wordlist": SPACED})
        self.assert_path_survives_shlex(command, SPACED)

    def test_feroxbuster_wordlist_with_spaces_stays_one_argument(self):
        command = self.run_tool("/api/tools/feroxbuster",
                                {"url": "http://127.0.0.1:5099", "wordlist": SPACED})
        self.assert_path_survives_shlex(command, SPACED)

    def test_ffuf_wordlist_with_spaces_stays_one_argument(self):
        command = self.run_tool("/api/tools/ffuf",
                                {"url": "http://127.0.0.1:5099/FUZZ", "wordlist": SPACED})
        self.assert_path_survives_shlex(command, SPACED)

    def test_httpx_single_url_uses_u_not_l(self):
        # -l reads a FILE of targets; a single URL must use -u.
        command = self.run_tool("/api/tools/httpx", {"target": "http://127.0.0.1:5099"})
        self.assertIn("-u http://127.0.0.1:5099", command)
        self.assertNotIn("-l http://127.0.0.1:5099", command)

    def test_quoting_helper_is_reversible(self):
        self.assertEqual(shlex.split(hexstrike_server._q(SPACED))[0], SPACED)


if __name__ == "__main__":
    unittest.main()
