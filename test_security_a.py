import json
import os
import shutil
import socket
import tempfile
import unittest
import uuid
from unittest import mock

import blastcheck


class SecurityATest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="blastcheck-home-")
        self.addCleanup(shutil.rmtree, self.home, True)

    def _no_network(self):
        return mock.patch("socket.socket", side_effect=AssertionError("network used"))

    def test_ssh_config_credential_shaped_tokens_are_hidden(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        host_token = "hostal" + uuid.uuid4().hex[:10]
        hostname_token = "hn" + uuid.uuid4().hex[:10]
        config_text = "Host {}\n  HostName {}\n".format(host_token, hostname_token)

        def cred_read(scanner, path, limit=blastcheck.MAX_SIZE):
            if os.path.basename(path) == "config":
                return config_text
            return None

        scanner = blastcheck.Scanner(self.home, True)
        with self._no_network(), mock.patch.object(
            blastcheck.Scanner, "read_text_limited", cred_read
        ):
            scanner.check_ssh()
        evidence = "\n".join(
            line
            for finding in scanner.findings
            if "SSH" in finding["title"]
            for line in finding["evidence"]
        )
        self.assertIn("[unusual name hidden]", evidence)
        self.assertNotIn(host_token, evidence)
        self.assertNotIn(hostname_token, evidence)

    def test_unknown_pem_label_is_never_printed(self):
        secret_part = uuid.uuid4().hex[:20]
        label = "ODD" + secret_part + " PRIVATE KEY"
        match = blastcheck._PEM_RE.match("-----BEGIN " + label + "-----")
        self.assertIsNotNone(match)
        kind = blastcheck.Scanner(self.home, False).pem_kind("unused", match)
        self.assertEqual(kind, "PRIVATE KEY")
        self.assertNotIn(secret_part, kind)

        other = "ODD" + uuid.uuid4().hex
        match2 = blastcheck._PEM_RE.match("-----BEGIN " + other + "-----")
        self.assertIsNotNone(match2)
        kind2 = blastcheck.Scanner(self.home, False).pem_kind("unused", match2)
        self.assertEqual(kind2, "UNRECOGNIZED BLOCK")
        self.assertNotIn(other, kind2)

    def test_unknown_dangerously_setting_is_generic(self):
        key = "dangerously" + uuid.uuid4().hex[:16]
        tokens = blastcheck.claude_risky_settings(json.dumps({key: True}))
        self.assertEqual(tokens, ["a dangerously* setting"])
        self.assertNotIn(key, " ".join(tokens))

    def test_safe_name_hides_mixed_eight_char_words(self):
        word = "ab" + uuid.uuid4().hex[:6] + "9"
        self.assertGreaterEqual(len(word), 8)
        self.assertTrue(blastcheck.token_shaped(word, 12))
        self.assertEqual(blastcheck.safe_name(word), "[unusual name hidden]")

    def test_display_path_hides_credential_shaped_parts(self):
        part = "tok" + uuid.uuid4().hex + "9"
        path = os.path.join(self.home, part, "file.txt")
        shown = blastcheck.display_path(path, self.home)
        self.assertIn("[name hidden]", shown)
        self.assertNotIn(part, shown)
        self.assertTrue(shown.startswith("~/"))
        self.assertIn("file.txt", shown)

    def test_settings_file_over_one_megabyte_is_parsed(self):
        key = "dangerously" + uuid.uuid4().hex[:16]
        settings = json.dumps({"pad": "x" * (2 * 1024 * 1024), key: True})
        claude_dir = os.path.join(self.home, ".claude")
        os.makedirs(claude_dir)
        path = os.path.join(claude_dir, "settings.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(settings)

        def opener(scanner, target, limit=blastcheck.MAX_SIZE):
            return open(target, "rb")

        scanner = blastcheck.Scanner(self.home, False)
        with self._no_network(), mock.patch.object(
            blastcheck.Scanner, "open_regular", opener
        ):
            text = scanner.read_text_limited(path, blastcheck.SETTINGS_MAX_SIZE)
            scanner.check_agents()
        self.assertIsNotNone(text)
        self.assertGreater(len(text or ""), blastcheck.MAX_SIZE)
        self.assertIn("a dangerously* setting", str(scanner.findings))
        self.assertIn(
            "Claude Code guardrails are disabled",
            [finding["title"] for finding in scanner.findings],
        )

    def test_deeply_nested_json_does_not_crash(self):
        deep = "[" * 100000 + "]" * 100000
        self.assertEqual(blastcheck.claude_risky_settings(deep), [])
        scanner = blastcheck.Scanner(self.home, False)
        with self._no_network(), mock.patch.object(
            blastcheck.Scanner, "read_text_limited",
            lambda self, path, limit=blastcheck.MAX_SIZE: deep,
        ):
            scanner.check_mcp()
        self.assertEqual(scanner.findings, [])


if __name__ == "__main__":
    unittest.main()
