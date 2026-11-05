#!/usr/bin/env python3
"""Tests for blastcheck's sudo, SSH agent, MCP and startup-file checks."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blastcheck

AF_UNIX = getattr(socket, "AF_UNIX", None)


class TestSecurityB(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lc")
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name

    def scanner(self):
        return blastcheck.Scanner(self.home, False)

    def test_passwordless_sudo_critical_and_high(self):
        cases = (
            ("critical", "/usr/bin/systemctl"),
            ("critical", "/usr/bin/*"),
            ("high", "/usr/sbin/reboot"),
        )
        for severity, rule in cases:
            with self.subTest(rule=rule):
                scanner = self.scanner()
                output = "(ALL) NOPASSWD: " + rule

                def fake_run(argv):
                    if argv == ["id", "-nG"]:
                        return subprocess.CompletedProcess(argv, 0, "users\n", "")
                    return subprocess.CompletedProcess(argv, 0, output + "\n", "")

                with mock.patch.object(blastcheck, "run_fixed", side_effect=fake_run):
                    scanner.check_root_paths()
                titles = {item["title"]: item["severity"] for item in scanner.findings}
                if severity == "critical":
                    self.assertEqual(
                        titles.get("Passwordless sudo gives full root"), "critical"
                    )
                else:
                    self.assertEqual(
                        titles.get(
                            "Passwordless sudo is allowed for some commands"
                        ),
                        "high",
                    )
                    self.assertNotIn("Passwordless sudo gives full root", titles)

    def test_ssh_auth_sock_socket_is_high(self):
        family = AF_UNIX
        if family is None:
            self.skipTest("unix sockets are unavailable here")
        sock_dir = tempfile.mkdtemp(prefix="lc", dir=tempfile.gettempdir())
        self.addCleanup(shutil.rmtree, sock_dir, True)
        path = os.path.join(sock_dir, "agent.sock")
        server = socket.socket(family, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(path)

        scanner = self.scanner()
        with mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": path}):
            scanner.check_ssh_agent()
        high = [item for item in scanner.findings if item["severity"] == "high"]
        self.assertEqual(len(high), 1)
        self.assertIn("SSH agent", high[0]["title"])

    def test_mcp_labels_never_show_value(self):
        secret = "k" + uuid.uuid4().hex
        config = {
            "mcpServers": {
                "svc": {
                    "args": ["--api-key", secret],
                    "url": (
                        "https://user:" + secret
                        + "@example.test/mcp?api_key=" + secret
                    ),
                }
            }
        }
        path = os.path.join(self.home, ".claude.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

        scanner = self.scanner()
        scanner.check_mcp()
        findings = [item for item in scanner.findings if item["severity"] == "high"]
        self.assertTrue(findings)
        labels = {item["title"] for item in findings}
        self.assertIn("Credential stored in an MCP config", labels)
        blob = "\n".join(e for item in findings for e in item["evidence"])
        for label in ("argument --api-key", "login inside url", "url parameter api_key"):
            self.assertIn(label, blob)
        self.assertNotIn(secret, blob)

    def test_startup_file_group_writable_is_high(self):
        path = os.path.join(self.home, ".bashrc")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('export PATH="$PATH"\n')
        os.chmod(path, 0o664)

        scanner = self.scanner()
        scanner.check_startup_writable()
        high = [item for item in scanner.findings if item["severity"] == "high"]
        self.assertEqual(len(high), 1)
        self.assertIn("Startup file writable by group or others", high[0]["title"])


if __name__ == "__main__":
    unittest.main()
