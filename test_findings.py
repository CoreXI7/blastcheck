#!/usr/bin/env python3
"""Finding-level tests for leasecheck on a temporary fake home.

Run with: python3 -m unittest test_findings.py
"""

import base64
import json
import os
import shutil
import tempfile
import types
import unittest
import uuid
from unittest import mock

import leasecheck


POSIX = os.name == "posix"


def fake_result(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def unique_hex():
    return uuid.uuid4().hex


def write_file(path, text, mode=None):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    if mode is not None and POSIX:
        os.chmod(path, mode)


def rsa_private_key(encrypted=False):
    body = base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).decode("ascii")
    lines = ["-----BEGIN RSA PRIVATE KEY-----"]
    if encrypted:
        lines.append("Proc-Type: 4,ENCRYPTED")
        lines.append("DEK-Info: AES-128-CBC," + uuid.uuid4().hex[:32].upper())
        lines.append("")
    lines.append(body)
    lines.append("-----END RSA PRIVATE KEY-----")
    return "\n".join(lines) + "\n"


def openssh_private_key(cipher):
    magic = b"openssh-key-v1\0"
    cipher_bytes = cipher.encode("ascii")
    raw = magic + len(cipher_bytes).to_bytes(4, "big") + cipher_bytes
    body = base64.b64encode(raw).decode("ascii")
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + body
        + "\n-----END OPENSSH PRIVATE KEY-----\n"
    )


class ScannerTestCase(unittest.TestCase):
    """Base case: a throwaway home and mocked id/sudo subprocess calls."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="leasecheck-findings-")
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.groups = []
        self.id_ok = True
        self.sudo_result = fake_result(1, "", "sudo: a password is required\n")
        patcher = mock.patch.object(
            leasecheck, "run_fixed", side_effect=self._fake_run_fixed
        )
        self.run_fixed_mock = patcher.start()
        self.addCleanup(patcher.stop)

    def _fake_run_fixed(self, argv):
        argv = list(argv)
        if argv == ["id", "-nG"]:
            if not self.id_ok:
                return None
            stdout = " ".join(self.groups)
            if stdout:
                stdout += "\n"
            return fake_result(0, stdout)
        if argv == ["sudo", "-n", "-l"]:
            return self.sudo_result
        raise AssertionError("unexpected fixed command: {!r}".format(argv))

    def reset_home(self):
        shutil.rmtree(self.home, ignore_errors=True)
        os.makedirs(self.home, exist_ok=True)

    def path(self, *parts):
        return os.path.join(self.home, *parts)

    def scan(self, show_hosts=False):
        return leasecheck.Scanner(self.home, show_hosts).run()

    def findings(self, data, title=None, severity=None):
        matches = []
        for finding in data["findings"]:
            if title is not None and finding["title"] != title:
                continue
            if severity is not None and finding["severity"] != severity:
                continue
            matches.append(finding)
        return matches

    def assert_finding(self, data, title, severity):
        matches = self.findings(data, title=title, severity=severity)
        self.assertTrue(matches, "missing {} finding: {}".format(severity, title))
        return matches

    def assert_no_finding(self, data, title):
        self.assertFalse(
            self.findings(data, title=title), "unexpected finding: " + title
        )


class RootGroupTests(ScannerTestCase):
    root_groups = ("docker", "lxd", "lxc", "libvirt", "libvirtd")

    def test_each_root_equivalent_group_is_reported(self):
        for group in self.root_groups:
            with self.subTest(group=group):
                self.reset_home()
                self.groups = ["users", group]
                data = self.scan()
                found = self.assert_finding(
                    data, "Your user is in a root-equivalent group", "critical"
                )
                self.assertEqual(len(found), 1)
                self.assertIn(group, found[0]["evidence"][0])
                self.run_fixed_mock.assert_any_call(["id", "-nG"])

    def test_no_root_equivalent_group_is_not_reported(self):
        self.groups = ["users", "audio", "video"]
        data = self.scan()
        self.assert_no_finding(data, "Your user is in a root-equivalent group")

    def test_group_check_failure_is_noted(self):
        self.id_ok = False
        data = self.scan()
        self.assertTrue(
            any(
                "Group membership could not be checked" in note
                for note in data["scan"]["notes"]
            )
        )
        self.assert_no_finding(data, "Your user is in a root-equivalent group")


class DockerSocketTests(ScannerTestCase):
    def test_writable_docker_socket_is_critical(self):
        import socket
        os.makedirs(self.path(".docker", "run"))
        server = socket.socket(socket.AF_UNIX)
        self.addCleanup(server.close)
        server.bind(self.path(".docker", "run", "docker.sock"))
        data = self.scan()
        found = self.assert_finding(data, "The Docker socket is writable", "critical")
        self.assertTrue(
            any(
                "~/.docker/run/docker.sock" in evidence
                for finding in found
                for evidence in finding["evidence"]
            )
        )


class SudoTests(ScannerTestCase):
    def test_passwordless_sudo_all_is_critical(self):
        self.sudo_result = fake_result(0, "(ALL) NOPASSWD: ALL\n", "")
        found = self.assert_finding(
            self.scan(), "Passwordless sudo gives full root", "critical"
        )
        self.assertEqual(len(found), 1)

    def test_limited_passwordless_sudo_is_high(self):
        self.sudo_result = fake_result(
            0, "(root) NOPASSWD: /usr/sbin/reboot, /usr/local/bin/tool x\n", ""
        )
        found = self.assert_finding(
            self.scan(), "Passwordless sudo is allowed for some commands", "high"
        )
        evidence = " ".join(found[0]["evidence"])
        self.assertIn("/usr/sbin/reboot", evidence)
        self.assertIn("/usr/local/bin/tool", evidence)

    def test_root_equivalent_program_is_critical(self):
        self.sudo_result = fake_result(0, "(root) NOPASSWD: /usr/bin/apt\n", "")
        self.assert_finding(self.scan(), "Passwordless sudo gives full root", "critical")

    def test_password_required_is_noted(self):
        data = self.scan()
        self.assert_no_finding(data, "Passwordless sudo gives full root")
        self.assert_no_finding(data, "Passwordless sudo is allowed for some commands")
        self.assertTrue(
            any(
                "Sudo rules could not be listed" in note
                for note in data["scan"]["notes"]
            )
        )

    def test_sudo_unavailable_is_noted(self):
        self.sudo_result = None
        data = self.scan()
        self.assertTrue(
            any(
                "Passwordless sudo could not be checked" in note
                for note in data["scan"]["notes"]
            )
        )


class SavedLoginTests(ScannerTestCase):
    directory_stores = {".config/gcloud", ".azure"}

    def test_each_saved_login_store_is_reported(self):
        for rel, label in leasecheck.SAVED_LOGINS:
            with self.subTest(store=rel):
                self.reset_home()
                target = self.path(*rel.split("/"))
                if rel in self.directory_stores:
                    os.makedirs(target, exist_ok=True)
                else:
                    write_file(
                        target, "fake-token=" + unique_hex() + "\n", mode=0o600
                    )
                found = self.assert_finding(
                    self.scan(), "Saved login store present: " + label, "high"
                )
                self.assertEqual(len(found), 1, rel)


class AgentDetectionTests(ScannerTestCase):
    agents = (
        ("Claude Code", ".claude", True),
        ("OpenCode", os.path.join(".config", "opencode"), True),
        ("Codex", ".codex", True),
        ("Cursor", ".cursor", True),
        ("Aider", ".aider.conf.yml", False),
        ("Gemini CLI", ".gemini", True),
    )

    def test_each_agent_is_detected(self):
        for label, rel, is_dir in self.agents:
            with self.subTest(agent=label):
                self.reset_home()
                target = os.path.join(self.home, rel)
                if is_dir:
                    os.makedirs(target, exist_ok=True)
                else:
                    write_file(target, "auto_commits: false\n", mode=0o600)
                found = self.assert_finding(
                    self.scan(), "Agent installed: " + label, "info"
                )
                self.assertEqual(len(found), 1, label)


class ClaudeSettingsTests(ScannerTestCase):
    title = "Claude Code guardrails are disabled"

    def write_settings(self, payload):
        self.reset_home()
        write_file(
            self.path(".claude", "settings.json"),
            json.dumps(payload),
            mode=0o600,
        )

    def test_bypass_permissions_is_critical(self):
        self.write_settings({"permissions": {"defaultMode": "bypassPermissions"}})
        found = self.assert_finding(self.scan(), self.title, "critical")
        self.assertIn("defaultMode: bypassPermissions", found[0]["evidence"][0])

    def test_dangerously_setting_is_critical(self):
        self.write_settings({"dangerouslySkipPermissions": True})
        found = self.assert_finding(self.scan(), self.title, "critical")
        self.assertIn("dangerouslySkipPermissions", found[0]["evidence"][0])

    def test_safe_settings_are_not_reported(self):
        self.write_settings({"permissions": {"defaultMode": "default"}})
        self.assert_no_finding(self.scan(), self.title)


class CodexSettingsTests(ScannerTestCase):
    title = "Codex runs without a sandbox or approvals"

    def write_config(self, text):
        self.reset_home()
        write_file(self.path(".codex", "config.toml"), text, mode=0o600)

    def test_each_risky_value_is_high(self):
        for text in (
            'sandbox_mode = "danger-full-access"\n',
            'approval_policy = "never"\n',
        ):
            with self.subTest(setting=text.strip()):
                self.write_config(text)
                found = self.assert_finding(self.scan(), self.title, "high")
                self.assertEqual(len(found), 1)

    def test_both_risky_values_are_listed(self):
        self.write_config(
            'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n'
        )
        found = self.assert_finding(self.scan(), self.title, "high")
        evidence = found[0]["evidence"][0]
        self.assertIn('sandbox_mode = "danger-full-access"', evidence)
        self.assertIn('approval_policy = "never"', evidence)

    def test_safe_values_are_not_reported(self):
        for text in (
            'sandbox_mode = "workspace-write"\n',
            'approval_policy = "on-request"\n',
            'sandbox_mode = "workspace-write"\napproval_policy = "on-request"\n',
        ):
            with self.subTest(setting=text.strip()):
                self.write_config(text)
                self.assert_no_finding(self.scan(), self.title)


class OpenCodePermissionTests(ScannerTestCase):
    allow_title = "OpenCode permission is set to allow"
    missing_title = "OpenCode has no permission restriction"

    def write_config(self, text=None, name="opencode.json"):
        self.reset_home()
        directory = self.path(".config", "opencode")
        os.makedirs(directory, exist_ok=True)
        if text is not None:
            write_file(os.path.join(directory, name), text, mode=0o600)

    def test_allow_is_high(self):
        for text in (
            '{"permission": "allow"}',
            '{"permission": {"bash": "allow"}}',
        ):
            with self.subTest(config=text):
                self.write_config(text)
                found = self.assert_finding(self.scan(), self.allow_title, "high")
                self.assertEqual(len(found), 1)

    def test_ask_is_not_reported(self):
        for text in (
            '{"permission": "ask"}',
            '{"permission": {"bash": "ask"}}',
        ):
            with self.subTest(config=text):
                self.write_config(text)
                data = self.scan()
                self.assert_no_finding(data, self.allow_title)
                self.assert_no_finding(data, self.missing_title)

    def test_missing_permission_is_a_note_not_a_finding(self):
        for text in ('{"model": "test-model"}', None):
            with self.subTest(config=text):
                self.write_config(text)
                data = self.scan()
                self.assert_no_finding(data, self.missing_title)
                self.assert_no_finding(data, self.allow_title)
                self.assertTrue(any("OpenCode" in n for n in data["scan"]["notes"]))

    def test_nested_allow_rule_is_high(self):
        self.write_config('{"permission": {"edit": "ask", "bash": {"git *": "ask", "*": "allow"}}}')
        self.assert_finding(self.scan(), self.allow_title, "high")


class StartupFileTests(ScannerTestCase):
    def test_each_writable_startup_file_is_reported(self):
        for name in (".bashrc", ".profile", os.path.join(".ssh", "authorized_keys")):
            with self.subTest(file=name):
                self.reset_home()
                write_file(
                    self.path(name),
                    "export FAKE_MARK=" + unique_hex() + "\n",
                    mode=0o620,
                )
                found = self.assert_finding(
                    self.scan(), "Startup file writable by group or others", "high"
                )
                self.assertEqual(len(found), 1, name)
                self.assertIn(name.replace(os.sep, "/"), found[0]["evidence"][0])


@unittest.skipUnless(POSIX, "POSIX mode bits are required")
class LoosePermissionTests(ScannerTestCase):
    title = "Secret file readable by group or others"

    def write_secret(self, mode):
        self.reset_home()
        write_file(self.path(".env"), "API_KEY=" + unique_hex() + "\n", mode=mode)
        return self.scan()

    def test_group_readable_secret_is_high(self):
        found = self.assert_finding(self.write_secret(0o640), self.title, "high")
        self.assertEqual(len(found), 1)
        self.assertIn("0640", found[0]["evidence"][0])

    def test_other_readable_secret_is_high(self):
        found = self.assert_finding(self.write_secret(0o604), self.title, "high")
        self.assertEqual(len(found), 1)
        self.assertIn("0604", found[0]["evidence"][0])

    def test_world_readable_secret_is_high(self):
        found = self.assert_finding(self.write_secret(0o644), self.title, "high")
        self.assertEqual(len(found), 1)

    def test_mode_600_secret_is_not_reported(self):
        self.assert_no_finding(self.write_secret(0o600), self.title)


class SshPrivateKeyTests(ScannerTestCase):
    high_title = "Private SSH key without a passphrase"
    info_title = "SSH access an agent could use"

    def write_key(self, name, text, mode=0o600):
        self.reset_home()
        write_file(self.path(".ssh", name), text, mode=mode)
        return self.scan()

    def test_plain_rsa_key_is_high(self):
        data = self.write_key("id_rsa", rsa_private_key(encrypted=False))
        found = self.assert_finding(data, self.high_title, "high")
        self.assertEqual(len(found), 1)
        evidence = found[0]["evidence"][0]
        self.assertIn("id_rsa", evidence)
        self.assertIn("RSA PRIVATE KEY", evidence)
        self.assertNotIn("ENCRYPTED", evidence)
        info = self.assert_finding(data, self.info_title, "info")
        self.assertIn("0 show an encrypted header", info[0]["evidence"][0])

    def test_encrypted_rsa_key_is_not_high(self):
        data = self.write_key("id_rsa", rsa_private_key(encrypted=True))
        self.assert_no_finding(data, self.high_title)
        info = self.assert_finding(data, self.info_title, "info")
        self.assertIn("1 show an encrypted header", info[0]["evidence"][0])

    def test_plain_openssh_key_is_high(self):
        data = self.write_key("id_ed25519", openssh_private_key("none"))
        found = self.assert_finding(data, self.high_title, "high")
        self.assertIn("OPENSSH PRIVATE KEY", found[0]["evidence"][0])

    def test_encrypted_openssh_key_is_not_high(self):
        data = self.write_key("id_ed25519", openssh_private_key("aes256-ctr"))
        self.assert_no_finding(data, self.high_title)
        info = self.assert_finding(data, self.info_title, "info")
        self.assertIn("1 show an encrypted header", info[0]["evidence"][0])


class KeyFileTests(ScannerTestCase):
    high_title = "Private key without a passphrase"
    medium_title = "Secret-looking file in the home directory"

    def write_pem(self, text, name="server.pem", mode=0o600):
        self.reset_home()
        write_file(self.path(name), text, mode=mode)
        return self.scan()

    def test_plain_pem_is_high_and_medium(self):
        data = self.write_pem(rsa_private_key(encrypted=False))
        high = self.assert_finding(data, self.high_title, "high")
        self.assertEqual(len(high), 1)
        self.assertIn("RSA PRIVATE KEY", high[0]["evidence"][0])
        self.assertIn("no passphrase detected", high[0]["evidence"][0])
        medium = self.assert_finding(data, self.medium_title, "medium")
        self.assertEqual(len(medium), 1)
        self.assertIn("PEM header: RSA PRIVATE KEY", medium[0]["evidence"][0])

    def test_encrypted_pem_is_medium_not_high(self):
        data = self.write_pem(rsa_private_key(encrypted=True))
        self.assert_no_finding(data, self.high_title)
        medium = self.assert_finding(data, self.medium_title, "medium")
        self.assertEqual(len(medium), 1)
        self.assertIn(
            "PEM header: RSA PRIVATE KEY ENCRYPTED", medium[0]["evidence"][0]
        )


class SecretNameTests(ScannerTestCase):
    title = "Secret-looking file in the home directory"

    def test_secret_variable_name_in_generic_file_is_medium(self):
        value = unique_hex()
        write_file(self.path("app.ini"), "[auth]\nAPI_KEY=" + value + "\n", mode=0o600)
        data = self.scan()
        found = self.assert_finding(data, self.title, "medium")
        self.assertTrue(any("API_KEY" in item for item in found[0]["evidence"]))
        self.assertNotIn(value, json.dumps(data))

    def test_harmless_variable_name_is_not_reported(self):
        write_file(self.path("app.ini"), "[app]\nLOG_LEVEL=verbose\n", mode=0o600)
        self.assert_no_finding(self.scan(), self.title)


if __name__ == "__main__":
    unittest.main()
