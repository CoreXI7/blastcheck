#!/usr/bin/env python3
"""Tests for blastcheck: subprocess scans of a fake home plus unit tables."""

import importlib.util
import json
import re
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "blastcheck.py")


def load_blastcheck():
    spec = importlib.util.spec_from_file_location("blastcheck", SCANNER)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load " + SCANNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


blastcheck = load_blastcheck()


def snapshot_tree(root):
    """Record path kind, permission bits, contents and mtime for everything."""
    entries = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            rel = os.path.relpath(path, root)
            if stat.S_ISLNK(st.st_mode):
                entries[rel] = ("link", os.readlink(path), st.st_mtime_ns)
            elif stat.S_ISREG(st.st_mode):
                with open(path, "rb") as handle:
                    data = handle.read()
                entries[rel] = (
                    "file",
                    stat.S_IMODE(st.st_mode),
                    data,
                    st.st_mtime_ns,
                )
            elif stat.S_ISDIR(st.st_mode):
                entries[rel] = ("dir", stat.S_IMODE(st.st_mode), st.st_mtime_ns)
            else:
                entries[rel] = ("other", stat.S_IFMT(st.st_mode), st.st_mtime_ns)
    return entries


def make_value(prefix):
    return prefix + "_" + uuid.uuid4().hex + uuid.uuid4().hex


class ScannerSubprocessTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="blastcheck-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.outside = tempfile.mkdtemp(prefix="blastcheck-outside-")
        self.addCleanup(shutil.rmtree, self.outside, True)

    def write_text(self, root, relpath, content, mode=None):
        path = os.path.join(root, relpath)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def scan(self):
        return subprocess.run(
            [sys.executable, SCANNER, "--home", self.home, "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )

    def test_fake_credential_values_never_appear(self):
        values = [
            make_value("apikey"),
            make_value("dbpassword"),
            make_value("stripesecret"),
            make_value("awssecret"),
            make_value("keybody"),
        ]
        self.write_text(
            self.home,
            ".env",
            "API_KEY={}\nDB_PASSWORD={}\nSTRIPE_SECRET={}\n".format(*values[:3]),
            mode=0o600,
        )
        self.write_text(
            self.home,
            os.path.join(".aws", "credentials"),
            "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n".format(
                "AKIA" + uuid.uuid4().hex[:16].upper(), values[3]
            ),
            mode=0o600,
        )
        self.write_text(
            self.home,
            os.path.join(".ssh", "id_test"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n"
            "-----END OPENSSH PRIVATE KEY-----\n".format(values[4]),
            mode=0o600,
        )

        proc = self.scan()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        combined = proc.stdout + proc.stderr
        for value in values:
            with self.subTest(value=value):
                self.assertNotIn(value, combined)
        self.assertIn("API_KEY", proc.stdout)
        data = json.loads(proc.stdout)
        self.assertIn("summary", data)
        self.assertIn("findings", data)

    def test_home_contents_and_modes_unchanged(self):
        self.write_text(
            self.home,
            ".env",
            "API_KEY={}\n".format(make_value("apikey")),
            mode=0o600,
        )
        self.write_text(
            self.home,
            os.path.join(".ssh", "id_test"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n"
            "-----END OPENSSH PRIVATE KEY-----\n".format(make_value("keybody")),
            mode=0o600,
        )
        self.write_text(
            self.home,
            os.path.join(".config", "plain", "notes.txt"),
            "nothing secret here\n",
            mode=0o644,
        )

        before = snapshot_tree(self.home)
        proc = self.scan()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        after = snapshot_tree(self.home)
        self.assertEqual(before, after)

    def test_symlinks_are_not_followed(self):
        value = make_value("linkedsecret")
        target_name = "outside_" + uuid.uuid4().hex + ".env"
        target = self.write_text(
            self.outside, target_name, "API_KEY={}\n".format(value), mode=0o600
        )
        link_name = "link_" + uuid.uuid4().hex + ".env"
        link = os.path.join(self.home, link_name)
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available on this platform")

        dir_secret_name = "dirseed_" + uuid.uuid4().hex + ".env"
        dir_target = os.path.join(self.outside, "dir_" + uuid.uuid4().hex)
        os.makedirs(dir_target, exist_ok=True)
        self.write_text(
            dir_target, dir_secret_name, "API_KEY={}\n".format(make_value("dirlink"))
        )
        dir_link_name = "dirlink_" + uuid.uuid4().hex
        dir_link = os.path.join(self.home, dir_link_name)
        try:
            os.symlink(dir_target, dir_link, target_is_directory=True)
        except (OSError, NotImplementedError):
            dir_link = None

        proc = self.scan()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(value, proc.stdout)
        self.assertNotIn(target_name, proc.stdout)
        self.assertNotIn(link_name, proc.stdout)
        if dir_link is not None:
            self.assertNotIn(dir_secret_name, proc.stdout)
            self.assertNotIn(dir_link_name, proc.stdout)

    def test_files_over_one_megabyte_are_skipped(self):
        value = make_value("bigsecret")
        name = "big_" + uuid.uuid4().hex + ".env"
        content = "API_KEY={}\n".format(value) + ("x" * (1024 * 1024 + 2048))
        self.write_text(self.home, name, content)

        proc = self.scan()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertGreaterEqual(data["scan"]["files_over_1mb_skipped"], 1)
        self.assertNotIn(value, proc.stdout)
        self.assertNotIn(name, proc.stdout)


class SudoNopassCommandsTests(unittest.TestCase):
    CASES = (
        ("all-commands rule still needing a password", "(ALL) ALL", []),
        ("all-commands rule tagged NOPASSWD", "(ALL) NOPASSWD: ALL", ["ALL"]),
        (
            "NOPASSWD rule for the reboot program",
            "(ALL) NOPASSWD: /sbin/reboot",
            ["/sbin/reboot"],
        ),
    )

    def test_sudo_table(self):
        for label, text, expected in self.CASES:
            with self.subTest(label=label):
                self.assertEqual(
                    blastcheck.sudo_nopass_commands(text + "\n"), expected
                )


class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="blastcheck-home-")
        self.addCleanup(shutil.rmtree, self.home, True)

    def put(self, relpath, content, mode=0o600):
        path = os.path.join(self.home, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(path, mode)
        return path

    def run_cli(self, *flags):
        return subprocess.run(
            [sys.executable, SCANNER, "--home", self.home, *flags],
            capture_output=True, text=True, timeout=120,
        )

    def scan_json(self):
        proc = self.run_cli("--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout, json.loads(proc.stdout)

    def titles(self, data):
        return [f["title"] for f in data["findings"]]

    def test_saved_login_stores_are_not_opened(self):
        self.put(".aws/credentials", "[default]\nodd_secret_name = abcdefghijkl\n")
        stdout, data = self.scan_json()
        self.assertNotIn("odd_secret_name", stdout)
        self.assertIn("Saved login store present: AWS credentials", self.titles(data))

    def test_code_and_references_are_not_called_secrets(self):
        self.put("a/app.py", 'API_KEY = "abcdefghijkl"\n')
        self.put("a/x.yaml", "api_key: ${FROM_ENV}\nmax_tokens: 1000\ntoken_count: abcdefgh\n")
        _, data = self.scan_json()
        self.assertNotIn("Secret-looking file in the home directory", self.titles(data))

    def test_literal_config_value_reports_name_only(self):
        value = "v" + uuid.uuid4().hex
        self.put("a/x.yaml", "db_password: {}\n".format(value))
        stdout, data = self.scan_json()
        self.assertIn("db_password", stdout)
        self.assertNotIn(value, stdout)
        self.assertIn("Secret-looking file in the home directory", self.titles(data))

    def test_credential_shaped_name_is_hidden(self):
        name = "token_" + uuid.uuid4().hex
        self.put("a/x.yaml", "{}: abcdefghijkl\n".format(name))
        stdout, _ = self.scan_json()
        self.assertNotIn(name, stdout)

    def test_passphrase_detection(self):
        keygen = shutil.which("ssh-keygen")
        if not keygen:
            self.skipTest("ssh-keygen is not available")
        ssh = os.path.join(self.home, ".ssh")
        os.makedirs(ssh, mode=0o700)
        make = lambda name, phrase: subprocess.run(
            [keygen, "-q", "-t", "ed25519", "-N", phrase, "-f", os.path.join(ssh, name)],
            check=True, stdin=subprocess.DEVNULL,
        )
        make("locked", "correct horse battery")
        make("open", "")
        self.put(".ssh/oldstyle", "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n")
        stdout, data = self.scan_json()
        evidence = [
            line for f in data["findings"]
            if f["title"] == "Private SSH key without a passphrase"
            for line in f["evidence"]
        ]
        joined = " ".join(evidence)
        self.assertIn("~/.ssh/open ", joined)
        self.assertNotIn("~/.ssh/locked", joined)
        self.assertNotIn("~/.ssh/oldstyle", joined)
        with open(os.path.join(ssh, "open")) as handle:
            for line in handle.read().splitlines()[1:-1]:
                self.assertNotIn(line, stdout)

    def test_reads_refuse_links_and_fifos(self):
        scanner = blastcheck.Scanner(self.home, False)
        target = self.put("real.env", "A=1\n")
        link = os.path.join(self.home, "link.env")
        fifo = os.path.join(self.home, "pipe.env")
        os.symlink(target, link)
        os.mkfifo(fifo)
        for path in (link, fifo):
            with self.assertRaises(OSError):
                scanner.open_regular(path)
        self.assertEqual(self.run_cli("--json").returncode, 0)

    def test_hostile_file_names_are_safe(self):
        base = os.fsencode(self.home) + b"/.env"
        try:
            # Linux allows any bytes; macOS rejects names that aren't UTF-8.
            raw = base + b"\xff\x1b[31m\xe2\x80\xae"
            handle = open(raw, "w")
        except OSError:
            raw = base + b"\x1b[31m\xe2\x80\xae"
            handle = open(raw, "w")
        with handle:
            handle.write("API_KEY=abcdefghijkl\n")
        proc = self.run_cli()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("\x1b", proc.stdout)
        self.assertNotIn("\u202e", proc.stdout)

    def test_grouping_and_all(self):
        for i in range(12):
            self.put("a/{}.env".format(i), "API_KEY=abcdefghijkl\n")
        title = "Secret-looking file in the home directory"
        short = self.run_cli().stdout
        self.assertRegex(short, re.escape(title) + r" +12 items")
        self.assertIn("MEDIUM", short)
        self.assertIn("2 more evidence lines not shown", short)
        self.assertEqual(self.run_cli("--all").stdout.count(title), 12)
        self.assertEqual(self.titles(self.scan_json()[1]).count(title), 12)

    def test_claude_settings_are_parsed(self):
        f = blastcheck.claude_risky_settings
        self.assertEqual(f('{"permissions": {"defaultMode": "bypassPermissions"}}'),
                         ["defaultMode: bypassPermissions"])
        self.assertEqual(f('{"dangerouslySkipPermissions": true}'), ["dangerouslySkipPermissions"])
        self.assertEqual(f('{"dangerouslySkipPermissions": false}'), [])
        self.assertEqual(f('{"note": "never use bypassPermissions"}'), [])
        self.assertEqual(f("not json"), [])

    def sudo_findings(self, listing):
        scanner = blastcheck.Scanner(self.home, False)
        def fake(argv):
            out = listing if argv[0] == "sudo" else ""
            return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")
        with mock.patch.object(blastcheck, "run_fixed", fake):
            scanner.check_root_paths()
        return [f for f in scanner.findings if "sudo" in f["title"].lower()]

    def test_sudo_severity(self):
        self.assertEqual(self.sudo_findings("    (ALL : ALL) ALL\n"), [])
        self.assertEqual(self.sudo_findings("    (ALL) NOPASSWD" + ": ALL\n")[0]["severity"], "critical")
        some = self.sudo_findings("    (ALL) NOPASSWD" + ": /usr/bin/tool --arg hiddenvalue\n")
        self.assertEqual(some[0]["severity"], "high")
        self.assertIn("/usr/bin/tool", some[0]["evidence"][0])
        self.assertNotIn("hiddenvalue", some[0]["evidence"][0])


if __name__ == "__main__":
    unittest.main()
