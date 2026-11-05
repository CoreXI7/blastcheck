"""Tests for the environment, MCP and --fail-on additions to leasecheck.

Standard library only. Every scanner run is a subprocess with --home pointing
at a temporary home and a controlled environment, so no real home is read.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "leasecheck.py")

RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}

BASE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "LC_ALL": "C",
    "PYTHONIOENCODING": "utf-8",
}


def scan(home, extra_env=None, *args):
    env = dict(BASE_ENV)
    env["HOME"] = str(home)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, SCANNER, "--home", str(home)] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=120,
    )


def unique_value(prefix):
    return prefix + uuid.uuid4().hex


def findings_with(data, title):
    return [item for item in data["findings"] if item["title"] == title]


def expected_exit(data, level):
    threshold = RANK[level]
    return 1 if any(RANK[f["severity"]] <= threshold for f in data["findings"]) else 0


class EnvironmentCheckTest(unittest.TestCase):
    def test_literal_credential_is_reported_without_its_value(self):
        with tempfile.TemporaryDirectory() as home:
            name = "LEASE_TOKEN_" + uuid.uuid4().hex[:8].upper()
            value = unique_value("tok_")
            result = scan(home, {name: value}, "--json")
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)

            matches = findings_with(data, "Credentials in your shell environment")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["severity"], "medium")
            evidence = " ".join(matches[0]["evidence"])
            self.assertIn(name, evidence)
            self.assertNotIn(value, result.stdout)
            self.assertNotIn(value, result.stderr)

    def test_reference_and_placeholder_values_are_ignored(self):
        with tempfile.TemporaryDirectory() as home:
            reference_name = "LEASE_TOKEN_" + uuid.uuid4().hex[:8].upper()
            placeholder_name = "LEASE_SECRET_" + uuid.uuid4().hex[:8].upper()
            result = scan(
                home,
                {reference_name: "${SOME_OTHER_TOKEN}", placeholder_name: "changeme"},
                "--json",
            )
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertEqual(
                findings_with(data, "Credentials in your shell environment"), []
            )

    def test_fail_on_levels(self):
        with tempfile.TemporaryDirectory() as home:
            name = "LEASE_TOKEN_" + uuid.uuid4().hex[:8].upper()
            value = unique_value("tok_")
            env = {name: value}

            default = scan(home, env, "--json")
            self.assertEqual(default.returncode, 0)
            default_data = json.loads(default.stdout)
            self.assertIn(
                "medium",
                [item["severity"] for item in default_data["findings"]],
            )

            for level in ("critical", "high", "medium"):
                result = scan(home, env, "--json", "--fail-on", level)
                data = json.loads(result.stdout)
                self.assertEqual(
                    result.returncode,
                    expected_exit(data, level),
                    "wrong exit code for --fail-on " + level,
                )
            self.assertEqual(
                scan(home, env, "--json", "--fail-on", "medium").returncode, 1
            )


class McpCheckTest(unittest.TestCase):
    def test_servers_and_credentials_are_reported_without_secrets(self):
        with tempfile.TemporaryDirectory() as home:
            server_a = "alpha-" + uuid.uuid4().hex[:6]
            server_b = "beta-" + uuid.uuid4().hex[:6]
            env_name = "API_TOKEN_" + uuid.uuid4().hex[:6].upper()
            env_value = unique_value("key_")
            header_name = "AUTH_TOKEN"
            header_value = unique_value("hdr_")
            arg_value = unique_value("arg_")
            url_value = "https://" + uuid.uuid4().hex + ".example.invalid/mcp"

            config = {
                "mcpServers": {
                    server_a: {
                        "command": "node",
                        "args": ["server.js", arg_value, url_value],
                        "url": url_value,
                        "env": {env_name: env_value, "PLAIN_SETTING": "a-value"},
                    },
                    server_b: {
                        "url": url_value,
                        "headers": {header_name: header_value},
                    },
                }
            }
            with open(os.path.join(home, ".claude.json"), "w", encoding="utf-8") as fh:
                json.dump(config, fh)

            default = scan(home, {}, "--json")
            self.assertEqual(default.returncode, 0)
            data = json.loads(default.stdout)

            info = findings_with(data, "MCP servers an agent can use")
            self.assertEqual(len(info), 1)
            self.assertEqual(info[0]["severity"], "info")
            info_evidence = " ".join(info[0]["evidence"])
            self.assertIn("2 server(s)", info_evidence)
            self.assertIn(server_a, info_evidence)
            self.assertIn(server_b, info_evidence)
            self.assertIn(".claude.json", info_evidence)

            credentials = findings_with(data, "Credential stored in an MCP config")
            self.assertEqual(len(credentials), 2)
            for item in credentials:
                self.assertEqual(item["severity"], "high")
            credential_evidence = " ".join(
                evidence
                for item in credentials
                for evidence in item["evidence"]
            )
            self.assertIn(".claude.json", credential_evidence)
            self.assertIn(server_a, credential_evidence)
            self.assertIn(server_b, credential_evidence)
            self.assertIn(env_name, credential_evidence)
            self.assertIn(header_name, credential_evidence)

            forbidden = (env_value, header_value, arg_value, url_value)
            for secret in forbidden:
                self.assertNotIn(secret, default.stdout)
                self.assertNotIn(secret, default.stderr)

            failed = scan(home, {}, "--json", "--fail-on", "high")
            self.assertEqual(failed.returncode, 1)
            self.assertNotIn(env_value, failed.stdout)
            self.assertNotIn(header_value, failed.stdout)
            self.assertNotIn(arg_value, failed.stdout)
            self.assertNotIn(url_value, failed.stdout)

    def test_invalid_json_is_skipped_quietly(self):
        with tempfile.TemporaryDirectory() as home:
            marker = uuid.uuid4().hex
            os.makedirs(os.path.join(home, ".cursor"))
            with open(
                os.path.join(home, ".cursor", "mcp.json"), "w", encoding="utf-8"
            ) as fh:
                fh.write("{ this is not json " + marker)

            result = scan(home, {}, "--json")
            self.assertEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertEqual(findings_with(data, "MCP servers an agent can use"), [])
            self.assertNotIn(marker, result.stdout)
            self.assertNotIn(marker, result.stderr)


if __name__ == "__main__":
    unittest.main()
