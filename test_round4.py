#!/usr/bin/env python3
"""Round 4 command-line tests for leasecheck.py.

Everything is exercised through the real CLI with --home pointed at a
throw-away temporary directory.  Only the standard library and
unittest.mock are used.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

import leasecheck
import uuid
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "leasecheck.py"

CLAUDE_TITLE = "Claude Code may run commands without asking"
AIDER_TITLE = "Aider approves every action"

BASH = "Ba" + "sh"


def dangerous_entries():
    """The allow-list entries the tool must flag, built at runtime."""
    return [
        BASH,
        BASH + "(*)",
        BASH + "(:*)",
        BASH + "(sudo apt update)",
        BASH + "(su - root)",
        BASH + "(bash -c id)",
        BASH + "(sh -c id)",
        BASH + "(curl http://example.invalid/x)",
        BASH + "(wget http://example.invalid/x)",
    ]


class LeasecheckCLITest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="lc-r4-")
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)
        (self.home / ".claude").mkdir()

    def run_cli(self, *args, home=None):
        target = Path(home) if home is not None else self.home
        with mock.patch.dict(os.environ, {"HOME": str(target)}):
            env = dict(os.environ)
            env.pop("XDG_CONFIG_HOME", None)
            env.pop("XDG_DATA_HOME", None)
            env.pop("XDG_CACHE_HOME", None)
            env["USERPROFILE"] = str(target)
            env["PYTHONIOENCODING"] = "utf-8"
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--home", str(target), *args],
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
            )
        return proc

    def write_claude(self, allow):
        path = self.home / ".claude" / "settings.json"
        path.write_text(
            json.dumps({"permissions": {"allow": list(allow)}}),
            encoding="utf-8",
        )
        return path

    def write_aider(self, text):
        path = self.home / ".aider.conf.yml"
        path.write_text(text, encoding="utf-8")
        return path


class TestVersion(LeasecheckCLITest):
    def test_version_prints_name_and_number(self):
        proc = self.run_cli("--version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(lines, ["leasecheck 0.2.0"])


class TestClaudeAllowRules(LeasecheckCLITest):
    def test_each_dangerous_entry_gets_a_high_finding(self):
        for entry in dangerous_entries():
            with self.subTest(entry=entry):
                self.write_claude([entry])
                proc = self.run_cli()
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(CLAUDE_TITLE, proc.stdout)
                self.assertIn("settings.json", proc.stdout)
                self.assertIn(leasecheck.rule_label(entry), proc.stdout)
                self.assertRegex(proc.stdout, r"(?i)\bhigh\b")

    def test_one_finding_per_file(self):
        self.write_claude(
            [BASH + "(sudo apt update)", BASH + "(curl http://example.invalid)"]
        )
        proc = self.run_cli()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.count(CLAUDE_TITLE), 1)

    def test_safe_allow_entries_are_not_flagged(self):
        self.write_claude(
            [
                BASH + "(ls)",
                BASH + "(git status)",
                BASH + " (sudo ls)",
                "Read(*)",
                "Edit(*)",
                "WebSearch",
            ]
        )
        proc = self.run_cli()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(CLAUDE_TITLE, proc.stdout)

    def test_evidence_lists_at_most_ten_rules(self):
        entries = [BASH + "(sudoCmd%02d)" % index for index in range(12)]
        self.write_claude(entries)
        proc = self.run_cli("--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(CLAUDE_TITLE, proc.stdout)
        self.assertEqual(proc.stdout.count(BASH + "(sudo ...)"), 10)
        self.assertIn("2 more rule(s) not shown", proc.stdout)
        self.assertNotIn("sudoCmd", proc.stdout)

    def test_no_claude_settings_means_no_finding(self):
        proc = self.run_cli()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(CLAUDE_TITLE, proc.stdout)


class TestAider(LeasecheckCLITest):
    def test_yes_always_true_is_flagged(self):
        self.write_aider("# fake config\nyes-always: true\n")
        proc = self.run_cli()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(AIDER_TITLE, proc.stdout)
        self.assertIn("aider.conf.yml", proc.stdout)
        self.assertRegex(proc.stdout, r"(?i)\bhigh\b")

    def test_yes_always_false_is_not_flagged(self):
        self.write_aider("yes-always: false\n")
        proc = self.run_cli()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(AIDER_TITLE, proc.stdout)

    def test_missing_aider_config_is_not_flagged(self):
        proc = self.run_cli()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(AIDER_TITLE, proc.stdout)


class TestSarif(LeasecheckCLITest):
    def plant_mixed_findings(self):
        self.write_claude(
            [
                BASH + "(sudo apt update)",
                BASH + "(curl http://example.invalid/x)",
            ]
        )
        (self.home / ".bashrc").write_text("# fake\n", encoding="utf-8")

    def sarif(self):
        proc = self.run_cli("--sarif")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc, json.loads(proc.stdout)

    def test_sarif_document_shape(self):
        self.plant_mixed_findings()
        proc, doc = self.sarif()

        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"]), 1)
        run = doc["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "leasecheck")
        self.assertEqual(driver["version"], "0.2.0")
        self.assertEqual(
            driver["informationUri"], "https://github.com/CoreXI7/leasecheck"
        )

        rules = driver["rules"]
        results = run["results"]
        self.assertTrue(rules)
        self.assertTrue(results)

        rule_ids = [rule["id"] for rule in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        for rule_id in rule_ids:
            self.assertIsInstance(rule_id, str)
            self.assertTrue(rule_id.strip())
            self.assertNotIn(" ", rule_id)

        result_ids = {result["ruleId"] for result in results}
        self.assertEqual(result_ids, set(rule_ids))
        for result in results:
            self.assertIn(result["ruleId"], rule_ids)

    def test_sarif_levels_match_severity(self):
        self.plant_mixed_findings()
        _, doc = self.sarif()
        results = doc["runs"][0]["results"]

        allowed = {"error", "warning", "note"}
        for result in results:
            self.assertIn(result.get("level"), allowed)

        self.assertIn("error", {result.get("level") for result in results})
        self.assertIn("note", {result.get("level") for result in results})

        risky = [r for r in results if r.get("level") == "error"]
        self.assertTrue(
            any(
                BASH + "(sudo ...)" in r["message"]["text"]
                and "settings.json" in r["message"]["text"]
                for r in risky
            ),
            "high SARIF message should join the reason and the evidence",
        )

    def test_sarif_has_no_absolute_paths(self):
        self.plant_mixed_findings()
        proc, doc = self.sarif()

        raw = proc.stdout
        self.assertNotIn(str(self.home), raw)
        self.assertNotIn(str(self.home.resolve()), raw)

        stack = [doc]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in ("uri", "uriBaseId", "artifactLocation") and isinstance(
                        value, str
                    ):
                        self.assertFalse(os.path.isabs(value), value)
                    stack.append(value)
            elif isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, str):
                self.assertNotIn(str(self.home), node)

    def test_sarif_rule_ids_are_stable(self):
        self.plant_mixed_findings()
        _, first = self.sarif()
        _, second = self.sarif()
        first_ids = {rule["id"] for rule in first["runs"][0]["tool"]["driver"]["rules"]}
        second_ids = {rule["id"] for rule in second["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(first_ids, second_ids)

    def test_sarif_replaces_text_output(self):
        self.plant_mixed_findings()
        proc, _ = self.sarif()
        self.assertNotIn("This shows common risks", proc.stdout)


class TestArgumentErrors(LeasecheckCLITest):
    def test_sarif_with_json_is_an_argparse_error(self):
        proc = self.run_cli("--sarif", "--json")
        self.assertEqual(proc.returncode, 2)
        self.assertTrue(proc.stderr.strip())

    def test_json_with_sarif_is_an_argparse_error(self):
        proc = self.run_cli("--json", "--sarif")
        self.assertEqual(proc.returncode, 2)
        self.assertTrue(proc.stderr.strip())



class RuleLabelTests(unittest.TestCase):
    def test_rule_details_are_not_printed(self):
        import leasecheck
        value = "v" + uuid.uuid4().hex
        rule = "Bash(curl -H 'Authorization: Bearer " + value + "' https://x)"
        label = leasecheck.rule_label(rule)
        self.assertEqual(label, "Bash(curl ...)")
        self.assertNotIn(value, label)
        self.assertEqual(leasecheck.rule_label("Bash(*)"), "Bash(*)")

if __name__ == "__main__":
    unittest.main()
