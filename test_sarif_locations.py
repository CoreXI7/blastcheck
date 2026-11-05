import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


BLASTCHECK = Path(__file__).resolve().with_name("blastcheck.py")


class SarifLocationsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BLASTCHECK.is_file():
            raise unittest.SkipTest(
                f"{BLASTCHECK.name} was not found next to {Path(__file__).name}"
            )

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.home = Path(self._temp_dir.name)
        self.secret_name = "OPENAI_API_KEY_" + uuid.uuid4().hex.upper()
        self.secret_value = "sk-fake-" + uuid.uuid4().hex
        (self.home / ".env").write_text(
            f"{self.secret_name}={self.secret_value}\n", encoding="utf-8"
        )
        ssh_dir = self.home / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519").write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8"
        )

    def tearDown(self):
        self._temp_dir.cleanup()

    def _run(self, *extra_args):
        command = [
            sys.executable,
            str(BLASTCHECK),
            "--home",
            str(self.home),
            "--sarif",
            *extra_args,
        ]
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            cwd=str(BLASTCHECK.parent),
        )

    def _parse_sarif(self, process):
        self.assertEqual(
            process.returncode,
            0,
            f"blastcheck exited {process.returncode}\n"
            f"stdout: {process.stdout[:2000]}\n"
            f"stderr: {process.stderr[:2000]}",
        )
        self.assertNotIn(self.secret_value, process.stdout)
        self.assertNotIn(self.secret_value, process.stderr)
        try:
            document = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"stdout is not valid JSON: {exc}\n"
                f"stdout: {process.stdout[:2000]}\n"
                f"stderr: {process.stderr[:2000]}"
            )
        self.assertIsInstance(document, dict)
        self.assertEqual(document.get("version"), "2.1.0")
        runs = document.get("runs")
        self.assertIsInstance(runs, list)
        self.assertTrue(runs, "SARIF document has no runs")
        results = []
        for run in runs:
            self.assertIsInstance(run, dict)
            run_results = run.get("results", [])
            self.assertIsInstance(run_results, list)
            results.extend(run_results)
        self.assertTrue(results, "SARIF output has no results")
        return results

    def _result_uri(self, result):
        locations = result.get("locations")
        self.assertIsInstance(locations, list)
        self.assertTrue(locations, "SARIF result has no locations")
        self.assertEqual(len(locations), 1, "result should have exactly one location")
        location = locations[0]
        self.assertIsInstance(location, dict)
        physical = location.get("physicalLocation")
        self.assertIsInstance(physical, dict)
        artifact = physical.get("artifactLocation")
        self.assertIsInstance(artifact, dict)
        uri = artifact.get("uri")
        self.assertIsInstance(uri, str)
        self.assertTrue(uri)
        return uri

    def _assert_uri_form(self, uri):
        self.assertIsInstance(uri, str)
        self.assertTrue(uri)
        if uri.startswith("file://"):
            return
        self.assertFalse(uri.startswith("/"), f"relative uri starts with /: {uri}")
        self.assertFalse(uri.startswith("~"), f"relative uri starts with ~: {uri}")
        self.assertFalse(uri.startswith("\\"), f"relative uri starts with \\: {uri}")
        self.assertIsNone(
            re.match(r"^[A-Za-z]:[\\/]", uri),
            f"relative uri is a drive-absolute path: {uri}",
        )
        self.assertNotIn("://", uri, f"uri is absolute but not file://: {uri}")
        self.assertFalse(
            uri.lower().startswith("file:"), f"uri is not a file:// uri: {uri}"
        )
        for home in {str(self.home), self.home.as_posix(), os.path.realpath(self.home)}:
            self.assertNotIn(home, uri, f"relative uri leaks the temporary home: {uri}")

    def test_sarif_results_carry_locations(self):
        results = self._parse_sarif(self._run())
        uris = []
        for result in results:
            self.assertIsInstance(result, dict)
            uri = self._result_uri(result)
            self._assert_uri_form(uri)
            fingerprints = result.get("partialFingerprints")
            self.assertIsInstance(fingerprints, dict)
            line_hash = fingerprints.get("primaryLocationLineHash")
            self.assertIsInstance(line_hash, str)
            self.assertTrue(line_hash)
            uris.append(uri.replace("\\", "/"))

        env_uris = [uri for uri in uris if ".env" in uri]
        key_uris = [uri for uri in uris if "id_ed25519" in uri]
        self.assertTrue(env_uris, "no result location names the planted .env file")
        self.assertTrue(key_uris, "no result location names the planted SSH key")

        for uri in env_uris:
            self.assertFalse(uri.startswith("file://"), uri)
            self.assertEqual(uri.rsplit("/", 1)[-1], ".env")
        for uri in key_uris:
            self.assertFalse(uri.startswith("file://"), uri)
            self.assertEqual(uri.rsplit("/", 1)[-1], "id_ed25519")

    def test_sarif_together_with_json_is_rejected(self):
        process = self._run("--json")
        self.assertEqual(
            process.returncode,
            2,
            f"expected exit 2, got {process.returncode}\n"
            f"stdout: {process.stdout[:2000]}\n"
            f"stderr: {process.stderr[:2000]}",
        )
        self.assertNotIn(self.secret_value, process.stdout)
        self.assertNotIn(self.secret_value, process.stderr)


if __name__ == "__main__":
    unittest.main()
