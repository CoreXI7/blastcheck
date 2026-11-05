"""Report rendering: hostile text must stay inert in HTML and the terminal."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "blastcheck.py")
HOSTILE = '<script>alert(1)</script>"\'><img src=x onerror=alert(2)>'


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="blastcheck-report-")
        self.addCleanup(shutil.rmtree, self.home, True)
        folder = os.path.join(self.home, "proj")
        os.makedirs(folder)
        # A hostile name for a file the scanner reports.
        name = os.path.join(folder, ".env" + HOSTILE.replace("/", "_"))
        with open(name, "w") as handle:
            handle.write("API_KEY=abcdefghijkl\n")
        os.chmod(name, 0o644)

    def run_cli(self, *flags):
        proc = subprocess.run(
            [sys.executable, SCANNER, "--home", self.home, *flags],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def test_html_escapes_hostile_names(self):
        page = self.run_cli("--html")
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script", page)
        self.assertNotIn("<img", page)
        self.assertNotIn("onerror=alert", page.replace("onerror=alert(2)&gt;", ""))
        self.assertIn("default-src 'none'", page)
        self.assertNotIn("http://", page.lower().replace("http://www.w3.org", ""))

    def test_html_has_no_scripts_or_remote_loads(self):
        page = self.run_cli("--html").lower()
        for marker in ("<script", "<link", "@import", "src=\"http", "url(http"):
            self.assertNotIn(marker, page)

    def test_terminal_has_no_escape_codes_when_piped(self):
        text = self.run_cli()
        self.assertNotIn("\x1b", text)
        self.assertIn("Overall risk", text)

    def test_html_conflicts_with_json(self):
        proc = subprocess.run(
            [sys.executable, SCANNER, "--home", self.home, "--html", "--json"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
