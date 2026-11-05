#!/usr/bin/env python3
"""leasecheck - show what an AI coding agent running as you could reach.

Read-only: this never changes, creates or deletes anything.
No network: no socket/urllib/http imports and no network subprocesses.
Single file, Python 3.10+, standard library only.

Usage: python3 leasecheck.py [--json] [--all] [--home DIR] [--show-hosts]
"""

import argparse
import base64
import json
import os
import re
import stat
import subprocess
import sys
import time

MAX_FILES = 20_000
MAX_SECONDS = 20.0
MAX_SIZE = 1024 * 1024
MAX_DEPTH = 4
MAX_GROUP_EVIDENCE = 10

SEVERITIES = ("critical", "high", "medium", "info")
RANK = {name: i for i, name in enumerate(SEVERITIES)}

DISCLAIMER = (
    "This shows common risks it knows to look for. "
    "It doesn't prove you're safe. Nothing left this computer."
)

COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "info": "\033[36m",
}

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".cache",
    "cache",
    "caches",
    ".npm",
    ".yarn",
    ".pnpm-store",
    "venv",
    ".venv",
    "virtualenv",
    ".virtualenv",
    "site-packages",
    "dist-packages",
    ".tox",
    ".gradle",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".trash",
    "trash",
}

SECRET_FILE_NAMES = {".netrc", ".pgpass", ".npmrc", ".pypirc"}

TEXT_EXTS = {
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".cnf",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".jsonc",
    ".json5",
    ".properties",
    ".props",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".bat",
    ".cmd",
    ".py",
    ".rb",
    ".php",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".pl",
    ".lua",
    ".xml",
    ".tf",
    ".tfvars",
    ".gradle",
    ".mk",
    ".service",
    ".txt",
    ".md",
    ".sql",
    ".c",
    ".h",
    ".hpp",
    ".cpp",
    ".cs",
}

SECRET_WORDS = {
    "SECRET",
    "SECRETS",
    "TOKEN",
    "PASSWORD",
    "PASSWORDS",
    "PASSWD",
    "PASS",
    "PASSPHRASE",
    "APIKEY",
    "ACCESSKEY",
    "SECRETKEY",
    "PRIVATEKEY",
    "CREDENTIAL",
    "CREDENTIALS",
    "CREDS",
    "AUTHTOKEN",
    "BEARER",
}

# Names like TOKEN_COUNT or PASSWORD_URL describe a secret, not hold one.
NOT_SECRET_ENDINGS = {
    "DATE", "TIME", "COUNT", "LIMIT", "LENGTH", "SIZE", "TYPE", "URL", "URI",
    "FILE", "PATH", "EXPIRY", "EXPIRES", "ENABLED", "REQUIRED", "USAGE",
}

KEY_PREFIXES = {"API", "ACCESS", "SECRET", "PRIVATE", "AUTH", "ENCRYPTION", "SIGNING"}

# Source code and notes usually name secrets without holding them.
CODE_EXTS = {
    ".py", ".rb", ".php", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java",
    ".kt", ".pl", ".lua", ".c", ".h", ".hpp", ".cpp", ".cs", ".md", ".txt",
}

PLACEHOLDER_VALUES = {
    "true", "false", "null", "none", "changeme", "change_me", "example",
    "password", "secret", "token", "required", "optional",
}

SAVED_LOGINS = (
    (".aws/credentials", "AWS credentials"),
    (".config/gh/hosts.yml", "GitHub CLI login"),
    (".docker/config.json", "Docker registry login"),
    (".kube/config", "Kubernetes cluster credentials"),
    (".config/gcloud", "Google Cloud credentials directory"),
    (".azure", "Azure credentials directory"),
    (".git-credentials", "Git credential store"),
)

_CONTROL_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]"
)

_ASSIGN_RE = re.compile(
    r"""^[\s\-*]*(?:export\s+|declare\s+-x\s+|set\s+)?"""
    r"""["']?([A-Za-z_][A-Za-z0-9_.\-]{0,80})["']?\s*[:=]"""
)

_PEM_RE = re.compile(r"-----BEGIN\s+([A-Za-z0-9 ]{1,40}?)\s*-----")

_CLAUDE_RISK_RE = re.compile(r"^dangerously[A-Za-z0-9_-]{0,40}$", re.I)

_CODEX_SANDBOX_RE = re.compile(
    r"""^\s*sandbox_mode\s*=\s*['"]danger-full-access['"]""", re.I | re.M
)

_CODEX_APPROVAL_RE = re.compile(
    r"""^\s*approval_policy\s*=\s*['"]never['"]""", re.I | re.M
)


def clean(value):
    """Replace control characters so filenames and paths cannot break output."""
    if not isinstance(value, str):
        value = str(value)
    value = value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return _CONTROL_RE.sub("?", value)


def display_path(path, home):
    try:
        apath = os.path.abspath(path)
        ahome = os.path.abspath(home)
        if os.path.commonpath([apath, ahome]) == ahome:
            rel = os.path.relpath(apath, ahome)
            if rel == ".":
                return "~"
            return "~/" + rel.replace(os.sep, "/")
    except (ValueError, OSError):
        pass
    return path.replace(os.sep, "/")


def name_words(name):
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.upper()) if w]


def looks_like_secret_name(name):
    words = name_words(name)
    if words and words[-1] in NOT_SECRET_ENDINGS:
        return False
    if any(w in SECRET_WORDS for w in words):
        return True
    return any(
        w in ("KEY", "KEYS") and i > 0 and words[i - 1] in KEY_PREFIXES
        for i, w in enumerate(words)
    )


def safe_name(name):
    """Hide a variable name that could itself hold a credential."""
    if len(name) > 48 or any(
        len(w) >= 16 and any(c.isdigit() for c in w) for w in name_words(name)
    ):
        return "[unusual name hidden]"
    return name


def holds_literal_value(value):
    """True when a value looks stored here, not a reference or a placeholder."""
    value = value.strip().rstrip(",;").strip("\"'` ")
    if len(value) < 6 or value.lower() in PLACEHOLDER_VALUES:
        return False
    if value[0] in "$<{[(%#" or value.startswith(("os.", "process.", "env.", "xxx")):
        return False
    return not re.fullmatch(r"[0-9.]+", value)


def is_text_candidate(basename):
    lower = basename.lower()
    if lower.startswith(".env"):
        return True
    ext = os.path.splitext(lower)[1]
    return ext == "" or (ext in TEXT_EXTS and ext not in CODE_EXTS)


def sudo_nopass_commands(text):
    """Return the commands that `sudo -l` output lets run without a password.

    A tag applies to later commands on its line until the opposite tag, so
    "(ALL) ALL" needs a password and only an exact command of ALL is unrestricted.
    """
    commands = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("("):
            continue
        no_password = False
        for piece in re.split(r",(?![^()]*\))", line):
            piece = piece.strip()
            while True:
                runas = re.match(r"\([^)]*\)\s*", piece)
                tag = re.match(r"([A-Z_]+):\s*", piece)
                if runas:
                    piece = piece[runas.end():]
                elif tag:
                    if tag.group(1) == "NOPASSWD":
                        no_password = True
                    elif tag.group(1) == "PASSWD":
                        no_password = False
                    piece = piece[tag.end():]
                else:
                    break
            if no_password and piece:
                commands.append(piece)
    return commands


def claude_risky_settings(text):
    """Names of settings that are on and turn off Claude Code's prompts."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    found = set()
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                if key == "defaultMode" and value == "bypassPermissions":
                    found.add("defaultMode: bypassPermissions")
                elif value is True and _CLAUDE_RISK_RE.match(key):
                    found.add(key)
                elif isinstance(value, (dict, list)):
                    stack.append(value)
    return sorted(found)


def run_fixed(argv):
    """Run one of the few allowed fixed commands. No shell, no prompting."""
    try:
        return subprocess.run(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=5,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None


def mode_string(st):
    return "%04o" % (stat.S_IMODE(st.st_mode),)


class Scanner:
    def __init__(self, home, show_hosts):
        self.home = home
        self.show_hosts = show_hosts
        self.findings = []
        self.notes = []
        self.files_scanned = 0
        self.permission_errors = 0
        self.skipped_large = 0
        self.secret_paths = []
        self.permission_paths = []
        self.key_high_paths = set()
        self.stop_reason = None
        self.start = time.monotonic()

    # -- bookkeeping ---------------------------------------------------

    def finding(self, severity, title, why, evidence, fix):
        self.findings.append(
            {
                "severity": severity,
                "title": clean(title),
                "why": clean(why),
                "evidence": [clean(e) for e in evidence if e],
                "fix": clean(fix),
            }
        )

    def note(self, text):
        self.notes.append(clean(text))

    def stop(self, reason):
        if self.stop_reason is None:
            self.stop_reason = reason

    def out_of_time(self):
        return (time.monotonic() - self.start) >= MAX_SECONDS

    def lstat_nofollow(self, path):
        try:
            return os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError:
            self.permission_errors += 1
            return None

    def is_dir_nolink(self, path):
        st = self.lstat_nofollow(path)
        return st is not None and stat.S_ISDIR(st.st_mode)

    def is_file_nolink(self, path):
        st = self.lstat_nofollow(path)
        return st is not None and stat.S_ISREG(st.st_mode)

    def open_regular(self, path):
        """Open a regular file without following a final symlink or blocking."""
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SIZE:
                raise OSError("not a regular file of allowed size")
            return os.fdopen(fd, "rb")
        except OSError:
            os.close(fd)
            raise

    def read_text_limited(self, path):
        st = self.lstat_nofollow(path)
        if st is None:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > MAX_SIZE:
            self.skipped_large += 1
            return None
        try:
            with self.open_regular(path) as handle:
                return handle.read(MAX_SIZE).decode("utf-8", errors="ignore")
        except OSError:
            self.permission_errors += 1
            return None

    def read_first_line(self, path):
        """Read only the first line of a key file, never its body."""
        try:
            with self.open_regular(path) as handle:
                raw = handle.readline(512)
        except OSError:
            self.permission_errors += 1
            return None
        return raw.decode("utf-8", errors="ignore").strip()

    def pem_kind(self, path, match):
        """Name a PEM block, adding ENCRYPTED when line 2 shows a passphrase.

        Line 2 of a key holds only format details at the part read here. It is
        never kept or printed. The first line alone can't tell for OpenSSH keys.
        """
        kind = match.group(1).upper()
        if "PRIVATE KEY" not in kind or "ENCRYPTED" in kind:
            return kind
        try:
            with self.open_regular(path) as handle:
                handle.readline(512)
                second = handle.readline(128).strip()
        except OSError:
            self.permission_errors += 1
            return kind
        if second.startswith(b"Proc-Type: 4,ENCRYPTED"):
            return kind + " ENCRYPTED"
        if kind == "OPENSSH PRIVATE KEY":
            try:
                raw = base64.b64decode(second[:64] + b"=" * (-len(second[:64]) % 4))
            except ValueError:
                return kind
            magic = b"openssh-key-v1\0"
            size = int.from_bytes(raw[len(magic):len(magic) + 4], "big")
            cipher = raw[len(magic) + 4:len(magic) + 4 + size]
            if raw.startswith(magic) and cipher and cipher != b"none":
                return kind + " ENCRYPTED"
        return kind

    def add_permission_path(self, path):
        if path not in self.permission_paths:
            self.permission_paths.append(path)

    # -- checks --------------------------------------------------------

    def check_root_paths(self):
        groups = set()
        result = run_fixed(["id", "-nG"])
        if result is None or result.returncode != 0:
            self.note("Group membership could not be checked (id failed).")
        else:
            groups = set(result.stdout.split())

        privileged = sorted(
            g
            for g in ("docker", "lxd", "lxc", "libvirt", "libvirtd")
            if g in groups
        )
        if privileged:
            self.finding(
                "critical",
                "Your user is in a root-equivalent group",
                "Membership in these groups lets a process act as root on this "
                "computer.",
                ["groups: " + ", ".join(privileged)],
                "Remove the agent's user from these groups and give it a narrow, "
                "dedicated path instead.",
            )

        sockets = (
            "/var/run/docker.sock",
            os.path.join(self.home, ".docker", "run", "docker.sock"),
        )
        for socket_path in sockets:
            st = self.lstat_nofollow(socket_path)
            if st is None:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if not (stat.S_ISSOCK(st.st_mode) or stat.S_ISREG(st.st_mode)):
                continue
            if os.access(socket_path, os.W_OK):
                self.finding(
                    "critical",
                    "The Docker socket is writable",
                    "Control of the Docker daemon is equivalent to root on the "
                    "host.",
                    [f"{display_path(socket_path, self.home)} (mode {mode_string(st)})"],
                    "Remove the agent's access to the Docker socket or put a "
                    "restricted proxy in front of it.",
                )

        result = run_fixed(["sudo", "-n", "-l"])
        if result is None:
            self.note("Passwordless sudo could not be checked (sudo unavailable).")
        elif result.returncode == 0:
            commands = sudo_nopass_commands(result.stdout)
            unrestricted = "ALL" in commands
            if unrestricted:
                self.finding(
                    "critical",
                    "Passwordless sudo allows everything",
                    "An agent could run any command as root without a password.",
                    ["sudo -n -l grants NOPASSWD: ALL"],
                    "Remove the NOPASSWD rule and require a password, or scope it "
                    "to a few read-only commands.",
                )
            elif commands:
                programs = sorted({c.split()[0] for c in commands if c.split()})
                shown = [clean(p)[:160] for p in programs[:8]]
                evidence = [
                    f"{len(commands)} rule(s), programs: " + "; ".join(shown)
                ]
                if len(programs) > len(shown):
                    evidence.append(
                        f"{len(programs) - len(shown)} more program(s) not shown"
                    )
                self.finding(
                    "high",
                    "Passwordless sudo is allowed for some commands",
                    "An agent can run those commands as root without a password.",
                    evidence,
                    "Remove the NOPASSWD rule or limit it to commands the agent "
                    "does not need.",
                )
            else:
                self.note("No passwordless sudo rules found.")
        else:
            self.note("Sudo rules could not be listed without a password.")

    def check_ssh(self):
        ssh_dir = os.path.join(self.home, ".ssh")
        if not self.is_dir_nolink(ssh_dir):
            return
        try:
            names = os.listdir(ssh_dir)
        except OSError:
            self.permission_errors += 1
            return

        skip_names = {
            "known_hosts",
            "known_hosts2",
            "config",
            "authorized_keys",
            "authorized_keys2",
            "environment",
            "rc",
        }
        keys = []
        encrypted_keys = 0
        for name in sorted(names):
            path = os.path.join(ssh_dir, name)
            lower = name.lower()
            st = self.lstat_nofollow(path)
            if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                continue
            if lower.endswith(".pub") or lower in skip_names:
                continue
            if st.st_size > MAX_SIZE:
                self.skipped_large += 1
                continue
            first = self.read_first_line(path)
            if not first:
                continue
            match = _PEM_RE.match(first)
            if not match:
                continue
            kind = self.pem_kind(path, match)
            if "PRIVATE KEY" not in kind:
                continue
            encrypted = "ENCRYPTED" in kind
            keys.append((path, kind))
            self.add_permission_path(path)
            if encrypted:
                encrypted_keys += 1

        unencrypted = [
            (path, kind)
            for path, kind in keys
            if "ENCRYPTED" not in kind
        ]

        hosts = []
        host_names = []
        config_path = os.path.join(ssh_dir, "config")
        config_text = self.read_text_limited(config_path)
        if config_text:
            for line in config_text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                host_match = re.match(r"Host\s+(.+)$", stripped, re.I)
                if host_match:
                    for token in host_match.group(1).split():
                        if token != "*" and token not in hosts:
                            hosts.append(token)
                    continue
                host_name_match = re.match(r"HostName\s+(.+)$", stripped, re.I)
                if host_name_match:
                    for token in host_name_match.group(1).split():
                        if token not in host_names:
                            host_names.append(token)

        known_count = 0
        known_text = self.read_text_limited(os.path.join(ssh_dir, "known_hosts"))
        if known_text:
            known_count = sum(
                1
                for line in known_text.splitlines()
                if line.strip() and not line.lstrip().startswith(("#", "@"))
            )

        if unencrypted:
            evidence = []
            for path, kind in unencrypted[:20]:
                evidence.append(
                    f"{display_path(path, self.home)} "
                    f"({kind}; no passphrase detected)"
                )
            if len(unencrypted) > 20:
                evidence.append(f"{len(unencrypted) - 20} more key(s) not shown")
            if known_count:
                evidence.append(
                    f"known_hosts has {known_count} entries "
                    "(machines these keys may reach)"
                )
            self.finding(
                "high",
                "Private SSH key without a passphrase",
                "An agent running as you can read the key and use it to log in "
                "to the machines it is authorized for.",
                evidence,
                "Add a passphrase (ssh-keygen -p -f <key>) or replace the key "
                "with a short-lived one.",
            )
            for path, _kind in unencrypted:
                self.key_high_paths.add(path)

        evidence = []
        if keys:
            evidence.append(
                f"{len(keys)} private key(s) in ~/.ssh; "
                f"{encrypted_keys} show an encrypted header"
            )
        if hosts:
            evidence.append(
                f"SSH config has {len(hosts)} Host entries: "
                + ", ".join(hosts[:20])
            )
            if len(hosts) > 20:
                evidence.append(f"{len(hosts) - 20} more Host alias(es) not shown")
            if self.show_hosts and host_names:
                evidence.append("HostName addresses: " + ", ".join(host_names[:20]))
        elif config_text is not None:
            evidence.append("SSH config has no Host entries")
        if known_count:
            evidence.append(
                f"known_hosts has {known_count} entries "
                "(machines these keys may reach)"
            )
        if evidence:
            self.finding(
                "info",
                "SSH access an agent could use",
                "Each host in your SSH setup is somewhere an agent could "
                "connect using your keys.",
                evidence,
                "Remove unused keys and hosts, and give agents a dedicated key "
                "with limited reach.",
            )

    def add_secret(self, path, line_count, names, header=None):
        if path in self.secret_paths:
            return
        self.secret_paths.append(path)
        self.add_permission_path(path)
        shown_names = sorted({safe_name(n) for n in names})[:12]
        if line_count is None:
            if header:
                line_part = "line count not read (header only)"
            else:
                line_part = "line count not read"
        else:
            line_part = f"{line_count} lines"
        if shown_names:
            name_part = ", ".join(shown_names)
            if len(names) > len(shown_names):
                name_part += f" (+{len(names) - len(shown_names)} more)"
            evidence = f"{display_path(path, self.home)} ({line_part}): {name_part}"
        elif header:
            evidence = (
                f"{display_path(path, self.home)} "
                f"({line_part}; PEM header: {header})"
            )
        else:
            evidence = (
                f"{display_path(path, self.home)} "
                f"({line_part}; matched by file name)"
            )
        self.finding(
            "medium",
            "Secret-looking file in the home directory",
            "Its contents look like credentials an agent could copy or use.",
            [evidence],
            "Remove it if unused; otherwise keep it outside the home and prefer "
            "short-lived credentials.",
        )

    def report_key_file(self, path, header):
        self.add_secret(path, None, set(), header=header)
        if (
            header
            and "PRIVATE KEY" in header
            and "ENCRYPTED" not in header
            and path not in self.key_high_paths
        ):
            self.key_high_paths.add(path)
            self.finding(
                "high",
                "Private key without a passphrase",
                "An agent running as you can read the key and use it "
                "wherever it is trusted.",
                [
                    f"{display_path(path, self.home)} "
                    f"({header}; no passphrase detected)"
                ],
                "Add a passphrase (ssh-keygen -p -f <key>) or replace the "
                "key with a short-lived one.",
            )

    def scan_secret_names(self, path):
        text = self.read_text_limited(path)
        if text is None:
            return None, None
        if "\x00" in text:
            return None, None
        names = set()
        lines = text.splitlines()
        for line in lines:
            match = _ASSIGN_RE.match(line.lstrip("\ufeff"))
            if match and looks_like_secret_name(match.group(1)):
                if holds_literal_value(line.lstrip("\ufeff")[match.end():]):
                    names.add(match.group(1))
        return names, len(lines)

    def consider_file(self, path, basename):
        st = self.lstat_nofollow(path)
        if st is None:
            return
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return
        self.files_scanned += 1
        if st.st_size > MAX_SIZE:
            self.skipped_large += 1
            return

        lower = basename.lower()
        if lower.endswith(".pub") or lower in {
            "known_hosts",
            "known_hosts2",
            "authorized_keys",
            "authorized_keys2",
        }:
            return

        if lower.endswith(".pem") or lower.endswith(".key"):
            first = self.read_first_line(path)
            header = None
            if first:
                match = _PEM_RE.match(first)
                if match:
                    header = self.pem_kind(path, match)
            self.report_key_file(path, header)
            return

        if lower.startswith(".env") or lower in SECRET_FILE_NAMES:
            first = self.read_first_line(path)
            if first:
                match = _PEM_RE.match(first)
                if match and "PRIVATE KEY" in match.group(1).upper():
                    self.report_key_file(path, self.pem_kind(path, match))
                    return
            names, line_count = self.scan_secret_names(path)
            if names is None:
                names = set()
            self.add_secret(path, line_count, names)
            return

        if is_text_candidate(basename):
            first = self.read_first_line(path)
            if first:
                if "\x00" in first:
                    return
                match = _PEM_RE.match(first)
                if match and "PRIVATE KEY" in match.group(1).upper():
                    self.report_key_file(path, self.pem_kind(path, match))
                    return
            names, line_count = self.scan_secret_names(path)
            if names:
                self.add_secret(path, line_count, names)

    def is_saved_login(self, path):
        for rel, _label in SAVED_LOGINS:
            store = os.path.join(self.home, rel)
            if path == store or path.startswith(store + os.sep):
                return True
        return False

    def scan_secrets_walk(self):
        home = self.home

        def on_error(_error):
            self.permission_errors += 1

        for dirpath, dirnames, filenames in os.walk(
            home, topdown=True, followlinks=False, onerror=on_error
        ):
            if self.stop_reason is not None or self.out_of_time():
                if self.stop_reason is None:
                    self.stop("20-second limit")
                break

            rel = os.path.relpath(dirpath, home)
            depth = 0 if rel in (".", "") else rel.count(os.sep) + 1

            kept = []
            for name in dirnames:
                lower = name.lower()
                child = os.path.join(dirpath, name)
                if os.path.islink(child):
                    continue
                if lower in SKIP_DIRS:
                    continue
                if lower == "env":
                    try:
                        if stat.S_ISREG(os.lstat(os.path.join(child, "pyvenv.cfg")).st_mode):
                            continue
                    except OSError:
                        pass
                kept.append(name)
            dirnames[:] = kept

            if depth >= MAX_DEPTH:
                dirnames[:] = []

            for basename in filenames:
                if self.stop_reason is not None:
                    break
                if self.files_scanned >= MAX_FILES:
                    self.stop("20,000-file limit")
                    break
                if self.out_of_time():
                    self.stop("20-second limit")
                    break
                child = os.path.join(dirpath, basename)
                if not self.is_saved_login(child):
                    self.consider_file(child, basename)

            if self.stop_reason is not None:
                break

    def check_saved_logins(self):
        for rel, label in SAVED_LOGINS:
            path = os.path.join(self.home, rel)
            st = self.lstat_nofollow(path)
            if st is None or stat.S_ISLNK(st.st_mode):
                continue
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                continue
            kind = "directory" if stat.S_ISDIR(st.st_mode) else "file"
            if stat.S_ISREG(st.st_mode):
                self.add_permission_path(path)
            self.finding(
                "high",
                f"Saved login store present: {label}",
                "An agent could read these saved logins and act as you.",
                [
                    f"{display_path(path, self.home)} "
                    f"({kind}, mode {mode_string(st)})"
                ],
                "Remove credentials you no longer use, keep permissions at 600, "
                "and prefer short-lived tokens.",
            )

    def detect_agent(self, label, candidates, fix):
        for path in candidates:
            st = self.lstat_nofollow(path)
            if st is None or stat.S_ISLNK(st.st_mode):
                continue
            if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                continue
            kind = "directory" if stat.S_ISDIR(st.st_mode) else "file"
            self.finding(
                "info",
                f"Agent installed: {label}",
                "A local coding agent can run with your user permissions.",
                [f"{display_path(path, self.home)} ({kind})"],
                fix,
            )
            return

    def check_agents(self):
        home = self.home

        claude_dir = os.path.join(home, ".claude")
        claude_json = os.path.join(home, ".claude.json")
        claude_dir_exists = self.is_dir_nolink(claude_dir)
        if claude_dir_exists or self.is_file_nolink(claude_json):
            located = claude_dir if claude_dir_exists else claude_json
            self.finding(
                "info",
                "Agent installed: Claude Code",
                "A local coding agent can run with your user permissions.",
                [display_path(located, home)],
                "Review its permission mode and avoid bypass/dangerous flags.",
            )
            for path in (
                os.path.join(claude_dir, "settings.json"),
                os.path.join(claude_dir, "settings.local.json"),
                claude_json,
            ):
                text = self.read_text_limited(path)
                if not text:
                    continue
                tokens = claude_risky_settings(text)
                if tokens:
                    self.finding(
                        "critical",
                        "Claude Code guardrails are disabled",
                        "A bypass or dangerously-* setting lets the agent act "
                        "without asking you.",
                        [
                            f"{display_path(path, home)} (settings: "
                            + ", ".join(tokens)
                            + ")"
                        ],
                        "Remove that setting or use the default permission mode.",
                    )

        opencode_dir = os.path.join(home, ".config", "opencode")
        opencode_files = (
            os.path.join(opencode_dir, "opencode.json"),
            os.path.join(opencode_dir, "opencode.jsonc"),
            os.path.join(opencode_dir, "config.json"),
        )
        if self.is_dir_nolink(opencode_dir):
            self.finding(
                "info",
                "Agent installed: OpenCode",
                "A local coding agent can run with your user permissions.",
                [display_path(opencode_dir, home)],
                "Review its permission settings and prefer ask over allow.",
            )
            saw_config = False
            saw_permission = False
            for path in opencode_files:
                text = self.read_text_limited(path)
                if text is None:
                    continue
                saw_config = True
                if not re.search(r'"permission"\s*:', text):
                    continue
                saw_permission = True
                if re.search(r'"permission"\s*:\s*"?allow"?', text) or re.search(
                    r'"permission"\s*:\s*\{[^}]*"allow"', text, re.S
                ):
                    self.finding(
                        "high",
                        "OpenCode permission is set to allow",
                        "The agent can use tools without asking you first.",
                        [display_path(path, home) + " (permission = allow)"],
                        'Change "permission" to "ask" or a narrower rule.',
                    )
            if not saw_permission:
                if saw_config:
                    self.finding(
                        "medium",
                        "OpenCode has no permission restriction",
                        "Without an explicit permission key, the agent may use "
                        "tools without asking.",
                        [
                            "configuration files found: "
                            + ", ".join(
                                display_path(p, home)
                                for p in opencode_files
                                if self.lstat_nofollow(p) is not None
                            )
                            + "; no permission key"
                        ],
                        'Add "permission": "ask" to the OpenCode config.',
                    )
                else:
                    self.finding(
                        "medium",
                        "OpenCode has no permission restriction",
                        "The agent is installed but has no permission settings "
                        "limiting what it may do.",
                        [display_path(opencode_dir, home) + "; no config file found"],
                        'Add "permission": "ask" to the OpenCode config.',
                    )

        codex_dir = os.path.join(home, ".codex")
        if self.is_dir_nolink(codex_dir):
            self.finding(
                "info",
                "Agent installed: Codex",
                "A local coding agent can run with your user permissions.",
                [display_path(codex_dir, home)],
                "Review sandbox_mode and approval_policy.",
            )
            config_path = os.path.join(codex_dir, "config.toml")
            config = self.read_text_limited(config_path)
            if config:
                evidence = []
                if _CODEX_SANDBOX_RE.search(config):
                    evidence.append('sandbox_mode = "danger-full-access"')
                if _CODEX_APPROVAL_RE.search(config):
                    evidence.append('approval_policy = "never"')
                if evidence:
                    self.finding(
                        "high",
                        "Codex runs without a sandbox or approvals",
                        "Codex can change files or run commands without asking "
                        "you.",
                        [
                            display_path(config_path, home)
                            + ": "
                            + "; ".join(evidence)
                        ],
                        'Set sandbox_mode to "workspace-write" and '
                        'approval_policy to "on-request".',
                    )

        self.detect_agent(
            "Cursor",
            [
                os.path.join(home, ".cursor"),
                os.path.join(home, ".config", "Cursor"),
                os.path.join(home, ".config", "cursor"),
            ],
            "Review its approval settings before letting it work unattended.",
        )
        self.detect_agent(
            "Aider",
            [
                os.path.join(home, ".aider.conf.yml"),
                os.path.join(home, ".aider"),
                os.path.join(home, ".config", "aider"),
            ],
            "Review its auto-approval settings before letting it work unattended.",
        )
        self.detect_agent(
            "Gemini CLI",
            [
                os.path.join(home, ".gemini"),
                os.path.join(home, ".config", "gemini"),
            ],
            "Review its approval settings before letting it work unattended.",
        )

    def check_startup_writable(self):
        for path in (
            os.path.join(self.home, ".bashrc"),
            os.path.join(self.home, ".profile"),
            os.path.join(self.home, ".ssh", "authorized_keys"),
        ):
            st = self.lstat_nofollow(path)
            if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                continue
            if not os.access(path, os.W_OK):
                continue
            self.finding(
                "info",
                "Writable startup file",
                "An agent could plant commands here to run at your next login.",
                [
                    f"{display_path(path, self.home)} "
                    f"(writable, mode {mode_string(st)})"
                ],
                "Review this file's contents; an agent with write access can add "
                "commands that run at login.",
            )

    def check_loose_perms(self):
        read_bits = stat.S_IRGRP | stat.S_IROTH
        for path in self.permission_paths:
            st = self.lstat_nofollow(path)
            if st is None or not stat.S_ISREG(st.st_mode):
                continue
            if stat.S_IMODE(st.st_mode) & read_bits:
                self.finding(
                    "high",
                    "Secret file readable by group or others",
                    "Other local users or processes can read this file.",
                    [
                        f"{display_path(path, self.home)} "
                        f"(mode {mode_string(st)})"
                    ],
                    "Restrict this file to its owner (chmod 600).",
                )

    def run(self):
        home_stat = self.lstat_nofollow(self.home)
        if home_stat is None or not stat.S_ISDIR(home_stat.st_mode):
            self.note(
                "Home directory not found or is a symlink: "
                + display_path(self.home, self.home)
            )
            return self.result()
        self.check_root_paths()
        self.check_ssh()
        self.check_saved_logins()
        self.check_agents()
        self.check_startup_writable()
        self.scan_secrets_walk()
        self.check_loose_perms()
        return self.result()

    def result(self):
        counts = {severity: 0 for severity in SEVERITIES}
        for item in self.findings:
            counts[item["severity"]] += 1
        findings = sorted(
            self.findings,
            key=lambda item: (RANK[item["severity"]], item["title"].lower()),
        )
        summary_line = summary_line_from_groups(group_findings(findings))
        scan = {
            "home": clean(display_path(self.home, self.home)),
            "files_scanned": self.files_scanned,
            "permission_errors": self.permission_errors,
            "files_over_1mb_skipped": self.skipped_large,
            "stopped_early": self.stop_reason is not None,
            "stop_reason": self.stop_reason,
            "elapsed_seconds": round(time.monotonic() - self.start, 1),
            "notes": list(self.notes),
        }
        return {
            "summary": counts,
            "summary_line": summary_line,
            "scan": scan,
            "findings": findings,
            "disclaimer": DISCLAIMER,
        }


def colorize(text, severity, enabled):
    if not enabled:
        return text
    return COLORS[severity] + text + "\033[0m"


def group_findings(findings):
    """Merge findings that share a severity and title into one entry."""
    groups = []
    index = {}
    for item in findings:
        key = (item["severity"], item["title"])
        group = index.get(key)
        if group is None:
            group = {
                "severity": item["severity"],
                "title": item["title"],
                "why": item["why"],
                "fix": item["fix"],
                "count": 0,
                "evidence": [],
                "evidence_total": 0,
            }
            index[key] = group
            groups.append(group)
        group["count"] += 1
        for evidence in item["evidence"]:
            if evidence not in group["evidence"]:
                group["evidence"].append(evidence)
    for group in groups:
        total = len(group["evidence"])
        if total > MAX_GROUP_EVIDENCE:
            group["evidence"] = group["evidence"][:MAX_GROUP_EVIDENCE]
        group["evidence_total"] = total
    return groups


def summary_line_from_groups(groups):
    group_counts = {severity: 0 for severity in SEVERITIES}
    item_counts = {severity: 0 for severity in SEVERITIES}
    for group in groups:
        group_counts[group["severity"]] += 1
        item_counts[group["severity"]] += group["count"]
    parts = []
    for severity in SEVERITIES:
        group_count = group_counts[severity]
        item_count = item_counts[severity]
        parts.append(
            "{} {} ({} item{})".format(
                group_count,
                severity,
                item_count,
                "" if item_count == 1 else "s",
            )
        )
    return ", ".join(parts)


def render_item(lines, item, color):
    label = "[{}]".format(item["severity"].upper())
    lines.append(
        "{} {}".format(colorize(label, item["severity"], color), item["title"])
    )
    lines.append("  Why: " + item["why"])
    if item["evidence"]:
        lines.append("  Evidence:")
        for evidence in item["evidence"]:
            lines.append("    - " + evidence)
    lines.append("  Fix: " + item["fix"])
    lines.append("")


def render_group(lines, group, color):
    label = "[{}]".format(group["severity"].upper())
    count = group["count"]
    lines.append(
        "{} {} ({} item{})".format(
            colorize(label, group["severity"], color),
            group["title"],
            count,
            "" if count == 1 else "s",
        )
    )
    lines.append("  Why: " + group["why"])
    if group["evidence"]:
        lines.append("  Evidence:")
        for evidence in group["evidence"]:
            lines.append("    - " + evidence)
        hidden = group["evidence_total"] - len(group["evidence"])
        if hidden > 0:
            lines.append(
                "    ... {} more evidence line{} not shown".format(
                    hidden, "" if hidden == 1 else "s"
                )
            )
    lines.append("  Fix: " + group["fix"])
    lines.append("")


def render_text(data, color, show_all=False):
    lines = [data["summary_line"]]
    scan = data["scan"]
    lines.append(
        "Files checked: {:,}. Permission errors skipped: {:,}. "
        "Files over 1 MB skipped: {:,}.".format(
            scan["files_scanned"],
            scan["permission_errors"],
            scan["files_over_1mb_skipped"],
        )
    )
    if scan["stopped_early"]:
        lines.append(
            "Scan stopped early: {} reached; results may be incomplete.".format(
                scan["stop_reason"]
            )
        )
    for note in scan["notes"]:
        lines.append("Note: " + note)
    lines.append("")

    if show_all:
        for item in data["findings"]:
            render_item(lines, item, color)
    else:
        for group in group_findings(data["findings"]):
            render_group(lines, group, color)

    lines.append(DISCLAIMER)
    return "\n".join(lines)


def render_json(data):
    return json.dumps(data, indent=2, ensure_ascii=False)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="leasecheck",
        description=(
            "Show what an AI coding agent running as the current user could "
            "reach. Read-only; nothing leaves this computer."
        ),
    )
    parser.add_argument(
        "--json", action="store_true", help="print the same data as JSON"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="list every finding separately instead of grouping them",
    )
    parser.add_argument(
        "--home", default=None, help="check this home directory instead of ~"
    )
    parser.add_argument(
        "--show-hosts",
        action="store_true",
        help="also show HostName addresses from the SSH config",
    )
    args = parser.parse_args(argv)

    try:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")
    except (AttributeError, OSError):
        pass

    if args.home:
        home = os.path.abspath(os.path.expanduser(args.home))
    else:
        home = os.path.expanduser("~")

    scanner = Scanner(home, args.show_hosts)
    data = scanner.run()

    color = (
        not args.json
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )
    if args.json:
        sys.stdout.write(render_json(data) + "\n")
    else:
        sys.stdout.write(render_text(data, color, args.all) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
