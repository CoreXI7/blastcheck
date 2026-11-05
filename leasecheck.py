#!/usr/bin/env python3
"""leasecheck - show what an AI coding agent running as you could reach.

Read-only: this never changes, creates or deletes anything.
No network: no socket/urllib/http imports and no network subprocesses.
Single file, Python 3.10+, standard library only.

Usage: python3 leasecheck.py [--json | --sarif | --html] [--all] [--home DIR]
                             [--show-hosts] [--fail-on critical|high|medium]
                             [--version]
"""

import argparse
import base64
import html
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
import time

VERSION = '0.2.0'

MAX_FILES = 20_000
MAX_SECONDS = 20.0
MAX_SIZE = 1024 * 1024
MAX_DEPTH = 4
SETTINGS_MAX_SIZE = 16 * 1024 * 1024
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
    "mobile documents",
    "cloudstorage",
}

SECRET_FILE_NAMES = {".netrc", ".pgpass", ".npmrc", ".pypirc"}

SKIP_ENV_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
}

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
    "AUTHORIZATION",
}

# Names like TOKEN_COUNT or PASSWORD_URL describe a secret, not hold one.
NOT_SECRET_ENDINGS = {
    "DATE", "TIME", "COUNT", "LIMIT", "LENGTH", "SIZE", "TYPE", "URL", "URI",
    "FILE", "PATH", "EXPIRY", "EXPIRES", "ENABLED", "REQUIRED", "USAGE",
    "NAME", "REF", "REFS", "KEYREF", "SECRETREF", "SELECTOR", "PREFIX",
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

KNOWN_PEM = {
    "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
    "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "CERTIFICATE", "PUBLIC KEY",
}

KNOWN_DANGER_SETTINGS = {"dangerouslySkipPermissions"}

BROAD_BASH_RULES = {"Bash", "Bash(*)", "Bash(:*)"}

BROAD_BASH_PREFIXES = (
    "Bash(sudo",
    "Bash(su ",
    "Bash(bash",
    "Bash(sh ",
    "Bash(curl",
    "Bash(wget",
)

# Running any of these as root without a password is as good as root itself.
ROOT_EQUIVALENT_PROGRAMS = {
    "su", "sudo", "sudoedit", "bash", "sh", "dash", "zsh", "fish", "env", "docker",
    "podman", "systemctl", "python", "python3", "perl", "ruby", "node", "vi", "vim",
    "nvim", "nano", "less", "more", "man", "find", "awk", "gawk", "sed", "tee", "cp",
    "mv", "dd", "chmod", "chown", "tar", "rsync", "apt", "apt-get", "dpkg", "yum",
    "dnf", "pip", "pip3", "git", "make", "crontab", "mount",
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

MCP_CONFIG_PATHS = (
    ".claude.json",
    ".cursor/mcp.json",
    ".codeium/windsurf/mcp_config.json",
    ".gemini/settings.json",
    ".config/opencode/opencode.json",
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

_AIDER_YES_ALWAYS_RE = re.compile(
    r"""^\s*yes-always\s*:\s*['"]?true['"]?\s*(?:#.*)?$""", re.I
)

_ABS_PATH_RE = re.compile(
    r"""(?<![\w./:~])/(?:[A-Za-z0-9._@%+-]+)(?:/[A-Za-z0-9._@%+-]+)*"""
)

_WIN_ABS_PATH_RE = re.compile(r"""(?<![\w])[A-Za-z]:[\\/][^\s;]*""")


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
            return "~/" + hide_token_parts(rel)
    except (ValueError, OSError):
        pass
    return hide_token_parts(path)


def hide_token_parts(path):
    parts = []
    for part in path.split(os.sep):
        words = re.split(r"[^A-Za-z0-9]+", part)
        hidden = any(len(w) >= 16 and token_shaped(w, 32) for w in words)
        parts.append("[name hidden]" if hidden else part)
    return "/".join(parts)


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
    if len(name) > 48 or any(token_shaped(w, 12) for w in name_words(name)):
        return "[unusual name hidden]"
    return name


def token_shaped(word, long_len):
    """A word long enough, or mixed enough, that it could be a credential."""
    mixed = any(c.isdigit() for c in word) and any(c.isalpha() for c in word)
    return len(word) >= long_len or (mixed and len(word) >= 8)


def holds_literal_value(value):
    """True when a value looks stored here, not a reference or a placeholder."""
    value = value.strip().rstrip(",;").strip("\"'` ")
    if len(value) < 6 or value.lower() in PLACEHOLDER_VALUES:
        return False
    if value[0] in "$<{[(%#" or value.startswith(
        (
            "os.",
            "process.",
            "env.",
            "xxx",
            "var.",
            "local.",
            "module.",
            "each.",
            "data.",
            "!vault",
        )
    ):
        return False
    return not re.fullmatch(r"[0-9.]+", value)


def stored_in_args(server):
    """Names of credentials passed in a server's args or embedded in its url.

    Returns labels only. Values are looked at to judge them, and never kept.
    """
    found = set()
    args = server.get("args") if isinstance(server.get("args"), list) else []
    args = [a for a in args if isinstance(a, str)]
    for i, arg in enumerate(args):
        if not arg.startswith("-"):
            continue
        flag, sep, value = arg.partition("=")
        if not sep:
            value = args[i + 1] if i + 1 < len(args) else ""
        if looks_like_secret_name(flag.lstrip("-")) and holds_literal_value(value):
            found.add("argument " + safe_name(flag))
    for key in ("url", "serverUrl", "httpUrl"):
        url = server.get(key)
        if not isinstance(url, str):
            continue
        if re.match(r"[a-z][a-z0-9+.-]*://[^/@?#]+@", url, re.I):
            found.add("login inside " + key)
        query = url.partition("?")[2].partition("#")[0]
        for pair in query.split("&"):
            name, sep, value = pair.partition("=")
            if sep and looks_like_secret_name(name) and holds_literal_value(value):
                found.add(key + " parameter " + safe_name(name))
    return found


def collect_mcp_servers(data):
    """Server name/object pairs found under any mcpServers or mcp key.

    Each child object of those keys is one server. Only names are kept; the
    server's args, env, headers and urls are never read out here.
    """
    servers = {}
    seen = set()
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if id(node) in seen:
                continue
            seen.add(id(node))
            for key in ("mcpServers", "mcp"):
                block = node.get(key)
                if isinstance(block, dict):
                    for name, server in block.items():
                        if isinstance(server, dict):
                            servers.setdefault(str(name), server)
            stack.extend(
                value for value in node.values()
                if isinstance(value, (dict, list))
            )
        elif isinstance(node, list):
            stack.extend(
                value for value in node if isinstance(value, (dict, list))
            )
    return servers


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
    except (ValueError, RecursionError):
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
                    found.add(key if key in KNOWN_DANGER_SETTINGS else "a dangerously* setting")
                elif isinstance(value, (dict, list)):
                    stack.append(value)
    return sorted(found)


def broad_bash_rule(rule):
    """True when a Claude allow rule lets an agent run wide shell commands."""
    rule = rule.strip()
    return rule in BROAD_BASH_RULES or rule.startswith(BROAD_BASH_PREFIXES)


def rule_label(rule):
    """Show which broad rule matched, never the rest, which may hold a value."""
    rule = rule.strip()
    if rule in BROAD_BASH_RULES:
        return rule
    for prefix in BROAD_BASH_PREFIXES:
        if rule.startswith(prefix):
            return prefix.strip() + (" ...)" if rule != prefix.strip() + ")" else ")")
    return "Bash(...)"


def claude_allow_rules(text):
    """Matching broad Bash entries from every permissions.allow list."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    found = []
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            permissions = node.get("permissions")
            if isinstance(permissions, dict):
                allow = permissions.get("allow")
                if isinstance(allow, list):
                    for rule in allow:
                        if (
                            isinstance(rule, str)
                            and broad_bash_rule(rule)
                            and rule not in found
                        ):
                            found.append(rule)
            stack.extend(
                value for value in node.values()
                if isinstance(value, (dict, list))
            )
    return found


def opencode_permission_tools(text):
    """Return (has_permission_key, allowed_tools) for an OpenCode config.

    allowed_tools holds "all" when the whole permission is allow, otherwise the
    names of bash, shell, edit or write rules that are set to allow.
    """
    match = re.search(r'"permission"\s*:', text)
    if not match:
        return False, []
    rest = text[match.end():].lstrip()
    if re.match(r'"allow"', rest):
        return True, ["all"]
    if not rest.startswith("{"):
        return True, []
    body = rest[:20000]
    tools = [
        tool
        for tool in ("bash", "shell", "edit", "write")
        if re.search(
            r'"' + tool + r'"\s*:\s*(\{[^{}]*"\*"\s*:\s*)?"allow"', body
        )
    ]
    return True, tools


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

    def open_regular(self, path, limit=MAX_SIZE):
        """Open a regular file without following a final symlink or blocking."""
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
                raise OSError("not a regular file of allowed size")
            return os.fdopen(fd, "rb")
        except OSError:
            os.close(fd)
            raise

    def read_text_limited(self, path, limit=MAX_SIZE):
        st = self.lstat_nofollow(path)
        if st is None:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > limit:
            self.skipped_large += 1
            self.note("Skipped, too large to check: " + display_path(path, self.home))
            return None
        try:
            with self.open_regular(path, limit) as handle:
                return handle.read(limit).decode("utf-8", errors="ignore")
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
        if kind not in KNOWN_PEM:
            return "PRIVATE KEY" if "PRIVATE KEY" in kind else "UNRECOGNIZED BLOCK"
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
            os.path.join(self.home, ".orbstack", "run", "docker.sock"),
            os.path.join(self.home, ".colima", "default", "docker.sock"),
        )
        for socket_path in sockets:
            st = self.lstat_nofollow(socket_path)
            if st is None:
                continue
            if stat.S_ISLNK(st.st_mode):
                socket_path = os.path.realpath(socket_path)
                st = self.lstat_nofollow(socket_path)
                if st is None:
                    continue
            if not stat.S_ISSOCK(st.st_mode):
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
            unrestricted = any(
                c == "ALL"
                or "*" in c.split()[0]
                or os.path.basename(c.split()[0]) in ROOT_EQUIVALENT_PROGRAMS
                or re.match(r"python[0-9.]*$", os.path.basename(c.split()[0]))
                for c in commands
                if c.split()
            )
            if unrestricted:
                self.finding(
                    "critical",
                    "Passwordless sudo gives full root",
                    "An agent could run any command as root without a password, "
                    "directly or through a program that can start other programs.",
                    ["programs: " + ", ".join(sorted({
                        clean(c.split()[0])[:80] for c in commands if c.split()
                    })[:8])],
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

    def check_ssh_agent(self):
        sock = os.environ.get("SSH_AUTH_SOCK")
        if not sock:
            return
        st = self.lstat_nofollow(sock)
        if st is None or not stat.S_ISSOCK(st.st_mode) or not os.access(sock, os.W_OK):
            return
        self.finding(
            "high",
            "SSH agent available to anything you start",
            "An agent can sign in with every key loaded in it, including keys "
            "that have a passphrase.",
            ["SSH_AUTH_SOCK points to a usable socket"],
            "Don't start agents from a shell with SSH_AUTH_SOCK set, or use "
            "ssh-add -c so each use needs your confirmation.",
        )

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
                + ", ".join(safe_name(h) for h in hosts[:20])
            )
            if len(hosts) > 20:
                evidence.append(f"{len(hosts) - 20} more Host alias(es) not shown")
            if self.show_hosts and host_names:
                evidence.append(
                    "HostName addresses: "
                    + ", ".join(safe_name(h) for h in host_names[:20])
                )
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
                line_part = "key file"
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
        if lower in SKIP_ENV_NAMES:
            return

        if lower.endswith(".pem") or lower.endswith(".key"):
            first = self.read_first_line(path)
            header = None
            if first:
                match = _PEM_RE.match(first)
                if match:
                    header = self.pem_kind(path, match)
            if header and "PRIVATE KEY" in header:
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
            if not names and (
                lower.startswith(".env") or lower in {".npmrc", ".pypirc"}
            ):
                return
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

        try:
            home_dev = os.lstat(home).st_dev
        except OSError:
            return

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
                try:
                    child_st = os.lstat(child)
                except OSError:
                    continue
                if stat.S_ISLNK(child_st.st_mode) or child_st.st_dev != home_dev:
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
                if dirpath == os.path.join(home, ".ssh"):
                    continue  # check_ssh covers these
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
                text = self.read_text_limited(path, SETTINGS_MAX_SIZE)
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
                rules = claude_allow_rules(text)
                if rules:
                    shown = [rule_label(rule) for rule in rules[:10]]
                    detail = (
                        f"{display_path(path, home)} (allow rules: "
                        + ", ".join(shown)
                        + ")"
                    )
                    if len(rules) > 10:
                        detail += (
                            f"; {len(rules) - 10} more rule(s) not shown"
                        )
                    self.finding(
                        "high",
                        "Claude Code may run commands without asking",
                        "An allow rule lets the agent run broad shell "
                        "commands without asking you.",
                        [detail],
                        "Remove broad Bash allow rules or narrow them to the "
                        "specific commands the agent needs.",
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
                has_permission, allowed = opencode_permission_tools(text)
                if not has_permission:
                    continue
                saw_permission = True
                if allowed:
                    if allowed == ["all"]:
                        detail = "permission = allow"
                    else:
                        detail = "permission allow for: " + ", ".join(allowed)
                    self.finding(
                        "high",
                        "OpenCode permission is set to allow",
                        "The agent can use tools without asking you first.",
                        [display_path(path, home) + " (" + detail + ")"],
                        'Change "permission" to "ask" or a narrower rule.',
                    )
            if not saw_permission:
                if saw_config:
                    self.note(
                        "OpenCode config has no permission key, so tool "
                        "permission is not confirmed; check it manually."
                    )
                else:
                    self.note(
                        "OpenCode is installed but no config file was found; "
                        "tool permission is not confirmed."
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
                os.path.join(home, "Library", "Application Support", "Cursor"),
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
        aider_config = os.path.join(home, ".aider.conf.yml")
        aider_text = self.read_text_limited(aider_config)
        if aider_text is not None and any(
            _AIDER_YES_ALWAYS_RE.match(line)
            for line in aider_text.splitlines()
        ):
            self.finding(
                "high",
                "Aider approves every action",
                "Aider applies edits and runs commands without asking you.",
                [display_path(aider_config, home)],
                "Remove yes-always: true or set it to false.",
            )
        self.detect_agent(
            "Gemini CLI",
            [
                os.path.join(home, ".gemini"),
                os.path.join(home, ".config", "gemini"),
            ],
            "Review its approval settings before letting it work unattended.",
        )

    def check_environment(self):
        names = set()
        for name, value in os.environ.items():
            if looks_like_secret_name(name) and holds_literal_value(value):
                names.add(safe_name(name))
        if not names:
            return
        shown = sorted(names)
        evidence = "environment variables: " + ", ".join(shown[:20])
        if len(shown) > 20:
            evidence += " (+{} more)".format(len(shown) - 20)
        self.finding(
            "medium",
            "Credentials in your shell environment",
            "Any agent you start inherits these variables and can read the "
            "credentials.",
            [evidence],
            "Remove long-lived credentials from your shell environment; use a "
            "credential helper or short-lived tokens instead.",
        )

    def check_mcp(self):
        for rel in MCP_CONFIG_PATHS:
            path = os.path.join(self.home, rel)
            text = self.read_text_limited(path, SETTINGS_MAX_SIZE)
            if text is None:
                continue
            try:
                data = json.loads(text)
            except (ValueError, RecursionError):
                continue
            servers = collect_mcp_servers(data)
            if not servers:
                continue
            count = len(servers)
            names = sorted({safe_name(name) for name in servers})
            evidence = "{}: {} server(s): {}".format(
                display_path(path, self.home), count, ", ".join(names[:20])
            )
            if len(names) > 20:
                evidence += " (+{} more name(s))".format(len(names) - 20)
            self.finding(
                "info",
                "MCP servers an agent can use",
                "Each MCP server gives an agent another tool it can call with "
                "your permissions.",
                [evidence],
                "Remove MCP servers you do not use and review what each one "
                "can reach.",
            )
            for name, server in servers.items():
                for label in sorted(stored_in_args(server)):
                    self.finding(
                        "high",
                        "Credential stored in an MCP config",
                        "The credential is stored in plain text, where an "
                        "agent can read it.",
                        [
                            "{}: server {}, {}".format(
                                display_path(path, self.home),
                                safe_name(str(name)),
                                label,
                            )
                        ],
                        "Replace the stored value with an environment "
                        "reference or a credential helper.",
                    )
                for key in ("env", "headers"):
                    block = server.get(key)
                    if not isinstance(block, dict):
                        continue
                    for child, value in block.items():
                        if not isinstance(value, str):
                            continue
                        if not looks_like_secret_name(str(child)):
                            continue
                        if not holds_literal_value(value):
                            continue
                        self.finding(
                            "high",
                            "Credential stored in an MCP config",
                            "The credential is stored in plain text, where an "
                            "agent can read it.",
                            [
                                "{}: server {}, {}".format(
                                    display_path(path, self.home),
                                    safe_name(str(name)),
                                    safe_name(str(child)),
                                )
                            ],
                            "Replace the stored value with an environment "
                            "reference or a credential helper.",
                        )

    def check_startup_writable(self):
        present = []
        for rel in (
            ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc",
            ".zprofile", ".zshenv", ".zlogin", ".ssh/authorized_keys",
        ):
            path = os.path.join(self.home, rel)
            st = self.lstat_nofollow(path)
            if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                continue
            present.append(rel)
            if stat.S_IMODE(st.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
                self.finding(
                    "high",
                    "Startup file writable by group or others",
                    "Another user could plant commands that run when you log in.",
                    [f"{display_path(path, self.home)} (mode {mode_string(st)})"],
                    "Restrict it to its owner (chmod 600 or 644).",
                )
        if present:
            self.note(
                "An agent running as you can edit your startup files ("
                + ", ".join(present)
                + "), so check them after unattended runs."
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
        self.check_ssh_agent()
        self.check_saved_logins()
        self.check_agents()
        self.check_environment()
        self.check_mcp()
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


TAGLINE = "Show what an AI coding agent running as you could reach."
MAX_TEXT_WIDTH = 100
MIN_TEXT_WIDTH = 40
LABEL_WIDTH = 7
FINDING_INDENT = 6
SUMMARY_BAR_WIDTH = 20

SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "info": "Info",
}


def use_unicode():
    """Box drawing is only safe when stdout really speaks UTF-8."""
    encoding = getattr(sys.stdout, "encoding", None) or ""
    normalised = encoding.lower().replace("-", "").replace("_", "")
    return normalised in ("utf8", "utf8mb4")


def glyphs():
    if use_unicode():
        return {"rule": "\u2500", "bar": "\u2588", "bullet": "\u2022"}
    return {"rule": "-", "bar": "#", "bullet": "-"}


def output_width():
    try:
        columns = shutil.get_terminal_size((80, 24)).columns
    except OSError:
        columns = 80
    return max(MIN_TEXT_WIDTH, min(columns, MAX_TEXT_WIDTH))


def plural(count, word):
    return "{} {}{}".format(count, word, "" if count == 1 else "s")


def wrap_lines(text, width):
    width = max(10, width)
    lines = []
    for paragraph in str(text).splitlines() or [""]:
        wrapped = textwrap.wrap(
            paragraph,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
        )
        lines.extend(wrapped or [""])
    return lines


def rule_heading(text, width, marks):
    label = " {} ".format(text)
    rule = marks["rule"]
    if width <= len(label) + 2:
        return label.strip()
    return rule * 2 + label + rule * (width - len(label) - 2)


def severity_heading(severity, detail, width, marks, color):
    name = severity.upper()
    plain = " {}  {} ".format(name, detail)
    if width <= len(plain) + 2:
        return colorize(name, severity, color) + plain[len(name) + 1:].rstrip()
    colored = " " + colorize(name, severity, color) + plain[len(name) + 1:]
    return marks["rule"] * 2 + colored + marks["rule"] * (
        width - len(plain) - 2
    )


def add_labelled(lines, label, text, width, indent=FINDING_INDENT, label_width=LABEL_WIDTH):
    column = indent + label_width
    body = wrap_lines(text, width - column)
    lines.append(" " * indent + label.ljust(label_width) + body[0])
    for line in body[1:]:
        lines.append(" " * column + line)


def add_evidence(lines, evidence, hidden, marks, width):
    column = FINDING_INDENT + LABEL_WIDTH
    available = width - column - 2
    bullet = marks["bullet"] + " "
    for index, item in enumerate(evidence):
        body = wrap_lines(item, available)
        if index == 0:
            label = " " * FINDING_INDENT + "Found".ljust(LABEL_WIDTH)
        else:
            label = " " * column
        lines.append(label + bullet + body[0])
        for line in body[1:]:
            lines.append(" " * (column + 2) + line)
    if hidden > 0:
        note = "... {} more evidence line{} not shown".format(
            hidden, "" if hidden == 1 else "s"
        )
        lines.append(" " * column + bullet + note)


def render_entry(lines, entry, number, width, marks, color):
    count = entry.get("count", 1)
    count_text = plural(count, "item")
    prefix = "  {:>2}  ".format(str(number) + ".")
    available = width - len(prefix) - len(count_text) - 2
    title_lines = wrap_lines(entry["title"], available)
    first = prefix + title_lines[0]
    gap = width - len(first) - len(count_text)
    lines.append(
        first[: len(prefix)]
        + bold(first[len(prefix):], color)
        + " " * max(1, gap)
        + dim(count_text, color)
    )
    for line in title_lines[1:]:
        lines.append(" " * len(prefix) + line)

    add_labelled(lines, "Why", entry["why"], width)
    evidence = entry["evidence"]
    if evidence:
        hidden = entry.get("evidence_total", len(evidence)) - len(evidence)
        add_evidence(lines, evidence, hidden, marks, width)
    add_labelled(lines, "Fix", entry["fix"], width)
    lines.append("")


def bold(text, enabled):
    return "\033[1m" + text + "\033[0m" if enabled else text


def dim(text, enabled):
    return "\033[2m" + text + "\033[0m" if enabled else text


def render_summary(lines, counts, width, marks, color):
    lines.append(rule_heading("Summary", width, marks))
    largest = max([counts[name] for name in SEVERITIES] + [1])
    for severity in SEVERITIES:
        count = counts[severity]
        filled = 0
        if count:
            filled = max(
                1, int(round(count / largest * SUMMARY_BAR_WIDTH))
            )
        name = colorize(severity.upper().ljust(len("critical")), severity, color)
        lines.append(
            "  {} {:>4}  {}".format(name, count, marks["bar"] * filled)
        )
    lines.append("")


def render_text(data, color, show_all=False):
    marks = glyphs()
    width = output_width()
    scan = data["scan"]
    findings = data["findings"]
    counts = data["summary"]
    lines = []

    lines.append(bold("leasecheck " + VERSION, color) + "  " + dim(TAGLINE, color))
    lines.append(marks["rule"] * width)
    lines.append("")

    if findings:
        top = min(
            findings,
            key=lambda item: (RANK[item["severity"]], item["title"].lower()),
        )
        tally = ", ".join(
            "{} {}".format(counts[name], name) for name in SEVERITIES if counts[name]
        )
        lines.append(
            "  Overall risk  "
            + colorize(top["severity"].upper(), top["severity"], color)
            + dim("   " + tally, color)
        )
        add_labelled(lines, "Start with", top["title"], width, indent=2, label_width=14)
    else:
        lines.append("  Overall risk  none detected")
        lines.append("  No known issues were found in this scan.")
    lines.append("")

    render_summary(lines, counts, width, marks, color)

    groups = group_findings(findings)
    for severity in SEVERITIES:
        if show_all:
            entries = [f for f in findings if f["severity"] == severity]
            detail = plural(len(entries), "item")
        else:
            entries = [g for g in groups if g["severity"] == severity]
            detail = "{} finding{} / {} item{}".format(
                len(entries),
                "" if len(entries) == 1 else "s",
                counts[severity],
                "" if counts[severity] == 1 else "s",
            )
        if not entries:
            continue
        lines.append(
            severity_heading(severity, detail, width, marks, color)
        )
        for number, entry in enumerate(entries, 1):
            if show_all:
                entry = dict(entry)
                entry["count"] = 1
                entry["evidence_total"] = len(entry["evidence"])
            render_entry(lines, entry, number, width, marks, color)

    lines.append(rule_heading("Scan details", width, marks))
    facts = (
        ("Files checked", "{:,}".format(scan["files_scanned"])),
        ("Files skipped", "{:,}".format(scan["files_over_1mb_skipped"])),
        ("Permission errors", "{:,}".format(scan["permission_errors"])),
        ("Elapsed time", "{:.1f} s".format(scan["elapsed_seconds"])),
    )
    for label, value in facts:
        lines.append("  " + label.ljust(20) + value)
    if scan["stopped_early"]:
        lines.append(
            "  " + "Scan stopped".ljust(20)
            + "early, {} reached".format(scan["stop_reason"])
        )
    if scan["notes"]:
        lines.append("")
        lines.append("  Scan notes:")
        for note in scan["notes"]:
            for index, line in enumerate(wrap_lines(note, width - 6)):
                lines.append(("    - " if index == 0 else "      ") + line)

    lines.append(marks["rule"] * width)
    for line in wrap_lines(DISCLAIMER, width - 2):
        lines.append("  " + dim(line, color))
    return "\n".join(lines)


HTML_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f3f5f8;
  --panel: #ffffff;
  --text: #1b2027;
  --muted: #5c6675;
  --border: #d9dee6;
  --code: #eef1f5;
  --critical: #b42318;
  --critical-bg: #fdeceb;
  --high: #b54708;
  --high-bg: #fdf3e7;
  --medium: #8a6100;
  --medium-bg: #fbf6e3;
  --info: #0b6b6e;
  --info-bg: #e9f8f8;
  --none: #1f6f43;
  --none-bg: #e9f5ee;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1319;
    --panel: #171c24;
    --text: #e7ebf0;
    --muted: #9aa5b3;
    --border: #2b323c;
    --code: #222833;
    --critical: #ff8f85;
    --critical-bg: #2c1515;
    --high: #ffab73;
    --high-bg: #2a1c10;
    --medium: #f2cf6b;
    --medium-bg: #28220f;
    --info: #7fdede;
    --info-bg: #0f2526;
    --none: #7fd6a2;
    --none-bg: #0f2418;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 16px;
  line-height: 1.55;
}
code, .evidence li {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
.wrap {
  max-width: 60rem;
  margin: 0 auto;
  padding: clamp(1rem, 3vw, 2.5rem);
}
.page-header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 1rem;
  margin-bottom: 1.5rem;
}
h1 {
  font-size: clamp(1.5rem, 4vw, 2.1rem);
  margin: 0;
  letter-spacing: -0.01em;
}
h1 .version {
  font-size: 0.55em;
  font-weight: 600;
  color: var(--muted);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.15em 0.6em;
  vertical-align: middle;
  margin-left: 0.4rem;
}
.tagline { color: var(--muted); margin: 0.4rem 0 0; }
.meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem 1.75rem;
  margin: 1rem 0 0;
  padding: 0;
  list-style: none;
  font-size: 0.95rem;
}
.meta dt {
  color: var(--muted);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.meta dd { margin: 0; font-weight: 600; }
.risk {
  border: 1px solid var(--border);
  border-left: 6px solid var(--none);
  background: var(--none-bg);
  border-radius: 0.6rem;
  padding: 1rem 1.1rem;
  margin-bottom: 1.75rem;
}
.risk-label {
  display: block;
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
}
.risk-value {
  display: block;
  margin-top: 0.15rem;
  font-size: 1.35rem;
  font-weight: 700;
  color: var(--none);
}
.risk-action { margin: 0.55rem 0 0; }
.risk-critical { border-left-color: var(--critical); background: var(--critical-bg); }
.risk-critical .risk-value { color: var(--critical); }
.risk-high { border-left-color: var(--high); background: var(--high-bg); }
.risk-high .risk-value { color: var(--high); }
.risk-medium { border-left-color: var(--medium); background: var(--medium-bg); }
.risk-medium .risk-value { color: var(--medium); }
.risk-info { border-left-color: var(--info); background: var(--info-bg); }
.risk-info .risk-value { color: var(--info); }
.section-title {
  font-size: 0.95rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin: 2rem 0 0.75rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.4rem;
}
.cards {
  list-style: none;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr));
  gap: 0.75rem;
  margin: 0;
  padding: 0;
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-top: 4px solid var(--info);
  border-radius: 0.55rem;
  padding: 0.8rem 0.9rem;
}
.card-critical { border-top-color: var(--critical); }
.card-high { border-top-color: var(--high); }
.card-medium { border-top-color: var(--medium); }
.card-info { border-top-color: var(--info); }
.card-sev {
  display: block;
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
}
.card-count {
  display: block;
  font-size: 1.9rem;
  font-weight: 700;
  line-height: 1.15;
}
.card-caption { display: block; font-size: 0.78rem; color: var(--muted); }
.sev-section { margin-top: 1.75rem; }
.sev-section > h3 {
  font-size: 1.02rem;
  margin: 0 0 0.6rem;
  padding-bottom: 0.35rem;
  border-bottom: 1px solid var(--border);
}
.finding {
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 4px solid var(--info);
  border-radius: 0.55rem;
  margin: 0.6rem 0;
}
.finding.sev-critical { border-left-color: var(--critical); }
.finding.sev-high { border-left-color: var(--high); }
.finding.sev-medium { border-left-color: var(--medium); }
.finding.sev-info { border-left-color: var(--info); }
.finding > summary {
  display: flex;
  align-items: baseline;
  gap: 0.6rem;
  flex-wrap: wrap;
  padding: 0.8rem 0.95rem;
  cursor: pointer;
  list-style: none;
}
.finding > summary::-webkit-details-marker { display: none; }
.badge {
  font-size: 0.68rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  border-radius: 999px;
  padding: 0.12rem 0.55rem;
  background: var(--info-bg);
  color: var(--info);
  border: 1px solid currentColor;
}
.badge-critical { background: var(--critical-bg); color: var(--critical); }
.badge-high { background: var(--high-bg); color: var(--high); }
.badge-medium { background: var(--medium-bg); color: var(--medium); }
.badge-info { background: var(--info-bg); color: var(--info); }
.finding-title { font-weight: 600; flex: 1 1 12rem; overflow-wrap: anywhere; }
.finding-count {
  margin-left: auto;
  color: var(--muted);
  font-size: 0.85rem;
  white-space: nowrap;
}
.finding-body {
  padding: 0 0.95rem 1rem;
  border-top: 1px solid var(--border);
}
.finding-body h4 {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin: 1rem 0 0.25rem;
}
.finding-body p { margin: 0; }
.evidence { list-style: none; margin: 0; padding: 0; }
.evidence li {
  font-size: 0.86rem;
  background: var(--code);
  border-radius: 0.35rem;
  padding: 0.35rem 0.5rem;
  margin: 0.3rem 0;
  overflow-wrap: anywhere;
}
.evidence li.more { color: var(--muted); font-style: italic; }
.facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
  gap: 0.75rem;
  margin: 0;
}
.facts div {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 0.6rem 0.75rem;
}
.facts dt {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--muted);
}
.facts dd {
  margin: 0;
  font-weight: 600;
  overflow-wrap: anywhere;
}
.notes { margin: 0.5rem 0 0; padding-left: 1.2rem; color: var(--muted); }
footer {
  margin-top: 2.5rem;
  border-top: 1px solid var(--border);
  padding-top: 1rem;
  color: var(--muted);
  font-size: 0.88rem;
}
@media (max-width: 34rem) {
  .wrap { padding: 1rem 0.85rem 2rem; }
  .finding > summary { padding: 0.7rem 0.75rem; }
  .finding-body { padding: 0 0.75rem 0.9rem; }
  .finding-count { margin-left: 0; width: 100%; }
  .meta { gap: 0.3rem 1rem; }
}
@media print {
  :root {
    --bg: #ffffff;
    --panel: #ffffff;
    --text: #000000;
    --muted: #333333;
    --border: #999999;
    --code: #f2f2f2;
    --critical: #8f1d14;
    --critical-bg: #ffffff;
    --high: #7a3006;
    --high-bg: #ffffff;
    --medium: #5f4300;
    --medium-bg: #ffffff;
    --info: #075254;
    --info-bg: #ffffff;
    --none: #175c37;
    --none-bg: #ffffff;
  }
  body { background: #ffffff; color: #000000; font-size: 11pt; }
  .wrap { max-width: none; padding: 0; }
  details { display: block; }
  details:not([open])::details-content { content-visibility: visible; }
  details > *:not(summary) { display: block; }
  .finding, .card, .risk, .facts div {
    break-inside: avoid;
    page-break-inside: avoid;
  }
  .finding > summary { cursor: default; }
}
"""


def render_html(data):
    scan = data["scan"]
    findings = data["findings"]
    counts = data["summary"]
    groups = group_findings(findings)
    by_severity = {name: [] for name in SEVERITIES}
    for group in groups:
        by_severity[group["severity"]].append(group)
    top = None
    if findings:
        top = min(
            findings,
            key=lambda item: (RANK[item["severity"]], item["title"].lower()),
        )
    scan_date = time.strftime("%Y-%m-%d")
    scan_time = time.strftime("%H:%M:%S")

    parts = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append(
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
    )
    parts.append(
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; style-src \'unsafe-inline\'; '
        'img-src data:">'
    )
    parts.append('<meta name="color-scheme" content="light dark">')
    parts.append(
        "<title>leasecheck {} - security report</title>".format(
            html.escape(VERSION, quote=True)
        )
    )
    parts.append("<style>" + HTML_STYLE + "</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append('<div class="wrap">')

    parts.append('<header class="page-header">')
    parts.append(
        '<h1>leasecheck <span class="version">{}</span></h1>'.format(
            html.escape(VERSION, quote=True)
        )
    )
    parts.append(
        '<p class="tagline">{}</p>'.format(html.escape(TAGLINE, quote=True))
    )
    parts.append('<dl class="meta">')
    parts.append(
        "<div><dt>Scan date</dt><dd>{}</dd></div>".format(
            html.escape(scan_date, quote=True)
        )
    )
    parts.append(
        "<div><dt>Scan time</dt><dd>{}</dd></div>".format(
            html.escape(scan_time, quote=True)
        )
    )
    parts.append(
        '<div><dt>Home</dt><dd><code>{}</code></dd></div>'.format(
            html.escape(scan["home"], quote=True)
        )
    )
    parts.append("</dl>")
    parts.append("</header>")

    if top is None:
        risk_class = "risk-none"
        risk_value = "None detected"
    else:
        risk_class = "risk-" + top["severity"]
        risk_value = SEVERITY_LABELS[top["severity"]]
    parts.append(
        '<section class="risk {}" role="status">'.format(
            html.escape(risk_class, quote=True)
        )
    )
    parts.append('<span class="risk-label">Overall risk</span>')
    parts.append(
        '<span class="risk-value">{}</span>'.format(
            html.escape(risk_value, quote=True)
        )
    )
    if top is None:
        parts.append(
            '<p class="risk-action">{}</p>'.format(
                html.escape(
                    "No known issues were found in this scan.", quote=True
                )
            )
        )
    else:
        parts.append(
            '<p class="risk-action">Start with: <strong>{}</strong></p>'
            '<p class="risk-action">{}</p>'.format(
                html.escape(top["title"], quote=True),
                html.escape(top["fix"], quote=True),
            )
        )
    parts.append("</section>")

    parts.append('<h2 class="section-title">Summary</h2>')
    parts.append('<ul class="cards">')
    for severity in SEVERITIES:
        item_count = counts[severity]
        group_count = len(by_severity[severity])
        if item_count:
            caption = "{} in {}".format(
                plural(item_count, "item"), plural(group_count, "finding")
            )
        else:
            caption = "none"
        parts.append(
            '<li class="card card-{sev}">'
            '<span class="card-sev">{label}</span>'
            '<span class="card-count">{count}</span>'
            '<span class="card-caption">{caption}</span>'
            "</li>".format(
                sev=html.escape(severity, quote=True),
                label=html.escape(SEVERITY_LABELS[severity], quote=True),
                count=item_count,
                caption=html.escape(caption, quote=True),
            )
        )
    parts.append("</ul>")

    parts.append('<h2 class="section-title">Findings</h2>')
    for severity in SEVERITIES:
        severity_groups = by_severity[severity]
        if not severity_groups:
            continue
        parts.append('<section class="sev-section">')
        parts.append(
            "<h3>{} - {}</h3>".format(
                html.escape(SEVERITY_LABELS[severity], quote=True),
                html.escape(plural(counts[severity], "item"), quote=True),
            )
        )
        for group in severity_groups:
            parts.append(
                '<details class="finding sev-{}"{}>'.format(
                    html.escape(severity, quote=True),
                    " open" if severity in ("critical", "high") else "",
                )
            )
            parts.append("<summary>")
            parts.append(
                '<span class="badge badge-{sev}">{label}</span>'.format(
                    sev=html.escape(severity, quote=True),
                    label=html.escape(
                        SEVERITY_LABELS[severity], quote=True
                    ),
                )
            )
            parts.append(
                '<span class="finding-title">{}</span>'.format(
                    html.escape(group["title"], quote=True)
                )
            )
            parts.append(
                '<span class="finding-count">{}</span>'.format(
                    html.escape(plural(group["count"], "item"), quote=True)
                )
            )
            parts.append("</summary>")
            parts.append('<div class="finding-body">')
            parts.append("<h4>Why</h4>")
            parts.append(
                "<p>{}</p>".format(html.escape(group["why"], quote=True))
            )
            if group["evidence"]:
                parts.append("<h4>Evidence</h4>")
                parts.append('<ul class="evidence">')
                for evidence in group["evidence"]:
                    parts.append(
                        "<li>{}</li>".format(
                            html.escape(evidence, quote=True)
                        )
                    )
                hidden = group["evidence_total"] - len(group["evidence"])
                if hidden > 0:
                    more = "... {} more evidence line{} not shown".format(
                        hidden, "" if hidden == 1 else "s"
                    )
                    parts.append(
                        '<li class="more">{}</li>'.format(
                            html.escape(more, quote=True)
                        )
                    )
                parts.append("</ul>")
            parts.append("<h4>Fix</h4>")
            parts.append(
                "<p>{}</p>".format(html.escape(group["fix"], quote=True))
            )
            parts.append("</div>")
            parts.append("</details>")
        parts.append("</section>")

    parts.append('<section class="scan">')
    parts.append('<h2 class="section-title">Scan details</h2>')
    facts = [
        ("Home", scan["home"]),
        ("Files checked", "{:,}".format(scan["files_scanned"])),
        ("Files skipped", "{:,}".format(scan["files_over_1mb_skipped"])),
        ("Permission errors", "{:,}".format(scan["permission_errors"])),
        ("Elapsed time", "{:.1f} seconds".format(scan["elapsed_seconds"])),
    ]
    if scan["stopped_early"]:
        facts.append(
            ("Scan stopped", "early, {} reached".format(scan["stop_reason"]))
        )
    parts.append('<dl class="facts">')
    for label, value in facts:
        parts.append(
            "<div><dt>{}</dt><dd>{}</dd></div>".format(
                html.escape(label, quote=True),
                html.escape(str(value), quote=True),
            )
        )
    parts.append("</dl>")
    if scan["notes"]:
        parts.append("<h3>Scan notes</h3>")
        parts.append('<ul class="notes">')
        for note in scan["notes"]:
            parts.append(
                "<li>{}</li>".format(html.escape(note, quote=True))
            )
        parts.append("</ul>")
    parts.append("</section>")

    parts.append("<footer>")
    parts.append(
        "<p>{}</p>".format(html.escape(DISCLAIMER, quote=True))
    )
    parts.append("</footer>")
    parts.append("</div>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


def render_json(data):
    return json.dumps(data, indent=2, ensure_ascii=False)


SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "info": "note",
}


def sarif_safe(value, home):
    """Clean a string and remove absolute filesystem paths for SARIF."""
    text = clean(value)
    try:
        ahome = os.path.abspath(home).rstrip(os.sep)
        if ahome:
            text = text.replace(ahome + os.sep, "~/")
            text = re.sub(re.escape(ahome) + r"(?![\w.-])", "~", text)
    except (OSError, ValueError):
        pass
    text = _WIN_ABS_PATH_RE.sub("[path hidden]", text)
    return _ABS_PATH_RE.sub("[path hidden]", text)


def sarif_rule_id(title):
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug or "finding"


def render_sarif(data, home):
    rules = []
    rule_ids = {}
    used_ids = set()
    results = []
    for item in data["findings"]:
        title = clean(item["title"])
        rule_id = rule_ids.get(title)
        if rule_id is None:
            base = sarif_rule_id(title)
            rule_id = base
            suffix = 2
            while rule_id in used_ids:
                rule_id = base + "-" + str(suffix)
                suffix += 1
            used_ids.add(rule_id)
            rule_ids[title] = rule_id
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": title},
                    "fullDescription": {
                        "text": sarif_safe(item["why"], home)
                    },
                    "help": {"text": sarif_safe(item["fix"], home)},
                }
            )
        parts = [sarif_safe(item["why"], home)]
        evidence = [sarif_safe(e, home) for e in item["evidence"]]
        if evidence:
            parts.append("Evidence: " + "; ".join(evidence))
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVELS[item["severity"]],
                "message": {"text": " ".join(parts)},
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "leasecheck",
                        "version": VERSION,
                        "informationUri": (
                            "https://github.com/CoreXI7/leasecheck"
                        ),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="leasecheck",
        description=(
            "Show what an AI coding agent running as the current user could "
            "reach. Read-only; nothing leaves this computer."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="leasecheck " + VERSION,
        help="print the version and exit",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--json", action="store_true", help="print the same data as JSON"
    )
    output.add_argument(
        "--sarif",
        action="store_true",
        help="print SARIF 2.1.0 JSON instead of text",
    )
    output.add_argument(
        "--html",
        action="store_true",
        help="print a self-contained HTML report instead of text",
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
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium"),
        default=None,
        help="exit 1 if any finding is at this severity or worse",
    )
    args = parser.parse_args(argv)
    if os.name != "posix":
        sys.stderr.write("leasecheck runs on Linux and macOS only.\n")
        return 2

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
        and not args.sarif
        and not args.html
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )
    if args.sarif:
        sys.stdout.write(render_sarif(data, home) + "\n")
    elif args.json:
        sys.stdout.write(render_json(data) + "\n")
    elif args.html:
        sys.stdout.write(render_html(data) + "\n")
    else:
        sys.stdout.write(render_text(data, color, args.all) + "\n")

    if args.fail_on is not None:
        threshold = RANK[args.fail_on]
        if any(RANK[item["severity"]] <= threshold for item in data["findings"]):
            return 1
        if data["scan"]["stopped_early"]:
            sys.stderr.write("Scan stopped early, so this result is incomplete.\n")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
