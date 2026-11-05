# leasecheck: spec

Shows what an AI coding agent running as the current user could reach on this computer, and how to reduce it.

Single file `leasecheck.py`, Python 3.10+ stdlib only, Linux first (macOS where easy). Run: `python3 leasecheck.py [--json] [--home DIR]`.

## Hard rules
- Read-only: never changes, creates or deletes anything outside what the user redirects.
- No network at all: never import socket, urllib, http or subprocess calls that contact anything.
- Never read or print a secret's value. To detect a secret-looking line, match variable NAMES only, and key files may read the start of line 2 only to detect a passphrase, and report only path, line count and names like API_KEY. Private key files: read only the first line, to detect the type and whether it's encrypted.
- Don't follow symlinks. Skip files over 1 MB. Skip node_modules, .git, caches, virtualenvs. Stop a scan cleanly at 20,000 files or 20 seconds, and say so in the report.
- Permission errors are skipped and counted, never fatal.
- Fixed subprocess calls only, with no shell and a timeout, and only `id` and `sudo -n -l` (the latter must never prompt).
- Output is escaped: strip control characters from file names.

## Checks, each giving severity (critical/high/medium/info), title, why it matters in one plain sentence, evidence (paths, counts, names) and fix
1. Root paths: in the docker, lxd or libvirt group (critical, equals root); docker socket writable; passwordless sudo from `sudo -n -l` (critical if ALL, else high and list commands).
2. SSH: private keys in ~/.ssh with no passphrase (high), count of Host entries in ~/.ssh/config and known_hosts lines as "machines these keys may reach"; report the names of Hosts only, not users or addresses, unless --show-hosts.
3. Secret files in home up to depth 4: .env*, *.pem, *.key, .netrc, .pgpass, .npmrc, .pypirc, and files with secret-looking variable names.
4. Saved logins: ~/.aws/credentials, ~/.config/gh/hosts.yml, ~/.docker/config.json, ~/.kube/config, ~/.config/gcloud, ~/.azure, ~/.git-credentials. Existence and permissions only: never open them.
5. Agents: detect Claude Code (~/.claude), Codex (~/.codex), OpenCode (~/.config/opencode), Cursor, Aider, Gemini CLI. For each, report risky settings by parsing only permission-related keys: Claude `bypassPermissions` or `dangerously` settings, OpenCode permission set to allow or missing, Codex `sandbox_mode = "danger-full-access"` or `approval_policy = "never"`.
6. Loose permissions: secret files readable by group or others (high).
7. Writable startup: user crontab readable via no command is out of scope; check that ~/.bashrc, ~/.profile, ~/.ssh/authorized_keys exist and are writable, as info: "an agent could plant commands here".

## Output
Plain text sorted by severity, with color only on a terminal; a one-line summary first, e.g. "1 critical, 3 high, 2 medium". `--json` gives the same data. Exit code 0 always unless the tool itself crashes. A final line states: "This shows common risks it knows to look for. It doesn't prove you're safe. Nothing left this computer."

## Also write
- `test_leasecheck.py`: stdlib unittest using a fake home in a temp dir with planted fake secrets. Must prove that planted secret values never appear in text or JSON output, that symlinks aren't followed, that nothing in the fake home changes (compare file list and mtimes before and after), and that each check fires. No real home access, and mock id and sudo.
- `README.md`: short: what it does, one-line run command, sample output with made-up data, what it never does, limits. No personal names, domains or addresses. No emoji headings.
