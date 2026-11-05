# leasecheck

Shows what an AI coding agent running as the current user could reach on this computer, and how to reduce it.

It checks your home directory, a few well-known locations and your shell environment, reports common ways an agent could gain more access than you intended, and gives a one-line fix for each finding. It is read-only.

## Quick start

```sh
python3 leasecheck.py
```

Options:

```sh
python3 leasecheck.py --json          # same data as JSON
python3 leasecheck.py --all           # every finding separately, not grouped
python3 leasecheck.py --home DIR      # check another home directory
python3 leasecheck.py --show-hosts    # also print HostName addresses from the SSH config
python3 leasecheck.py --fail-on high  # exit 1 if any high or critical finding is reported
```

Python 3.10 or newer, standard library only, one file. Tested on Linux. macOS has not been tested.

## Exit codes

Without `--fail-on` it exits 0. On a platform other than Linux or macOS it exits 2 before scanning.

With `--fail-on critical|high|medium`, the exit code is:

- `1` if any finding is at the chosen severity or worse.
- `2` if no such finding was reported but the scan stopped early (file or time limit), so the result may be incomplete.
- `0` otherwise.

Permission errors and skipped files do not change the exit code.

## Sample output

Made-up data:

```text
0 critical (0 items), 3 high (3 items), 2 medium (2 items), 2 info (2 items)
Files checked: 1,204. Permission errors skipped: 2. Files over 1 MB skipped: 1.

[HIGH] Credential stored in an MCP config (1 item)
  Why: The credential is stored in plain text, where an agent can read it.
  Evidence:
    - ~/.claude.json: server example, API_TOKEN
  Fix: Replace the stored value with an environment reference or a credential helper.

[HIGH] Private SSH key without a passphrase (1 item)
  Why: An agent running as you can read the key and use it to log in to the machines it is authorized for.
  Evidence:
    - ~/.ssh/id_example (RSA PRIVATE KEY; no passphrase detected)
    - known_hosts has 4 entries (machines these keys may reach)
  Fix: Add a passphrase (ssh-keygen -p -f <key>) or replace the key with a short-lived one.

[HIGH] Saved login store present: AWS credentials (1 item)
  Why: An agent could read these saved logins and act as you.
  Evidence:
    - ~/.aws/credentials (file, mode 600)
  Fix: Remove credentials you no longer use, keep permissions at 600, and prefer short-lived tokens.

[MEDIUM] Credentials in your shell environment (1 item)
  Why: Any agent you start inherits these variables and can read the credentials.
  Evidence:
    - environment variables: AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN
  Fix: Remove long-lived credentials from your shell environment; use a credential helper or short-lived tokens instead.

[MEDIUM] Secret-looking file in the home directory (1 item)
  Why: Its contents look like credentials an agent could copy or use.
  Evidence:
    - ~/.env.local (7 lines): API_KEY, DB_PASSWORD
  Fix: Remove it if unused; otherwise keep it outside the home and prefer short-lived credentials.

[INFO] Agent installed: Claude Code (1 item)
  Why: A local coding agent can run with your user permissions.
  Evidence:
    - ~/.claude (directory)
  Fix: Review its permission mode and avoid bypass/dangerous flags.

[INFO] MCP servers an agent can use (1 item)
  Why: Each MCP server gives an agent another tool it can call with your permissions.
  Evidence:
    - ~/.claude.json: 2 server(s): filesystem, example
  Fix: Remove MCP servers you do not use and review what each one can reach.

This shows common risks it knows to look for. It doesn't prove you're safe. Nothing left this computer.
```

## What it checks

1. Root-equivalent access: membership in the docker, lxd, lxc or libvirt groups; a writable Docker socket (`/var/run/docker.sock` and the Docker, OrbStack and Colima sockets under your home); passwordless sudo (critical for `ALL`, a wildcard, or a program that can run others such as a shell, editor, `systemctl` or `docker`; high for other commands).
2. SSH: private keys in `~/.ssh` without a passphrase, plus counts of `Host` entries and `known_hosts` lines as "machines these keys may reach". Only Host aliases are shown unless `--show-hosts` is given. An `SSH_AUTH_SOCK` socket that anything you start could use is reported as high.
3. Secret-looking files in the home directory up to depth 4: `.env*`, `*.pem`, `*.key`, `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, and files whose assignment names look like secrets.
4. Saved login stores: AWS, GitHub CLI, Docker, Kubernetes, Google Cloud, Azure and git credential files. Existence and permissions only; they are never opened.
5. Installed agents (Claude Code, Codex, OpenCode, Cursor, Aider, Gemini CLI) and risky permission settings: Claude bypass/dangerously settings, OpenCode permission set to allow or missing, Codex `danger-full-access` or `approval_policy = "never"`.
6. The shell environment: variables whose names look like secrets and whose values look stored rather than referenced (medium). Variable names are listed, up to 20, and never their values.
7. MCP servers (info) in `~/.claude.json`, `~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.gemini/settings.json` and `~/.config/opencode/opencode.json`, and plain-text credentials stored for them (high): in a server's arguments, a login inside its URL, a URL query parameter, or its `env` or `headers`.
8. Secret files readable by group or others.
9. Startup files (`.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.zprofile`, `.zshenv`, `.zlogin`, `~/.ssh/authorized_keys`): high when group or others can write them, otherwise a note that any agent running as you can edit them.

## What it never does

- Never changes, creates or deletes anything. It only reads, and only writes to stdout or stderr.
- Never uses the network: no socket, urllib or http, and no network subprocesses.
- Never prints a secret's value. To decide whether a value is stored, it inspects environment variables and MCP entries in memory and reports names only. For private key files it reads the first line and, for PEM keys, the start of the second to tell whether a passphrase is set; key material is never kept or printed. Unusual names that could hold a credential are hidden.
- Never opens saved login stores; it reports that they exist and their permissions.
- Does not follow symlinks. Files are opened so that a link at the final path is refused, even if it appears mid-scan. A parent folder swapped for a link during the scan is not covered.
- Never runs a shell. The only subprocesses are the fixed commands `id -nG` and `sudo -n -l` (which cannot prompt), with a timeout.
- Never proves a system is safe. It reports common risks it knows how to look for.

## Limits

- Scans only the home directory (or `--home DIR`) and the fixed paths listed above; other locations are not covered.
- The environment check sees the variables of the process that runs leasecheck, and the MCP check reads only the listed config files.
- Stops cleanly at 20,000 files or 20 seconds and says so in the report, so results can be incomplete.
- Skips files over 1 MB, symlinks, and directories such as `node_modules`, `.git`, caches and virtualenvs.
- Permission errors are skipped and counted, never fatal.
- Secret detection uses names and a simple value check, and skips most source code and notes, so it can miss credentials and can flag harmless files.
- Severity is a heuristic, not a measurement of exploitability.

See SECURITY.md for private reporting and THREAT-MODEL.md for assumptions and known limits.

## License

MIT. See [LICENSE](LICENSE).
