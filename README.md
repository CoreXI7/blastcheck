# leasecheck

Shows what an AI coding agent running as the current user could reach on this computer, and how to reduce it.

It walks your home directory and a few well-known locations, reports common ways an agent could gain more access than you intended, and gives a one-line fix for each finding. It is read-only.

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
```

Python 3.10 or newer, standard library only, one file. Tested on Linux. macOS has not been tested.

## Sample output

Made-up data:

```text
0 critical (0 items), 2 high (2 items), 1 medium (1 item), 3 info (3 items)
Files checked: 1,204. Permission errors skipped: 2. Files over 1 MB skipped: 1.

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

This shows common risks it knows to look for. It doesn't prove you're safe. Nothing left this computer.
```

## What it checks

1. Root-equivalent access: membership in the docker, lxd, lxc or libvirt groups; a writable Docker socket; passwordless sudo (critical for `ALL`, high for a list of commands).
2. SSH: private keys in `~/.ssh` without a passphrase, plus counts of `Host` entries and `known_hosts` lines as "machines these keys may reach". Only Host aliases are shown unless `--show-hosts` is given.
3. Secret-looking files in the home directory up to depth 4: `.env*`, `*.pem`, `*.key`, `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, and files whose assignment names look like secrets.
4. Saved login stores: AWS, GitHub CLI, Docker, Kubernetes, Google Cloud, Azure and git credential files. Existence and permissions only; they are never opened.
5. Installed agents (Claude Code, Codex, OpenCode, Cursor, Aider, Gemini CLI) and risky permission settings: Claude bypass/dangerously settings, OpenCode permission set to allow or missing, Codex `danger-full-access` or `approval_policy = "never"`.
6. Secret files readable by group or others.
7. Writable startup files: `~/.bashrc`, `~/.profile`, `~/.ssh/authorized_keys`.

## What it never does

- Never changes, creates or deletes anything. It only reads, and only writes to stdout.
- Never uses the network: no socket, urllib or http, and no network subprocesses.
- Never reads or prints a secret's value. It matches variable names only, and for private key files reads the first line, plus the start of the second to tell whether a passphrase is set. Key contents are never kept or printed. Unusual names that could hold a credential are hidden.
- Never opens saved login stores; it reports that they exist and their permissions.
- Does not follow symlinks. Files are opened so that a link at the final path is refused, even if it appears mid-scan. A parent folder swapped for a link during the scan is not covered.
- Never runs a shell. The only subprocesses are the fixed commands `id -nG` and `sudo -n -l` (which cannot prompt), with a timeout.
- Never proves a system is safe. It reports common risks it knows how to look for.

## Limits

- Scans only the home directory (or `--home DIR`) and the fixed paths listed above; other locations are not covered.
- Stops cleanly at 20,000 files or 20 seconds and says so in the report, so results can be incomplete.
- Skips files over 1 MB, symlinks, and directories such as `node_modules`, `.git`, caches and virtualenvs.
- Permission errors are skipped and counted, never fatal.
- Secret detection uses names and a simple value check, and skips source code and notes, so it can miss credentials and can flag harmless files.
- Severity is a heuristic, not a measurement of exploitability.

## License

MIT. See [LICENSE](LICENSE).
