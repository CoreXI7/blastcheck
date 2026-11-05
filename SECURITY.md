# Security policy

## Reporting a problem

Report privately through GitHub security advisories: open the repository's Security tab and choose "Report a vulnerability". Please do not open a public issue for a security problem.

Include the blastcheck version or commit, your operating system and Python version, the command you ran, and the smallest reproduction you can. Redact real credentials; never paste a working secret into a report.

## What counts as a vulnerability

blastcheck is read-only and makes no network connections. Within that, these count:

- Any credential value reaching the output. stdout, stderr and `--json` must never contain a secret, token, password, passphrase or private key material, whether it arrives through a file name, a variable name, an MCP config field, a URL, or an error message. Names and paths are expected; values are not.
- A way to make blastcheck change, create, move or delete anything, or contact the network.
- A symlink or path trick that makes it read a file it says it never opens, such as a saved login store, or read a file's contents outside the home directory beyond the fixed system paths it checks.
- A crash, hang or unbounded memory use caused by a hostile file or config, for example a deeply nested JSON document.
- Output that a hostile file name can make unsafe: control characters that pass through `clean()` and reach the terminal.
- A subprocess other than the fixed `id -nG` and `sudo -n -l`, or a way to make either prompt, use a shell, or run arbitrary commands.
- `--fail-on` reporting success (exit 0) when a finding at or above the requested severity was reported, or when the scan stopped early.

## What does not count

- A missed risk from the name-based detection. False negatives are a known limit; see THREAT-MODEL.md. The tool says it does not prove safety.
- A finding for a harmless file or variable, unless it also exposes a value.
- Problems that require an attacker who already controls the account or the machine.
- Running on a platform other than Linux or macOS; it refuses to scan there.

## Supported versions

The latest revision on the main branch. Fixes are made there.
