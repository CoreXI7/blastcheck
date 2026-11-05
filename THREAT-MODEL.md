# Threat model

leasecheck answers one question: what could a program running as me reach with my permissions? This is what it assumes, and where its answers stop.

## What it protects against

An AI coding agent, or any other process started as your user, reading local credentials and using them to act as you. It looks for the common paths to that: root-equivalent groups and a writable Docker socket, passwordless sudo, private SSH keys without a passphrase, an SSH agent socket it can use, saved login stores, credentials in the shell environment, plain-text credentials in MCP server configs, secret-looking files in the home directory, secret files readable by other users, and startup files another user could edit.

It reduces exposure by telling you where access exists and what to change. It does not block anything.

## What it does not protect against

- A remote attacker, or malware running with more access than your user.
- An agent that has already escalated to root or another account.
- Anything outside the chosen home directory and the fixed paths it knows about.
- Credentials held in cloud services, browser profiles, keychains or password managers, and exposure that happens over the network.
- The contents of saved login stores: it reports that they exist, not whether the logins still work.
- Files it skips: over 1 MB, symlinks, skipped directories, deeper than 4 levels, or anything after the 20,000-file or 20-second limit.
- A compromise that has already happened. The report is a snapshot, not a monitor.

## Assumptions

- The scanner runs as the user being assessed, the same account an agent would run as, with that user's environment (including `SSH_AUTH_SOCK`) and file permissions. Pointing `--home` at another account tells you about that account's files, not its environment or group membership.
- The machine is not already compromised while the scan runs.
- `id` and `sudo` are the normal system tools, and `sudo -n -l` does not prompt.
- Linux or macOS. On other platforms it exits 2 without scanning.
- Results are read by the person who ran it. Nothing is sent anywhere.
- Detection uses names and simple value shapes. It does not validate that a credential works.

## Known limits

- **Parent folder swapped for a link mid-scan.** A symlink at the final path is refused when the file is opened, but a parent directory replaced by a symlink between listing and opening can redirect the read. The scan does not hold directory handles to rule this out.
- **Hung network mounts.** Directories on another device are skipped, but that device check cannot detect a mount that hangs. The home directory itself may be a network mount, files directly inside a scanned directory are not device-checked, and the 20-second limit is checked between files rather than during a blocked read.
- **`sudo -n -l` can leave a log entry.** Even though it cannot prompt, the call may appear in the system or sudo logs, so the scan can be visible to an administrator.
- **Name-based detection.** Variables, MCP fields and files are judged by their names plus a simple literal-value check. A credential with an innocent name is missed; a harmless value with a suggestive name may be flagged. Most source code and notes (`.py`, `.js`, `.md`, `.txt` and similar) are skipped on purpose, so a credential written there is not reported.
- **Heuristic severity.** Levels describe how direct the access usually is, not a measured exploit path.
- **Races.** Files and configs can change between being listed and being read. The report shows what was seen, not a guaranteed state.
- **Containers and namespaces.** Group membership and socket checks describe the environment the scanner sees, which may differ from the host.
- **Values are inspected in memory** to decide whether a literal is stored, and key headers and first lines are parsed to detect passphrases. They are not written to the output. If that ever fails, it is a security issue; see SECURITY.md.
