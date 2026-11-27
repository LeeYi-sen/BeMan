# BeMan — SSH Security Toolbox

[简体中文](README.md) · [Official website](https://beman.teadan.com/) · [GitHub](https://github.com/LeeYi-sen/BeMan)

BeMan is a lightweight Linux SSH allowlist manager. OpenSSH enforces user/IP allowlisting and public-key authentication directly. No resident BeMan daemon, Docker or third-party Python package is required.

## 1. Installation

Target: Ubuntu 22.04/24.04 or compatible Debian with systemd, Python 3.10+ and OpenSSH Server. Configure working administrative public keys and keep a console or independent recovery channel available.

### One-command installation

Copy and run this single command in a Linux terminal (root or sudo privileges required):

```bash
wget --https-only --max-redirect=0 -O install.sh https://beman.teadan.com/install.sh && bash install.sh
```

The installer detects and installs missing system dependencies automatically, skipping those already available. The initial download requires wget; non-root users automatically use sudo. The system package manager may start SSH when installing OpenSSH for the first time. BeMan does not automatically activate protection or change existing SSH configuration. Inspect the installer and its trusted source before execution.

## 2. Daily use

```bash
beman
```

Non-root users can run `sudo beman`. Preserve SSH_CONNECTION when starting or confirming over sudo, for example `sudo --preserve-env=SSH_CONNECTION beman`.

| Menu | Function |
| --- | --- |
| 1 | Start / confirm protection |
| 2 | Stop protection |
| 3 | Restart protection |
| 4 | Show status |
| 5 | Manage allowlist |
| 6 | Log management |
| 7 | Check for updates (install newer releases automatically) |
| 8 | Uninstall BeMan (keep SSH) |
| 0 | Exit |

Shortcut commands:

| Command | Purpose |
| --- | --- |
| `beman start` | Apply allowlist or confirm from a new session |
| `beman stop` | Remove BeMan SSH policy and restore original authentication rules |
| `beman restart` | Reread and apply settings |
| `beman status` | Display protection, allowed users, IPs and port |
| `beman audit` | Show BeMan operation audit records |
| `beman logs` | Read the last 50 SSH journal entries |
| `beman check-update` | Detect versions without installing |
| `beman update` | Detect and install updates |
| `beman version` | Show version (also `beman --version`) |
| `beman uninstall` | Confirm and uninstall BeMan, preserving system SSH and dependencies |

For initial activation or changed rules, keep the old session open. Establish a **new public-key SSH session** from an allowed IP using an allowed user, and run start again to confirm. The fixed 300-second timeout attempts rollback if not confirmed. Do not rely on the timer as your only recovery channel or reboot before confirmation. If login fails, run stop from the old session or local console. Stopping does not override other system access restrictions or disconnect existing SSH sessions.

### Log management (item 6)

| Submenu | Function |
| --- | --- |
| 1 | SSH login counts (redacted) |
| 2 | BeMan audit counts (redacted) |
| 3 | View original SSH and BeMan logs after confirmation |
| 4 | Log access, storage and retention status (read-only) |
| 5 | Export encrypted redacted counts |
| 6 | Clean BeMan program cache |
| 0 | Return to main menu |

Each summary reads at most the latest 50 records and emits fixed categories and counts only, without raw messages, timestamps, user names, source IPs, UIDs or key fingerprints. Unrecognized entries are counted as other; summaries are not substitutes for full audit records. The original logs, `beman logs` and `beman audit` remain available. Root is required. Additional commands: `beman log-summary-ssh`, `beman log-summary-audit`, `beman log-status`.

The access report shows common log-path modes and explicit group member counts, not all ACLs or other grants. The storage and configuration report does not establish effective runtime retention. No log permissions, retention configuration or records are modified. Administrators manage retention according to their audit and compliance requirements.

Encrypted export contains summary counts only and uses an existing GnuPG installation (not installed automatically), with AES256 symmetric encryption and its passphrase prompt. Choose a new absolute `.gpg` path in a root-owned directory not writable by group or others. The archive has mode 0600; existing files are not overwritten. Administrators keep these independent archives; uninstall does not delete them. Original SSH login records, system logs and security audit records remain intact. Login-record erasure is not provided.

#### Program cache maintenance

Select log-management item 6 or run `sudo beman clean-cache`. The tool checks only reproducible Python bytecode cache in the BeMan installation, previews file count and size, and requests confirmation. Personal directories, logs, login and command history, configuration, backups, and SSH state are untouched. Unknown files are retained. Unexpected file types or permissions block cleanup, and the operation remains auditable. Python can regenerate bytecode; the cache is typically small or absent.

### SSH public-key login

Once BeMan protection is enabled and confirmed, new SSH logins must satisfy all of the following:

- The login user is listed in `allowed_users`.
- The client source IP as seen by the server is listed in `allowed_ips`.
- The client holds a private key matching a public key authorized for the target user, and satisfies all remaining system SSH authentication and access restrictions.

| Allowed user | Allowed IP | Authentication | BeMan policy result |
| --- | --- | --- | --- |
| Yes | Yes | Valid public-key authentication | Allowed, subject to other system restrictions |
| Yes | Yes | Password or keyboard-interactive authentication | Denied |
| Yes | No | Valid public-key authentication | Denied |
| No | Yes | Valid public-key authentication | Denied |

Configure the target user's authorized public key in OpenSSH beforehand (typically in `~/.ssh/authorized_keys`). Keep the private key on the client, not on the server. BeMan does not generate or manage user keys and does not require a separate BeMan login password.

Run on the client (replace the example address with your server address):

```bash
ssh root@192.0.2.10
```

To specify a private key:

```bash
ssh -i ~/.ssh/id_ed25519 root@192.0.2.10
```

Use `-p PORT` for a non-default SSH port. A passphrase-protected private key may still prompt for unlocking on the client. The IP allowlist refers to the client source address, not the server destination address in these commands. After initial activation or a rule change, keep the original session open and run `beman start` from a new public-key SSH session to confirm protection.

## 3. Configuration

Use menu item 5 or edit /opt/beman/settings.json. There are only two fields, each on one line with value/comment. The addresses below are examples; replace them with the administrative source addresses actually observed by the server.

```json
{
    "allowed_users": {"value": ["root"], "comment": "允许SSH登录的用户列表，必须使用公钥认证。"},
    "allowed_ips": {"value": ["192.168.31.7", "192.168.31.236"], "comment": "允许SSH登录的精确IPv4/IPv6地址，空值忽略。"}
}
```

Every listed user can authenticate from every listed IP, subject to public-key authentication. CIDR ranges are not supported. The menu adds or removes individual users and IPs, saving each successful change. The SSH port is detected from SSH_CONNECTION, live listeners, ssh.socket, or labeled sshd -T configuration as a fallback; it is never changed. Rollback is fixed at 300 seconds and cannot be configured. After editing, run restart and confirm with start in a new session.

## 4. Online updates and migration

```bash
beman update
```

Default installation, version checks and online updates access only https://beman.teadan.com ; clients do not need access to GitHub domains. Updates fetch the installer and Python program over HTTPS, check the installer's pinned SHA256 and Python/Bash syntax, and reject download redirects. Unsynchronized or mismatched release files are rejected. Opening the interactive toolbox checks local dependencies, program and inventory integrity, allowlists, SSH service and policy, without contacting the release server. Press Enter after the checks to open the menu. Select item 7 to check for updates; a newer release is installed immediately without another confirmation. After success, press Enter to reopen the updated toolbox. When local checks are normal and no rules are pending, startup attempts to repair missing ordinary dependencies. It does not reinstall SSH, force a Python upgrade, or overwrite unknown configurations. Pending confirmation blocks upgrades; emergency CLI commands never access the network. No background update schedule is configured. This trusts the official domain and HTTPS certificate chain; SHA256 checks integrity, not an independent signature or anti-downgrade mechanism. For older versions that still require GitHub Raw or lack online updates, rerun the installation command to migrate.

Legacy settings migrate to two fields, preserving users and IPs and dropping manual port and rollback-time settings. Original nested-format legacy settings are backed up at /opt/beman/backups/settings-before-simplification.json. Existing SSH policy is retained; the old owned beman.service is disabled and removed. If a legacy policy is pending or isolation is recorded, confirm/stop protection or release isolation using the old version before upgrading. Legacy logs and data volumes remain untouched; no data is deleted or automatically unlocked.

## 5. Safe uninstall

Select item 8 in `beman` or run `sudo beman uninstall`. After confirmation, the tool removes its managed SSH policy, validates the SSH configuration and reloads SSH as needed, cleans up owned rollback units and legacy service, and removes BeMan executables, command link, settings, own backups and legacy log. Unknown files are not recursively removed. If policy recovery fails, the program and recovery records are retained for troubleshooting. Non-interactive automation requires explicit `sudo beman uninstall --yes`.

The installer automatically installs missing dependencies, but this does not change the uninstall scope. Regardless of whether SSH was already installed or installed by BeMan, uninstall preserves openssh-server, openssh-client, authorized keys, host keys, all other SSH configuration and all system packages. It never runs apt remove/purge/autoremove. Keep the current SSH session open and verify a new connection before exiting. Any decision to remove OpenSSH must be made separately by an administrator with independent console access, after assessing dependencies and remote-access risks.

## 6. Layout and security boundaries

```text
/opt/beman/
├── beman.py
├── install.sh
├── settings.json
├── manifest.json  # BeMan resource inventory
└── backups/      # SSH policy state and migration backup
/usr/local/bin/beman
/etc/ssh/sshd_config.d/00-beman.conf  # Created on start
```

Temporary systemd rollback timer/oneshot units exist only while confirmation is pending and are removed after confirmation or rollback. There is no resident BeMan daemon. Login logs come directly from the ssh.service journal. Legacy diagnostic commands check, confirm and rollback remain available (beman --help).

BeMan manages standard Ubuntu/Debian OpenSSH configurations. Existing Match, AllowUsers, DenyUsers, AllowGroups, DenyGroups or nonstandard Include rules require manual review. Other firewalls, storage, local consoles and remote entry points remain untouched. Root access can bypass local rules. Never commit live settings, keys or logs.

Startup checks are local diagnostics, not independent proof against root tampering. System audit logs and the global runtime install lock are retained; unknown files are not deleted. v3.0 passed real Ubuntu 24.04 ARM64 acceptance, including rollback across reboot; other systems and architectures require separate validation.

Versioning: the current release is v3.4 (internal comparison value 3.4). Major versions are integers (1, 2, 3); minor versions use integer components (1.1, 1.2, 1.10). Increment the version for every release, keeping VERSION in beman.py and BEMAN_VERSION in install.sh identical. Release contents are immutable for a given version. Compare integer components and reject downgrades by default. SHA256 is internal integrity metadata. Legacy installations without a numeric version can migrate once; no extra version file is needed.

Interactive menus clear the terminal and separate user, IP and action sections. Operation results remain visible until Enter is pressed. Non-interactive commands do not clear the terminal.

Publishing: GitHub main → https://beman.teadan.com . When beman.py changes, update PYTHON_SHA256 in install.sh.
