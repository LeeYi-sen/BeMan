# BeMan — SSH Security Toolbox

[简体中文](README.md) · [GitHub](https://github.com/LeeYi-sen/BeMan)

BeMan is a lightweight Linux SSH allowlist manager. OpenSSH enforces user/IP allowlisting and public-key authentication directly. No resident BeMan daemon, Docker or third-party Python package is required.

## 1. Installation

Target: Ubuntu 22.04/24.04 or compatible Debian with systemd, Python 3.10+ and OpenSSH Server. Configure working administrative public keys and keep a console or independent recovery channel available.

```bash
sudo apt update
sudo apt install -y python3 openssh-server wget ca-certificates coreutils util-linux
wget --https-only --max-redirect=0 -O install.sh https://beman.teadan.com/install.sh && sudo bash install.sh
```

Installation downloads and verifies the program and prepares settings; it does not automatically change SSH policy. Inspect the installer and its trusted source before execution.

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
| 6 | View login logs |
| 7 | Uninstall BeMan (keep SSH) |
| 0 | Exit |

Shortcut commands:

| Command | Purpose |
| --- | --- |
| `beman start` | Apply allowlist or confirm from a new session |
| `beman stop` | Remove BeMan SSH policy and restore original authentication rules |
| `beman restart` | Reread and apply settings |
| `beman status` | Display protection, allowed users, IPs and port |
| `beman logs` | Read the last 50 SSH journal entries |
| `beman check-update` | Detect versions without installing |
| `beman update` | Detect and install updates |
| `beman version` | Show version (also `beman --version`) |
| `beman uninstall` | Confirm and uninstall BeMan, preserving system SSH and dependencies |

For initial activation or changed rules, keep the old session open. Establish a **new public-key SSH session** from an allowed IP using an allowed user, and run start again to confirm. The fixed 300-second timeout attempts rollback if not confirmed. Do not rely on the timer as your only recovery channel or reboot before confirmation. If login fails, run stop from the old session or local console. Stopping does not override other system access restrictions or disconnect existing SSH sessions.

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

Default installation, version checks and online updates access only https://beman.teadan.com ; clients do not need access to GitHub domains. Updates fetch the installer and Python program over HTTPS, check the installer's pinned SHA256 and Python/Bash syntax, and reject download redirects. Unsynchronized or mismatched release files are rejected. Opening the interactive toolbox automatically checks and installs updates, reopening the new version after success. If already current, the menu opens directly; if an update fails, the installed version continues. Pending confirmation skips automatic updates; emergency CLI commands never access the network. No background update schedule is configured. This trusts the official domain and HTTPS certificate chain; SHA256 checks integrity, not an independent signature or anti-downgrade mechanism. For older versions that still require GitHub Raw or lack online updates, rerun the installation command to migrate.

Legacy settings migrate to two fields, preserving users and IPs and dropping manual port and rollback-time settings. Original nested-format legacy settings are backed up at /opt/beman/backups/settings-before-simplification.json. Existing SSH policy is retained; the old owned beman.service is disabled and removed. If a legacy policy is pending or isolation is recorded, confirm/stop protection or release isolation using the old version before upgrading. Legacy logs and data volumes remain untouched; no data is deleted or automatically unlocked.

## 5. Safe uninstall

Select item 7 in `beman` or run `sudo beman uninstall`. After confirmation, the tool removes its managed SSH policy, validates the SSH configuration and reloads SSH as needed, cleans up owned rollback units and legacy service, and removes BeMan executables, command link, settings, own backups and legacy log. Unknown files are not recursively removed. If policy recovery fails, the program and recovery records are retained for troubleshooting. Non-interactive automation requires explicit `sudo beman uninstall --yes`.

The installer checks that OpenSSH exists; it does not install packages via apt. The apt command in this README is run by the administrator. Regardless of whether SSH was already installed or installed specifically for BeMan, uninstall preserves openssh-server, openssh-client, authorized keys, host keys, all other SSH configuration and all system packages. It never runs apt remove/purge/autoremove. Keep the current SSH session open and verify a new connection before exiting. Any decision to remove OpenSSH must be made separately by an administrator with independent console access, after assessing dependencies and remote-access risks.

## 6. Layout and security boundaries

```text
/opt/beman/
├── beman.py
├── install.sh
├── settings.json
└── backups/      # SSH policy state and migration backup
/usr/local/bin/beman
/etc/ssh/sshd_config.d/00-beman.conf  # Created on start
```

Temporary systemd rollback timer/oneshot units exist only while confirmation is pending and are removed after confirmation or rollback. There is no resident BeMan daemon. Login logs come directly from the ssh.service journal. Legacy diagnostic commands check, confirm and rollback remain available (beman --help).

BeMan manages standard Ubuntu/Debian OpenSSH configurations. Existing Match, AllowUsers, DenyUsers, AllowGroups, DenyGroups or nonstandard Include rules require manual review. Other firewalls, storage, local consoles and remote entry points remain untouched. Root access can bypass local rules. Never commit live settings, keys or logs.

The new version has isolated mock tests; real Ubuntu/systemd acceptance, including rollback across reboot, is still outstanding.

Versioning: the current release is 1.1. Major versions are integers (1, 2, 3); minor versions use integer components (1.1, 1.2, 1.10). Increment the version for every release, keeping VERSION in beman.py and BEMAN_VERSION in install.sh identical. Release contents are immutable for a given version. Compare integer components and reject downgrades by default. SHA256 is internal integrity metadata. Legacy installations without a numeric version can migrate once; no extra version file is needed.

Publishing: GitHub main → https://beman.teadan.com . When beman.py changes, update PYTHON_SHA256 in install.sh.
