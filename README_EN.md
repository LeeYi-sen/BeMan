# BeMan — SSH Security Toolbox

[简体中文](README.md) · [GitHub](https://github.com/LeeYi-sen/BeMan)

BeMan is a lightweight Linux SSH allowlist manager. OpenSSH enforces user/IP allowlisting and public-key authentication directly. No resident BeMan daemon, Docker or third-party Python package is required.

## 1. Installation

Target: Ubuntu 22.04/24.04 or compatible Debian with systemd, Python 3.10+ and OpenSSH Server. Configure working administrative public keys and keep a console or independent recovery channel available.

```bash
sudo apt update
sudo apt install -y python3 openssh-server wget ca-certificates coreutils util-linux
wget --https-only -O install.sh https://beman.teadan.com/install.sh && sudo bash install.sh
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
| 7 | Detect and install updates |
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

For initial activation or changed rules, keep the old session open. Establish a **new public-key SSH session** from an allowed IP using an allowed user, and run start again to confirm. The default 300-second timeout attempts rollback if not confirmed. Do not rely on the timer as your only recovery channel or reboot before confirmation. If login fails, run stop from the old session or local console. Stopping does not override other system access restrictions or disconnect existing SSH sessions.

## 3. Configuration

Use menu item 5 or edit /opt/beman/settings.json. There are only four fields, each on one line with value/comment. The addresses below are examples; replace them with the administrative source addresses actually observed by the server.

```json
{
    "allowed_users": {"value": ["root"], "comment": "允许SSH登录的用户列表，必须使用公钥认证。"},
    "allowed_ips": {"value": ["192.168.31.7", "192.168.31.236"], "comment": "允许SSH登录的精确IPv4/IPv6地址，空值忽略。"},
    "ssh_port": {"value": 22, "comment": "现有SSH端口，不改变监听端口。"},
    "rollback_seconds": {"value": 300, "comment": "新策略未确认时自动回滚的秒数，60至900。"}
}
```

Every listed user can authenticate from every listed IP, subject to public-key authentication. CIDR ranges are not supported. The port is validated, not changed. After editing, run restart and confirm with start in a new session.

## 4. Online updates and migration

```bash
beman update
```

The updater compares the raw installer in GitHub main with the Pages installer via HTTPS, checks the pinned Python SHA256 and syntax, then executes the verified installer. No background update schedule is configured. This trusts the repository and HTTPS certificate chain, not an independent signature or anti-downgrade mechanism. For older versions without online updates, rerun the installation command.

Legacy settings migrate to four fields, preserving users, IPs, port and rollback time. The original settings are backed up at /opt/beman/backups/settings-before-simplification.json. Existing SSH policy is retained; the old owned beman.service is disabled and removed. If a legacy policy is pending or isolation is recorded, confirm/stop protection or release isolation using the old version before upgrading. Legacy logs and data volumes remain untouched; no data is deleted or automatically unlocked.

## 5. Layout and security boundaries

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

Publishing: GitHub main → https://beman.teadan.com . When beman.py changes, update PYTHON_SHA256 in install.sh.
