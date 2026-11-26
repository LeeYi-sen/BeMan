# BeMan

**Linux SSH access protection and reversible incident response**

[简体中文](README.md) · [GitHub](https://github.com/LeeYi-sen/BeMan) · [Official installer](https://beman.teadan.com/install.sh)

BeMan combines a Bash installer with a standard-library Python program for SSH user/IP allowlisting, successful-authentication auditing, policy rollback, authorized network isolation and dedicated LUKS volume locking. It runs as a systemd service without Docker or third-party Python packages.

> Important: a fresh installation starts auditing only; it does not enforce SSH restrictions automatically. Keep a local console or independent recovery channel available and test on a disposable server first. Syntax, configuration and mocked integration tests have passed. Real Ubuntu/systemd, nftables and LUKS end-to-end acceptance testing is still outstanding.

## Quick start

Run `beman` after installation (or `sudo beman` as a non-root user) to open the colored terminal toolbox. The numbered menu provides start/confirm, stop, restart, status, allowlist editing, security settings, recent logs, advanced tools and update detection/installation. Enter users or IPs separated by spaces or commas; save and restart/confirm to apply SSH changes.

```bash
beman
beman start
beman stop
beman restart
beman status
beman check-update
beman update
```

On initial activation or changed rules, keep the old connection and select start/confirm again in a new allowed SSH session. Specify a command in non-interactive environments. ANSI colors are disabled for NO_COLOR or TERM=dumb.

## 1. Requirements

- Target: Ubuntu 22.04/24.04 or compatible Debian Linux with running systemd.
- Root or sudo privileges, Python 3.10+, OpenSSH Server (`ssh.service`) and preconfigured administrative public keys.
- Bash, wget, CA certificates, coreutils, util-linux and systemd. Network isolation requires nftables; volume locking requires cryptsetup and existing dedicated LUKS volumes; the independent controller requires an SSH client and iproute2.
- Standard SSH Include at `/etc/ssh/sshd_config.d/*.conf`. Existing Match, AllowUsers, DenyUsers, AllowGroups or DenyGroups rules require manual review; BeMan refuses automatic application in these cases.

Example dependencies for Ubuntu/Debian (install optional packages as needed):

```bash
sudo apt update
sudo apt install -y python3 openssh-server openssh-client wget ca-certificates coreutils util-linux
# Optional
sudo apt install -y nftables cryptsetup iproute2
```

## 2. Deployment

### 2.1 Download and install

Download and inspect the installer and its provenance before executing it as root.

```bash
wget --https-only -O install.sh https://beman.teadan.com/install.sh && sudo bash install.sh
```

The installer downloads beman.py from the official domain, checks its pinned SHA256 and syntax, creates or merges settings, registers and starts beman.service. A failed checksum prevents installation of the downloaded program. Protection is disabled by default on fresh installations.

### 2.2 Configure the allowlist

```bash
sudoedit /opt/beman/settings.json
```

Settings use valid JSON with single-line `value + comment` entries and Chinese explanations. Edit only the value fields. The following is a partial example; edit the corresponding entries in the generated file rather than replacing the entire file.

```json
{
    "enabled": {"value": true, "comment": "总防护开关"},
    "authentication": {
        "allowed_users": {"value": ["root"], "comment": "允许SSH登录的用户"},
        "allowed_ips": {"value": ["192.168.31.7", "192.168.31.10", "192.168.31.11"], "comment": "主IP及备用IP"},
        "ssh_port": {"value": 22, "comment": "现有SSH端口"},
        "public_key_only": {"value": true, "comment": "强制公钥认证"}
    }
}
```

Replace example addresses with source IPs actually observed by the server. Empty strings are ignored. Multiple exact IPv4/IPv6 addresses are supported, but CIDR ranges are not. Every listed user can authenticate from every listed IP, subject to public-key authentication. The port setting does not change SSH's listening port. Ensure both primary and backup administrative channels are available.

### 2.3 Start protection

```bash
sudo --preserve-env=SSH_CONNECTION beman start
```

On initial activation or after allowlist changes, keep the existing session open. Establish a **new SSH session** from an allowed device using an allowed user, verify public-key login, and run start again to confirm:

```bash
sudo --preserve-env=SSH_CONNECTION beman start
sudo beman status
```

If not confirmed within 300 seconds by default, a systemd timer attempts to restore the previous SSH policy. Do not rely on rollback as the only recovery channel or reboot before confirmation. If the new session fails, run `sudo beman stop` from the original session or local console. After allowlist changes, run restart and then start from a new session. Root can run beman start/stop/restart/status directly; no manual enabled toggle is needed.

## 3. Installation layout

```text
/opt/beman/
├── beman.py
├── install.sh     # Copy of the installed release installer
├── settings.json
├── backups/       # Policy state, rollback records and operation lock
└── logs/
    └── beman.log  # Authentication audit log, when file logging is enabled

/usr/local/bin/beman                          # Command symlink
/etc/systemd/system/beman.service             # Daemon service
/etc/ssh/sshd_config.d/00-beman.conf           # SSH policy generated after apply
```

## 4. Command reference

Server-side commands require root privileges. Examples use sudo; root can omit it. Preserve SSH_CONNECTION when applying, reloading or confirming policies over SSH.

| Command | Purpose |
| --- | --- |
| `sudo beman status` | Show settings, allowlist, policy and service state |
| `sudo beman check` | Validate settings without applying SSH policy |
| `sudo beman init` | Generate or merge settings, preserving values and updating Chinese comments |
| `sudo --preserve-env=SSH_CONNECTION beman apply` | Apply SSH allowlist and schedule rollback |
| `sudo --preserve-env=SSH_CONNECTION beman reload` | Reapply SSH policy; confirmation in a new session is still required |
| `sudo --preserve-env=SSH_CONNECTION beman confirm` | Confirm pending policy from a new allowed session |
| `sudo beman rollback` | Restore pending policy, or remove BeMan SSH policy if none is pending |
| `sudo beman start` | Apply SSH protection and start the daemon; run again from a new session to confirm |
| `sudo beman stop` | Release isolation, remove all BeMan SSH policies, stop and disable the daemon |
| `sudo beman restart` | Reload settings, apply policy and restart daemon; confirm changed rules in a new session |
| `sudo beman release` | Release BeMan network isolation without unlocking storage |
| `sudo beman isolate --authorized-incident` | Perform authorized, time-limited network isolation |
| `sudo beman lock-storage --authorized-incident` | Normally unmount and close authorized dedicated LUKS volumes |
| `sudo beman respond --authorized-incident` | Run enabled incident-response modules |
| `sudo beman check-update` | Detect official Python and installer changes without modifying the system |
| `sudo beman update` | Verify official release and automatically upgrade both scripts, retaining settings and service state |
| `sudo beman update-pinned` | Update Python using a manually configured trusted SHA256 |
| `sudo beman uninstall` | Release isolation, restore SSH policy and disable service; retain program, settings and logs |

Internal commands `monitor` and `rollback-pending` are used by the service and rollback timer; normally they need not be run manually. See `beman --help` for all arguments.

## 5. Configuration reference

| Field | Default / meaning |
| --- | --- |
| enabled | false; managed by start/stop; editing alone does not remove applied protection |
| authentication.allowed_users | ["root"]; allowed users |
| authentication.allowed_ips | ["192.168.31.7", "", ""]; exact source addresses |
| authentication.ssh_port | 22; existing SSH port |
| authentication.public_key_only | true; must remain true |
| network_isolation.enabled | true; permits authorized isolation |
| network_isolation.preserve_whitelist | true; must remain true |
| network_isolation.auto_release_minutes | 10; 1–60 minutes |
| encrypted_storage.enabled | false; optional |
| encrypted_storage.volumes | []; existing dedicated LUKS mappings and mount points |
| external_controller.enabled | false; configure on a separate controller |
| external_controller.allowed_ips | []; inherit SSH allowlist when empty, otherwise a subset |
| external_controller.server_ip | ""; exact protected server IP |
| external_controller.login_user | "root"; target SSH user |
| external_controller.ssh_key | ""; existing absolute private-key path; empty uses SSH defaults |
| protection.rollback_seconds | 300; 60–900 seconds |
| protection.logging | true; file logging; disabling may still leave system journal messages |
| update.python_url | Populated from download URL on first installation |
| update.sha256 | Populated with trusted checksum on first installation |

## 6. Incident response and independent controller

Network isolation creates a separate nftables table, retaining allowlisted SSH, loopback and necessary IPv6 neighbor discovery traffic. Other network services, including Docker forwarding, may be interrupted. Confirm the SSH policy first and use isolation only for authorized incidents. By default a timer attempts to release it after ten minutes; release can restore networking earlier.

Storage locking is limited to previously configured dedicated LUKS data volumes. It does not format disks, delete data or keys, or force unmounts. Busy volumes or additional mounts may cause refusal; a multi-volume operation can partially succeed. An administrator must manually unlock, mount and restore affected applications using the original procedure.

Run the independent controller on a separate trusted Linux device. Configure its external_controller target, source IPs, user and existing SSH key, and verify the target host key in advance. The protected server must have BeMan installed and allow the controller's source address and user; non-root target users need appropriate non-interactive sudo permissions.

| Controller command | Purpose |
| --- | --- |
| `sudo beman controller status` | Query target status |
| `sudo beman controller release --authorized-incident` | Request authorized release of target isolation |
| `sudo beman controller respond --authorized-incident` | Request authorized combined response |

The controller also supports isolate and lock-storage. The controller-event command is an internal interface for a trusted local root audit integration, not a public API. An independent trusted event source must be supplied separately; BeMan does not automatically provision an external audit pipeline. Its SSH monitor logs successful authentication and allowlist anomalies; ordinary failed logins do not trigger host isolation.

## 7. Updates, logs and recovery

The recommended update method is to download and run the latest installer. Existing configuration values are preserved. Confirm pending SSH changes and release isolation before updating.

```bash
wget --https-only -O install.sh https://beman.teadan.com/install.sh && sudo bash install.sh
sudo beman status
sudo journalctl -u beman.service -n 100 --no-pager
sudo tail -n 100 /opt/beman/logs/beman.log
```

Use `beman check-update` to detect changes or `beman update` (menu item 9) to install an update on demand. The updater compares the official GitHub main raw installer with the Pages installer over HTTPS, verifies the pinned Python SHA256 and Python/Bash syntax, and runs the verified installer. It refuses unsynchronized releases, unavailable downloads, pending policy confirmation or isolation. The installer retains configuration and service activation state and attempts rollback on installation failure. Versions are identified by file SHA256; no manual new digest is required. Reopen the toolbox after updating. No background update schedule is enabled by default. This trusts the official GitHub repository and HTTPS certificate chain; it is not an independent signature or anti-downgrade mechanism.

The legacy manually pinned Python-only update remains available as `beman update-pinned`: set update.python_url and a trusted update.sha256 first. Restart the daemon as appropriate after that operation.

For everyday use, only start, stop, restart and status are needed. Stop restores the original SSH policy and releases BeMan isolation without modifying other firewall or authentication rules; it does not unlock encrypted volumes. Uninstall also stops protection while retaining files. Legacy apply and confirm remain available for compatibility and troubleshooting. Installer upgrades preserve the previous service activation state.

## 8. Publishing and security boundaries

The main branch is published by GitHub Pages at https://beman.teadan.com . Whenever beman.py changes, update PYTHON_SHA256 in install.sh and verify the two published downloads match. Never commit live settings.json, private keys, audit logs or backups to the public repository.

BeMan is not an absolute intrusion-prevention or data-security guarantee. It governs the configured SSH service, not local consoles or other remote entry points. Source IP is not a device identity; an attacker with root privileges can potentially bypass local policies. The external controller still depends on target SSH and does not independently control a switch or out-of-band hardware. Use upstream firewalls, independent backups and out-of-band recovery as complementary controls. SHA256 validation does not replace trust in the installer and release channel themselves.
