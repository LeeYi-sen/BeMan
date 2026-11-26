# BeMan — SSH 安全管理工具箱

[English](README_EN.md) · [GitHub](https://github.com/LeeYi-sen/BeMan)

BeMan 是轻量级 Linux SSH 白名单管理工具。使用 OpenSSH 自身执行用户/IP 白名单与公钥认证，无需常驻 BeMan 服务、Docker 或第三方 Python 库。

## 1. 安装

适用于 Ubuntu 22.04/24.04 或兼容 Debian（systemd、Python 3.10+、OpenSSH Server）。先配置可用的管理公钥，并保留本地控制台或独立恢复通道。

```bash
sudo apt update
sudo apt install -y python3 openssh-server wget ca-certificates coreutils util-linux
wget --https-only -O install.sh https://beman.teadan.com/install.sh && sudo bash install.sh
```

安装仅下载、校验程序和生成配置，不自动修改 SSH 策略。建议先检查安装脚本及可信发布来源。

## 2. 日常使用

```bash
beman
```

普通用户使用 `sudo beman`；通过 sudo 执行启动或确认时需要保留 SSH_CONNECTION，例如 `sudo --preserve-env=SSH_CONNECTION beman`。

| 菜单 | 功能 |
| --- | --- |
| 1 | 启动 / 确认防护 |
| 2 | 停止防护 |
| 3 | 重启防护 |
| 4 | 查看状态 |
| 5 | 白名单管理 |
| 6 | 查看登录日志 |
| 7 | 检测并自动升级 |
| 8 | 一键卸载 BeMan（保留 SSH） |
| 0 | 退出 |

快捷命令：

| 命令 | 用途 |
| --- | --- |
| `beman start` | 应用白名单，或从新会话确认 |
| `beman stop` | 撤销 BeMan 的 SSH 规则，恢复原有认证规则 |
| `beman restart` | 重新读取并应用配置 |
| `beman status` | 查看 SSH 防护状态、用户、IP、端口 |
| `beman logs` | 读取最近 50 条 SSH 系统日志 |
| `beman check-update` | 检测版本，不安装 |
| `beman update` | 检测并升级 |
| `beman uninstall` | 确认后完整卸载 BeMan，保留系统 SSH 和依赖 |

首次启动或规则改变时，保留旧 SSH 会话，从白名单 IP 以允许用户建立**新的公钥 SSH 连接**，再次执行 start 确认。默认 300 秒未确认则尝试自动回滚。请勿依赖定时器作为唯一恢复途径；确认前不要重启服务器。若新会话无法登录，从原会话或控制台执行 stop。停止不会强制开放其他原本被系统策略禁止的登录，也不会断开已有 SSH 会话。

## 3. 配置

菜单第 5 项可直接修改名单，或编辑 /opt/beman/settings.json。仅四个配置项，每个参数保持单行 value/comment。以下 IP 仅为示例，请替换成服务器实际看到的管理来源 IP。

```json
{
    "allowed_users": {"value": ["root"], "comment": "允许SSH登录的用户列表，必须使用公钥认证。"},
    "allowed_ips": {"value": ["192.168.31.7", "192.168.31.236"], "comment": "允许SSH登录的精确IPv4/IPv6地址，空值忽略。"},
    "ssh_port": {"value": 22, "comment": "现有SSH端口，不改变监听端口。"},
    "rollback_seconds": {"value": 300, "comment": "新策略未确认时自动回滚的秒数，60至900。"}
}
```

用户和 IP 按所有组合匹配；不支持 CIDR 网段，公钥认证固定开启。端口仅用于验证，不改变监听端口。修改后执行 restart，并在新会话中再次 start。

## 4. 在线升级及旧版迁移

```bash
beman update
```

升级比对 GitHub main 原始安装器与 Pages 安装器，通过 HTTPS 下载、校验 Python SHA256 与语法后执行安装器。不安排后台定时升级；信任 GitHub 仓库与 HTTPS 证书链，不是独立数字签名或防降级机制。旧版本没有在线升级功能时，重新执行安装命令即可。

旧版配置自动迁移至四个字段；保留现有用户/IP、端口和回滚时间。原配置备份至 /opt/beman/backups/settings-before-simplification.json。已有 SSH 防护规则不会改变；旧版自有 beman.service 将停用并移除。若旧版存在待确认策略或网络隔离记录，必须先通过旧版确认/停止防护或解除隔离后升级。旧日志与数据卷保持原状，不自动解锁或删除任何数据。

## 5. 安全卸载

输入 `beman` 选择第 8 项，或执行 `sudo beman uninstall`，确认后自动撤销 BeMan SSH 策略、校验 SSH 配置并按需重载 SSH，清理自有回滚单元及旧服务，删除 BeMan 程序、命令链接、配置和自身备份/旧日志。未知文件与目录不会被递归删除；如果规则恢复失败，保留程序和恢复记录以便排查。非交互自动化必须明确指定 `sudo beman uninstall --yes`。

安装器只检查 OpenSSH 是否存在，并不通过 apt 安装依赖。README 中的 apt 命令由管理员自行执行；即使重复安装了系统原有的 SSH，也不会改变本工具的卸载范围。无论 SSH 原先存在还是管理员为 BeMan 单独安装，卸载一律保留 openssh-server、openssh-client、SSH 公钥、主机密钥、其他 SSH 配置及全部软件包，不执行 apt remove/purge/autoremove。保持当前 SSH 会话，验证新连接成功后再退出；如果需要删除 OpenSSH，必须由管理员在独立控制台上另行评估依赖和远程访问风险。

## 6. 运行结构与安全边界

```text
/opt/beman/
├── beman.py
├── install.sh
├── settings.json
└── backups/      # SSH策略状态及迁移备份
/usr/local/bin/beman
/etc/ssh/sshd_config.d/00-beman.conf  # 启动后生成
```

只有待确认时才建立临时 systemd 回滚 timer/oneshot 单元，确认或回滚后清理。无需长期运行 BeMan 守护服务。登录日志直接读取 ssh.service 的系统日志。保留 check、confirm、rollback 等兼容与故障排查命令（beman --help）。

BeMan 仅管理标准 Ubuntu/Debian OpenSSH 配置，存在其他 Match、AllowUsers、DenyUsers、AllowGroups、DenyGroups 或非标准 Include 时拒绝应用。不会修改其他防火墙、存储、本地控制台或远程入口。拥有 root 权限的人仍可绕过本机规则。不要提交真实配置、密钥或日志。

当前新版本已进行隔离模拟测试，真实 Ubuntu/systemd（包括跨重启回滚）仍需实机验收。

发布：GitHub main → https://beman.teadan.com 。更新 beman.py 时必须同步更新 install.sh 内的 PYTHON_SHA256。
