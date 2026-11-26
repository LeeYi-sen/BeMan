# BeMan — SSH 安全管理工具箱

[English](README_EN.md) · [官方网站](https://beman.teadan.com/) · [GitHub](https://github.com/LeeYi-sen/BeMan)

BeMan 是轻量级 Linux SSH 白名单管理工具。使用 OpenSSH 自身执行用户/IP 白名单与公钥认证，无需常驻 BeMan 服务、Docker 或第三方 Python 库。

## 1. 安装

适用于 Ubuntu 22.04/24.04 或兼容 Debian（systemd、Python 3.10+、OpenSSH Server）。先配置可用的管理公钥，并保留本地控制台或独立恢复通道。

### 一键安装

复制以下一条命令到 Linux 终端执行（需要 root 或 sudo 权限）：

```bash
wget --https-only --max-redirect=0 -O install.sh https://beman.teadan.com/install.sh && bash install.sh
```

安装器自动检测并安装缺失的系统依赖，已有依赖直接跳过，无需手动执行 apt。初次下载安装器需要系统已有 wget；非 root 用户自动通过 sudo 获取安装权限。首次安装 OpenSSH 可能由系统包管理器启动 SSH 服务；BeMan 不自动应用防护策略或更改已有 SSH 配置。建议先检查安装脚本及可信发布来源。

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
| 7 | 检查更新（发现新版自动升级） |
| 8 | 一键卸载 BeMan（保留 SSH） |
| 0 | 退出 |

快捷命令：

| 命令 | 用途 |
| --- | --- |
| `beman start` | 应用白名单，或从新会话确认 |
| `beman stop` | 撤销 BeMan 的 SSH 规则，恢复原有认证规则 |
| `beman restart` | 重新读取并应用配置 |
| `beman status` | 查看 SSH 防护状态、用户、IP、端口 |
| `beman audit` | 查看 BeMan 操作审计日志 |
| `beman logs` | 读取最近 50 条 SSH 系统日志 |
| `beman check-update` | 检测版本，不安装 |
| `beman update` | 检测并升级 |
| `beman version` | 查看版本号（也支持 `beman --version`） |
| `beman uninstall` | 确认后完整卸载 BeMan，保留系统 SSH 和依赖 |

首次启动或规则改变时，保留旧 SSH 会话，从白名单 IP 以允许用户建立**新的公钥 SSH 连接**，再次执行 start 确认。固定 300 秒未确认则尝试自动回滚。请勿依赖定时器作为唯一恢复途径；确认前不要重启服务器。若新会话无法登录，从原会话或控制台执行 stop。停止不会强制开放其他原本被系统策略禁止的登录，也不会断开已有 SSH 会话。

## 3. 配置

菜单第 5 项可直接修改名单，或编辑 /opt/beman/settings.json。仅两个配置项，每个参数保持单行 value/comment。以下 IP 仅为示例，请替换成服务器实际看到的管理来源 IP。

```json
{
    "allowed_users": {"value": ["root"], "comment": "允许SSH登录的用户列表，必须使用公钥认证。"},
    "allowed_ips": {"value": ["192.168.31.7", "192.168.31.236"], "comment": "允许SSH登录的精确IPv4/IPv6地址，空值忽略。"}
}
```

用户和 IP 按所有组合匹配；不支持 CIDR 网段，公钥认证固定开启。菜单仅支持单独增删用户及 IP，每次成功修改自动保存。SSH 端口自动检测：优先当前 SSH_CONNECTION，其次实际监听、ssh.socket 或标明为配置值的 sshd -T；不修改端口。回滚时间固定 300 秒，不支持手动调整。修改白名单后执行 restart，并在新会话中再次 start。

## 4. 在线升级及旧版迁移

```bash
beman update
```

默认安装、版本检测和在线升级只访问 https://beman.teadan.com ，不要求客户端访问 GitHub 域名。升级通过 HTTPS 获取安装器与 Python 主程序，验证安装器中固定的 SHA256 和 Python/Bash 语法，不允许下载重定向；发布文件尚未同步或校验失败时拒绝升级。打开交互工具箱时只检查本地系统依赖、程序与资源清单、白名单、SSH 服务和策略，不联网检测版本。检测结果按 Enter 后进入菜单。选择第 7 项才检测更新，发现新版立即升级，无需再次确认；升级成功后按 Enter 进入新版工具箱。在本地完整性正常且没有待确认规则时，自动尝试补齐缺失的普通依赖；不会在启动检查时重装 SSH、强制升级 Python 或覆盖未知配置。待确认期间拒绝升级，避免阻断确认。紧急 CLI 命令不访问网络；不安排后台定时升级。信任官方域名及 HTTPS 证书链，SHA256 用于文件完整性校验，不是独立数字签名或防降级机制。旧版本仍依赖 GitHub Raw 或没有在线升级功能时，重新执行安装命令即可切换到新版。

旧版配置自动迁移至两个字段，保留现有用户/IP，移除旧端口及回滚时间参数。旧版嵌套格式原配置备份至 /opt/beman/backups/settings-before-simplification.json。已有 SSH 防护规则不会改变；旧版自有 beman.service 将停用并移除。若旧版存在待确认策略或网络隔离记录，必须先通过旧版确认/停止防护或解除隔离后升级。旧日志与数据卷保持原状，不自动解锁或删除任何数据。

## 5. 安全卸载

输入 `beman` 选择第 8 项，或执行 `sudo beman uninstall`，确认后自动撤销 BeMan SSH 策略、校验 SSH 配置并按需重载 SSH，清理自有回滚单元及旧服务，删除 BeMan 程序、命令链接、配置和自身备份/旧日志。未知文件与目录不会被递归删除；如果规则恢复失败，保留程序和恢复记录以便排查。非交互自动化必须明确指定 `sudo beman uninstall --yes`。

安装器自动安装缺失的依赖，但卸载范围不随依赖安装情况改变。无论 SSH 原先存在还是由 BeMan 安装，卸载一律保留 openssh-server、openssh-client、SSH 公钥、主机密钥、其他 SSH 配置及全部软件包，不执行 apt remove/purge/autoremove。保持当前 SSH 会话，验证新连接成功后再退出；如果需要删除 OpenSSH，必须由管理员在独立控制台上另行评估依赖和远程访问风险。

## 6. 运行结构与安全边界

```text
/opt/beman/
├── beman.py
├── install.sh
├── settings.json
├── manifest.json  # BeMan 资源清单
└── backups/      # SSH策略状态及迁移备份
/usr/local/bin/beman
/etc/ssh/sshd_config.d/00-beman.conf  # 启动后生成
```

只有待确认时才建立临时 systemd 回滚 timer/oneshot 单元，确认或回滚后清理。无需长期运行 BeMan 守护服务。登录日志直接读取 ssh.service 的系统日志。保留 check、confirm、rollback 等兼容与故障排查命令（beman --help）。

BeMan 仅管理标准 Ubuntu/Debian OpenSSH 配置，存在其他 Match、AllowUsers、DenyUsers、AllowGroups、DenyGroups 或非标准 Include 时拒绝应用。不会修改其他防火墙、存储、本地控制台或远程入口。拥有 root 权限的人仍可绕过本机规则。不要提交真实配置、密钥或日志。

启动检查属于本地诊断，不是对 root 篡改的独立证明。系统审计日志与全局运行时安装锁保留；未知文件不删除。v3.0 已在 Ubuntu 24.04 ARM64 上通过实机验收（包括跨重启回滚）；其他系统及架构仍需分别验收。

版本规则：当前版本为 v3.2（内部比较值 3.2），大版本用整数（1、2、3），小版本用整数段（1.1、1.2、1.10）。每次正式发布必须提高版本号，并同步 beman.py 的 VERSION 与 install.sh 的 BEMAN_VERSION；同版本发布文件不可变更。按整数段比较，默认拒绝降级。SHA256 只用于内部文件校验。旧版无数字版本号时可一次性迁移至新版，不需要新增版本文件。

交互菜单自动清屏，用户、IP 与操作区分别使用分割线；操作结果保留至按 Enter 返回。非交互命令不清屏。

发布：GitHub main → https://beman.teadan.com 。更新 beman.py 时必须同步更新 install.sh 内的 PYTHON_SHA256。
