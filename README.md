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
| 6 | 日志管理 |
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
| `beman stranger` | 巡检非白名单登录，并按固定参数执行一次 `ls` 记录现场 |
| `beman stranger-hook-on` | 启用自动 `ls`：非白名单登录时触发 |
| `beman stranger-hook-off` | 停止自动 `ls` 并删除钩子 |
| `beman stranger-hook-status` | 查看自动 `ls` 状态与白名单快照 |
| `beman check-update` | 检测版本，不安装 |
| `beman update` | 检测并升级 |
| `beman version` | 查看版本号（也支持 `beman --version`） |
| `beman uninstall` | 确认后完整卸载 BeMan，保留系统 SSH 和依赖 |

首次启动或规则改变时，保留旧 SSH 会话，从白名单 IP 以允许用户建立**新的公钥 SSH 连接**，再次执行 start 确认。固定 300 秒未确认则尝试自动回滚。请勿依赖定时器作为唯一恢复途径；确认前不要重启服务器。若新会话无法登录，从原会话或控制台执行 stop。停止不会强制开放其他原本被系统策略禁止的登录，也不会断开已有 SSH 会话。

### 陌生登录巡检（第 7 项）

仅读取最近 200 条成功登录记录，与 `settings.json` 的用户白名单和 IP 白名单比对。命中非白名单的会话会列出时间、用户、来源 IP、认证方式和判定原因，并对该用户在个人主目录执行一次固定参数 `ls -la`（不经 shell、目录取自 `pwd` 记录），输出最多 40 行，供管理员核对现场。

该操作只读：不改变会话权限，不向任何终端写入内容，不删除或截断日志，也不会阻止对方继续操作。判定依赖精确 IP 比对，网络出口变化（如更换宽带、运营商 NAT、IPv6 前缀轮换）会产生误报，需人工确认。`ls` 只能反映目录条目名称与属性，无法说明登录者做过什么；要还原行为应使用 `beman logs`、`beman audit` 与系统审计工具。

### 自动 ls（可选，默认关闭）

`sudo beman stranger-hook-on` 会在 `/etc/profile.d/beman-stranger.sh` 写入一个托管脚本，并生成 `/opt/beman/whitelist.txt`（0644，仅含用户名与 IP，不含密钥）。非白名单 SSH 登录时，该脚本先在该用户自己的终端回显一行 `user@host:~$ ls`，再执行一次 `ls -la $HOME`（最多 40 行），并写入一条 `authpriv.notice` 系统日志，标签 `beman-stranger`。回显只为还原“有人输入了命令”的画面，提示符按 `用户@主机:~` 拼接，与对方自定义的 `PS1` 可能不完全一致；不需要回显时用 `beman stranger-hook-off` 关闭整个功能。

设计边界：不修改 PAM 和 sshd 规则，因此不会造成登录锁死；脚本整体在子 shell 中执行，任何异常都不影响会话；仅在交互式 SSH 登录时触发，非 SSH 会话与自动化任务不触发。白名单快照在 `beman start` 和白名单保存时刷新，可用 `beman stranger-hook-status` 检查是否过期。

局限：输出显示在对方终端，等于告知对方已被识别，可能促使其立即转向其他目标或清理现场；`ls` 不限制权限、不断开会话、不隐藏任何内容。若目标是阻断而非提示，应使用出站收敛与凭据隔离，而不是本功能。

### 日志管理（第 6 项）

| 子菜单 | 功能 |
| --- | --- |
| 1 | SSH 登录分类统计（脱敏） |
| 2 | BeMan 审计分类统计（脱敏） |
| 3 | 确认后查看原始 SSH 及 BeMan 日志 |
| 4 | 日志权限、容量与保留状态（只读） |
| 5 | 加密导出脱敏统计 |
| 6 | 一键清理 BeMan 程序缓存 |
| 0 | 返回主菜单 |

统计各读取最近最多 50 条日志，仅输出固定类别与计数，不输出原始消息、时间、用户名、来源 IP、UID 或密钥指纹；未识别的记录计入其他，不能代替完整审计。原始日志及 `beman logs`、`beman audit` 继续保留，管理功能需要 root。新增 `beman log-summary-ssh`、`beman log-summary-audit`、`beman log-status` 命令。

权限检查显示典型日志路径的权限及相关组的显式成员数量，不包含完整 ACL 或其他授权；容量与配置报告不保证运行时有效保留期限。不修改系统日志权限、保留配置或日志内容。日志保留由管理员依据审计及合规要求统一管理。

加密导出只保存统计摘要，依赖已安装的 GnuPG（不自动安装），通过其口令提示使用 AES256 对称加密。用户选择 root 所有且组/其他用户不可写目录中的新绝对 `.gpg` 路径，文件权限为 0600；拒绝覆盖已有文件。归档由用户独立保管，卸载不删除。原始 SSH 登录、系统日志及安全审计完整保留，不提供登录记录擦除功能。

#### 程序缓存维护

选择日志管理子菜单第 6 项，或运行 `sudo beman clean-cache`。仅检查 BeMan 安装目录中的可再生 Python 字节码缓存，显示文件数及大小，确认后清理。不会扫描个人目录、删除日志、登录历史、命令历史、配置、备份或 SSH 状态；未知文件保持不变。异常文件类型或权限会阻止清理，操作仍写入系统审计日志。字节码可由 Python 重新生成，通常占用空间很小，也可能没有可清理文件。

### SSH 公钥登录

BeMan 防护启用并确认后，新的 SSH 登录必须同时满足以下条件：

- 登录用户名在用户白名单 `allowed_users` 中。
- 服务器实际看到的客户端来源 IP 在 IP 白名单 `allowed_ips` 中。
- 客户端持有与目标用户授权公钥匹配的私钥，且满足系统其余 SSH 认证及访问限制。

| 用户在白名单 | IP 在白名单 | 认证方式 | BeMan 防护结果 |
| --- | --- | --- | --- |
| 是 | 是 | 有效公钥认证 | 允许（仍须满足系统其他限制） |
| 是 | 是 | 密码或键盘交互认证 | 拒绝 |
| 是 | 否 | 有效公钥认证 | 拒绝 |
| 否 | 是 | 有效公钥认证 | 拒绝 |

服务器应事先通过 OpenSSH 配置目标用户的授权公钥（通常为 `~/.ssh/authorized_keys`）。私钥保留在客户端，不上传到服务器。BeMan 不生成或管理用户密钥，也不要求额外的 BeMan 登录密码。

在客户端执行（将示例地址替换为实际服务器地址）：

```bash
ssh root@192.0.2.10
```

如需指定私钥：

```bash
ssh -i ~/.ssh/id_ed25519 root@192.0.2.10
```

如使用非默认 SSH 端口，请添加 `-p 端口号`。私钥设有口令时，SSH 客户端仍可能提示解锁私钥。白名单 IP 指的是客户端来源地址，而不是上述命令中的服务器地址。首次启用或修改规则后，请保留原会话，并在新公钥 SSH 会话中执行 `beman start` 确认防护。

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

默认安装、版本检测和在线升级只访问 https://beman.teadan.com ，不要求客户端访问 GitHub 域名。升级通过 HTTPS 获取安装器与 Python 主程序，验证安装器中固定的 SHA256 和 Python/Bash 语法，不允许下载重定向；发布文件尚未同步或校验失败时拒绝升级。打开交互工具箱时只检查本地系统依赖、程序与资源清单、白名单、SSH 服务和策略，不联网检测版本。检测结果按 Enter 后进入菜单。选择第 8 项才检测更新，发现新版立即升级，无需再次确认；升级成功后按 Enter 进入新版工具箱。在本地完整性正常且没有待确认规则时，自动尝试补齐缺失的普通依赖；不会在启动检查时重装 SSH、强制升级 Python 或覆盖未知配置。待确认期间拒绝升级，避免阻断确认。紧急 CLI 命令不访问网络；不安排后台定时升级。信任官方域名及 HTTPS 证书链，SHA256 用于文件完整性校验，不是独立数字签名或防降级机制。旧版本仍依赖 GitHub Raw 或没有在线升级功能时，重新执行安装命令即可切换到新版。

旧版配置自动迁移至两个字段，保留现有用户/IP，移除旧端口及回滚时间参数。旧版嵌套格式原配置备份至 /opt/beman/backups/settings-before-simplification.json。已有 SSH 防护规则不会改变；旧版自有 beman.service 将停用并移除。若旧版存在待确认策略或网络隔离记录，必须先通过旧版确认/停止防护或解除隔离后升级。旧日志与数据卷保持原状，不自动解锁或删除任何数据。

## 5. 安全卸载

输入 `beman` 选择第 9 项，或执行 `sudo beman uninstall`，确认后自动撤销 BeMan SSH 策略、校验 SSH 配置并按需重载 SSH，清理自有回滚单元及旧服务，删除 BeMan 程序、命令链接、配置和自身备份/旧日志。未知文件与目录不会被递归删除；如果规则恢复失败，保留程序和恢复记录以便排查。非交互自动化必须明确指定 `sudo beman uninstall --yes`。

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

版本规则：当前版本为 v3.4（内部比较值 3.4），大版本用整数（1、2、3），小版本用整数段（1.1、1.2、1.10）。每次正式发布必须提高版本号，并同步 beman.py 的 VERSION 与 install.sh 的 BEMAN_VERSION；同版本发布文件不可变更。按整数段比较，默认拒绝降级。SHA256 只用于内部文件校验。旧版无数字版本号时可一次性迁移至新版，不需要新增版本文件。

交互菜单自动清屏，用户、IP 与操作区分别使用分割线；操作结果保留至按 Enter 返回。非交互命令不清屏。

发布：GitHub main → https://beman.teadan.com 。更新 beman.py 时必须同步更新 install.sh 内的 PYTHON_SHA256。
