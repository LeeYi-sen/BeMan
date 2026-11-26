# BeMan

**Linux SSH 安全防护与可恢复事件响应工具**

[English](README_EN.md) · [GitHub](https://github.com/LeeYi-sen/BeMan) · [官方安装地址](https://beman.teadan.com/install.sh)

BeMan 使用 Bash 安装程序和 Python 标准库实现 SSH 用户/IP 联合白名单、成功认证审计、配置回滚、授权网络隔离及专用 LUKS 数据卷锁定。安装后通过 systemd 运行，无需 Docker 或第三方 Python 包。

> 重要：首次安装仅启动审计，不自动启用 SSH 限制。请保留本地控制台或其他独立恢复通道，先在测试服务器验证。当前已通过语法、配置和模拟集成测试，尚未完成真实 Ubuntu/systemd、nftables 和 LUKS 的端到端验收。

## 快速使用

安装完成后输入 `beman`（普通用户使用 `sudo beman`），打开彩色终端工具箱。数字菜单支持启停/确认、重启、状态、白名单、安全配置、最近日志、高级工具及检测并自动升级。白名单可直接输入以空格或逗号分隔的用户/IP，保存后按提示重启并确认。

```bash
beman
beman start
beman stop
beman restart
beman status
beman check-update
beman update
```

首次启用或改变规则后，保留旧连接，在新白名单 SSH 会话再次选择启动/确认。非交互环境请指定命令；NO_COLOR 或 TERM=dumb 时不输出 ANSI 配色。

## 1. 环境要求

- 目标系统：Ubuntu 22.04/24.04 或兼容 Debian Linux，正在运行 systemd。
- root 或 sudo 权限；Python 3.10+；OpenSSH Server（`ssh.service`）和预先配置的管理公钥。
- Bash、wget、CA 证书、coreutils、util-linux、systemd；网络隔离需要 nftables，存储锁定需要 cryptsetup 和已存在的专用 LUKS 卷，独立控制端需要 SSH 客户端及 iproute2。
- SSH 使用标准 `/etc/ssh/sshd_config.d/*.conf` Include。已有 Match、AllowUsers、DenyUsers、AllowGroups、DenyGroups 等规则时，程序会拒绝自动应用，需人工审查。

Ubuntu/Debian 依赖安装示例（如需可选功能，安装对应软件包）：

```bash
sudo apt update
sudo apt install -y python3 openssh-server openssh-client wget ca-certificates coreutils util-linux
# 可选
sudo apt install -y nftables cryptsetup iproute2
```

## 2. 部署流程

### 2.1 下载并安装

建议先下载并检查安装脚本内容及来源，再以 root 执行。

```bash
wget --https-only -O install.sh https://beman.teadan.com/install.sh && sudo bash install.sh
```

安装程序从官方域名下载 beman.py，校验脚本内固定的 SHA256，检查语法，生成或合并配置，注册并启动 beman.service。校验失败时不会安装下载的程序。首次安装默认关闭防护总开关。

### 2.2 配置白名单

```bash
sudoedit /opt/beman/settings.json
```

配置文件采用合法 JSON，每个参数均为单行 `value + comment`，只需修改 value。以下为部分字段示例，请修改生成文件中的对应字段，而不是覆盖整个配置文件。

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

示例地址须换成服务器实际看到的 SSH 来源 IP；空字符串会忽略，支持多个精确 IPv4/IPv6 地址，不支持 CIDR 网段。多个用户名与多个 IP 组成所有允许组合，并且仍须通过公钥认证。端口参数不会修改 SSH 监听端口。确认至少一个主用和一个备用管理通道可用。

### 2.3 启动防护

```bash
sudo --preserve-env=SSH_CONNECTION beman start
```

首次启用或白名单变更时，保留原连接，在白名单设备上以允许用户建立**新的 SSH 会话**，验证公钥登录成功后，在新会话再次执行 start 确认：

```bash
sudo --preserve-env=SSH_CONNECTION beman start
sudo beman status
```

默认 300 秒内未确认时，程序通过 systemd 定时任务尝试恢复应用前的 SSH 策略。不要依赖回滚作为唯一恢复途径，不要在确认前重启服务器。若新会话失败，可从原会话或本地控制台执行 `sudo beman stop` 恢复原规则。修改白名单后，执行 restart 并从新会话再次执行 start。root 可直接使用 beman start/stop/restart/status；无须手动修改 enabled。

## 3. 安装结构

```text
/opt/beman/
├── beman.py
├── install.sh     # 已安装版本的安装器副本
├── settings.json
├── backups/       # 策略状态、回滚记录与操作锁
└── logs/
    └── beman.log  # 认证审计日志（启用文件日志时）

/usr/local/bin/beman                          # 命令软链接
/etc/systemd/system/beman.service             # 守护服务
/etc/ssh/sshd_config.d/00-beman.conf           # 应用后生成的 SSH 策略
```

## 4. 命令用法

服务器端命令需要 root 权限。以下以 sudo 为例；root 可直接运行。通过 SSH 执行 apply、reload、confirm 时建议保留 SSH_CONNECTION。

| 命令 | 用途 |
| --- | --- |
| `sudo beman status` | 查看配置开关、白名单、策略和服务状态 |
| `sudo beman check` | 检查配置格式及参数，不应用 SSH 策略 |
| `sudo beman init` | 生成或合并配置，保留已有 value 并更新中文说明 |
| `sudo --preserve-env=SSH_CONNECTION beman apply` | 应用 SSH 白名单并启动回滚定时器 |
| `sudo --preserve-env=SSH_CONNECTION beman reload` | 重新应用 SSH 策略，仍需新会话确认 |
| `sudo --preserve-env=SSH_CONNECTION beman confirm` | 从新的白名单会话确认待生效策略 |
| `sudo beman rollback` | 恢复待确认策略；无待确认时撤销 BeMan SSH 策略 |
| `sudo beman start` | 应用 SSH 防护并启动守护服务；新会话再次 start 确认 |
| `sudo beman stop` | 解除网络隔离、撤销所有 BeMan SSH 策略、停止并禁用守护服务 |
| `sudo beman restart` | 读取并应用配置、重启守护服务；规则变更需新会话确认 |
| `sudo beman release` | 解除 BeMan 网络隔离，不解锁存储 |
| `sudo beman isolate --authorized-incident` | 经授权执行限时网络隔离 |
| `sudo beman lock-storage --authorized-incident` | 经授权正常卸载并关闭专用 LUKS 卷 |
| `sudo beman respond --authorized-incident` | 按已启用模块执行联合响应 |
| `sudo beman check-update` | 检测官方 Python 和安装器版本，不修改系统 |
| `sudo beman update` | 校验官方发布并自动升级两个脚本，保留配置与服务状态 |
| `sudo beman update-pinned` | 使用配置中手工指定的可信 SHA256 更新 Python |
| `sudo beman uninstall` | 解除隔离、恢复 SSH 策略并停用服务，保留程序、配置和日志 |

内部命令 `monitor` 和 `rollback-pending` 由服务及回滚定时器调用，通常无需手动运行。完整参数可用 `beman --help` 查看。

## 5. 配置参数

| 字段 | 默认值 / 说明 |
| --- | --- |
| enabled | false；start/stop 自动维护，单独编辑不会撤销已经应用的防护 |
| authentication.allowed_users | ["root"]；允许用户列表 |
| authentication.allowed_ips | ["192.168.31.7", "", ""]；精确来源 IP 列表 |
| authentication.ssh_port | 22；现有 SSH 端口 |
| authentication.public_key_only | true；必须为 true |
| network_isolation.enabled | true；允许授权隔离 |
| network_isolation.preserve_whitelist | true；必须为 true |
| network_isolation.auto_release_minutes | 10；1–60 分钟 |
| encrypted_storage.enabled | false；按需启用 |
| encrypted_storage.volumes | []；已有专用 LUKS 映射及挂载点列表 |
| external_controller.enabled | false；在独立控制端配置 |
| external_controller.allowed_ips | []；为空继承 SSH 白名单，否则须为其子集 |
| external_controller.server_ip | ""；被保护服务器精确 IP |
| external_controller.login_user | "root"；目标 SSH 用户 |
| external_controller.ssh_key | ""；已有私钥绝对路径，空值使用 SSH 默认密钥 |
| protection.rollback_seconds | 300；60–900 秒 |
| protection.logging | true；启用文件日志，关闭后仍可能写入系统日志 |
| update.python_url | 首次安装自动填写下载地址 |
| update.sha256 | 首次安装自动填写可信校验值 |

## 6. 安全响应与独立控制端

网络隔离会建立独立的 nftables 表，保留白名单 SSH、回环及必要 IPv6 邻居发现流量，其他网络业务可能中断（含 Docker 转发）。必须先确认 SSH 策略；只在确有授权的事件中使用。默认十分钟后尝试自动解除，也可使用 release 提前恢复。

存储锁定仅面向事先配置的专用 LUKS 数据卷，不格式化、不删除数据或密钥、不强制卸载。卷正在使用或存在其他挂载时可能拒绝操作；多个卷可能部分成功。恢复需管理员按原有方式手动解锁、挂载及启动相关业务。

独立控制端应部署在另一台可信 Linux 设备上。配置 external_controller 的目标地址、源 IP、用户及已有 SSH 密钥，预先核验目标 SSH 主机密钥。目标服务器必须已安装 BeMan，允许该控制端来源 IP 和用户；非 root 目标用户需配置适当的非交互 sudo 权限。

| 控制端命令 | 用途 |
| --- | --- |
| `sudo beman controller status` | 查询目标服务器状态 |
| `sudo beman controller release --authorized-incident` | 经授权解除目标服务器隔离 |
| `sudo beman controller respond --authorized-incident` | 经授权请求目标执行联合响应 |

controller 还支持 isolate、lock-storage。controller-event 是供可信本地 root 审计程序接入的内部接口，不是公网 API；需要额外提供可信事件源，程序不会自动建立外部审计链路。SSH 守护监控只记录成功认证及异常白名单告警，普通失败登录不会触发整机隔离。

## 7. 更新、日志与恢复

推荐重新下载最新版安装器执行更新，已有配置值会保留。更新前应先确认 SSH 策略并解除网络隔离。

```bash
wget --https-only -O install.sh https://beman.teadan.com/install.sh && sudo bash install.sh
sudo beman status
sudo journalctl -u beman.service -n 100 --no-pager
sudo tail -n 100 /opt/beman/logs/beman.log
```

使用 `beman check-update` 仅检测版本，使用 `beman update` 或菜单第 9 项按需自动升级。升级器通过 HTTPS 比对官方 GitHub main 原始安装器与 Pages 安装器，验证安装器固定的 Python SHA256、Python/Bash 语法，再运行经过校验的安装器。若发布尚未同步、网络不可达、存在待确认策略或隔离，拒绝升级。安装器保留原配置和服务启停状态，安装失败时尝试恢复旧文件。版本以文件 SHA256 标识，不需要手工填写新版哈希。更新后重新进入工具箱。该功能不默认安排后台定时升级；信任官方 GitHub 仓库及 HTTPS 证书链，不是独立数字签名或防降级机制。

手动固定哈希的旧式更新仍可通过 `beman update-pinned` 使用：先设置 update.python_url 和可信 update.sha256。该操作仅替换 Python，更新后按需重新启动守护服务。

日常仅需 start、stop、restart、status 四个命令。stop 恢复原 SSH 规则并解除 BeMan 网络隔离，但不改变其他防火墙或认证规则，也不会自动解锁加密卷。uninstall 同样停用防护并保留文件。旧版 apply、confirm 等命令仍保留用于兼容和故障排查。升级安装保留原服务启停状态。

## 8. 发布维护与安全边界

仓库 main 分支由 GitHub Pages 发布至 https://beman.teadan.com 。发布新版 beman.py 时必须同步更新 install.sh 中的 PYTHON_SHA256，并验证两个公开下载文件一致。实际 settings.json、密钥、审计日志和备份不得提交到公开仓库。

BeMan 不是防入侵或数据安全的绝对保证：只约束配置范围内的 SSH 服务，不控制本地控制台及其他远程入口。来源 IP 不等同于设备身份；已取得 root 的攻击者可能绕过本机策略。外部控制端仍依赖目标服务器 SSH，不是独立交换机或带外硬件隔离。建议配合上游防火墙、独立备份和带外恢复通道使用。SHA256 校验也不能代替对安装脚本及发布渠道本身的信任验证。
