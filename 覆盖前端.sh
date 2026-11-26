#!/bin/bash
# macOS / Linux；单向同步，成功后在远端更新 Docker Compose。
set -euo pipefail

# ================= 修改这里 =================
# 粘贴脚本1生成的 ssh 别名命令；也支持 ssh root@192.168.31.193 或 ssh -p 2222 root@192.168.31.193
SSH_LOGIN="ssh srv-root-192.168.31.193-22-bf57ae49f5e4"
LOCAL_DIR="$HOME/MyCode/GPT控制中/VideoHub_Distributed_v2.1/VideoHub/"
REMOTE_DIR="/opt/docker/VideoHub/VideoHub/"

# false：仅覆盖和新增，保留远程额外文件；true：删除远程额外文件（需确认）
DELETE_REMOTE_EXTRA=false
# true：仅预览，不写入远程目录
DRY_RUN=${DRY_RUN:-false}
# false 仅同步，true 同步后自动部署。
AUTO_DEPLOY=true
# 默认保护运行数据；如需同步某项，从列表中删除对应规则。
EXCLUDE=(
    '.env'
    '.env.*'
    '.git/'
    'data/'
    'backups/'
    'logs/'
    '__pycache__/'
    'node_modules/'
    '.venv/'
    '.DS_Store'
    '*.db'
    '*.db-wal'
    '*.db-shm'
    '*.sqlite'
    '*.sqlite3'
)
# ============================================

fail(){ printf '错误：%s\n' "$*" >&2; exit 1; }
for cmd in ssh rsync; do command -v "$cmd" >/dev/null || fail "缺少 $cmd"; done
# 优先 Homebrew rsync，兼容 macOS openrsync。
RSYNC=$(command -v rsync)
for candidate in /opt/homebrew/bin/rsync /usr/local/bin/rsync; do
    if [[ -x "$candidate" ]]; then RSYNC="$candidate"; break; fi
done
rsync_help=$("$RSYNC" --help 2>&1) || fail '无法运行 rsync'
[[ "$rsync_help" == *--rsync-path* && "$rsync_help" == *--partial-dir* ]] || fail 'rsync 缺少必要参数'
[[ "$AUTO_DEPLOY" == true || "$AUTO_DEPLOY" == false ]] || fail 'AUTO_DEPLOY 只能是 true 或 false'
[[ "$DELETE_REMOTE_EXTRA" == true || "$DELETE_REMOTE_EXTRA" == false ]] || fail 'DELETE_REMOTE_EXTRA 只能是 true 或 false'
[[ "$DRY_RUN" == true || "$DRY_RUN" == false ]] || fail 'DRY_RUN 只能是 true 或 false'
[[ -d "$LOCAL_DIR" ]] || fail "本地目录不存在：$LOCAL_DIR"
LOCAL_DIR=$(cd -- "$LOCAL_DIR" && pwd -P) || fail '本地目录无法访问'
[[ "$LOCAL_DIR" != / ]] || fail '禁止同步本地根目录'
[[ "$REMOTE_DIR" == /* && "$REMOTE_DIR" != *$'\n'* && "$REMOTE_DIR" != *$'\r'* ]] || fail '远程目录必须是绝对路径且不能含换行'
while [[ "$REMOTE_DIR" == */ && "$REMOTE_DIR" != / ]]; do REMOTE_DIR=${REMOTE_DIR%/}; done
[[ "$REMOTE_DIR" != / && "$REMOTE_DIR" != *//* && "$REMOTE_DIR/" != */../* && "$REMOTE_DIR/" != */./* ]] || fail '禁止根目录、重复斜杠及 . / .. 路径段'
# 不执行 SSH_LOGIN 字符串（无 eval）；只解析 ssh、目标与标准 -p 端口选项。
read -r -a tokens <<< "$SSH_LOGIN"
[[ ${#tokens[@]} -ge 2 && "${tokens[0]}" == ssh ]] || fail '登录命令格式：ssh 用户@主机 或 ssh -p 端口 用户@主机 或 ssh 别名'
ssh_args=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none -o ControlPersist=no -o ServerAliveInterval=15 -o ServerAliveCountMax=3)
remote_shell='ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none -o ControlPersist=no -o ServerAliveInterval=15 -o ServerAliveCountMax=3'
target=''; port=''; i=1
while (( i < ${#tokens[@]} )); do
    token=${tokens[i]}
    case "$token" in
        -p) i=$((i+1)); (( i < ${#tokens[@]} )) || fail '缺少端口'; [[ -z "$port" ]] || fail '重复端口'; port=${tokens[i]} ;;
        -*) fail "不支持登录命令选项：$token；请使用 SSH 别名" ;;
        *) [[ -z "$target" ]] || fail '登录命令只能包含一个目标'; target=$token ;;
    esac
    i=$((i+1))
done
[[ "$target" =~ ^([A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9:][A-Za-z0-9._:-]*$ ]] || fail 'SSH 主机或别名格式无效'
if [[ -n "$port" ]]; then
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || fail '无效端口'; port=$((10#$port)); (( port>=1 && port<=65535 )) || fail '无效端口'
    ssh_args+=(-p "$port"); remote_shell+=" -p $port"
fi
# rsync 的 IPv6 地址需方括号包裹；SSH 命令本身仍使用原地址。
rsync_target="$target"; host=${target##*@}
if [[ "$host" == *:* ]]; then
    if [[ "$target" == *@* ]]; then rsync_target="${target%@*}@[$host]"; else rsync_target="[$host]"; fi
fi
# POSIX shell 单引号转义，用于远程 mkdir/路径验证；不执行本地配置中的命令。
quote(){ local q=${1//\'/\'\\\'\'}; printf "'%s'" "$q"; }
qdir=$(quote "$REMOTE_DIR")
printf '本地：%s/\n远程：%s:%s/\n删除远程额外文件：%s\n仅预览：%s\n\n' "$LOCAL_DIR" "$target" "$REMOTE_DIR" "$DELETE_REMOTE_EXTRA" "$DRY_RUN"
remote_rsync=$(ssh "${ssh_args[@]}" "$target" 'for f in /opt/homebrew/bin/rsync /usr/local/bin/rsync /usr/bin/rsync; do if test -x "$f"; then printf "%s\n" "$f"; exit 0; fi; done; exit 1') || fail '无法免密连接，或远程缺少 rsync'
case "$remote_rsync" in /opt/homebrew/bin/rsync|/usr/local/bin/rsync|/usr/bin/rsync) ;; *) fail '远程 rsync 路径异常';; esac
# 远程先 cd 到目标目录，再接收至 ./，兼容中文路径及旧版 rsync。
args=(-rlptch --partial-dir=.rsync-partial --stats --itemize-changes -e "$remote_shell" --rsync-path="cd $qdir && test \"\$(pwd -P)\" != / && exec $remote_rsync")
if [[ "$rsync_help" == *--info* ]]; then args+=(--info=progress2); else args+=(--progress); fi
for pattern in "${EXCLUDE[@]}"; do args+=(--exclude="$pattern"); done
if [[ "$DELETE_REMOTE_EXTRA" == true ]]; then args+=(--delete-delay); fi
if [[ "$DRY_RUN" == true ]]; then args+=(--dry-run); fi
# 先确认路径不解析到根目录；预览不创建远程目录。
if [[ "$DRY_RUN" == true ]]; then
    ssh "${ssh_args[@]}" "$target" "test -d $qdir && cd $qdir && test \"\$(pwd -P)\" != /" || fail '预览要求远程目录已存在且不是根目录'
else
    if [[ "$DELETE_REMOTE_EXTRA" == true ]]; then
        printf '危险：将删除远程目标中本地没有的文件（排除项仍保留）。\n'
        read -r -p '输入 DELETE 确认：' confirm; [[ "$confirm" == DELETE ]] || fail '已取消'
    fi
    ssh "${ssh_args[@]}" "$target" "mkdir -p -- $qdir && cd $qdir && test \"\$(pwd -P)\" != /" || fail '远程目录创建或安全检查失败'
fi
if [[ "$DRY_RUN" == false && "$AUTO_DEPLOY" == true ]]; then
    printf '\n检查远程 Docker 环境...\n'
    ssh "${ssh_args[@]}" "$target" 'docker compose version && docker info >/dev/null' || fail '远程 Docker 或 Compose 不可用；未同步源码'
fi
"$RSYNC" "${args[@]}" -- "$LOCAL_DIR/" "$rsync_target:./" || fail '同步失败；未执行 Docker 更新'
if [[ "$DRY_RUN" == true ]]; then
    printf '\n预览完成，未写入远程文件，未部署 Docker。\n'
    exit 0
fi
printf '\n单向覆盖同步完成，本地文件未删除。\n'
if [[ "$AUTO_DEPLOY" == false ]]; then exit 0; fi
printf '\n开始远程 Docker 更新（docker compose）...\n'
ssh "${ssh_args[@]}" "$target" "sh -s -- $qdir" <<'REMOTE_DEPLOY'
set -eu
compose() { docker compose "$@"; }
cd "$1"
test "$(pwd -P)" != /
test -f docker-compose.yml
test -f .env
compose config --quiet
compose up -d --build --force-recreate --wait --wait-timeout 180
compose ps
REMOTE_DEPLOY
printf '\nDocker 更新成功，容器运行检查通过，SSH 已断开。\n'
