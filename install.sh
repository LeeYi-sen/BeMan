#!/usr/bin/env bash
# Beman 安装及更新（Ubuntu/Debian systemd）；首次安装不会启用SSH限制。
set -Eeuo pipefail
umask 077

# 官方发布地址；可通过 BEMAN_BASE_URL 或命令行参数覆盖。
BASE_URL="${BEMAN_BASE_URL:-https://beman.teadan.com}"
# 发布新版时更新此处的 SHA256，必须对应随附的 beman.py。
PYTHON_SHA256="97fcc6f911254d072f5e14f5cd3ac1fdaef857e6939a6e53a2987df5e464632f"
ROOT=/opt/beman
UNIT=/etc/systemd/system/beman.service
BIN=/usr/local/bin/beman
RED='' GREEN='' CYAN='' RESET=''
if [[ -t 1 && "${TERM:-}" != dumb && -z "${NO_COLOR+x}" ]]; then RED=$'\033[31m'; GREEN=$'\033[32m'; CYAN=$'\033[36m'; RESET=$'\033[0m'; fi
info(){ printf '%s[INFO]%s %s\n' "$CYAN" "$RESET" "$*"; }
ok(){ printf '%s[ OK ]%s %s\n' "$GREEN" "$RESET" "$*"; }
fail(){ printf '%s[ERR ]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
[[ $EUID == 0 ]] || fail '请使用root或sudo执行'
[[ -d /run/systemd/system ]] || fail '仅支持正在运行的systemd Linux'
for cmd in python3 wget sha256sum systemctl install flock; do command -v "$cmd" >/dev/null || fail "缺少依赖：$cmd"; done
python3 -c 'import sys; assert sys.version_info >= (3,10)' || fail '需要Python 3.10及以上'
[[ -x /usr/sbin/sshd ]] || fail '请先安装openssh-server并配置管理公钥'
# 可使用 bash install.sh https://example.com/beman，或在顶部填写BASE_URL。
BASE_URL="${1:-$BASE_URL}"
BASE_URL=${BASE_URL%/}
[[ "$BASE_URL" == https://* && "$BASE_URL" != *[[:space:]]* && "$BASE_URL" != *\?* && "$BASE_URL" != *\#* ]] || fail '请填写真实HTTPS发布目录：bash install.sh https://你的域名/beman'
[[ "$PYTHON_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail '发布SHA256格式无效'
exec 9>/run/lock/beman-install.lock
flock -x 9
for dir in "$ROOT" "$ROOT/backups" "$ROOT/logs"; do
    [[ ! -L "$dir" ]] || fail "拒绝符号链接目录：$dir"
    install -d -m 0700 -o root -g root "$dir"
done
[[ ! -e "$ROOT/backups/ssh-pending.json" && ! -e "$ROOT/backups/network-owned.json" ]] || fail '存在待确认SSH配置或网络隔离，请先确认/恢复'
for target in "$ROOT/beman.py" "$ROOT/install.sh" "$ROOT/settings.json" "$UNIT"; do [[ ! -L "$target" ]] || fail "拒绝符号链接：$target"; done
if [[ -e "$BIN" || -L "$BIN" ]]; then [[ -L "$BIN" && $(readlink "$BIN") == "$ROOT/beman.py" ]] || fail 'beman命令已被其他程序占用'; fi
if [[ -e "$UNIT" ]]; then grep -Fxq '# Managed by Beman installer' "$UNIT" || fail '同名服务不属于Beman'; fi
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
info '下载并校验Python主程序'
[[ -f "${BASH_SOURCE[0]}" ]] || fail '请先将安装器下载到文件再运行'
cp -- "${BASH_SOURCE[0]}" "$TMP/install.sh"
wget --https-only --timeout=20 --tries=2 -q -O "$TMP/beman.py" "$BASE_URL/beman.py"
printf '%s  %s\n' "$PYTHON_SHA256" "$TMP/beman.py" | sha256sum -c - || fail 'SHA256校验失败，未安装'
python3 -m py_compile "$TMP/beman.py" || fail 'Python语法校验失败'
for pair in "$ROOT/beman.py:python" "$ROOT/install.sh:installer" "$ROOT/settings.json:settings" "$UNIT:unit"; do
    path=${pair%:*}; name=${pair##*:}; if [[ -f "$path" ]]; then cp -p -- "$path" "$TMP/$name.old"; fi
done
was_active=false; was_enabled=false
systemctl is-active --quiet beman.service && was_active=true
systemctl is-enabled --quiet beman.service && was_enabled=true
restore(){
    local rc=$?; trap - ERR; set +e
    echo '安装失败，尝试恢复安装前的Beman程序、配置和服务。' >&2
    systemctl stop beman.service
    for pair in "$ROOT/beman.py:python" "$ROOT/install.sh:installer" "$ROOT/settings.json:settings" "$UNIT:unit"; do
        path=${pair%:*}; name=${pair##*:}
        if [[ -f "$TMP/$name.old" ]]; then cp -p -- "$TMP/$name.old" "$path"; else rm -f -- "$path"; fi
    done
    if [[ ! -f "$TMP/python.old" && -L "$BIN" && $(readlink "$BIN") == "$ROOT/beman.py" ]]; then rm -f -- "$BIN"; fi
    systemctl daemon-reload
    if [[ "$was_enabled" == true ]]; then systemctl enable beman.service; else systemctl disable beman.service; fi
    if [[ "$was_active" == true ]]; then systemctl start beman.service; fi
    exit "$rc"
}
trap restore ERR
install -m 0700 -o root -g root "$TMP/beman.py" "$ROOT/.beman.py.new"
mv -f -- "$ROOT/.beman.py.new" "$ROOT/beman.py"
install -m 0700 -o root -g root "$TMP/install.sh" "$ROOT/install.sh"
python3 "$ROOT/beman.py" init --url "$BASE_URL/beman.py" --sha256 "$PYTHON_SHA256"
python3 "$ROOT/beman.py" check
[[ -L "$BIN" ]] || ln -s "$ROOT/beman.py" "$BIN"
cat > "$TMP/beman.service" <<'UNITFILE'
# Managed by Beman installer
[Unit]
Description=Beman SSH access audit and recovery
After=ssh.service network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/beman/beman.py monitor
WorkingDirectory=/opt/beman
User=root
UMask=0077
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
UNITFILE
install -m 0644 -o root -g root "$TMP/beman.service" "$UNIT"
systemctl daemon-reload
if [[ -f "$TMP/unit.old" ]]; then
    if [[ "$was_enabled" == true ]]; then systemctl enable beman.service; else systemctl disable beman.service; fi
    if [[ "$was_active" == true ]]; then
        systemctl restart beman.service
        systemctl is-active --quiet beman.service
    else
        systemctl stop beman.service
    fi
else
    systemctl enable beman.service
    systemctl restart beman.service
    systemctl is-active --quiet beman.service
fi
trap - ERR
ok "BeMan 已安装/升级：$ROOT"
info '输入 beman 打开彩色管理工具箱；输入 beman update 自动升级'
info '首次启用或修改白名单时，保留旧会话，从新白名单SSH会话再次启动确认。'
