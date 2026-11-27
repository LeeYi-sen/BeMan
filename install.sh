#!/usr/bin/env bash
# Beman 安装及更新（Ubuntu/Debian systemd）；首次安装不会启用SSH限制。
set -Eeuo pipefail
umask 077

# 官方发布地址；可通过 BEMAN_BASE_URL 或命令行参数覆盖。
BASE_URL="${BEMAN_BASE_URL:-https://beman.teadan.com}"
# 发布新版时同步更新版本及两个 Python 文件的 SHA256。
BEMAN_VERSION="3.10"
PYTHON_SHA256="c5cc29865464cfc4fcc4bc28e4dbae9c1be8c72b9c346c118af215ff553e29d4"
ALERT_SHA256="3aec86377f38bc455538716be047cf277add40b2b57cb479e2bcab5f738275fb"
ROOT=/opt/beman
UNIT=/etc/systemd/system/beman.service
BIN=/usr/local/bin/beman
LEGACY_HOOK=/etc/profile.d/beman-stranger.sh
LEGACY_ALLOWLIST="$ROOT/whitelist.txt"
RED='' GREEN='' CYAN='' RESET=''
if [[ -t 1 && "${TERM:-}" != dumb && -z "${NO_COLOR+x}" ]]; then RED=$'\033[31m'; GREEN=$'\033[32m'; CYAN=$'\033[36m'; RESET=$'\033[0m'; fi
info(){ printf '%s[INFO]%s %s\n' "$CYAN" "$RESET" "$*"; }
ok(){ printf '%s[ OK ]%s %s\n' "$GREEN" "$RESET" "$*"; }
fail(){ printf '%s[ERR ]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
if [[ $EUID != 0 ]]; then
    command -v sudo >/dev/null || fail '需要root权限或sudo'
    exec sudo -- bash "$0" "$@"
fi
[[ -d /run/systemd/system ]] || fail '仅支持正在运行的systemd Linux'
command -v systemctl >/dev/null || fail '需要可用的systemd系统'

# Only install missing dependencies; never explicitly upgrade or remove packages.
ensure_dependencies(){
    local -a missing=()
    command -v python3 >/dev/null || missing+=(python3)
    command -v wget >/dev/null || missing+=(wget)
    if ! command -v sha256sum >/dev/null || ! command -v install >/dev/null; then missing+=(coreutils); fi
    command -v flock >/dev/null || missing+=(util-linux)
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || missing+=(ca-certificates)
    if [[ ! -x /usr/sbin/sshd ]]; then
        if systemctl is-active --quiet ssh.service || systemctl is-active --quiet ssh.socket; then
            fail 'SSH已在运行但标准sshd路径异常，请检查系统，不自动重装SSH'
        fi
        missing+=(openssh-server)
    fi
    if command -v python3 >/dev/null; then
        python3 -c 'import sys; assert sys.version_info >= (3,10)' || fail '现有Python版本低于3.10，请使用支持的系统'
    fi
    if ((${#missing[@]})); then
        command -v apt-get >/dev/null || fail '仅支持通过APT安装缺失依赖的系统'
        info "安装缺失依赖：${missing[*]}"
        apt-get -o APT::Update::Error-Mode=any update
        DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 apt-get install -y --no-upgrade --no-remove --no-install-recommends -o Dpkg::Options::=--force-confold "${missing[@]}"
    else
        ok '系统依赖已满足，跳过APT安装'
    fi
    local cmd
    for cmd in python3 wget sha256sum systemctl journalctl install flock; do command -v "$cmd" >/dev/null || fail "缺少依赖：$cmd"; done
    python3 -c 'import sys; assert sys.version_info >= (3,10)' || fail '需要Python 3.10及以上'
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || fail '系统CA证书不可用'
    [[ -x /usr/sbin/sshd ]] || fail 'OpenSSH Server未正确安装'
    ok '依赖检查完成'
}
# Startup can repair missing ordinary dependencies without changing SSH.
if [[ "${1:-}" == --repair-dependencies ]]; then
    [[ -x /usr/sbin/sshd ]] || fail 'SSH Server缺失，启动检测不自动安装或启动SSH'
    [[ ! -e "$ROOT/backups/ssh-pending.json" ]] || fail '待确认期间不修复依赖'
    ensure_dependencies
    exit 0
fi
# 可使用 bash install.sh https://example.com/beman，或在顶部填写BASE_URL。
BASE_URL="${1:-$BASE_URL}"
BASE_URL=${BASE_URL%/}
[[ "$BASE_URL" == https://* && "$BASE_URL" != *[[:space:]]* && "$BASE_URL" != *\?* && "$BASE_URL" != *\#* ]] || fail '请填写真实HTTPS发布目录：bash install.sh https://你的域名/beman'
[[ "$PYTHON_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail '发布SHA256格式无效'
ensure_dependencies
LOCK=/run/lock/beman-install.lock
if [[ ! -e "$LOCK" && ! -L "$LOCK" ]]; then
    (set -C; : > "$LOCK") 2>/dev/null || true
fi
[[ -f "$LOCK" && ! -L "$LOCK" && -O "$LOCK" ]] || fail '安装锁文件类型或所有者异常'
exec 9>>"$LOCK"
flock -x 9
for dir in "$ROOT" "$ROOT/backups"; do
    [[ ! -L "$dir" ]] || fail "拒绝符号链接目录：$dir"
    install -d -m 0700 -o root -g root "$dir"
done
[[ ! -L "$ROOT/backups/operation.lock" ]] || fail '拒绝符号链接锁文件'
exec 8>"$ROOT/backups/operation.lock"
flock -x 8
[[ ! -e "$ROOT/backups/ssh-pending.json" && ! -e "$ROOT/backups/network-owned.json" ]] || fail '请先使用旧版本确认SSH策略或停止防护、解除隔离'
for target in "$ROOT/beman.py" "$ROOT/kill.py" "$ROOT/install.sh" "$ROOT/settings.json" "$ROOT/manifest.json" "$UNIT"; do [[ ! -L "$target" ]] || fail "拒绝符号链接：$target"; done
# Retire only the previous BeMan-owned hook and its generated allowlist snapshot.
for target in "$LEGACY_HOOK" "$LEGACY_ALLOWLIST"; do
    if [[ -e "$target" || -L "$target" ]]; then
        [[ -f "$target" && ! -L "$target" && -O "$target" ]] || fail "旧版巡检文件异常：$target"
    fi
done
if [[ -f "$LEGACY_HOOK" ]]; then
    grep -Fxq '# Managed by BeMan' "$LEGACY_HOOK" || fail '同名巡检脚本不属于 BeMan'
fi
if [[ -f "$LEGACY_ALLOWLIST" ]]; then
    if grep -Eqv '^(user|ip) [^[:space:]]+$' "$LEGACY_ALLOWLIST"; then fail '旧版白名单快照格式异常'; fi
fi
if [[ -e "$BIN" || -L "$BIN" ]]; then [[ -L "$BIN" && $(readlink "$BIN") == "$ROOT/beman.py" ]] || fail 'beman命令已被其他程序占用'; fi
if [[ -e "$UNIT" ]]; then grep -Fxq '# Managed by Beman installer' "$UNIT" || fail '同名服务不属于Beman'; fi
# Never stop a service not owned by the previous installer.
if [[ ! -f "$UNIT" ]] && systemctl is-active --quiet beman.service; then fail '存在未知来源的同名服务'; fi
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
info '下载并校验Python主程序'
[[ -f "${BASH_SOURCE[0]}" ]] || fail '请先将安装器下载到文件再运行'
cp -- "${BASH_SOURCE[0]}" "$TMP/install.sh"
wget --no-cache --https-only --max-redirect=0 --timeout=20 --tries=2 -q -O "$TMP/beman.py" "$BASE_URL/beman.py"
printf '%s  %s\n' "$PYTHON_SHA256" "$TMP/beman.py" | sha256sum -c - || fail 'SHA256校验失败，未安装'
wget --no-cache --https-only --max-redirect=0 --timeout=20 --tries=2 -q -O "$TMP/kill.py" "$BASE_URL/kill.py"
printf '%s  %s\n' "$ALERT_SHA256" "$TMP/kill.py" | sha256sum -c - || fail '告警模块SHA256校验失败，未安装'
python3 -m py_compile "$TMP/beman.py" "$TMP/kill.py" || fail 'Python语法校验失败'
python3 - "$TMP/beman.py" "$ROOT/beman.py" "$BEMAN_VERSION" "$TMP/install.sh" "$ROOT/install.sh" <<'PY' || fail '版本校验失败，未安装'
import pathlib
import re
import sys

new, old, version, new_installer, old_installer = sys.argv[1:]
def key(v):
    if not re.fullmatch(r'[1-9][0-9]{0,8}(?:\.[1-9][0-9]{0,8})?', v):
        raise SystemExit('无效版本号')
    major, _, minor = v.partition('.')
    return int(major), int(minor or 0)

def declared(data):
    matches = re.findall(rb"^VERSION = '([^'\r\n]*)'$", data, re.M)
    if len(matches) != 1:
        raise SystemExit('Python版本声明无效')
    return matches[0].decode('ascii')

source = pathlib.Path(new).read_bytes()
if declared(source) != version:
    raise SystemExit('安装器与Python版本不一致')
target = key(version)
if pathlib.Path(old).is_file():
    previous = pathlib.Path(old).read_bytes()
    if re.search(rb'^VERSION\s*=', previous, re.M):
        current = key(declared(previous))
        if current > target:
            raise SystemExit('拒绝降级')
        if current == target:
            if previous != source or (pathlib.Path(old_installer).is_file() and pathlib.Path(old_installer).read_bytes() != pathlib.Path(new_installer).read_bytes()):
                raise SystemExit('同版本发布文件不一致，请检查版本号')
    else:
        print('旧版无数字版本号，迁移至 BeMan '+version)
PY
for pair in "$ROOT/beman.py:python" "$ROOT/kill.py:alert" "$ROOT/install.sh:installer" "$ROOT/settings.json:settings" "$ROOT/manifest.json:manifest" "$UNIT:unit" "$LEGACY_HOOK:legacy-hook" "$LEGACY_ALLOWLIST:legacy-allowlist"; do
    path=${pair%:*}; name=${pair##*:}; if [[ -f "$path" ]]; then cp -p -- "$path" "$TMP/$name.old"; fi
done
was_active=false; was_enabled=false
systemctl is-active --quiet beman.service && was_active=true
systemctl is-enabled --quiet beman.service && was_enabled=true
restore(){
    local rc=$?; trap - ERR; set +e
    echo '安装失败，尝试恢复安装前的Beman程序、配置和服务。' >&2
    if [[ -f "$TMP/unit.old" ]]; then systemctl stop beman.service; fi
    for pair in "$ROOT/beman.py:python" "$ROOT/kill.py:alert" "$ROOT/install.sh:installer" "$ROOT/settings.json:settings" "$ROOT/manifest.json:manifest" "$UNIT:unit" "$LEGACY_HOOK:legacy-hook" "$LEGACY_ALLOWLIST:legacy-allowlist"; do
        path=${pair%:*}; name=${pair##*:}
        if [[ -f "$TMP/$name.old" ]]; then cp -p -- "$TMP/$name.old" "$path"; else rm -f -- "$path"; fi
    done
    if [[ ! -f "$TMP/python.old" && -L "$BIN" && $(readlink "$BIN") == "$ROOT/beman.py" ]]; then rm -f -- "$BIN"; fi
    systemctl daemon-reload
    if [[ -f "$TMP/unit.old" ]]; then
        if [[ "$was_enabled" == true ]]; then systemctl enable beman.service; else systemctl disable beman.service; fi
        if [[ "$was_active" == true ]]; then systemctl start --no-block beman.service; fi
    fi
    exit "$rc"
}
trap restore ERR
if [[ -f "$TMP/unit.old" ]]; then
    systemctl disable --now beman.service
    rm -- "$UNIT"
    systemctl daemon-reload
fi
install -m 0700 -o root -g root "$TMP/beman.py" "$ROOT/.beman.py.new"
mv -f -- "$ROOT/.beman.py.new" "$ROOT/beman.py"
install -m 0600 -o root -g root "$TMP/kill.py" "$ROOT/kill.py"
install -m 0700 -o root -g root "$TMP/install.sh" "$ROOT/install.sh"
PYTHONDONTWRITEBYTECODE=1 python3 -c 'import sys; sys.path.insert(0,"/opt/beman"); import beman; beman.ConfigManager.init(); beman.ConfigManager.load(); beman.dump(beman.MANIFEST,beman.manifest_data())'
[[ -L "$BIN" ]] || ln -s "$ROOT/beman.py" "$BIN"
PYTHONDONTWRITEBYTECODE=1 python3 -c 'import sys; sys.path.insert(0,"/opt/beman"); import beman; problems=beman.dependency_issues(); beman.need(not problems,"；".join(problems))'
rm -f -- "$LEGACY_HOOK" "$LEGACY_ALLOWLIST"
trap - ERR
ok "BeMan v$BEMAN_VERSION 已安装/升级：$ROOT"
info '输入 beman 打开 SSH 管理工具箱；选择检查更新按需升级'
info '无常驻服务；原有 SSH 策略未改变。'
info '首次启用或修改白名单时，保留旧会话，从新白名单SSH会话再次启动确认。'
