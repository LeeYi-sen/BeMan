#!/usr/bin/env python3
"""BeMan: lightweight SSH allowlist management."""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import datetime
import secrets
import os
import pwd
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path('/opt/beman')
SETTINGS = ROOT / 'settings.json'
STATE = ROOT / 'backups'
POLICY = Path('/etc/ssh/sshd_config.d/00-beman.conf')
SSHD = '/usr/sbin/sshd'
SSH_SERVICE = 'ssh.service'
ROLLBACK = 'beman-ssh-rollback'
SELF = ROOT / 'beman.py'
BIN = Path('/usr/local/bin/beman')
INSTALL_LOCK = Path('/run/lock/beman-install.lock')


def item(value, comment):
    return {'value': value, 'comment': comment}


DEFAULTS = {
    'allowed_users': item(['root'], '允许SSH登录的用户列表，必须使用公钥认证。'),
    'allowed_ips': item(['192.168.31.7', '', ''], '允许SSH登录的精确IPv4/IPv6地址，空值忽略。'),
    'ssh_port': item(22, '现有SSH端口，不改变监听端口。'),
    'rollback_seconds': item(300, '新策略未确认时自动回滚的秒数，60至900。'),
}


class BemanError(Exception):
    pass


def need(condition, message):
    if not condition:
        raise BemanError(message)


def run(*args, check=True, timeout=30, input=None):
    try:
        p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise BemanError(f'{args[0]} 执行失败：{e}') from e
    if check and p.returncode:
        raise BemanError(f'{args[0]} 执行失败（{p.returncode}）：{p.stderr.strip()[-1000:]}')
    return p


def atomic(path, content, mode=0o600):
    path = Path(path)
    need(not path.is_symlink(), f'拒绝写入符号链接：{path}')
    fd, tmp = tempfile.mkstemp(prefix='.beman-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.fchmod(f.fileno(), mode)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def dump(path, value):
    atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def ips(values, empty=False):
    need(isinstance(values, list) and all(isinstance(x, str) for x in values), 'IP必须为字符串数组')
    need(all('%' not in x for x in values), '不支持带网卡区域标识的IPv6地址')
    result = list(dict.fromkeys(str(ipaddress.ip_address(x.strip())) for x in values if x.strip()))
    need(empty or bool(result), '至少配置一个白名单IP')
    return result


def user_valid(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', value) is not None


class ConfigManager:
    @staticmethod
    def merge(schema, old):
        need(isinstance(old, dict), '配置必须是JSON对象')
        # Migrate only the four retained fields; never silently replace a legacy allowlist.
        if 'authentication' in old:
            need(not set(old).intersection(schema),'混合新旧配置格式，请人工检查')
            auth=old['authentication']; protection=old.get('protection',{})
            need(isinstance(auth,dict) and isinstance(protection,dict),'旧配置格式无效')
            need('allowed_users' in auth and 'allowed_ips' in auth,'旧白名单缺失，拒绝迁移')
            old={k:auth[k] for k in ('allowed_users','allowed_ips','ssh_port') if k in auth}
            if 'rollback_seconds' in protection: old['rollback_seconds']=protection['rollback_seconds']
        need(not set(old)-set(schema),'存在未知配置字段')
        result={}
        for k,v in schema.items():
            prev=old.get(k,v)
            need(isinstance(prev,dict) and 'value' in prev and set(prev)<={'value','comment'},k+'须使用value/comment结构')
            result[k]=item(prev['value'],v['comment'])
        return result

    @staticmethod
    def format(data):
        return '{\n'+',\n'.join('    '+json.dumps(k)+': '+json.dumps(v,ensure_ascii=False) for k,v in data.items())+'\n}'

    @staticmethod
    def unwrap(data):
        return {k:v['value'] for k,v in data.items()}

    @classmethod
    def init(cls):
        old=read(SETTINGS) if SETTINGS.exists() else {}
        data=cls.merge(DEFAULTS,old)
        cfg=cls.unwrap(data); cls.validate(cfg)
        if 'authentication' in old:
            backup=STATE/'settings-before-simplification.json'
            if not backup.exists(): atomic(backup,SETTINGS.read_text())
        atomic(SETTINGS,cls.format(data)+'\n')
        return cfg

    @classmethod
    def load(cls):
        cfg=cls.unwrap(cls.merge(DEFAULTS,read(SETTINGS)))
        cls.validate(cfg)
        return cfg

    @staticmethod
    def validate(c):
        need(isinstance(c['allowed_users'],list) and c['allowed_users'] and all(user_valid(u) for u in c['allowed_users']),'用户名白名单无效')
        c['allowed_users']=list(dict.fromkeys(c['allowed_users']))
        c['allowed_ips']=ips(c['allowed_ips'])
        for k,lo,hi in [('ssh_port',1,65535),('rollback_seconds',60,900)]:
            need(type(c[k]) is int and lo<=c[k]<=hi,f'{k}须为{lo}至{hi}的整数')


@contextlib.contextmanager
def locked():
    with open(STATE/'operation.lock','a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


# Temporary persistent rollback units survive a reboot while a change is pending.
UNIT_DIR=Path('/etc/systemd/system')
UNIT_MARK='# Managed by Beman temporary rollback'

def timer(name, seconds, operation, token):
    units=[UNIT_DIR/(name+'.service'),UNIT_DIR/(name+'.timer')]
    need(all(not p.exists() and not p.is_symlink() for p in units),'存在同名回滚单元，请先检查')
    deadline=datetime.datetime.fromtimestamp(time.time()+seconds,datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    try:
        atomic(units[0],UNIT_MARK+'\n[Unit]\nAfter=ssh.service\nWants=ssh.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /opt/beman/beman.py '+operation+' --rollback-token '+token+'\n',0o644)
        atomic(units[1],UNIT_MARK+'\n[Timer]\nOnCalendar='+deadline+'\nPersistent=true\nAccuracySec=1s\n[Install]\nWantedBy=timers.target\n',0o644)
        run('systemctl','daemon-reload')
        run('systemctl','enable','--now',name+'.timer')
        need(run('systemctl','is-active','--quiet',name+'.timer',check=False).returncode==0,'回滚计时器未运行')
    except Exception:
        stop_timer(name)
        raise

def stop_timer(name):
    units=[UNIT_DIR/(name+'.service'),UNIT_DIR/(name+'.timer')]
    for p in units:
        if p.exists() or p.is_symlink():
            need(not p.is_symlink() and p.read_text().startswith(UNIT_MARK+'\n'),'拒绝修改非BeMan回滚单元')
    if any(p.exists() for p in units):
        run('systemctl','disable','--now',name+'.timer',check=False)
        for p in units: p.unlink(missing_ok=True)
        run('systemctl','daemon-reload')
    else:
        run('systemctl','stop',name+'.timer',check=False)


def root_check():
    need(os.geteuid()==0, '服务器端需要root权限')
    need(Path('/run/systemd/system').is_dir(), '需要正在运行的systemd Linux')


class SSHGuard:
    META = STATE/'ssh-policy.json'
    PENDING = STATE/'ssh-pending.json'

    @staticmethod
    def pattern(c):
        a=c
        return [f'{u}@{ip}/{ipaddress.ip_address(ip).max_prefixlen}' for u in a['allowed_users'] for ip in a['allowed_ips']]

    @classmethod
    def candidate(cls,c):
        return '# Managed by Beman\nAllowUsers '+' '.join(cls.pattern(c))+'\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin '+('prohibit-password' if 'root' in c['allowed_users'] else 'no')+'\n'

    @staticmethod
    def inspect():
        main=Path('/etc/ssh/sshd_config'); folder=POLICY.parent
        need(folder.is_dir(), '缺少sshd_config.d')
        includes=0
        for file in [main,*sorted(folder.glob('*.conf'))]:
            if file==POLICY: continue
            for i,line in enumerate(file.read_text().splitlines(),1):
                words=shlex.split(line,comments=True)
                if not words: continue
                key,sep,val=words[0].partition('='); args=([val] if sep and val else [])+words[1:]
                if args and args[0]=='=': args=args[1:]
                key=key.lower()
                if key=='include':
                    need(file==main and args==['/etc/ssh/sshd_config.d/*.conf'],f'不支持的Include：{file}:{i}')
                    includes+=1
                elif key in ('match','allowusers','denyusers','allowgroups','denygroups'):
                    raise BemanError(f'存在需人工审查的SSH规则：{file}:{i} {key}')
        need(includes==1,'要求标准Ubuntu/Debian SSH Include配置')

    @classmethod
    def verify(cls,c):
        run(SSHD,'-t')
        a=c; expected=set(cls.pattern(c))
        for u in a['allowed_users']:
            for ip in a['allowed_ips']:
                out=run(SSHD,'-T','-C',f'user={u},host={ip},addr={ip}').stdout
                lines=out.splitlines(); actual={x for l in lines if l.startswith('allowusers ') for x in l.split()[1:]}
                need(actual==expected,'实际SSH白名单与配置不一致')
                for x in ('pubkeyauthentication yes','authenticationmethods publickey','passwordauthentication no','kbdinteractiveauthentication no',f"port {a['ssh_port']}"):
                    need(x in lines,'SSH实际配置不符合预期：'+x)
                root_values={'permitrootlogin prohibit-password','permitrootlogin without-password'} if 'root' in a['allowed_users'] else {'permitrootlogin no'}
                need(bool(root_values.intersection(lines)),'root认证策略不一致')
                need(set(l for l in lines if l.startswith('port '))=={f"port {a['ssh_port']}"},'存在额外SSH监听端口，请人工审查')

    @classmethod
    def owned(cls):
        if not POLICY.exists():
            need(not POLICY.is_symlink(),'SSH策略为符号链接'); return None
        need(not POLICY.is_symlink() and cls.META.exists(),'同名策略不属于Beman')
        old=POLICY.read_text(); need(sha(old)==read(cls.META)['hash'],'策略已被外部修改，拒绝覆盖')
        return old

    @classmethod
    def restore_pending(cls):
        if not cls.PENDING.exists(): return
        data=read(cls.PENDING); old=data['previous']
        need(not POLICY.is_symlink(),'SSH策略为符号链接，拒绝恢复')
        if POLICY.exists():
            current=POLICY.read_text()
            need(sha(current) in {data['candidate_hash'],sha(old) if old is not None else ''},'策略被外部修改，需人工恢复')
        if old is None:
            POLICY.unlink(missing_ok=True); cls.META.unlink(missing_ok=True)
        else:
            atomic(POLICY,old); dump(cls.META,{'hash':sha(old)})
        run(SSHD,'-t'); run('systemctl','reload',SSH_SERVICE)
        cls.PENDING.unlink(); stop_timer(ROLLBACK)
        print('已恢复应用前SSH策略')

    @classmethod
    def apply(cls,c):
        need(not cls.PENDING.exists(),'存在未确认配置，请先confirm或rollback')
        need(run('systemctl','is-active','--quiet',SSH_SERVICE,check=False).returncode==0,'ssh.service未运行')
        a=c; conn=os.environ.get('SSH_CONNECTION',''); parts=conn.split()
        if conn:
            need(len(parts)==4 and str(ipaddress.ip_address(parts[0])) in a['allowed_ips'],'当前SSH来源不在新白名单，拒绝应用')
        for u in a['allowed_users']: pwd.getpwnam(u)
        cls.inspect(); run(SSHD,'-t'); old=cls.owned(); candidate=cls.candidate(c)
        token=secrets.token_hex(16)
        dump(cls.PENDING,{'token':token,'previous':old,'candidate_hash':sha(candidate),'connection':conn,'users':a['allowed_users'],'ips':a['allowed_ips']})
        try: timer(ROLLBACK,c['rollback_seconds'],'rollback-pending',token)
        except Exception:
            cls.PENDING.unlink(); raise
        try:
            atomic(POLICY,candidate); dump(cls.META,{'hash':sha(candidate)})
            cls.verify(c); run('systemctl','reload',SSH_SERVICE)
        except Exception:
            cls.restore_pending(); raise
        print('SSH策略已应用。保留当前会话，从白名单IP新建SSH连接后执行 beman start（或 confirm）；超时自动回滚。')

    @classmethod
    def confirm(cls):
        need(cls.PENDING.exists(),'没有待确认配置'); d=read(cls.PENDING)
        conn=os.environ.get('SSH_CONNECTION',''); p=conn.split(); user=os.environ.get('SUDO_USER') or pwd.getpwuid(os.getuid()).pw_name
        need(len(p)==4 and conn!=d['connection'] and str(ipaddress.ip_address(p[0])) in d['ips'] and user in d['users'],'请从白名单用户/IP的新SSH会话确认；sudo需保留SSH_CONNECTION')
        need(run('systemctl','is-active','--quiet',ROLLBACK+'.timer',check=False).returncode==0,'回滚计时器未运行')
        need(cls.owned() is not None and sha(POLICY.read_text())==d['candidate_hash'],'待确认策略已变化')
        run(SSHD,'-t'); cls.PENDING.unlink(); stop_timer(ROLLBACK); print('SSH策略已确认')

    @classmethod
    def rollback(cls):
        if cls.PENDING.exists(): return cls.restore_pending()
        old=cls.owned()
        if old is None: print('无Beman SSH策略'); return
        POLICY.unlink()
        try: run(SSHD,'-t'); run('systemctl','reload',SSH_SERVICE)
        except Exception:
            atomic(POLICY,old); raise
        cls.META.unlink(missing_ok=True); print('已撤销Beman策略，其他SSH配置未修改')


class Console:
    @staticmethod
    def color(text, code):
        if sys.stdout.isatty() and os.environ.get('TERM')!='dumb' and 'NO_COLOR' not in os.environ:
            return '\033['+code+'m'+str(text)+'\033[0m'
        return str(text)

    @classmethod
    def say(cls, text, kind='info'):
        labels={'ok':('32','OK'),'warn':('33','!'),'error':('31','ERR'),'info':('36','INFO')}
        code,label=labels[kind]
        print(cls.color('['+label+']',code),text)

    @classmethod
    def title(cls, text):
        print('\n'+cls.color('BeMan  /  '+text,'1;36'))
        print(cls.color('─'*48,'90'))

    @staticmethod
    def ask(prompt):
        return input(prompt).strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BemanError('发布地址发生重定向，拒绝继续')


class Release:
    # The official HTTPS domain is the only default client-side release source.
    BASE='https://beman.teadan.com'
    MAX_SIZE=2_000_000

    @classmethod
    def fetch(cls,url):
        req=urllib.request.Request(url,headers={'Cache-Control':'no-cache','User-Agent':'BeMan-Updater'})
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=20) as response:
            need(response.geturl()==url,'更新地址发生重定向，拒绝继续')
            data=response.read(cls.MAX_SIZE+1)
        need(0<len(data)<=cls.MAX_SIZE,'发布文件为空或过大')
        return data

    @classmethod
    def inspect(cls):
        installer=cls.fetch(cls.BASE+'/install.sh')
        matches=re.findall(rb'^PYTHON_SHA256="([a-f0-9]{64})"$',installer,re.M)
        need(len(matches)==1,'安装器缺少唯一有效SHA256')
        digest=matches[0].decode()
        source=cls.fetch(cls.BASE+'/beman.py')
        need(hashlib.sha256(source).hexdigest()==digest,'发布文件SHA256不一致，可能尚未同步；请稍后重试')
        compile(source,str(SELF),'exec')
        local=hashlib.sha256(SELF.read_bytes()).hexdigest()
        saved=ROOT/'install.sh'
        same_installer=saved.is_file() and not saved.is_symlink() and saved.read_bytes()==installer
        return installer,digest,local,local!=digest or not same_installer

    @classmethod
    def update(cls,check_only=False):
        Console.say('正在检测官方发布…')
        installer,digest,local,changed=cls.inspect()
        print('本地版本：'+local[:12]+'  发布版本：'+digest[:12])
        if not changed:
            Console.say('已是最新版本','ok'); return False
        Console.say('检测到新版本或安装器变更','warn')
        if check_only: return False
        need(not SSHGuard.PENDING.exists(),'请先确认或停止SSH策略')
        with tempfile.TemporaryDirectory(prefix='beman-release-') as tmp:
            path=Path(tmp)/'install.sh'; path.write_bytes(installer); path.chmod(0o700)
            run('bash','-n',str(path))
            # Do not hold operation.lock: the installer invokes beman init.
            p=run('bash',str(path),cls.BASE,timeout=180)
            print(p.stdout,end='')
        need(hashlib.sha256(SELF.read_bytes()).hexdigest()==digest,'升级后版本校验失败')
        need((ROOT/'install.sh').read_bytes()==installer,'升级后安装器校验失败')
        Console.say('升级完成；白名单及SSH策略已保留','ok')
        return True


class Toolbox:
    @staticmethod
    def call(*args):
        p=subprocess.run([sys.executable,str(SELF),*args])
        if p.returncode: Console.say('操作未完成（退出码 '+str(p.returncode)+'）','error')
        return p.returncode==0

    @classmethod
    def whitelist(cls):
        fields=[('allowed_users','允许用户'),('allowed_ips','允许IP'),('ssh_port','SSH端口'),('rollback_seconds','回滚秒数')]
        with locked():
            original=SETTINGS.read_text()
            data=ConfigManager.merge(DEFAULTS,json.loads(original))
        while True:
            Console.title('白名单管理')
            for i,(key,label) in enumerate(fields,1):
                print(f'[{i}] {label}: {json.dumps(data[key]["value"],ensure_ascii=False)}')
            print('[s] 保存  [0] 返回（放弃未保存修改）')
            choice=Console.ask('请选择：')
            if choice=='0': return
            if choice.lower()=='s':
                try:
                    with locked():
                        need(SETTINGS.read_text()==original,'配置已改变，请重新进入菜单')
                        need(not SSHGuard.PENDING.exists(),'请先确认或停止待确认策略')
                        ConfigManager.validate(ConfigManager.unwrap(data))
                        atomic(SETTINGS,ConfigManager.format(data)+'\n')
                    Console.say('已保存；选择重启防护应用新规则','ok')
                    return
                except (BemanError,ValueError,OSError,KeyError) as e: Console.say(str(e),'error')
                continue
            if choice not in ('1','2','3','4'):
                Console.say('无效选项','warn'); continue
            key,label=fields[int(choice)-1]
            raw=Console.ask('输入新值（名单用空格或逗号分隔，空行取消）：')
            if not raw: continue
            try:
                data[key]['value']=list(dict.fromkeys(re.split(r'[\s,]+',raw))) if key in ('allowed_users','allowed_ips') else int(raw)
            except ValueError as e: Console.say(str(e),'error')

    @classmethod
    def menu(cls):
        need(sys.stdin.isatty() and sys.stdout.isatty(),'非交互环境请指定命令，例如 beman status')
        while True:
            Console.title('SSH 安全管理')
            cls.call('status')
            print(Console.color('─'*48,'90'))
            for label,code in [('1  启动 / 确认防护','32'),('2  停止防护','31'),('3  重启防护','33'),('4  查看状态','36'),('5  白名单管理','36'),('6  查看登录日志','36'),('7  检测并自动升级','36'),('8  一键卸载 BeMan','31'),('0  退出','90')]:
                print(Console.color('['+label[0]+']'+label[1:],code))
            try:
                choice=Console.ask('请选择 [0-8]：')
                if choice=='0': return
                if choice in ('1','2','3','4'):
                    cls.call({'1':'start','2':'stop','3':'restart','4':'status'}[choice])
                elif choice=='5': cls.whitelist()
                elif choice=='6': cls.call('logs')
                elif choice=='7':
                    if Console.ask('从官方渠道检测并安装新版？[y/N]：').lower()=='y':
                        cls.call('update'); Console.say('如已升级，请退出并重新运行 beman')
                elif choice=='8':
                    if Console.ask('确认撤销防护并删除 BeMan 程序、配置及自身备份？SSH 服务和系统依赖保留。[y/N]：').lower()=='y':
                        if cls.call('uninstall','--yes'): return
                    else: Console.say('已取消卸载','warn')
                else: Console.say('无效选项','warn')
                Console.ask('按 Enter 返回主菜单…')
            except (EOFError,KeyboardInterrupt):
                print(); return
            except (BemanError,OSError,ValueError,KeyError) as e: Console.say(str(e),'error')


class Beman:
    @staticmethod
    def start():
        with locked():
            c=ConfigManager.load()
            old=SSHGuard.owned(); candidate=SSHGuard.candidate(c)
            if SSHGuard.PENDING.exists():
                need(old==candidate,'待确认期间配置已变化，请先停止防护')
                SSHGuard.verify(c); SSHGuard.confirm()
                Console.say('防护已启用','ok')
            elif old==candidate:
                SSHGuard.inspect(); SSHGuard.verify(c)
                need(run('systemctl','is-active','--quiet',SSH_SERVICE,check=False).returncode==0,'SSH服务未运行')
                run('systemctl','reload',SSH_SERVICE)
                Console.say('防护已启用','ok')
            else:
                SSHGuard.apply(c)

    @staticmethod
    def stop():
        with locked():
            SSHGuard.rollback()
            if POLICY.exists(): SSHGuard.rollback()
            need(not POLICY.exists() and not SSHGuard.PENDING.exists(),'SSH策略仍存在，请检查')
            Console.say('防护已停止，原SSH规则已恢复','ok')

    @staticmethod
    def uninstall(yes=False):
        if not yes:
            need(sys.stdin.isatty(),'非交互卸载需明确指定 --yes')
            if Console.ask('确认卸载 BeMan（删除程序、配置及自身备份；保留 SSH 与依赖）？[y/N]：').lower()!='y':
                Console.say('已取消卸载','warn'); return
        # Use the same lock order as install.sh; never remove the global install lock.
        need(not INSTALL_LOCK.is_symlink(),'拒绝符号链接安装锁')
        with open(INSTALL_LOCK,'a') as install_lock:
            fcntl.flock(install_lock,fcntl.LOCK_EX)
            need(ROOT.is_dir() and not ROOT.is_symlink() and STATE.is_dir() and not STATE.is_symlink(),'BeMan安装目录异常')
            need(SELF.is_file() and not SELF.is_symlink(),'BeMan主程序不存在或路径异常')
            need(not (STATE/'operation.lock').is_symlink(),'拒绝符号链接操作锁')
            with locked():
                need(not (STATE/'network-owned.json').exists() and not (STATE/'network-owned.json').is_symlink(),'存在旧版网络隔离记录，请先用旧版解除隔离')
                need(not (BIN.exists() or BIN.is_symlink()) or (BIN.is_symlink() and os.readlink(BIN)==str(SELF)),'同名命令不属于BeMan，拒绝卸载')
                legacy=UNIT_DIR/'beman.service'
                if legacy.exists() or legacy.is_symlink():
                    need(not legacy.is_symlink() and legacy.is_file() and '# Managed by Beman installer' in legacy.read_text().splitlines(),'同名服务不属于BeMan，拒绝卸载')
                else:
                    need(run('systemctl','is-active','--quiet','beman.service',check=False).returncode!=0,'存在未知来源的同名服务，拒绝卸载')
                units=[UNIT_DIR/(ROLLBACK+suffix) for suffix in ('.service','.timer')]
                for path in units:
                    if path.exists() or path.is_symlink():
                        need(not path.is_symlink() and path.is_file() and path.read_text().startswith(UNIT_MARK+'\n'),'同名回滚单元不属于BeMan，拒绝卸载')
                logs=ROOT/'logs'; cache=ROOT/'__pycache__'
                for directory in (logs,cache):
                    need(not directory.is_symlink() and (not directory.exists() or directory.is_dir()),'目录异常：'+str(directory))
                files=[ROOT/'install.sh',SETTINGS,STATE/'settings-before-simplification.json',STATE/'operation.lock',SSHGuard.META,SSHGuard.PENDING,logs/'beman.log',ROOT/'.beman.py.new']
                if cache.is_dir(): files.extend(cache.glob('beman.*.pyc'))
                for path in files:
                    need(not path.is_symlink() and (not path.exists() or path.is_file()),'文件异常：'+str(path))
                # Restore only our managed SSH rules. Failure aborts before deleting the program.
                SSHGuard.rollback()
                if POLICY.exists(): SSHGuard.rollback()
                need(not POLICY.exists() and not POLICY.is_symlink() and not SSHGuard.PENDING.exists(),'SSH策略未完全撤销')
                run(SSHD,'-t')
                if SSHGuard.META.exists():
                    # An externally removed policy might still be loaded by sshd.
                    run('systemctl','reload',SSH_SERVICE)
                    SSHGuard.META.unlink()
                if any(p.exists() for p in units):
                    stop_timer(ROLLBACK)
                need(run('systemctl','is-active','--quiet',ROLLBACK+'.timer',check=False).returncode!=0,'回滚定时器仍在运行，拒绝卸载')
                if legacy.exists():
                    run('systemctl','disable','--now','beman.service')
                    legacy.unlink()
                    run('systemctl','daemon-reload')
                Console.say('SSH防护已撤销；系统SSH服务及依赖保留','ok')
                # Do not recursively delete: retain any unknown user files.
                for path in files:
                    if path!=STATE/'operation.lock': path.unlink(missing_ok=True)
                BIN.unlink(missing_ok=True)
                SELF.unlink()
                (STATE/'operation.lock').unlink(missing_ok=True)
                for directory in (logs,cache,STATE,ROOT):
                    if directory.is_dir() and not any(directory.iterdir()): directory.rmdir()
                if ROOT.exists(): Console.say('保留安装目录中非BeMan文件：'+str(ROOT),'warn')
                Console.say('BeMan 已卸载；建议保持当前SSH会话并测试新连接','ok')

    @staticmethod
    def status():
        with locked():
            c=ConfigManager.load()
            pending=SSHGuard.PENDING.exists()
            try:
                old=SSHGuard.owned()
                if old is None:
                    state,code=('待回滚 / 请检查','33') if pending else ('已停止','90')
                elif old!=SSHGuard.candidate(c):
                    state,code='规则已应用，配置待更新','33'
                else:
                    SSHGuard.inspect(); SSHGuard.verify(c)
                    active=run('systemctl','is-active','--quiet',SSH_SERVICE,check=False).returncode==0
                    state,code=('待确认','33') if pending else ('已启用','32') if active else ('SSH服务未运行','33')
                print('防护状态：'+Console.color(state,code))
            except (BemanError,OSError,ValueError,KeyError) as e:
                Console.say('防护状态异常：'+str(e),'error')
            print('允许用户：'+', '.join(c['allowed_users']))
            print('允许 IP：'+', '.join(c['allowed_ips']))
            print('SSH 端口：'+str(c['ssh_port']))
            if pending: Console.say('保留旧会话，从新白名单SSH会话再次启动确认','warn')

    @classmethod
    def main(cls):
        parser=argparse.ArgumentParser(description='BeMan SSH 安全管理')
        parser.add_argument('operation',nargs='?',default='menu',choices=['menu','start','stop','restart','status','logs','check-update','update','init','check','confirm','rollback','rollback-pending','apply','reload','uninstall'])
        parser.add_argument('--rollback-token',default='')
        parser.add_argument('--yes',action='store_true',help='明确确认卸载')
        args=parser.parse_args(); op=args.operation
        root_check()
        if op=='menu': Toolbox.menu(); return
        if op in ('start','restart','apply','reload'): cls.start(); return
        if op=='stop': cls.stop(); return
        if op=='uninstall': cls.uninstall(yes=args.yes); return
        if op=='status': cls.status(); return
        if op=='logs':
            print(run('journalctl','-u',SSH_SERVICE,'-n','50','--no-pager','--output=short-iso').stdout,end=''); return
        if op in ('check-update','update'): Release.update(check_only=op=='check-update'); return
        with locked():
            if op=='init': ConfigManager.init(); Console.say('配置已生成/迁移','ok')
            elif op=='check': ConfigManager.load(); Console.say('配置有效','ok')
            elif op=='confirm': SSHGuard.confirm()
            elif op=='rollback': SSHGuard.rollback()
            elif op=='rollback-pending':
                if SSHGuard.PENDING.exists() and read(SSHGuard.PENDING).get('token','')==args.rollback_token:
                    SSHGuard.restore_pending()


if __name__=='__main__':
    try:
        Beman.main()
    except (BemanError,OSError,ValueError,KeyError) as exc:
        print('错误：'+str(exc),file=sys.stderr); sys.exit(1)
