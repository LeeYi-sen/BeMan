#!/usr/bin/env python3
"""BeMan: lightweight SSH allowlist management."""
import argparse
import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
import json
import datetime
import secrets
import os
import pwd
import re
import shlex
import shutil
import subprocess
import stat
import sys
import syslog
import tempfile
import time
import urllib.request
from pathlib import Path

VERSION = '3'
DISPLAY_VERSION = 'v3.0'
ROOT = Path('/opt/beman')
SETTINGS = ROOT / 'settings.json'
STATE = ROOT / 'backups'
POLICY = Path('/etc/ssh/sshd_config.d/00-beman.conf')
SSHD = '/usr/sbin/sshd'
SSH_SERVICE = 'ssh.service'
ROLLBACK = 'beman-ssh-rollback'
ROLLBACK_SECONDS = 300
SELF = ROOT / 'beman.py'
BIN = Path('/usr/local/bin/beman')
INSTALL_LOCK = Path('/run/lock/beman-install.lock')
MANIFEST = ROOT/'manifest.json'


def manifest_data():
    # An inventory, not a user-editable list of paths to delete.
    return {'schema':1,'version':VERSION,
            'files':['beman.py','install.sh','settings.json','manifest.json',
                     'backups/operation.lock','backups/ssh-policy.json',
                     'backups/ssh-pending.json','backups/settings-before-simplification.json'],
            'external':[str(BIN),str(POLICY),str(UNIT_DIR/(ROLLBACK+'.service')),
                        str(UNIT_DIR/(ROLLBACK+'.timer'))],
            'legacy':['logs/beman.log','.beman.py.new','__pycache__/beman.*.pyc',
                      str(UNIT_DIR/'beman.service')],
            'retained':['system packages','system journal','global runtime install lock']}


def dependency_issues():
    issues=[]
    if sys.version_info<(3,10): issues.append('需要 Python 3.10+')
    for cmd in ('bash','wget','systemctl','journalctl','sha256sum','install','flock'):
        if not shutil.which(cmd): issues.append('缺少 '+cmd)
    if not os.access(SSHD,os.X_OK): issues.append('OpenSSH Server 不可用')
    try:
        if Path('/etc/ssl/certs/ca-certificates.crt').stat().st_size==0: issues.append('CA 证书为空')
    except OSError: issues.append('CA 证书缺失')
    return issues


def item(value, comment):
    return {'value': value, 'comment': comment}


DEFAULTS = {
    'allowed_users': item(['root'], '允许SSH登录的用户列表，必须使用公钥认证。'),
    'allowed_ips': item(['192.168.31.7', '', ''], '允许SSH登录的精确IPv4/IPv6地址，空值忽略。'),
}


class BemanError(Exception):
    pass


def need(condition, message):
    if not condition:
        raise BemanError(message)


def audit(operation, result):
    # Local system journal, not a resident BeMan logging process.
    try:
        syslog.openlog('beman',syslog.LOG_PID,syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_NOTICE,f'operation={operation} result={result} uid={os.getuid()} euid={os.geteuid()}')
    except (OSError,ValueError):
        print('警告：无法写入系统审计日志',file=sys.stderr)


def integrity_issues():
    # Diagnostic only: never prevent the administrator from stopping protection.
    issues=[]
    entries=[(ROOT,True,True),(STATE,True,True),(SELF,False,True),
             (ROOT/'install.sh',False,True),(SETTINGS,False,True),(MANIFEST,False,True),
             (STATE/'operation.lock',False,False),(SSHGuard.META,False,False),
             (SSHGuard.PENDING,False,False),(POLICY,False,False)]
    for path,directory,required in entries:
        try:
            st=path.lstat()
            if st.st_uid!=0 or st.st_mode & 0o022 or not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
                issues.append(str(path)+'：所有者、权限或文件类型异常')
        except FileNotFoundError:
            if required: issues.append(str(path)+'：缺失')
        except OSError:
            issues.append(str(path)+'：无法读取属性')
    try:
        if not BIN.is_symlink() or BIN.readlink()!=SELF:
            issues.append(str(BIN)+'：命令链接异常')
        installer=(ROOT/'install.sh').read_bytes()
        matches=re.findall(rb'^PYTHON_SHA256="([a-f0-9]{64})"$',installer,re.M)
        if len(matches)!=1 or hashlib.sha256(SELF.read_bytes()).hexdigest().encode()!=matches[0]:
            issues.append('本地主程序与安装器SHA256不一致')
        if Release.declared_version(installer,True)!=VERSION or Release.declared_version(SELF.read_bytes())!=VERSION:
            issues.append('本地版本声明不一致')
    except (BemanError,OSError,ValueError):
        issues.append('本地发布文件无法校验')
    try:
        if read(MANIFEST)!=manifest_data():
            issues.append('安装资源清单不一致')
    except (OSError,ValueError,KeyError):
        issues.append('安装资源清单无法读取')
    try:
        if SSHGuard.owned() is None and SSHGuard.META.exists():
            issues.append('SSH防护文件缺失但仍有管理记录，请检查实际SSH状态')
        if SSHGuard.PENDING.exists() and run('systemctl','is-active','--quiet',ROLLBACK+'.timer',check=False).returncode!=0:
            issues.append('待确认策略的回滚计时器未运行')
    except (BemanError,OSError,ValueError,KeyError):
        issues.append('SSH策略完整性无法确认')
    return issues


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
        # Preserve existing allowlists while dropping obsolete manual settings.
        if 'authentication' in old:
            need(not set(old).intersection(schema),'混合新旧配置格式，请人工检查')
            auth=old['authentication']; protection=old.get('protection',{})
            need(isinstance(auth,dict) and isinstance(protection,dict),'旧配置格式无效')
            need('allowed_users' in auth and 'allowed_ips' in auth,'旧白名单缺失，拒绝迁移')
            old={k:auth[k] for k in ('allowed_users','allowed_ips')}
        elif old:
            need(set(schema)<=set(old),'白名单配置缺失，拒绝恢复默认值')
            old={k:v for k,v in old.items() if k not in ('ssh_port','rollback_seconds')}
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


@contextlib.contextmanager
def file_lock(path,mode):
    fd=os.open(path,os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as f:
        st=os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and not st.st_mode&0o022,'锁文件权限或类型异常：'+str(path))
        fcntl.flock(f,mode)
        yield


@contextlib.contextmanager
def locked(installation_locked=False):
    # Serialize normal operations with installation/uninstallation. Keep the
    # global runtime lock so waiters never lock a different inode after removal.
    outer=contextlib.nullcontext() if installation_locked else file_lock(INSTALL_LOCK,fcntl.LOCK_SH)
    with outer:
        need(STATE.is_dir() and not STATE.is_symlink(),'BeMan状态目录异常')
        with file_lock(STATE/'operation.lock',fcntl.LOCK_EX):
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
    def ports():
        # The fourth SSH_CONNECTION field is the real server-side session port.
        conn=os.environ.get('SSH_CONNECTION','').split()
        if len(conn)==4 and conn[3].isdigit() and 1<=int(conn[3])<=65535:
            return conn[3]+'（当前SSH连接）'
        # At a local console, prefer live sshd listeners; otherwise label config only.
        try:
            output=run('ss','-ltnpH').stdout
            ports=set()
            for line in output.splitlines():
                fields=line.split()
                if len(fields)>=6 and re.search(r'"sshd(?:-session)?"',line):
                    port=fields[3].rsplit(':',1)[-1]
                    if port.isdigit() and 1<=int(port)<=65535: ports.add(int(port))
            if ports: return ', '.join(map(str,sorted(ports)))+'（实际监听）'
        except (BemanError,OSError):
            pass
        try:
            if run('systemctl','is-active','--quiet','ssh.socket',check=False).returncode==0:
                output=run('systemctl','show','ssh.socket','--property=Listen','--value').stdout
                ports={int(p) for p in re.findall(r':([0-9]+)\s+\(Stream\)',output) if 1<=int(p)<=65535}
                if ports: return ', '.join(map(str,sorted(ports)))+'（SSH socket）'
            output=run(SSHD,'-T').stdout
            ports={int(p) for p in re.findall(r'^port ([0-9]+)$',output,re.M) if 1<=int(p)<=65535}
            if ports: return ', '.join(map(str,sorted(ports)))+'（配置端口，实际监听未确认）'
        except (BemanError,OSError):
            pass
        return '未检测到'

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
                for x in ('pubkeyauthentication yes','authenticationmethods publickey','passwordauthentication no','kbdinteractiveauthentication no'):
                    need(x in lines,'SSH实际配置不符合预期：'+x)
                root_values={'permitrootlogin prohibit-password','permitrootlogin without-password'} if 'root' in a['allowed_users'] else {'permitrootlogin no'}
                need(bool(root_values.intersection(lines)),'root认证策略不一致')

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
        Console.say('已恢复应用前 SSH 策略','ok')

    @classmethod
    def apply(cls,c):
        need(not cls.PENDING.exists(),'存在未确认配置，请先confirm或rollback')
        need(run('systemctl','is-active','--quiet',SSH_SERVICE,check=False).returncode==0,'ssh.service未运行')
        a=c; conn=os.environ.get('SSH_CONNECTION',''); parts=conn.split()
        if conn:
            need(len(parts)==4 and str(ipaddress.ip_address(parts[0])) in a['allowed_ips'],'当前SSH来源不在新白名单，拒绝应用')
        for u in a['allowed_users']: pwd.getpwnam(u)
        cls.inspect(); run(SSHD,'-t'); old=cls.owned(); candidate=cls.candidate(c)
        Console.say('SSH 配置校验通过','ok')
        token=secrets.token_hex(16)
        dump(cls.PENDING,{'token':token,'previous':old,'candidate_hash':sha(candidate),'connection':conn,'users':a['allowed_users'],'ips':a['allowed_ips']})
        try:
            timer(ROLLBACK,ROLLBACK_SECONDS,'rollback-pending',token)
            Console.say('已建立临时回滚机制','ok')
        except Exception:
            cls.PENDING.unlink(); raise
        try:
            atomic(POLICY,candidate); dump(cls.META,{'hash':sha(candidate)})
            cls.verify(c); run('systemctl','reload',SSH_SERVICE)
        except Exception:
            cls.restore_pending(); raise
        Console.say('SSH 策略已应用','ok')
        Console.divider()
        Console.say('防护等待确认，回滚期限：'+str(ROLLBACK_SECONDS)+' 秒','warn')
        print('保留当前 SSH 会话，从白名单 IP 建立新连接后进入 beman，选择启动 / 确认防护。')

    @classmethod
    def confirm(cls):
        need(cls.PENDING.exists(),'没有待确认配置'); d=read(cls.PENDING)
        conn=os.environ.get('SSH_CONNECTION',''); p=conn.split(); user=os.environ.get('SUDO_USER') or pwd.getpwuid(os.getuid()).pw_name
        need(len(p)==4 and conn!=d['connection'] and str(ipaddress.ip_address(p[0])) in d['ips'] and user in d['users'],'请从白名单用户/IP的新SSH会话确认；sudo需保留SSH_CONNECTION')
        need(run('systemctl','is-active','--quiet',ROLLBACK+'.timer',check=False).returncode==0,'回滚计时器未运行')
        need(cls.owned() is not None and sha(POLICY.read_text())==d['candidate_hash'],'待确认策略已变化')
        run(SSHD,'-t'); cls.PENDING.unlink(); stop_timer(ROLLBACK); Console.say('SSH 策略已确认','ok')

    @classmethod
    def rollback(cls):
        if cls.PENDING.exists(): return cls.restore_pending()
        old=cls.owned()
        if old is None: Console.say('无 BeMan SSH 策略'); return
        POLICY.unlink()
        try: run(SSHD,'-t'); run('systemctl','reload',SSH_SERVICE)
        except Exception:
            atomic(POLICY,old); raise
        cls.META.unlink(missing_ok=True); Console.say('已撤销 BeMan 策略，其他 SSH 配置未修改','ok')


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
        print('\n'+cls.color('BeMan '+DISPLAY_VERSION+'  /  '+text,'1;36'))
        cls.divider()

    @classmethod
    def divider(cls):
        print(cls.color('─'*48,'90'))

    @staticmethod
    def clear():
        if sys.stdout.isatty() and os.environ.get('TERM') not in (None,'','dumb'):
            print('\033[2J\033[H',end='',flush=True)

    @staticmethod
    def ask(prompt):
        return input(prompt).strip()

    @classmethod
    def result(cls,label,detail,kind='ok'):
        colors={'ok':('32','通过'),'warn':('33','警告'),'error':('31','异常')}
        code,tag=colors[kind]
        print(cls.color('['+tag+']',code)+' '+label+'：'+detail)

    @classmethod
    def pause(cls,prompt='按 Enter 返回主菜单…'):
        cls.divider()
        cls.ask(prompt)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BemanError('发布地址发生重定向，拒绝继续')


class Release:
    # The official HTTPS domain is the only default client-side release source.
    BASE='https://beman.teadan.com'
    MAX_SIZE=2_000_000

    @staticmethod
    def version_key(version):
        need(re.fullmatch(r'[1-9][0-9]{0,8}(?:\.[1-9][0-9]{0,8})?',version) is not None,'版本号无效：'+version)
        parts=version.split('.')
        return int(parts[0]),int(parts[1]) if len(parts)==2 else 0

    @classmethod
    def declared_version(cls,data,installer=False):
        pattern=rb'^BEMAN_VERSION="([^"\r\n]*)"$' if installer else rb"^VERSION = '([^'\r\n]*)'$"
        matches=re.findall(pattern,data,re.M)
        need(len(matches)==1,'发布文件缺少唯一版本号')
        version=matches[0].decode('ascii')
        cls.version_key(version)
        return version

    @classmethod
    def fetch(cls,url):
        req=urllib.request.Request(url,headers={'Cache-Control':'no-cache','User-Agent':'BeMan-Updater'})
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=5) as response:
            need(response.geturl()==url,'更新地址发生重定向，拒绝继续')
            data=response.read(cls.MAX_SIZE+1)
        need(0<len(data)<=cls.MAX_SIZE,'发布文件为空或过大')
        return data

    @classmethod
    def inspect(cls):
        installer=cls.fetch(cls.BASE+'/install.sh')
        published=cls.declared_version(installer,installer=True)
        matches=re.findall(rb'^PYTHON_SHA256="([a-f0-9]{64})"$',installer,re.M)
        need(len(matches)==1,'安装器缺少唯一有效SHA256')
        digest=matches[0].decode()
        source=cls.fetch(cls.BASE+'/beman.py')
        need(hashlib.sha256(source).hexdigest()==digest,'发布文件SHA256不一致，可能尚未同步；请稍后重试')
        compile(source,str(SELF),'exec')
        need(cls.declared_version(source)==published,'安装器与Python版本不一致')
        local_source=SELF.read_bytes()
        local_version=cls.declared_version(local_source)
        saved=ROOT/'install.sh'
        same_installer=saved.is_file() and not saved.is_symlink() and saved.read_bytes()==installer
        same_source=hashlib.sha256(local_source).hexdigest()==digest
        if cls.version_key(published)==cls.version_key(local_version):
            need(same_source and same_installer,'同一版本的发布文件发生变化，请检查发布版本或重新下载安装器修复')
        return installer,digest,local_version,published

    @classmethod
    def update(cls,check_only=False,quiet=False):
        if not quiet: Console.say('正在检测官方发布…')
        installer,digest,local,published=cls.inspect()
        if not quiet or published!=local:
            print('本地版本：'+local)
            print('最新版本：'+published)
        if cls.version_key(published)<cls.version_key(local):
            if quiet: raise BemanError('发布版本低于本地版本，拒绝降级')
            Console.say('发布版本低于本地版本，拒绝自动降级','warn'); return False
        if published==local:
            if not quiet: Console.say('已是最新版本','ok')
            return False
        Console.say('发现新版本 '+published,'warn')
        if check_only: return False
        need(not SSHGuard.PENDING.exists(),'请先确认或停止SSH策略')
        with tempfile.TemporaryDirectory(prefix='beman-release-') as tmp:
            path=Path(tmp)/'install.sh'; path.write_bytes(installer); path.chmod(0o700)
            run('bash','-n',str(path))
            # The installer acquires its own install and operation locks.
            p=run('bash',str(path),cls.BASE,timeout=180)
            print(p.stdout,end='')
        need(hashlib.sha256(SELF.read_bytes()).hexdigest()==digest,'升级后版本校验失败')
        need((ROOT/'install.sh').read_bytes()==installer,'升级后安装器校验失败')
        Console.say('升级成功：'+local+' → '+published+'；白名单及SSH策略已保留','ok')
        return True


class Toolbox:
    @classmethod
    def startup(cls,skip_auto_update=False):
        Console.clear()
        Console.title('启动检测')
        Console.result('系统环境','Linux / systemd')
        dependencies=dependency_issues()
        issues=integrity_issues()
        if dependencies and not issues and not SSHGuard.PENDING.exists() and os.access(SSHD,os.X_OK) and shutil.which('apt-get'):
            try:
                # Do not automatically reinstall or start SSH, alter its policy,
                # or attempt to replace an incompatible system Python.
                if sys.version_info>=(3,10) and shutil.which('systemctl') and shutil.which('journalctl'):
                    Console.say('正在修复缺失依赖…')
                    with locked():
                        need(not SSHGuard.PENDING.exists(),'待确认期间不修复依赖')
                        run('bash',str(ROOT/'install.sh'),'--repair-dependencies',timeout=None)
                    dependencies=dependency_issues()
            except (BemanError,OSError,ValueError) as e:
                Console.result('依赖修复',str(e),'warn')
        Console.result('系统依赖','；'.join(dependencies) if dependencies else '满足运行要求','error' if dependencies else 'ok')
        Console.result('本地完整性','；'.join(issues) if issues else '未发现异常','error' if issues else 'ok')
        try:
            with locked(): ConfigManager.load()
            Console.result('白名单配置','有效')
        except (BemanError,OSError,ValueError,KeyError) as e:
            Console.result('白名单配置',str(e),'error')
        try:
            run(SSHD,'-t')
            active=run('systemctl','is-active','--quiet',SSH_SERVICE,check=False).returncode==0
            Console.result('SSH 服务','配置有效，服务运行' if active else '服务未运行','ok' if active else 'error')
        except (BemanError,OSError) as e:
            Console.result('SSH 服务',str(e),'error')
        state,code=Beman.summary()
        Console.result('安全策略',state,'error' if code=='31' else 'warn' if code=='33' else 'ok')
        if skip_auto_update:
            Console.result('版本检测','已完成本次升级')
        elif SSHGuard.PENDING.exists() or issues or dependencies:
            Console.result('版本检测','待确认或本地异常，跳过自动升级','warn')
        else:
            try:
                if Release.update(quiet=True):
                    sys.stdout.flush(); sys.stderr.flush()
                    os.execv(sys.executable,[sys.executable,str(SELF),'menu','--skip-auto-update'])
                Console.result('版本检测','最新版本')
            except (BemanError,OSError,ValueError,KeyError,SyntaxError,http.client.HTTPException) as e:
                Console.result('版本检测',str(e),'warn')
        Console.pause('按 Enter 进入管理工具箱…')

    @staticmethod
    def call(*args):
        p=subprocess.run([sys.executable,str(SELF),*args])
        if p.returncode: Console.say('操作未完成（退出码 '+str(p.returncode)+'）','error')
        return p.returncode==0

    @classmethod
    def whitelist(cls):
        while True:
            with locked():
                original=SETTINGS.read_text()
                data=ConfigManager.merge(DEFAULTS,json.loads(original))
                c=ConfigManager.unwrap(data); ConfigManager.validate(c)
            Console.clear()
            Console.title('白名单管理')
            for key,label in [('allowed_users','用户白名单'),('allowed_ips','IP 白名单')]:
                print(Console.color(label+'（'+str(len(c[key]))+'）','36'))
                for i,value in enumerate(c[key],1): print(f'  {i}. {value}')
                Console.divider()
            for label,color in [('[1] 添加 IP','34'),('[2] 删除 IP','31'),('[3] 添加用户','34'),('[4] 删除用户','31'),('[0] 返回主菜单','90')]:
                print(Console.color(label,color))
            Console.divider()
            choice=Console.ask('请选择 [0-4]：')
            if choice=='0': return
            if choice not in ('1','2','3','4'):
                Console.say('无效选项','warn')
                Console.ask('按 Enter 继续…')
                continue
            key='allowed_ips' if choice in ('1','2') else 'allowed_users'
            adding=choice in ('1','3')
            Console.clear()
            Console.title(('添加' if adding else '删除')+(' IP' if key=='allowed_ips' else '用户'))
            if not adding:
                for i,value in enumerate(c[key],1): print(f'  {i}. {value}')
                Console.divider()
            raw=Console.ask('输入要添加的'+('IP' if key=='allowed_ips' else '用户名')+'（空行取消）：' if adding else '输入要删除的编号（空行取消）：')
            if not raw: continue
            try:
                if adding:
                    value=ips([raw])[0] if key=='allowed_ips' else raw
                    need(value not in c[key],'已存在于白名单')
                    if key=='allowed_users':
                        need(user_valid(value),'用户名无效')
                        try: pwd.getpwnam(value)
                        except KeyError: raise BemanError('系统中不存在该用户')
                    c[key].append(value)
                else:
                    need(raw.isdecimal() and 1<=int(raw)<=len(c[key]),'无效编号')
                    need(len(c[key])>1,'至少保留一个白名单成员')
                    c[key].pop(int(raw)-1)
                ConfigManager.validate(c)
                with locked():
                    need(SETTINGS.read_text()==original,'配置已改变，请重新操作')
                    need(not SSHGuard.PENDING.exists(),'请先确认或停止待确认策略')
                    for k,v in c.items(): data[k]['value']=v
                    old=SSHGuard.owned()
                    atomic(SETTINGS,ConfigManager.format(data)+'\n')
                Console.say('白名单已保存','ok')
                audit('allowlist-change','success')
                if old is not None: Console.say('选择重启防护应用新规则，并从新SSH会话确认','warn')
            except (BemanError,ValueError,OSError,KeyError) as e:
                audit('allowlist-change','failed')
                Console.say(str(e),'error')
            Console.pause('按 Enter 返回白名单管理…')

    @classmethod
    def menu(cls,skip_auto_update=False):
        need(sys.stdin.isatty() and sys.stdout.isatty(),'非交互环境请指定命令，例如 beman status')
        try: cls.startup(skip_auto_update)
        except (EOFError,KeyboardInterrupt): return
        while True:
            Console.clear()
            state,code=Beman.summary()
            print('\n'+Console.color('BeMan '+DISPLAY_VERSION,'1;36')+'  /  '+Console.color(state,code))
            Console.divider()
            for label,code in [('1  启动 / 确认防护','32'),('2  停止防护','31'),('3  重启防护','33'),('4  查看状态','34'),('5  白名单管理','34'),('6  查看登录日志','34'),('7  一键卸载 BeMan','31'),('0  退出','90')]:
                print(Console.color('['+label[0]+']'+label[1:],code))
            Console.divider()
            try:
                choice=Console.ask('请选择 [0-7]：')
                if choice=='0': return
                if choice in ('1','2','3','4'):
                    Console.clear()
                    cls.call({'1':'start','2':'stop','3':'restart','4':'status'}[choice])
                elif choice=='5':
                    cls.whitelist()
                    continue
                elif choice=='6':
                    Console.clear()
                    cls.call('logs')
                elif choice=='7':
                    Console.clear()
                    Console.title('卸载 BeMan')
                    if Console.ask('确认撤销防护并删除 BeMan 程序、配置及自身备份？SSH 服务和系统依赖保留。[y/N]：').lower()=='y':
                        if cls.call('uninstall','--yes'): return
                    else: continue
                else: Console.say('无效选项','warn')
                Console.pause()
            except (EOFError,KeyboardInterrupt):
                print(); return
            except (BemanError,OSError,ValueError,KeyError) as e:
                Console.say(str(e),'error')
                try: Console.ask('按 Enter 返回主菜单…')
                except (EOFError,KeyboardInterrupt): return


class Beman:
    @staticmethod
    def start():
        with locked():
            c=ConfigManager.load()
            Console.say('白名单配置校验通过','ok')
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
            if SSHGuard.META.exists():
                # A missing policy on disk might still be active in sshd.
                run(SSHD,'-t')
                run('systemctl','reload',SSH_SERVICE)
                SSHGuard.META.unlink()
            Console.say('防护已停止，原SSH规则已恢复','ok')

    @staticmethod
    def uninstall(yes=False):
        if not yes:
            need(sys.stdin.isatty(),'非交互卸载需明确指定 --yes')
            if Console.ask('确认卸载 BeMan（删除程序、配置及自身备份；保留 SSH 与依赖）？[y/N]：').lower()!='y':
                Console.say('已取消卸载','warn'); return
        # Use the same lock order as install.sh; never remove the global install lock.
        with file_lock(INSTALL_LOCK,fcntl.LOCK_EX):
            need(ROOT.is_dir() and not ROOT.is_symlink() and STATE.is_dir() and not STATE.is_symlink(),'BeMan安装目录异常')
            need(SELF.is_file() and not SELF.is_symlink(),'BeMan主程序不存在或路径异常')
            need(not (STATE/'operation.lock').is_symlink(),'拒绝符号链接操作锁')
            with locked(installation_locked=True):
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
                files=[ROOT/'install.sh',SETTINGS,MANIFEST,STATE/'settings-before-simplification.json',STATE/'operation.lock',SSHGuard.META,SSHGuard.PENDING,logs/'beman.log',ROOT/'.beman.py.new']
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
                remaining=[p for p in [*files,BIN,SELF,POLICY,*units,legacy] if p.exists() or p.is_symlink()]
                need(not remaining,'卸载残留：'+', '.join(map(str,remaining)))
                Console.say('BeMan 自有资源残留检查通过','ok')
                if ROOT.exists(): Console.say('保留安装目录中非BeMan文件：'+str(ROOT),'warn')
                Console.say('BeMan 已卸载；建议保持当前SSH会话并测试新连接','ok')

    @staticmethod
    def protection_state(c):
        pending=SSHGuard.PENDING.exists()
        old=SSHGuard.owned()
        if old is None:
            if SSHGuard.META.exists(): return '策略文件缺失，请检查','31'
            return ('待回滚 / 请检查','33') if pending else ('已停止','90')
        if run('systemctl','is-active','--quiet',SSH_SERVICE,check=False).returncode!=0:
            return 'SSH服务未运行','33'
        if pending:
            return '待确认','33'
        if old!=SSHGuard.candidate(c):
            return '配置待应用','33'
        SSHGuard.inspect(); SSHGuard.verify(c)
        return '已开启','32'

    @classmethod
    def summary(cls):
        try:
            with locked(): return cls.protection_state(ConfigManager.load())
        except (BemanError,OSError,ValueError,KeyError):
            return '状态异常','31'

    @classmethod
    def status(cls):
        Console.title('防护状态')
        print('当前版本：'+DISPLAY_VERSION)
        with locked():
            c=ConfigManager.load()
            try:
                state,code=cls.protection_state(c)
                print('防护状态：'+Console.color(state,code))
            except (BemanError,OSError,ValueError,KeyError) as e:
                Console.say('防护状态异常：'+str(e),'error')
            active=run('systemctl','is-active','--quiet',SSH_SERVICE,check=False).returncode==0
            print('SSH 服务：'+Console.color('运行中' if active else '未运行','32' if active else '31'))
            print('SSH 端口：'+SSHGuard.ports())
            print('回滚时间：'+str(ROLLBACK_SECONDS)+' 秒（固定）')
            print('运行方式：OpenSSH 原生规则，无常驻 BeMan 进程')
            issues=integrity_issues()
            print('本地完整性：'+Console.color('存在异常' if issues else '未发现异常','31' if issues else '32'))
            for issue in issues: Console.say(issue,'warn')
            for key,label in [('allowed_users','用户白名单'),('allowed_ips','IP 白名单')]:
                Console.divider()
                print(Console.color(label+'（'+str(len(c[key]))+'）','36'))
                for i,value in enumerate(c[key],1): print(f'  {i}. {value}')
            if SSHGuard.PENDING.exists(): Console.say('保留旧会话，从新白名单SSH会话再次启动确认','warn')

    @classmethod
    def main(cls):
        parser=argparse.ArgumentParser(description='BeMan SSH 安全管理')
        parser.add_argument('operation',nargs='?',default='menu',choices=['menu','start','stop','restart','status','logs','audit','check-update','update','version','init','check','confirm','rollback','rollback-pending','apply','reload','uninstall'])
        parser.add_argument('--version',action='version',version='BeMan '+DISPLAY_VERSION)
        parser.add_argument('--rollback-token',default='')
        parser.add_argument('--yes',action='store_true',help='明确确认卸载')
        parser.add_argument('--skip-auto-update',action='store_true',help=argparse.SUPPRESS)
        args=parser.parse_args(); op=args.operation
        if op=='version': print('BeMan '+DISPLAY_VERSION); return
        root_check()
        if op=='menu': Toolbox.menu(skip_auto_update=args.skip_auto_update); return
        if op in ('start','restart','apply','reload'):
            Console.title('重启防护' if op in ('restart','reload') else '启动 / 确认防护'); cls.start(); return
        if op=='stop': Console.title('停止防护'); cls.stop(); return
        if op=='uninstall': cls.uninstall(yes=args.yes); return
        if op=='status': cls.status(); return
        if op=='logs':
            Console.title('SSH 登录日志')
            for line in run('journalctl','-u',SSH_SERVICE,'-n','50','--no-pager','--output=short-iso').stdout.splitlines():
                color='32' if 'Accepted ' in line else '31' if any(t in line for t in ('Failed password','Failed publickey','not allowed','Invalid user')) else '90' if 'Disconnected from' in line else '37'
                print(Console.color(line,color))
            Console.title('BeMan 操作审计')
            print(run('journalctl','-t','beman','-n','20','--no-pager','--output=short-iso').stdout,end=''); return
        if op=='audit':
            print(run('journalctl','-t','beman','-n','50','--no-pager','--output=short-iso').stdout,end=''); return
        if op in ('check-update','update'): Release.update(check_only=op=='check-update'); return
        with locked():
            if op=='init': ConfigManager.init(); Console.say('配置已生成/迁移','ok')
            elif op=='check':
                ConfigManager.load()
                issues=integrity_issues()
                for issue in issues: Console.say(issue,'warn')
                need(not issues,'本地完整性检查发现异常')
                Console.say('配置有效，本地完整性未发现异常','ok')
            elif op=='confirm': SSHGuard.confirm()
            elif op=='rollback': SSHGuard.rollback()
            elif op=='rollback-pending':
                if SSHGuard.PENDING.exists() and read(SSHGuard.PENDING).get('token','')==args.rollback_token:
                    SSHGuard.restore_pending()


if __name__=='__main__':
    try:
        op=sys.argv[1] if len(sys.argv)>1 else 'menu'
        sensitive=op in ('start','stop','restart','confirm','rollback','rollback-pending','apply','reload','uninstall','update','init')
        if sensitive: audit(op,'requested')
        Beman.main()
        if sensitive: audit(op,'returned')
    except (BemanError,OSError,ValueError,KeyError) as exc:
        if sensitive: audit(op,'failed')
        print('错误：'+str(exc),file=sys.stderr); sys.exit(1)
