#!/usr/bin/env python3
"""BeMan: Linux SSH allowlist, audit and reversible authorized incident response."""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import logging
import os
import pwd
import re
import shlex
import shutil
import stat
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
SERVICE = 'beman.service'
ROLLBACK = 'beman-ssh-rollback'
RELEASE = 'beman-network-release'
TABLE = 'beman_isolation'
SELF = ROOT / 'beman.py'


def item(value, comment):
    return {'value': value, 'comment': comment}


DEFAULTS = {
    'enabled': item(False, '总开关：由beman start/stop自动管理；直接修改此值不会应用或撤销SSH策略。'),
    'authentication': {
        'allowed_users': item(['root'], '允许SSH登录的本地用户列表；每个用户与白名单中所有IP组合匹配。'),
        'allowed_ips': item(['192.168.31.7', '', ''], '主IP及备用IP，支持任意数量的精确IPv4/IPv6地址，空值忽略，不支持网段。'),
        'ssh_port': item(22, '现有SSH监听端口，整数1至65535；仅用于验证及隔离规则，不改变监听端口。'),
        'public_key_only': item(True, '仅公钥认证；必须为true，以避免降低认证强度。'),
    },
    'network_isolation': {
        'enabled': item(True, 'true允许可信事件或明确授权触发网络隔离，false禁止新的隔离。'),
        'preserve_whitelist': item(True, '隔离时保留全部白名单IP的SSH通道和本地回环；必须为true，避免锁死。'),
        'auto_release_minutes': item(10, '自动解除隔离时间，整数1至60分钟；隔离将暂停其他网络业务。'),
    },
    'encrypted_storage': {
        'enabled': item(False, 'true允许正常卸载并关闭指定LUKS专用数据卷，false不操作磁盘。'),
        'volumes': item([], '专用LUKS卷数组，每项格式为{"name":"secure_data","mount":"/mnt/secure_data"}；仅允许/mnt或/srv下专用卷，不强制卸载、不删除数据或密钥。'),
    },
    'external_controller': {
        'enabled': item(False, 'true允许本机作为独立控制端发送SSH响应命令，false禁用。'),
        'allowed_ips': item([], '控制端源IP列表；为空继承authentication.allowed_ips，必须属于SSH白名单。'),
        'server_ip': item('', '目标被保护服务器的精确IP地址；在独立控制端上填写。'),
        'login_user': item('root', '控制端用于SSH登录目标的用户，必须属于目标白名单；非root需要预先配置sudo权限。'),
        'ssh_key': item('', '控制端已有SSH私钥绝对路径，留空使用系统SSH默认密钥；不生成或上传密钥。'),
    },
    'protection': {
        'rollback_seconds': item(300, '新SSH配置未确认时自动回滚时间，整数60至900秒；确认前保留原会话。'),
        'logging': item(True, 'true记录本地SSH认证及告警日志，false不写日志文件；不记录密码或私钥。'),
    },
    'update': {
        'python_url': item('', 'beman.py的HTTPS更新地址；也可以重新执行新版install.sh。'),
        'sha256': item('', '更新文件的可信SHA256值，64位十六进制；不自动信任远端提供的哈希。'),
    },
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
    def merge(schema, old, prefix=''):
        need(isinstance(old, dict), f'{prefix or "settings"}必须是对象')
        extra = set(old) - set(schema)
        need(not extra, f'未知配置字段：{prefix}{", ".join(sorted(extra))}')
        result = {}
        for k, v in schema.items():
            if 'value' in v and 'comment' in v:
                prev = old.get(k, v)
                need(isinstance(prev, dict) and 'value' in prev and set(prev) <= {'value', 'comment'}, f'{prefix}{k}须使用value/comment结构')
                result[k] = item(prev['value'], v['comment'])
            else:
                result[k] = ConfigManager.merge(v, old.get(k, {}), prefix+k+'.')
        return result

    @staticmethod
    def format(data, depth=0):
        lines = ['{']
        for k, v in data.items():
            key = json.dumps(k, ensure_ascii=False)
            val = json.dumps(v, ensure_ascii=False, separators=(', ', ': ')) if 'value' in v else ConfigManager.format(v, depth+1)
            lines.append('    '*(depth+1)+key+': '+val+',')
        if len(lines) > 1:
            lines[-1] = lines[-1][:-1]
        lines.append('    '*depth+'}')
        return '\n'.join(lines)

    @classmethod
    def init(cls, url='', digest=''):
        old = read(SETTINGS) if SETTINGS.exists() else {}
        data = cls.merge(DEFAULTS, old)
        if not old and url:
            data['update']['python_url']['value'] = url
            data['update']['sha256']['value'] = digest
        cfg = cls.unwrap(data)
        cls.validate(cfg)
        atomic(SETTINGS, cls.format(data)+'\n')
        return cfg

    @staticmethod
    def unwrap(data):
        return {k: v['value'] if 'value' in v else ConfigManager.unwrap(v) for k,v in data.items()}

    @classmethod
    def load(cls):
        cfg = cls.unwrap(cls.merge(DEFAULTS, read(SETTINGS)))
        cls.validate(cfg)
        return cfg

    @staticmethod
    def validate(c):
        def boolean(v, name):
            need(type(v) is bool, name+'必须为true或false')
        def integer(v, lo, hi, name):
            need(type(v) is int and lo <= v <= hi, f'{name}须为{lo}至{hi}的整数')
        boolean(c['enabled'], 'enabled')
        a = c['authentication']
        need(isinstance(a['allowed_users'], list) and a['allowed_users'] and all(user_valid(x) for x in a['allowed_users']), '用户名白名单无效')
        a['allowed_users'] = list(dict.fromkeys(a['allowed_users']))
        a['allowed_ips'] = ips(a['allowed_ips'])
        integer(a['ssh_port'], 1, 65535, 'ssh_port')
        need(a['public_key_only'] is True, '必须启用公钥认证')
        n = c['network_isolation']; boolean(n['enabled'], 'network_isolation.enabled')
        need(n['preserve_whitelist'] is True, '必须保留白名单管理通道')
        integer(n['auto_release_minutes'], 1, 60, 'auto_release_minutes')
        p = c['protection']; boolean(p['logging'], 'logging'); integer(p['rollback_seconds'], 60, 900, 'rollback_seconds')
        e = c['encrypted_storage']; boolean(e['enabled'], 'encrypted_storage.enabled')
        need(isinstance(e['volumes'], list), 'volumes必须为数组')
        names, mounts = set(), set()
        for v in e['volumes']:
            need(isinstance(v, dict) and set(v)=={'name','mount'}, '每个卷需要name和mount')
            need(isinstance(v['name'], str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*',v['name']), 'LUKS映射名称无效')
            m = v['mount']; need(isinstance(m, str) and re.fullmatch(r'/(mnt|srv)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*',m) and not {'.','..'}.intersection(m.split('/')), '只允许/mnt或/srv下专用挂载点')
            need(v['name'] not in names and m not in mounts, '重复加密卷'); names.add(v['name']); mounts.add(m)
        need(not e['enabled'] or bool(e['volumes']), '启用存储锁定前请填写专用LUKS卷')
        x = c['external_controller']; boolean(x['enabled'], 'external_controller.enabled')
        x['allowed_ips'] = ips(x['allowed_ips'], True)
        need(set(x['allowed_ips']) <= set(a['allowed_ips']), '控制端来源IP必须属于SSH白名单')
        need(user_valid(x['login_user']), '控制端用户格式无效')
        need(not x['enabled'] or x['login_user'] in a['allowed_users'], '控制端用户不在白名单')
        need(isinstance(x['server_ip'], str) and isinstance(x['ssh_key'], str), '控制端IP或密钥路径格式无效')
        if x['server_ip']:
            need('%' not in x['server_ip'], '不支持带区域标识的服务器IPv6地址')
            x['server_ip'] = str(ipaddress.ip_address(x['server_ip']))
        need(not x['enabled'] or bool(x['server_ip']), '启用控制端前请填写目标服务器IP')
        need(not x['ssh_key'] or Path(x['ssh_key']).is_absolute(), 'SSH密钥须为绝对路径')
        u=c['update']; need(isinstance(u['python_url'],str) and isinstance(u['sha256'],str), '更新参数格式无效')
        need(not u['python_url'] or u['python_url'].startswith('https://'), '更新地址必须使用HTTPS')
        need(not u['sha256'] or re.fullmatch(r'[a-fA-F0-9]{64}',u['sha256']), 'SHA256格式无效')


@contextlib.contextmanager
def locked():
    with open(STATE/'operation.lock','a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def timer(name, seconds, operation):
    run('systemd-run','--quiet','--unit='+name,'--on-active='+str(seconds)+'s','--timer-property=AccuracySec=1s',sys.executable,str(SELF),operation)


def stop_timer(name):
    run('systemctl','stop',name+'.timer',check=False)


def audit(message):
    print(message)
    try:
        run('logger','-t','beman','--',message,check=False)
    except BemanError:
        pass


def root_check():
    need(os.geteuid()==0, '服务器端需要root权限')
    need(Path('/run/systemd/system').is_dir(), '需要正在运行的systemd Linux')


class SSHGuard:
    META = STATE/'ssh-policy.json'
    PENDING = STATE/'ssh-pending.json'

    @staticmethod
    def pattern(c):
        a=c['authentication']
        return [f'{u}@{ip}/{ipaddress.ip_address(ip).max_prefixlen}' for u in a['allowed_users'] for ip in a['allowed_ips']]

    @classmethod
    def candidate(cls,c):
        return '# Managed by Beman\nAllowUsers '+' '.join(cls.pattern(c))+'\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin '+('prohibit-password' if 'root' in c['authentication']['allowed_users'] else 'no')+'\n'

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
        a=c['authentication']; expected=set(cls.pattern(c))
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
        need(c['enabled'],'请先在settings.json启用总开关')
        need(not cls.PENDING.exists(),'存在未确认配置，请先confirm或rollback')
        need(run('systemctl','is-active','--quiet',SSH_SERVICE,check=False).returncode==0,'ssh.service未运行')
        a=c['authentication']; conn=os.environ.get('SSH_CONNECTION',''); parts=conn.split()
        if conn:
            need(len(parts)==4 and str(ipaddress.ip_address(parts[0])) in a['allowed_ips'],'当前SSH来源不在新白名单，拒绝应用')
        for u in a['allowed_users']: pwd.getpwnam(u)
        cls.inspect(); run(SSHD,'-t'); old=cls.owned(); candidate=cls.candidate(c)
        dump(cls.PENDING,{'previous':old,'candidate_hash':sha(candidate),'connection':conn,'users':a['allowed_users'],'ips':a['allowed_ips']})
        try: timer(ROLLBACK,c['protection']['rollback_seconds'],'rollback-pending')
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


class NetworkGuard:
    OWN=STATE/'network-owned.json'

    @staticmethod
    def active():
        data=json.loads(run('nft','-j','list','tables').stdout)
        return any(x.get('table',{}).get('family')=='inet' and x['table'].get('name')==TABLE for x in data.get('nftables',[]))

    @staticmethod
    def rules(c):
        a=c['authentication']; port=a['ssh_port']; ins=[]; outs=[]
        for version,family in ((4,'ip'),(6,'ip6')):
            addresses=[x for x in a['allowed_ips'] if ipaddress.ip_address(x).version==version]
            if not addresses: continue
            s='{ '+', '.join(addresses)+' }'
            if version==6:
                ins.append('icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept')
                outs.append('icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept')
            ins.append(f'{family} saddr {s} tcp dport {port} accept')
            outs.append(f'{family} daddr {s} tcp sport {port} ct state established accept')
        return f'table inet {TABLE} {{\n chain input {{ type filter hook input priority -150; policy drop;\n iifname "lo" accept\n '+ '\n '.join(ins)+'\n }\n chain output { type filter hook output priority -150; policy drop;\n oifname "lo" accept\n '+'\n '.join(outs)+'\n }\n chain forward { type filter hook forward priority -150; policy drop; }\n}\n'

    @classmethod
    def isolate(cls,c):
        need(c['enabled'] and c['network_isolation']['enabled'],'未启用网络隔离')
        need(not SSHGuard.PENDING.exists() and SSHGuard.owned() is not None,'必须先应用并确认SSH策略')
        SSHGuard.verify(c)
        conn=os.environ.get('SSH_CONNECTION','').split()
        if conn: need(len(conn)==4 and str(ipaddress.ip_address(conn[0])) in c['authentication']['allowed_ips'] and int(conn[3])==c['authentication']['ssh_port'],'当前连接不符合管理白名单')
        if cls.active():
            need(cls.OWN.exists(),'同名nft表不属于Beman'); print('隔离已启用，不延长计时器'); return
        need(not cls.OWN.exists(),'存在未清理隔离状态，请先release')
        rules=cls.rules(c); run('nft','-c','-f','-',input=rules)
        timer(RELEASE,c['network_isolation']['auto_release_minutes']*60,'release')
        dump(cls.OWN,{'created':time.time()})
        try: run('nft','-f','-',input=rules)
        except Exception:
            cls.release(); raise
        audit('网络隔离启用：保留白名单SSH、回环及必要IPv6邻居发现；其他网络业务暂停，到期自动解除。')

    @classmethod
    def release(cls):
        if not cls.OWN.exists():
            if shutil.which('nft'): need(not cls.active(),'同名表不属于Beman，拒绝删除')
            print('无Beman隔离状态'); return
        if cls.active(): run('nft','delete','table','inet',TABLE)
        cls.OWN.unlink(); stop_timer(RELEASE); audit('网络隔离已解除；不自动解锁存储')


class StorageGuard:
    @staticmethod
    def lock(c):
        need(c['enabled'] and c['encrypted_storage']['enabled'],'未启用专用LUKS存储锁定')
        for v in c['encrypted_storage']['volumes']:
            name,mount=v['name'],v['mount']; dev=Path('/dev/mapper')/name
            if not dev.exists(): print(f'{name} 未打开，跳过'); continue
            need(stat.S_ISBLK(dev.stat().st_mode),'映射不是块设备')
            need(re.search(r'^\s*type:\s+LUKS[12]\s*$',run('cryptsetup','status',name).stdout,re.M),'映射不是LUKS')
            need(Path(mount).resolve(strict=True)==Path(mount),'挂载点包含符号链接或不存在')
            mm=run('lsblk','-dnro','MAJ:MIN',str(dev)).stdout.strip()
            need(re.fullmatch(r'\d+:\d+',mm),'设备编号异常')
            need(run('lsblk','-nr','-o','MAJ:MIN',str(dev)).stdout.split()==[mm],'映射有下游设备，拒绝操作')
            root=run('findmnt','-nro','MAJ:MIN','--mountpoint','/').stdout.strip(); need(mm!=root,'禁止根文件系统')
            rows=[line.split(maxsplit=1) for line in run('findmnt','-rn','-o','MAJ:MIN,TARGET').stdout.splitlines()]
            found=[row[1] for row in rows if len(row)==2 and row[0]==mm]
            if found:
                need(found==[mount],'存在其他挂载位置或绑定挂载，拒绝操作')
                need(run('findmnt','-Rrn','-o','TARGET','--mountpoint',mount).stdout.splitlines()==[mount],'存在子挂载点，拒绝操作')
                run('umount','--',mount)
            else:
                need(not any(len(row)==2 and row[1]==mount for row in rows),'挂载点属于其他设备')
            run('cryptsetup','close',name); audit(f'已正常关闭LUKS映射 {name}；需管理员手动解锁及挂载')


class ExternalController:
    @staticmethod
    def send(c,op):
        x=c['external_controller']; a=c['authentication']; need(x['enabled'],'未启用独立控制端')
        allowed=x['allowed_ips'] or a['allowed_ips']
        need(bool(allowed),'控制端无源地址')
        route=run('ip','-j','route','get',x['server_ip']).stdout
        rows=json.loads(route); src=rows[0].get('prefsrc') or rows[0].get('src')
        need(src and str(ipaddress.ip_address(src)) in allowed,'实际路由源IP不在控制端白名单')
        args=['ssh','-T','-b',src,'-p',str(a['ssh_port']),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ControlMaster=no','-o','ControlPath=none']
        if x['ssh_key']: args+=['-i',x['ssh_key'],'-o','IdentitiesOnly=yes']
        command=('/usr/local/bin/beman ' if x['login_user']=='root' else 'sudo -n /usr/local/bin/beman ')+op
        if op!='status': command+=' --authorized-incident'
        p=run(*args,x['login_user']+'@'+x['server_ip'],command,timeout=90); print(p.stdout,end='')

    @staticmethod
    def event(c):
        # Local trusted audit integration; never expose as a network endpoint.
        need(c['external_controller']['enabled'], '未启用独立控制端')
        raw=sys.stdin.read(8193); need(len(raw)<=8192,'事件过大'); e=json.loads(raw)
        need(isinstance(e,dict),'事件格式错误')
        if e.get('event')!='ssh_login_accepted' or e.get('server_ip')!=c['external_controller']['server_ip']:
            print('事件不匹配，忽略'); return
        ts=e.get('timestamp'); need(type(ts) in (int,float) and -5<=time.time()-ts<=60,'事件过期或时间无效')
        user=e.get('user'); need(user_valid(user),'事件用户无效'); addr=str(ipaddress.ip_address(e.get('source_ip')))
        a=c['authentication']
        if user in a['allowed_users'] and addr in a['allowed_ips']: print('合法登录，忽略'); return
        ExternalController.send(c,'respond')


class LoginMonitor:
    ACCEPTED=re.compile(r'Accepted \S+ for (\S+) from (\S+) port \d+')

    @staticmethod
    def log(c, message):
        print(message,flush=True)
        if c['protection']['logging']:
            logging.warning(message)

    @classmethod
    def watch(cls):
        with locked():
            if SSHGuard.PENDING.exists():
                if run('systemctl','is-active','--quiet',ROLLBACK+'.timer',check=False).returncode!=0:
                    SSHGuard.restore_pending()
            if NetworkGuard.OWN.exists() and run('systemctl','is-active','--quiet',RELEASE+'.timer',check=False).returncode!=0:
                NetworkGuard.release()
        p=subprocess.Popen(['journalctl','-f','-n','0','-o','json','-u',SSH_SERVICE],stdout=subprocess.PIPE,text=True)
        try:
            for line in p.stdout:
                try:
                    data=json.loads(line); match=cls.ACCEPTED.search(data.get('MESSAGE',''))
                    if not match: continue
                    c=ConfigManager.load(); user,ip=match.groups(); ip=str(ipaddress.ip_address(ip)); a=c['authentication']
                    if c['enabled'] and (user not in a['allowed_users'] or ip not in a['allowed_ips']):
                        cls.log(c,f'警报：SSH成功认证不符合白名单 user={user} ip={ip}；需可信外部事件核验')
                    else: cls.log(c,f'SSH成功认证 user={user} ip={ip}')
                except (ValueError, BemanError) as e:
                    print('审计记录或配置无效：'+str(e),file=sys.stderr,flush=True)
            raise BemanError('journalctl监控已退出')
        finally:
            p.terminate(); p.wait(timeout=5)


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


class Release:
    # The official repository is the trust root; Pages is the delivery endpoint.
    BASE='https://beman.teadan.com'
    SOURCE='https://raw.githubusercontent.com/LeeYi-sen/BeMan/main'
    MAX_SIZE=2_000_000

    @classmethod
    def fetch(cls,url):
        req=urllib.request.Request(url,headers={'Cache-Control':'no-cache','User-Agent':'BeMan-Updater'})
        with urllib.request.urlopen(req,timeout=20) as response:
            need(response.geturl()==url,'更新地址发生重定向，拒绝继续')
            data=response.read(cls.MAX_SIZE+1)
        need(0<len(data)<=cls.MAX_SIZE,'发布文件为空或过大')
        return data

    @classmethod
    def inspect(cls):
        installer=cls.fetch(cls.BASE+'/install.sh')
        official=cls.fetch(cls.SOURCE+'/install.sh')
        need(installer==official,'Pages 与 GitHub 发布版本不一致，请稍后重试')
        matches=re.findall(rb'^PYTHON_SHA256="([a-f0-9]{64})"$',installer,re.M)
        need(len(matches)==1,'安装器缺少唯一有效SHA256')
        digest=matches[0].decode()
        source=cls.fetch(cls.BASE+'/beman.py')
        need(hashlib.sha256(source).hexdigest()==digest,'Python主程序校验失败')
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
        need(not SSHGuard.PENDING.exists() and not NetworkGuard.OWN.exists(),'请先确认SSH策略并解除隔离')
        with tempfile.TemporaryDirectory(prefix='beman-release-') as tmp:
            path=Path(tmp)/'install.sh'; path.write_bytes(installer); path.chmod(0o700)
            run('bash','-n',str(path))
            # Do not hold operation.lock: the installer invokes beman init.
            p=run('bash',str(path),cls.BASE,timeout=180)
            print(p.stdout,end='')
        need(hashlib.sha256(SELF.read_bytes()).hexdigest()==digest,'升级后版本校验失败')
        need((ROOT/'install.sh').read_bytes()==installer,'升级后安装器校验失败')
        Console.say('升级完成；原配置和服务启停状态已保留','ok')
        return True


class Toolbox:
    @staticmethod
    def call(*args):
        # Dispatch through the same validated CLI, not a second implementation.
        p=subprocess.run([sys.executable,str(SELF),*args])
        if p.returncode: Console.say('操作未完成（退出码 '+str(p.returncode)+'）','error')
        return p.returncode==0

    @classmethod
    def edit(cls, group, fields):
        with locked():
            original=SETTINGS.read_text()
            data=ConfigManager.merge(DEFAULTS,json.loads(original))
        while True:
            Console.title(group)
            for i,(path,label) in enumerate(fields,1):
                node=data
                for key in path.split('.'): node=node[key]
                print(f'[{i}] {label}: {json.dumps(node["value"],ensure_ascii=False)}')
            print('[s] 保存  [0] 返回（放弃未保存修改）')
            choice=Console.ask('请选择：')
            if choice=='0': return
            if choice.lower()=='s':
                try:
                    with locked():
                        need(SETTINGS.read_text()==original,'配置已被其他进程修改，请重新进入菜单')
                        need(not SSHGuard.PENDING.exists(),'请先确认或停止待确认策略')
                        need(not NetworkGuard.OWN.exists(),'隔离期间禁止修改配置，请先解除隔离')
                        ConfigManager.validate(ConfigManager.unwrap(data))
                        atomic(SETTINGS,ConfigManager.format(data)+'\n')
                    Console.say('配置已保存；SSH规则变更请执行重启，并从新会话确认','ok')
                    return
                except (BemanError,ValueError,OSError,KeyError) as e:
                    Console.say(str(e),'error')
                continue
            if not choice.isdigit() or not 1<=int(choice)<=len(fields):
                Console.say('无效选项','warn'); continue
            path,label=fields[int(choice)-1]; node=data
            for key in path.split('.'): node=node[key]
            current=node['value']
            if path in ('authentication.allowed_users','authentication.allowed_ips'):
                raw=Console.ask('输入完整名单（多个值用空格或逗号分隔，空行取消）：')
            elif type(current) is bool:
                raw=Console.ask('输入 y 启用 / n 关闭（空行取消）：')
            elif type(current) is int:
                raw=Console.ask('输入数字（空行取消）：')
            else:
                raw=Console.ask('输入JSON数组（空行取消）：')
            if not raw: continue
            try:
                if path in ('authentication.allowed_users','authentication.allowed_ips'):
                    value=list(dict.fromkeys(re.split(r'[\s,]+',raw)))
                elif type(current) is bool:
                    need(raw.lower() in ('y','n'),'请输入 y 或 n')
                    value=raw.lower()=='y'
                elif type(current) is int:
                    value=int(raw)
                else:
                    value=json.loads(raw)
                need(type(value)==type(node['value']),'值类型与原配置不同')
                node['value']=value
            except (ValueError,BemanError) as e: Console.say(str(e),'error')

    @classmethod
    def whitelist(cls):
        cls.edit('白名单管理',[('authentication.allowed_users','允许用户'),('authentication.allowed_ips','允许IP'),('authentication.ssh_port','SSH端口')])

    @classmethod
    def settings(cls):
        cls.edit('安全配置',[('network_isolation.enabled','允许网络隔离'),('network_isolation.auto_release_minutes','隔离分钟'),('protection.rollback_seconds','回滚秒数'),('protection.logging','文件日志'),('encrypted_storage.enabled','专用LUKS卷锁定'),('encrypted_storage.volumes','专用LUKS卷列表')])

    @classmethod
    def advanced(cls):
        Console.title('高级工具')
        print('[1] 检查配置  [2] 回滚SSH  [3] 解除隔离\n[4] 授权网络隔离  [5] 授权锁定专用LUKS卷\n[0] 返回')
        choice=Console.ask('请选择：')
        operations={'1':'check','2':'rollback','3':'release','4':'isolate','5':'lock-storage'}
        if choice not in operations: return
        op=operations[choice]
        if choice in ('2','3','4','5'):
            if Console.ask('确认执行 '+op+'？输入 YES：')!='YES':
                Console.say('已取消','warn'); return
        cls.call(op,*(['--authorized-incident'] if choice in ('4','5') else []))

    @classmethod
    def menu(cls):
        need(sys.stdin.isatty() and sys.stdout.isatty(),'非交互环境请指定命令，例如 beman status')
        while True:
            Console.title('Security Toolbox  ·  Linux服务器安全管理')
            cls.call('status')
            print(Console.color('─'*48,'90'))
            for label,code in [('1  启动 / 确认防护','32'),('2  停止防护','31'),('3  重启防护','33'),('4  查看状态','36'),('5  白名单管理','36'),('6  安全配置','36'),('7  安全日志','36'),('8  高级工具','36'),('9  检测并自动升级','36'),('0  退出','90')]:
                print(Console.color('['+label[0]+']'+label[1:],code))
            try:
                choice=Console.ask('请选择 [0-9]：')
                if choice=='0': return
                if choice in ('1','2','3','4'):
                    cls.call({'1':'start','2':'stop','3':'restart','4':'status'}[choice])
                elif choice=='5': cls.whitelist()
                elif choice=='6': cls.settings()
                elif choice=='7':
                    subprocess.run(['journalctl','-u',SERVICE,'-n','50','--no-pager'])
                elif choice=='8': cls.advanced()
                elif choice=='9':
                    if Console.ask('从官方渠道检测并自动安装新版？输入 YES：')=='YES':
                        cls.call('update')
                        Console.say('如已升级，请退出并重新运行 beman')
                else: Console.say('无效选项','warn')
                Console.ask('按 Enter 返回主菜单…')
            except (EOFError,KeyboardInterrupt):
                print(); return
            except (BemanError,OSError,ValueError,KeyError) as e:
                Console.say(str(e),'error')


class Beman:
    @staticmethod
    def set_enabled(value):
        data=ConfigManager.merge(DEFAULTS,read(SETTINGS))
        data['enabled']['value']=value
        atomic(SETTINGS,ConfigManager.format(data)+'\n')

    @classmethod
    def start(cls,restart=False):
        with locked():
            c=ConfigManager.load(); c['enabled']=True
            candidate=SSHGuard.candidate(c)
            old=SSHGuard.owned()
            pending=SSHGuard.PENDING.exists()
            need(old==candidate or not NetworkGuard.OWN.exists(),'网络隔离期间不能修改SSH白名单，请先执行beman stop或release')
            created=False
            try:
                if pending:
                    need(old==candidate,'待确认期间配置已变化，请先执行beman stop或rollback')
                    SSHGuard.verify(c)
                elif old==candidate:
                    SSHGuard.inspect(); SSHGuard.verify(c)
                else:
                    SSHGuard.apply(c); created=True
                run('systemctl','enable','--now',SERVICE)
                if restart:
                    run('systemctl','restart',SERVICE)
                if pending:
                    SSHGuard.confirm()
                cls.set_enabled(True)
            except Exception:
                if created and SSHGuard.PENDING.exists():
                    SSHGuard.restore_pending()
                raise
            if SSHGuard.PENDING.exists():
                Console.say('防护临时启用。保留当前会话，从白名单IP新建SSH连接，再执行 beman start 确认。','warn')
            else:
                Console.say('防护已启用','ok')

    @classmethod
    def stop(cls):
        with locked():
            # Restore the original rules even if apply was updating an older confirmed policy.
            errors=[]
            try:
                NetworkGuard.release()
            except Exception as e:
                errors.append('解除网络隔离失败：'+str(e))
            try:
                SSHGuard.rollback()
                if POLICY.exists(): SSHGuard.rollback()
                need(not POLICY.exists() and not SSHGuard.PENDING.exists(),'SSH策略仍存在')
            except Exception as e:
                errors.append('撤销SSH策略失败：'+str(e))
            need(not errors,'；'.join(errors)+'；守护服务保留，请检查后重试stop')
            run('systemctl','disable','--now',SERVICE)
            try:
                cls.set_enabled(False)
            except (OSError,ValueError,KeyError,BemanError) as e:
                print('防护已停止，但配置开关写入失败：'+str(e),file=sys.stderr)
            Console.say('防护已停止，原SSH规则已恢复；加密数据卷不自动解锁。','ok')

    @staticmethod
    def status():
        service=run('systemctl','is-active',SERVICE,check=False).stdout.strip()
        pending=SSHGuard.PENDING.exists()
        try:
            c=ConfigManager.load()
            if POLICY.exists():
                owned=SSHGuard.owned()
                need(owned==SSHGuard.candidate(c),'当前策略与配置不一致，请重新启动防护')
                SSHGuard.inspect(); SSHGuard.verify(c)
                policy='待确认（临时生效）' if pending else '已应用'
            else:
                policy='未应用'
            if pending: state='待确认'
            elif policy=='已应用' and service=='active' and c['enabled']: state='运行中'
            elif policy=='未应用' and not NetworkGuard.OWN.exists(): state='未启动（仅审计）' if service=='active' else '已停止'
            else: state='部分生效 / 请检查'
            print('防护状态：',Console.color(state,'32' if state=='运行中' else '90' if state=='已停止' else '33'))
            print('总开关：',c['enabled'])
            print('白名单：',c['authentication']['allowed_users'],c['authentication']['allowed_ips'])
            print('SSH策略：',Console.color(policy,'32' if policy=='已应用' else '33' if pending else '90'))
            print('存储卷：',[(v['name'],(Path('/dev/mapper')/v['name']).exists()) for v in c['encrypted_storage']['volumes']])
        except (OSError,ValueError,KeyError,BemanError) as e:
            print('防护状态：异常；',str(e))
            print('SSH策略文件：','存在' if POLICY.exists() else '不存在')
        print('待确认：',pending)
        print('隔离状态记录：',NetworkGuard.OWN.exists())
        print('守护服务：',Console.color(service,'32' if service=='active' else '90'))

    @staticmethod
    def respond(c):
        if c['network_isolation']['enabled']: NetworkGuard.isolate(c)
        if c['encrypted_storage']['enabled']: StorageGuard.lock(c)
        need(c['network_isolation']['enabled'] or c['encrypted_storage']['enabled'], '没有启用任何响应模块')

    @staticmethod
    def update(c):
        need(not SSHGuard.PENDING.exists() and not NetworkGuard.OWN.exists(),'请先确认SSH策略并解除隔离')
        u=c['update']; need(u['python_url'] and u['sha256'],'请设置HTTPS更新地址及可信SHA256，或重新运行新版install.sh')
        with urllib.request.urlopen(u['python_url'],timeout=30) as response:
            need(response.geturl().startswith('https://'),'拒绝非HTTPS重定向'); data=response.read(2_000_001)
        need(len(data)<=2_000_000 and hashlib.sha256(data).hexdigest()==u['sha256'].lower(),'更新文件过大或SHA256不匹配')
        source=data.decode('utf-8'); compile(source,str(SELF),'exec')
        previous=SELF.read_text(); previous_settings=SETTINGS.read_text()
        atomic(SELF,source,0o700)
        try:
            run(sys.executable,str(SELF),'check')
        except Exception:
            atomic(SELF,previous,0o700); atomic(SETTINGS,previous_settings); raise
        print('更新文件已校验并替换；请执行beman restart以重新载入守护程序。')

    @classmethod
    def main(cls):
        parser=argparse.ArgumentParser(description='Beman SSH安全守护程序')
        parser.add_argument('operation',nargs='?',default='menu',choices=['menu','init','check','apply','reload','confirm','rollback','rollback-pending','status','start','stop','restart','monitor','isolate','release','lock-storage','respond','controller','controller-event','check-update','update','update-pinned','uninstall'])
        parser.add_argument('remote_operation',nargs='?',choices=['status','isolate','release','lock-storage','respond'])
        parser.add_argument('--authorized-incident',action='store_true'); parser.add_argument('--trusted-source',action='store_true'); parser.add_argument('--url',default=''); parser.add_argument('--sha256',default='')
        args=parser.parse_args(); op=args.operation
        if op=='controller' or op=='controller-event':
            c=ConfigManager.load()
            if op=='controller-event':
                need(args.trusted_source and os.geteuid()==0,'仅可信本地root审计程序可提交事件'); ExternalController.event(c)
            else:
                remote=args.remote_operation or 'status'; need(remote=='status' or args.authorized_incident,'需要明确授权 --authorized-incident'); ExternalController.send(c,remote)
            return
        root_check()
        if op=='menu': Toolbox.menu(); return
        if op in ('check-update','update'): Release.update(check_only=op=='check-update'); return
        if op=='monitor':
            logging.basicConfig(filename=ROOT/'logs/beman.log',level=logging.WARNING,format='%(asctime)s %(message)s'); LoginMonitor.watch(); return
        if op=='check':
            ConfigManager.load(); print('配置有效'); return
        if op in ('start','restart'):
            cls.start(restart=op=='restart'); return
        if op=='stop':
            cls.stop(); return
        if op=='uninstall':
            cls.stop(); print('保留/opt/beman、配置及日志供审计。'); return
        with locked():
            if op=='init': ConfigManager.init(args.url,args.sha256); print('配置已生成/合并：'+str(SETTINGS)); return
            if op=='rollback-pending': SSHGuard.restore_pending(); return
            if op=='rollback': SSHGuard.rollback(); return
            if op=='release': NetworkGuard.release(); return
            if op=='confirm': SSHGuard.confirm(); return
            c=ConfigManager.load()
            if op=='status': cls.status(); return
            if op in ('apply','reload'): SSHGuard.apply(c); return
            if op=='update-pinned': cls.update(c); return
            need(args.authorized_incident,'安全响应需要明确授权 --authorized-incident')
            if op=='isolate': NetworkGuard.isolate(c)
            elif op=='lock-storage': StorageGuard.lock(c)
            elif op=='respond': cls.respond(c)


if __name__=='__main__':
    try:
        Beman.main()
    except (BemanError, OSError, ValueError, KeyError) as exc:
        print('错误：'+str(exc),file=sys.stderr); sys.exit(1)
