import os, sqlite3, time, json, hashlib, secrets, hmac, re, uuid
from pathlib import Path
from contextlib import contextmanager
from urllib.parse import urlsplit, urlunsplit
ROOT=Path(__file__).resolve().parent.parent
DB=Path(os.getenv('VIDEOHUB_DB',str(ROOT/'data/video.db')))
BACKUPS=Path(os.getenv('VIDEOHUB_BACKUPS',str(ROOT/'backups')))
NOW=lambda:int(time.time())
def connect():
    DB.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB,timeout=15); c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA busy_timeout=15000'); return c
@contextmanager
def db():
    c=connect()
    try:
        with c: yield c
    finally: c.close()
def rows(c,sql,args=()): return [dict(r) for r in c.execute(sql,args)]
def one(c,sql,args=()):
    r=c.execute(sql,args).fetchone(); return dict(r) if r else None
def init():
    with db() as c:
        c.execute('PRAGMA journal_mode=WAL'); c.executescript((ROOT/'backend/schema.sql').read_text())
        for k,v in [('site_name','VideoHub'),('site_description','Discover videos from the web'),('site_url','http://localhost:8080'),('seo_index','0'),('search_enabled','1'),('search_order','latest')]: c.execute('INSERT OR IGNORE INTO settings VALUES(?,?)',(k,v))
        # v1 credentials and schedules are obsolete; no site-local operator accounts or scheduler.
        c.execute('DROP TABLE IF EXISTS scheduled_tasks'); c.execute('DROP TABLE IF EXISTS admins'); c.execute("DELETE FROM settings WHERE key='session_secret'")
def audit(c,actor,action,entity='',detail=''):
    c.execute('INSERT INTO operation_logs(actor,action,entity_id,detail,created_at) VALUES(?,?,?,?,?)',(actor,action,str(entity),str(detail)[:500],NOW()))
def url(value):
    v=str(value or '').strip()
    if not v: return ''
    if len(v)>4096 or any(ord(x)<33 or ord(x)==127 for x in v) or '\\' in v: raise ValueError('Invalid URL')
    p=urlsplit(v)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password: raise ValueError('Only HTTP(S) URLs without credentials are allowed')
    if p.port not in (None,80,443): raise ValueError('Only ports 80/443 are allowed')
    host=p.hostname.lower().rstrip('.').encode('idna').decode('ascii')
    if ':' in host: host='['+host+']'
    return urlunsplit((p.scheme,host+((':'+str(p.port)) if p.port and p.port!=(443 if p.scheme=='https' else 80) else ''),p.path or '/',p.query,''))
def slugify(v): return re.sub(r'[^\w-]+','-',str(v).lower(),flags=re.UNICODE).strip('-_')[:100] or 'video'
def make_backup():
    BACKUPS.mkdir(parents=True,exist_ok=True); name=time.strftime('video-%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)+'.db'; dest=BACKUPS/name
    src=connect(); out=sqlite3.connect(dest)
    try: src.backup(out); assert out.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    finally: out.close(); src.close()
    os.chmod(dest,0o600); return name
