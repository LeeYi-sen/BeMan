import os,sqlite3,time,json,secrets,hashlib,hmac
from pathlib import Path
from contextlib import contextmanager
from cryptography.fernet import Fernet
ROOT=Path(__file__).resolve().parent.parent
DB=Path(os.getenv('MC_DB',str(ROOT/'data/management.db')))
BACKUPS=Path(os.getenv('MC_BACKUPS',str(ROOT/'backups')))
now=lambda:int(time.time())
@contextmanager
def db():
    DB.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB,timeout=15); c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA busy_timeout=15000')
    try:
        with c: yield c
    finally: c.close()
def rows(c,s,args=()): return [dict(r) for r in c.execute(s,args)]
def one(c,s,args=()):
    r=c.execute(s,args).fetchone(); return dict(r) if r else None
def cipher():
    key=os.getenv('MC_MASTER_KEY','')
    if len(key)<32: raise RuntimeError('MC_MASTER_KEY must be at least 32 characters')
    import base64
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(('site-credentials:'+key).encode()).digest()))
def encrypt(s): return cipher().encrypt(s.encode()).decode()
def decrypt(s): return cipher().decrypt(s.encode()).decode()
def init():
    cipher()
    if len(os.getenv('MC_PASSWORD',''))<12: raise RuntimeError('MC_PASSWORD must be at least 12 characters')
    with db() as c:
        c.execute('PRAGMA journal_mode=WAL'); c.executescript('''
        CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY,name TEXT NOT NULL,base_url TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,secret_enc TEXT NOT NULL,region TEXT DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,last_seen INTEGER,last_status TEXT DEFAULT 'unknown',last_error TEXT DEFAULT '',last_dashboard TEXT DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY,site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,kind TEXT NOT NULL,payload TEXT NOT NULL DEFAULT '{}',status TEXT NOT NULL DEFAULT 'queued',created_at INTEGER NOT NULL,started_at INTEGER,finished_at INTEGER,result TEXT DEFAULT '',error TEXT DEFAULT '',schedule_id INTEGER REFERENCES schedules(id) ON DELETE SET NULL);
        CREATE TABLE IF NOT EXISTS schedules(id INTEGER PRIMARY KEY,site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,kind TEXT NOT NULL,payload TEXT NOT NULL DEFAULT '{}',interval_seconds INTEGER NOT NULL,next_run INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,UNIQUE(site_id,kind));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,site_id INTEGER,action TEXT NOT NULL,detail TEXT DEFAULT '',created_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status,site_id,id);
        CREATE TABLE IF NOT EXISTS media_library(id INTEGER PRIMARY KEY,media_key TEXT NOT NULL UNIQUE,document TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,revision INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS media_site_mappings(media_id INTEGER NOT NULL REFERENCES media_library(id),site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,remote_id INTEGER,version INTEGER NOT NULL DEFAULT 0,desired TEXT NOT NULL DEFAULT 'sync',actual TEXT NOT NULL DEFAULT 'not_distributed',job_id INTEGER,error TEXT NOT NULL DEFAULT '',PRIMARY KEY(media_id,site_id));
        CREATE TABLE IF NOT EXISTS media_source_keys(source_url TEXT PRIMARY KEY,media_id INTEGER NOT NULL REFERENCES media_library(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS media_revisions(media_id INTEGER NOT NULL REFERENCES media_library(id),revision INTEGER NOT NULL,document TEXT NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(media_id,revision));
        PRAGMA user_version=2;
        ''')
        if not any(r[1]=='progress' for r in c.execute('PRAGMA table_info(jobs)')): c.execute("ALTER TABLE jobs ADD COLUMN progress TEXT NOT NULL DEFAULT ''")
    os.chmod(DB,0o600)
def audit(c,site,action,detail=''): c.execute('INSERT INTO audit(site_id,action,detail,created_at) VALUES(?,?,?,?)',(site,action,str(detail)[:500],now()))
def backup():
    BACKUPS.mkdir(parents=True,exist_ok=True); path=BACKUPS/(time.strftime('management-%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)+'.db')
    with db() as src:
        dest=sqlite3.connect(path)
        try: src.backup(dest); assert dest.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        finally: dest.close()
    os.chmod(path,0o600); return path.name
