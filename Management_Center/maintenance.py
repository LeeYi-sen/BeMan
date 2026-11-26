import sys,sqlite3,os
from pathlib import Path
from backend.store import DB,BACKUPS,backup,db,init
if len(sys.argv)<2:sys.exit('backup | diagnose | restore NAME --offline')
if sys.argv[1]=='backup':init();print(backup())
elif sys.argv[1]=='diagnose':
    init()
    with db() as c: print({'integrity':c.execute('PRAGMA quick_check').fetchone()[0],'sites':c.execute('SELECT count(*) FROM sites').fetchone()[0],'jobs':c.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running','needs_review')").fetchone()[0]})
elif sys.argv[1]=='restore' and len(sys.argv)==4 and sys.argv[3]=='--offline':
    path=BACKUPS/Path(sys.argv[2]).name
    if not path.is_file():sys.exit('Backup not found')
    with sqlite3.connect(path) as src:
        if src.execute('PRAGMA integrity_check').fetchone()[0]!='ok' or not src.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sites'").fetchone():sys.exit('Invalid management backup')
        if DB.exists():print('Pre-restore:',backup())
        tmp=DB.with_suffix('.restore.tmp')
        with sqlite3.connect(tmp) as out:src.backup(out)
    for suffix in ('-wal','-shm'):Path(str(DB)+suffix).unlink(missing_ok=True)
    os.replace(tmp,DB);os.chmod(DB,0o600)
else:sys.exit('Invalid command')
