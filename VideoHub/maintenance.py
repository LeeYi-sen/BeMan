import argparse, os, sqlite3, shutil, time, sys
from pathlib import Path
from backend.db import db,DB,BACKUPS,init,make_backup,NOW
p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='cmd',required=True)
sub.add_parser('backup'); sub.add_parser('diagnose'); r=sub.add_parser('restore');r.add_argument('path');r.add_argument('--offline',action='store_true');args=p.parse_args()
if args.cmd=='backup': init();print(make_backup())
elif args.cmd=='diagnose':
    init()
    with db() as c:
        print('database:',DB,'integrity:',c.execute('PRAGMA quick_check').fetchone()[0]); print('schema version:',c.execute('PRAGMA user_version').fetchone()[0]);print('videos:',c.execute('SELECT count(*) FROM videos').fetchone()[0]);print('pending imports:',c.execute("SELECT count(*) FROM import_task_items WHERE status='queued'").fetchone()[0]);print('disk free bytes:',shutil.disk_usage(DB.parent).free)
    print('CPU count:',os.cpu_count());
    if Path('/proc/meminfo').exists():print('\n'.join(Path('/proc/meminfo').read_text().splitlines()[:3]))

else:
    if not args.offline: sys.exit('Stop all API and worker processes, then pass --offline')
    path=Path(args.path).resolve()
    if path==DB.resolve() or not path.is_file():sys.exit('Invalid backup path')
    with sqlite3.connect(path) as src:
        if src.execute('PRAGMA integrity_check').fetchone()[0]!='ok' or src.execute('PRAGMA user_version').fetchone()[0] not in (1,2) or not src.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='videos'").fetchone():sys.exit('Invalid backup or schema version')
    if DB.exists():print('Pre-restore snapshot:',make_backup())
    temp=DB.with_suffix('.restore.tmp');DB.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(path) as src, sqlite3.connect(temp) as dest: src.backup(dest)
    for suffix in ('-wal','-shm'):
        Path(str(DB)+suffix).unlink(missing_ok=True)
    os.replace(temp,DB);os.chmod(DB,0o600);print('Restored:',DB)
