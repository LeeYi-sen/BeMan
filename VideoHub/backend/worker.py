import json,time,logging,signal,fcntl,os
from .db import *
from .catalog import video_save
from .checker import check_source
log=logging.getLogger('worker'); running=True
def process_import(task_id):
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); item=one(c,"SELECT * FROM import_task_items WHERE status='queued' AND task_id=? ORDER BY id LIMIT 1",(task_id,))
        if not item: return False
        c.execute('SAVEPOINT item'); status='created'; vid=None; error=''
        try:
            payload=json.loads(item['payload']); u=url(item['source_url']); existing=one(c,'SELECT video_id FROM video_sources WHERE source_url=?',(u,))
            if existing: status='duplicate'; vid=existing['video_id']
            else: vid=video_save(c,{**payload,'status':0,'rights_status':'pending','sources':[{'source_url':u,'embed_url':payload.get('embed_url',''),'source_type':payload.get('source_type')} ]})
        except Exception as e:
            c.execute('ROLLBACK TO item'); status='failed'; error=str(e)[:500]; vid=None
        c.execute('RELEASE item'); c.execute('UPDATE import_task_items SET status=?,video_id=?,error=? WHERE id=?',(status,vid,error,item['id']))
        col={'created':'created_count','duplicate':'duplicate_count','failed':'failed_count'}[status]
        c.execute(f"UPDATE import_tasks SET processed=processed+1,{col}={col}+1,status=CASE WHEN processed+1>=total THEN 'done' ELSE 'running' END,updated_at=? WHERE id=?",(NOW(),item['task_id']))
    return True
