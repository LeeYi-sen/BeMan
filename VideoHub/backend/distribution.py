"""Transactional, versioned distribution primitive; no site-local scheduling."""
import re
from fastapi import HTTPException
from .catalog import *

def apply(key,d,actor):
    if not re.fullmatch(r'[a-f0-9]{32}',key): raise HTTPException(422,'Invalid media key')
    rev=int(d.get('revision',0)); action=d.get('action'); data=d.get('video',{})
    if rev<1 or action not in ('publish','sync','unpublish','freeze','unfreeze','delete','restore'): raise HTTPException(422,'Invalid revision or action')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        m=one(c,'SELECT * FROM distributed_media WHERE media_key=?',(key,)); vid=m['video_id'] if m else None
        if m and rev<=m['revision']:
            return {'id':vid,'revision':m['revision'],'action':m['action'],'stale':rev<m['revision']}
        life=one(c,'SELECT state FROM video_lifecycle WHERE video_id=?',(vid,)) if vid else None
        if action in ('publish','sync'):
            if life: raise HTTPException(409,'Explicit restore/unfreeze required')
            fields={k:v for k,v in data.items() if k in FIELDS or k=='tags'}; fields.pop('category_id',None)
            cat=data.get('category_name','').strip()
            if cat:
                slug=slugify(cat)+'-'+hashlib.sha256(cat.encode()).hexdigest()[:8]
                row=one(c,'SELECT id FROM categories WHERE name=? ORDER BY status DESC, CASE WHEN slug=? THEN 0 ELSE 1 END,id LIMIT 1',(cat,slug))
                if not row:
                    base=slug; suffix=1
                    while one(c,'SELECT id FROM categories WHERE slug=?',(slug,)):
                        slug=f'{base}-{suffix}';suffix+=1
                    cid=c.execute('INSERT INTO categories(name,slug,created_at) VALUES(?,?,?)',(cat,slug,NOW())).lastrowid
                else: cid=row['id']
                fields['category_id']=cid
            elif 'category_name' in data: fields['category_id']=None
            sources=data.get('sources',[])
            if not sources or len(sources)>50: raise HTTPException(422,'1–50 sources required')
            wanted={validate_url(s.get('source_url'),True):s for s in sources}
            if len(wanted)!=len(sources): raise HTTPException(422,'Duplicate source')
            fields['status']=0
            old_status=one(c,'SELECT status FROM videos WHERE id=?',(vid,))['status'] if vid else 0
            vid=video_save(c,fields,vid)
            old={s['source_url']:s for s in rows(c,'SELECT * FROM video_sources WHERE video_id=?',(vid,))}
            for u,s in old.items():
                if u not in wanted: c.execute('DELETE FROM video_sources WHERE id=?',(s['id'],))
            for u,s in wanted.items():
                if u not in old: source_add(c,vid,s)
                else:
                    before=old[u]; e=validate_url(s.get('embed_url')); typ=s.get('source_type','iframe')
                    if typ not in ('iframe','mp4','hls','external') or (e and typ!='iframe'): raise HTTPException(422,'Invalid source type')
                    if (e,typ)!=(before['embed_url'],before['source_type']):
                        c.execute("UPDATE video_sources SET health_status='unknown',failure_count=0,last_checked_at=NULL WHERE id=?",(before['id'],));c.execute('DELETE FROM source_policy WHERE source_id=?',(before['id'],))
                    c.execute('UPDATE video_sources SET embed_url=?,source_type=?,quality=?,priority=?,status=?,updated_at=? WHERE id=?',(e,typ,str(s.get('quality',''))[:100],int(s.get('priority',0)),int(bool(s.get('status',1))),NOW(),before['id']))
            if action=='publish' or old_status: video_save(c,{'status':1},vid)
        else:
            if not vid: raise HTTPException(404,'Not distributed')
            if action=='unfreeze':
                if not life or life['state']!='frozen': raise HTTPException(409,'Not frozen')
                c.execute('DELETE FROM video_lifecycle WHERE video_id=?',(vid,))
            elif action=='restore':
                if not life or life['state']!='deleted': raise HTTPException(409,'Not in recycle bin')
                c.execute('DELETE FROM video_lifecycle WHERE video_id=?',(vid,))
            elif action in ('freeze','delete'):
                if life and life['state']=='deleted' and action=='freeze': raise HTTPException(409,'Restore deleted video first')
                c.execute('INSERT OR REPLACE INTO video_lifecycle VALUES(?,?)',(vid,'frozen' if action=='freeze' else 'deleted'))
            c.execute('UPDATE videos SET status=0,updated_at=? WHERE id=?',(NOW(),vid))
        c.execute('INSERT INTO distributed_media VALUES(?,?,?,?) ON CONFLICT(media_key) DO UPDATE SET revision=excluded.revision,action=excluded.action',(key,vid,rev,action));audit(c,actor,'distribution.'+action,vid)
        return {'id':vid,'revision':rev,'action':action}
