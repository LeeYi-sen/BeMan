import json, uuid, sqlite3
from urllib.parse import urlsplit
from .db import *
from fastapi import HTTPException
PUBLIC="v.status=1 AND v.rights_status='authorized'"
def validate_url(v,required=False):
    try:
        x=url(v)
        if required and not x: raise ValueError('URL required')
        return x
    except ValueError as e: raise HTTPException(422,str(e))
def source_add(c,vid,d):
    u=validate_url(d.get('source_url'),True); e=validate_url(d.get('embed_url'))
    typ=d.get('source_type') or ('hls' if urlsplit(u).path.lower().endswith('.m3u8') else 'mp4' if urlsplit(u).path.lower().endswith('.mp4') else 'external')
    if typ not in ('iframe','mp4','hls','external'): raise HTTPException(422,'Invalid source type')
    p=one(c,'SELECT id FROM source_providers WHERE domain=? AND enabled=1',(urlsplit(u).hostname,))
    if e and typ!='iframe': raise HTTPException(422,'Embed URL only applies to iframe')
    sid=c.execute('INSERT INTO video_sources(video_id,provider_id,source_url,embed_url,source_type,quality,priority,is_default,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(vid,p['id'] if p else None,u,e,typ,str(d.get('quality',''))[:100],int(d.get('priority',0)),int(bool(d.get('is_default',False))),int(bool(d.get('status',1))),NOW(),NOW())).lastrowid
    return sid
def tag_set(c,vid,names):
    c.execute('DELETE FROM video_tags WHERE video_id=?',(vid,))
    for n in dict.fromkeys(str(x).strip()[:100] for x in names if str(x).strip()):
        c.execute('INSERT OR IGNORE INTO tags(name,slug,created_at) VALUES(?,?,?)',(n,slugify(n)+'-'+hashlib.sha256(n.encode()).hexdigest()[:8],NOW()))
        t=one(c,'SELECT id FROM tags WHERE name=?',(n,)); c.execute('INSERT OR IGNORE INTO video_tags VALUES(?,?)',(vid,t['id']))
FIELDS=('title','title_en','original_title','description','description_en','cover_url','duration','category_id','language','release_date','is_featured','is_pinned','sort_order','rights_status','rights_reference','status')
def video_save(c,d,vid=None):
    old=one(c,'SELECT * FROM videos WHERE id=?',(vid,)) if vid else None
    if vid and not old: raise HTTPException(404,'Video not found')
    values={k:d[k] for k in FIELDS if k in d}
    title=str(values.get('title',old['title'] if old else '')).strip()[:300]
    if not title: raise HTTPException(422,'Title required')
    values['title']=title
    if 'cover_url' in values: values['cover_url']=validate_url(values['cover_url'])
    for k in ('title_en','original_title','description','description_en','language','release_date','rights_reference'):
        if k in values: values[k]=str(values[k] or '')[:10000 if 'description' in k else 2000]
    for k in ('duration','sort_order','status','is_featured','is_pinned'):
        if k in values: values[k]=int(values[k] or 0)
    if values.get('duration',0)<0 or any(values.get(k,0) not in (0,1) for k in ('status','is_featured','is_pinned')): raise HTTPException(422,'Invalid numeric field')
    if 'category_id' in values: values['category_id']=int(values['category_id']) if values['category_id'] else None
    status=values.get('status',old['status'] if old else 0); rights=values.get('rights_status',old['rights_status'] if old else 'pending'); ref=values.get('rights_reference',old['rights_reference'] if old else '')
    if rights not in ('pending','authorized','blocked'): raise HTTPException(422,'Invalid rights status')
    if status and vid and one(c,'SELECT state FROM video_lifecycle WHERE video_id=?',(vid,)): raise HTTPException(409,'Video frozen or deleted; restore explicitly first')
    if status and (rights!='authorized' or not ref.strip()): raise HTTPException(422,'Publishing requires rights authorization and reference')
    values['updated_at']=NOW()
    if status and not (old and old['published_at']): values['published_at']=NOW()
    if old: c.execute('UPDATE videos SET '+','.join(k+'=?' for k in values)+' WHERE id=?',(*values.values(),vid))
    else:
        uid=uuid.uuid4().hex; values.update(uuid=uid,slug=slugify(title)+'-'+uid[:10],created_at=NOW()); vid=c.execute('INSERT INTO videos('+','.join(values)+') VALUES('+','.join('?' for _ in values)+')',tuple(values.values())).lastrowid
    if 'tags' in d: tag_set(c,vid,d['tags'] if isinstance(d['tags'],list) else str(d['tags']).split(','))
    for src in d.get('sources',[]): source_add(c,vid,src)
    if status and not one(c,"SELECT id FROM video_sources WHERE video_id=? AND status=1",(vid,)): raise HTTPException(422,'At least one enabled source required')
    return vid
def get_video(c,slug,public=True):
    v=one(c,'SELECT v.*,c.name category_name,c.name_en category_name_en,c.slug category_slug FROM videos v LEFT JOIN categories c ON c.id=v.category_id WHERE '+('v.slug=? AND '+PUBLIC if public else 'v.id=?'),(slug,))
    if not v: return None
    v['tags']=rows(c,'SELECT t.* FROM tags t JOIN video_tags vt ON vt.tag_id=t.id WHERE vt.video_id=?',(v['id'],))
    v['sources']=rows(c,'SELECT s.* FROM video_sources s LEFT JOIN source_providers p ON p.id=s.provider_id WHERE s.video_id=? '+('AND s.status=1 AND (p.id IS NULL OR p.enabled=1) ' if public else '')+"ORDER BY CASE WHEN s.health_status='dead' THEN 1 ELSE 0 END,s.is_default DESC,s.priority DESC,s.id",(v['id'],))
    if public:
        for k in ('rights_reference','rights_status'): v.pop(k,None)
        v['sources']=[{k:s[k] for k in ('id','source_url','embed_url','source_type','quality','health_status')} for s in v['sources'] if not one(c,'SELECT 1 FROM source_policy WHERE source_id=? AND excluded=1',(s['id'],))]
    return v
def list_videos(c,q='',category='',tag='',sort='latest',page=1,limit=24,public=True):
    where=[PUBLIC] if public else ['1=1']; params=[]
    if category: where.append('c.slug=?'); params.append(category)
    if tag: where.append('EXISTS(SELECT 1 FROM video_tags vt JOIN tags t ON t.id=vt.tag_id WHERE vt.video_id=v.id AND t.slug=?)'); params.append(tag)
    if public and q:
        cfg={x['key']:x['value'] for x in rows(c,"SELECT * FROM settings WHERE key IN ('search_enabled','search_order')")}
        if cfg.get('search_enabled')=='0': return {'items':[],'total':0,'page':page,'limit':limit}
        if sort=='latest': sort=cfg.get('search_order','latest')
    if q:
        q=q.strip()[:200]; like='%'+q.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
        if len(q)>=3: search="v.id IN (SELECT rowid FROM videos_fts WHERE videos_fts MATCH ?)"; params.append('"'+q.replace('"','""')+'"')
        else: search="(v.title LIKE ? ESCAPE '\\' OR v.title_en LIKE ? ESCAPE '\\' OR v.description LIKE ? ESCAPE '\\' OR v.description_en LIKE ? ESCAPE '\\')"; params.extend([like]*4)
        where.append('('+search+" OR EXISTS(SELECT 1 FROM video_tags vt JOIN tags t ON t.id=vt.tag_id WHERE vt.video_id=v.id AND (t.name LIKE ? ESCAPE '\\' OR t.name_en LIKE ? ESCAPE '\\')))"); params.extend([like,like])
    base=' FROM videos v LEFT JOIN categories c ON c.id=v.category_id WHERE '+' AND '.join(where)
    total=c.execute('SELECT count(*)'+base,params).fetchone()[0]
    order={'latest':'v.is_pinned DESC,v.published_at DESC,v.id DESC','random':'random()','featured':'v.is_featured DESC,v.sort_order DESC,v.id DESC'}.get(sort,'v.id DESC')
    if public and sort in ('popular','today','week','month'):
        # Management_Center computes these snapshots; VideoHub only reads them.
        base=base.replace(' WHERE ', ' JOIN ranking_entries r ON r.video_id=v.id AND r.board=? WHERE ',1)
        params=[sort,*params]; total=c.execute('SELECT count(*)'+base,params).fetchone()[0]; order='r.position ASC'
    fields='v.id,v.slug,v.title,v.title_en,v.cover_url,v.duration,v.view_count,v.published_at,v.is_featured,c.name category_name,c.name_en category_name_en' if public else 'v.*,c.name category_name'
    return {'items':rows(c,'SELECT '+fields+base+' ORDER BY '+order+' LIMIT ? OFFSET ?',(*params,limit,(page-1)*limit)),'total':total,'page':page,'limit':limit}
