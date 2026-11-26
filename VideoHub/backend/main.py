import os, time, json, sqlite3, secrets, re, datetime, html, csv, io
from pathlib import Path
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from fastapi import FastAPI, Request, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from .db import *
from .catalog import *
from .security import admin
from .checker import check_source
@asynccontextmanager
async def lifespan(app):
    init(); yield
app=FastAPI(title='VideoHub',version='2.1.0',lifespan=lifespan,docs_url=None,redoc_url=None)
app.mount('/static',StaticFiles(directory=ROOT/'frontend/static'),name='static')
templates=Jinja2Templates(directory=ROOT/'frontend/templates')
@app.exception_handler(sqlite3.IntegrityError)
async def conflict(req,e): return JSONResponse({'detail':'Duplicate or invalid related record'},409)
@app.exception_handler(ValueError)
async def invalid(req,e): return JSONResponse({'detail':str(e)[:300]},422)
@app.middleware('http')
async def headers(req,call_next):
    r=await call_next(req); r.headers['X-Content-Type-Options']='nosniff'; r.headers['Referrer-Policy']='strict-origin-when-cross-origin'; r.headers['X-Frame-Options']='DENY' if not req.url.path.startswith('/ad/') else 'SAMEORIGIN'
    if req.url.path.startswith(('/api/v1/admin',)): r.headers['Cache-Control']='no-store'
    if not req.url.path.startswith('/ad/'): r.headers['Content-Security-Policy']="default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' https: http: data:; media-src 'self' https: http: blob:; connect-src 'self' https: http:; frame-src 'self' https: http:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    return r
@app.get('/healthz')
def health():
    with db() as c: c.execute('SELECT 1').fetchone()
    return {'status':'ok'}
# public APIs
@app.get('/api/public/config')
def config():
    with db() as c:
        cfg={r['key']:r['value'] for r in rows(c,"SELECT * FROM settings WHERE key IN ('site_name','site_description','site_url','seo_title','seo_description','seo_index','search_enabled','search_order')")}
        cfg['categories']=rows(c,'SELECT id,name,name_en,slug,parent_id FROM categories WHERE status=1 ORDER BY sort_order DESC,id'); cfg['tags']=rows(c,'SELECT t.name,t.name_en,t.slug FROM tags t WHERE EXISTS(SELECT 1 FROM video_tags vt JOIN videos v ON v.id=vt.video_id WHERE vt.tag_id=t.id AND '+PUBLIC+') ORDER BY t.name LIMIT 100')
        cfg['ads']=rows(c,"SELECT id,name,position,width,height,device_type FROM advertisements WHERE enabled=1 AND (start_at IS NULL OR start_at<=?) AND (end_at IS NULL OR end_at>=?)",(NOW(),NOW()))
    return cfg
@app.get('/api/public/catalog')
def catalog(q:str='',category:str='',tag:str='',sort:str='latest',page:int=Query(1,ge=1,le=100000),limit:int=Query(24,ge=1,le=100)):
    with db() as c: return list_videos(c,q,category,tag,sort,page,limit)
@app.get('/api/public/video/{slug}')
def public_video(slug:str):
    with db() as c:
        v=get_video(c,slug)
        if not v: raise HTTPException(404,'Video not found')
        v['related']=[x for x in list_videos(c,category=v['category_slug'] or '',limit=9)['items'] if x['id']!=v['id']][:8]
        return v
@app.post('/api/public/video/{slug}/view')
def view(slug:str,req:Request):
    # Browser/session deduplication only; not an ad impression or verified playback.
    key='vh_seen_'+re.sub(r'[^a-zA-Z0-9]','',slug[-12:]); today=datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    with db() as c:
        v=one(c,'SELECT v.id FROM videos v WHERE v.slug=? AND '+PUBLIC,(slug,))
        if not v: raise HTTPException(404)
        if req.cookies.get(key)!=today:
            c.execute('UPDATE videos SET view_count=view_count+1 WHERE id=?',(v['id'],)); c.execute('INSERT INTO video_stats_daily(video_id,date,view_count) VALUES(?,?,1) ON CONFLICT(video_id,date) DO UPDATE SET view_count=view_count+1',(v['id'],today))
    r=JSONResponse({'ok':True}); r.set_cookie(key,today,max_age=86400,httponly=True,samesite='lax',secure=os.getenv('VIDEOHUB_SECURE_COOKIE')=='1'); return r
@app.post('/api/public/video/{slug}/report')
def report(slug:str,d:dict,req:Request):
    reason=d.get('reason',''); detail=str(d.get('details',''))[:2000]
    if reason not in ('broken','copyright','other'): raise HTTPException(422,'Invalid reason')
    if req.cookies.get('vh_report')=='1': raise HTTPException(429,'Please wait before submitting another report')
    with db() as c:
        v=one(c,'SELECT v.id FROM videos v WHERE v.slug=? AND '+PUBLIC,(slug,))
        if not v: raise HTTPException(404)
        c.execute('INSERT INTO video_reports(video_id,reason,details,created_at) VALUES(?,?,?,?)',(v['id'],reason,detail,NOW())); c.execute('INSERT INTO video_stats_daily(video_id,date,report_count) VALUES(?,?,1) ON CONFLICT(video_id,date) DO UPDATE SET report_count=report_count+1',(v['id'],datetime.datetime.now(datetime.timezone.utc).date().isoformat()))
    r=JSONResponse({'ok':True}); r.set_cookie('vh_report','1',max_age=60,httponly=True,samesite='lax'); return r
# Admin
@app.get('/api/v1/admin/dashboard')
def dashboard(actor=Depends(admin)):
    with db() as c:
        scalar=lambda s:c.execute(s).fetchone()[0]
        return {'videos':scalar('SELECT count(*) FROM videos'),'published':scalar("SELECT count(*) FROM videos v WHERE "+PUBLIC),'sources':scalar('SELECT count(*) FROM video_sources'),'dead':scalar("SELECT count(*) FROM source_policy WHERE excluded=1"),'unknown':scalar("SELECT count(*) FROM video_sources WHERE health_status='unknown'"),'views':scalar('SELECT COALESCE(sum(view_count),0) FROM videos'),'reports':scalar("SELECT count(*) FROM video_reports WHERE status='open'"),'frozen':scalar("SELECT count(*) FROM video_lifecycle WHERE state='frozen'"),'today_views':scalar("SELECT COALESCE(sum(view_count),0) FROM video_stats_daily WHERE date=date('now')"),'daily':rows(c,"SELECT date,sum(view_count) views FROM video_stats_daily WHERE date>=date('now','-30 days') GROUP BY date ORDER BY date"),'database_bytes':DB.stat().st_size if DB.exists() else 0}
@app.get('/api/v1/admin/videos')
def admin_videos(q:str='',page:int=Query(1,ge=1),limit:int=Query(30,ge=1,le=100),actor=Depends(admin)):
    with db() as c: return list_videos(c,q=q,page=page,limit=limit,public=False)
@app.get('/api/v1/admin/videos/{vid}')
def admin_video(vid:int,actor=Depends(admin)):
    with db() as c:
        v=get_video(c,vid,False)
        if not v: raise HTTPException(404)
        return v
@app.post('/api/v1/admin/videos')
def add_video(d:dict,actor=Depends(admin)):
    with db() as c: vid=video_save(c,d); audit(c,actor,'video.create',vid); return get_video(c,vid,False)
@app.put('/api/v1/admin/videos/{vid}')
def edit_video(vid:int,d:dict,actor=Depends(admin)):
    with db() as c: video_save(c,d,vid); audit(c,actor,'video.edit',vid); return get_video(c,vid,False)
@app.delete('/api/v1/admin/videos/{vid}')
def del_video(vid:int,actor=Depends(admin)):
    with db() as c: c.execute('UPDATE videos SET status=0,rights_status=\'blocked\',updated_at=? WHERE id=?',(NOW(),vid)); audit(c,actor,'video.unpublish',vid)
    return {'ok':True}
@app.post('/api/v1/admin/videos/{vid}/sources')
def add_source(vid:int,d:dict,actor=Depends(admin)):
    with db() as c: sid=source_add(c,vid,d); audit(c,actor,'source.create',sid); return {'id':sid}
@app.put('/api/v1/admin/sources/{sid}')
def edit_source(sid:int,d:dict,actor=Depends(admin)):
    with db() as c:
        old=one(c,'SELECT * FROM video_sources WHERE id=?',(sid,))
        if not old: raise HTTPException(404)
        u=validate_url(d.get('source_url',old['source_url']),True); e=validate_url(d.get('embed_url',old['embed_url'])); typ=d.get('source_type',old['source_type'])
        if typ not in ('iframe','mp4','hls','external') or (e and typ!='iframe'): raise HTTPException(422,'Invalid source type')
        p=one(c,'SELECT id FROM source_providers WHERE domain=?',(urlsplit(u).hostname,)); changed=(u,e,typ)!=(old['source_url'],old['embed_url'],old['source_type'])
        c.execute('UPDATE video_sources SET source_url=?,embed_url=?,source_type=?,provider_id=?,quality=?,priority=?,is_default=?,status=?,health_status=?,failure_count=?,last_checked_at=?,updated_at=? WHERE id=?',(u,e,typ,p['id'] if p else None,str(d.get('quality',old['quality']))[:100],int(d.get('priority',old['priority'])),int(bool(d.get('is_default',old['is_default']))),int(bool(d.get('status',old['status']))),'unknown' if changed else old['health_status'],0 if changed else old['failure_count'],None if changed else old['last_checked_at'],NOW(),sid)); audit(c,actor,'source.edit',sid)
        if changed: c.execute('DELETE FROM source_policy WHERE source_id=?',(sid,))
    return {'ok':True}
@app.post('/api/v1/admin/sources/{sid}/check')
def manual_check(sid:int,actor=Depends(admin)):
    r=check_source(sid)
    if not r: raise HTTPException(404)
    return r
@app.put('/api/v1/admin/sources/{sid}/policy')
def set_source_policy(sid:int,d:dict,actor=Depends(admin)):
    with db() as c:
        if not one(c,'SELECT id FROM video_sources WHERE id=?',(sid,)): raise HTTPException(404)
        c.execute('INSERT OR REPLACE INTO source_policy VALUES(?,?)',(sid,int(bool(d.get('excluded',False))))); audit(c,actor,'source.policy',sid)
    return {'ok':True}
@app.get('/api/v1/admin/stats')
def stats(after:int=Query(0,ge=0),limit:int=Query(500,ge=1,le=1000),actor=Depends(admin)):
    with db() as c:
        return rows(c,"SELECT id,video_id,date,view_count,play_count,report_count FROM video_stats_daily WHERE id>? AND date>=date('now','-30 days') ORDER BY id LIMIT ?",(after,limit))
@app.get('/api/v1/admin/published')
def published(after:int=Query(0,ge=0),limit:int=Query(500,ge=1,le=1000),actor=Depends(admin)):
    with db() as c: return rows(c,'SELECT v.id,v.slug,v.view_count,v.title,v.title_en,v.description,v.description_en FROM videos v WHERE '+PUBLIC+' AND v.id>? ORDER BY v.id LIMIT ?',(after,limit))
@app.get('/api/v1/admin/rankings')
def rankings(actor=Depends(admin)):
    with db() as c: return rows(c,'SELECT * FROM ranking_entries ORDER BY board,position')
@app.put('/api/v1/admin/rankings/{board}')
def rank_save(board:str,d:dict,actor=Depends(admin)):
    if board not in ('popular','today','week','month'): raise HTTPException(422,'Invalid board')
    ids=d.get('ids',[]); version=int(d.get('version',0))
    if not isinstance(ids,list) or len(ids)>10000 or len(set(ids))!=len(ids) or version<=0: raise HTTPException(422,'Invalid ranking snapshot')
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); old=one(c,'SELECT version FROM snapshot_versions WHERE name=?',(board,))
        if old and version<=old['version']: raise HTTPException(409,'Stale snapshot')
        c.execute('DELETE FROM ranking_entries WHERE board=?',(board,)); c.executemany('INSERT INTO ranking_entries(board,video_id,position) VALUES(?,?,?)',[(board,int(x),i) for i,x in enumerate(ids,1)]); c.execute('INSERT OR REPLACE INTO snapshot_versions VALUES(?,?)',(board,version)); audit(c,actor,'ranking.replace',board)
    return {'ok':True,'count':len(ids)}
@app.put('/api/v1/admin/sitemap')
def sitemap_save(d:dict,actor=Depends(admin)):
    ids=d.get('ids',[]); version=int(d.get('version',0))
    if not isinstance(ids,list) or len(ids)>1000000 or len(set(ids))!=len(ids) or version<=0: raise HTTPException(422,'Invalid sitemap snapshot')
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); old=one(c,"SELECT version FROM snapshot_versions WHERE name='sitemap'")
        if old and version<=old['version']: raise HTTPException(409,'Stale snapshot')
        c.execute('DELETE FROM sitemap_entries'); c.executemany('INSERT INTO sitemap_entries VALUES(?)',[(int(x),) for x in ids]); c.execute("INSERT OR REPLACE INTO snapshot_versions VALUES('sitemap',?)",(version,)); audit(c,actor,'sitemap.replace')
    return {'ok':True,'count':len(ids)}
@app.put('/api/v1/admin/videos/{vid}/seo')
def seo_save(vid:int,d:dict,actor=Depends(admin)):
    with db() as c:
        if not one(c,'SELECT id FROM videos WHERE id=?',(vid,)): raise HTTPException(404)
        c.execute('INSERT OR REPLACE INTO video_seo VALUES(?,?,?,?,?)',(vid,*[str(d.get(k,''))[:500] for k in ('title','title_en','description','description_en')])); audit(c,actor,'seo.save',vid)
    return {'ok':True}
@app.get('/api/v1/admin/capabilities')
def capabilities(actor=Depends(admin)):
    return {'api_version':'1','site_id':os.getenv('VIDEOHUB_SITE_ID','videohub'),'features':['videos','sources','providers','categories','tags','ads','imports','stats','rankings','seo','sitemap','reports','backup','distribution'],'autonomous_operations':False}
@app.get('/api/v1/admin/backups')
def backups(actor=Depends(admin)):
    return [{'name':x.name,'bytes':x.stat().st_size} for x in sorted(BACKUPS.glob('video-*.db'),reverse=True)[:100]]
@app.post('/api/v1/admin/imports/{tid}/run')
def run_import(tid:int,actor=Depends(admin)):
    from .worker import process_import
    for _ in range(25):
        if not process_import(tid): break
    with db() as c:
        task=one(c,'SELECT * FROM import_tasks WHERE id=?',(tid,))
        if not task: raise HTTPException(404)
    return task
@app.put('/api/v1/admin/distribution/{key}')
def distribute(key:str,d:dict,actor=Depends(admin)):
    from .distribution import apply
    return apply(key,d,actor)

@app.get('/api/v1/admin/distribution/{key}')
def distribution_status(key:str,actor=Depends(admin)):
    with db() as c:
        m=one(c,'SELECT * FROM distributed_media WHERE media_key=?',(key,))
        if not m: raise HTTPException(404,'Not distributed')
        return {**m,'video':get_video(c,m['video_id'],False),'lifecycle':one(c,'SELECT state FROM video_lifecycle WHERE video_id=?',(m['video_id'],))}

@app.delete('/api/v1/admin/{kind}/{ident}')
def delete_resource(kind:str,ident:int,actor=Depends(admin)):
    tables={'categories':'categories','tags':'tags','providers':'source_providers','ads':'advertisements','sources':'video_sources'}
    if kind not in tables: raise HTTPException(404)
    with db() as c:
        if not c.execute('DELETE FROM '+tables[kind]+' WHERE id=?',(ident,)).rowcount: raise HTTPException(404)
        audit(c,actor,kind+'.delete',ident)
    return {'ok':True}
@app.get('/api/v1/admin/{kind}')
def admin_list(kind:str,page:int=Query(1,ge=1),limit:int=Query(100,ge=1,le=500),actor=Depends(admin)):
    mapping={'categories':'categories','tags':'tags','providers':'source_providers','ads':'advertisements','imports':'import_tasks','reports':'video_reports','logs':'operation_logs','sources':'video_sources'}
    if kind=='settings': return settings_read(actor)
    if kind=='export': return export(actor)
    if kind not in mapping: raise HTTPException(404)
    with db() as c:
        if kind=='sources': return rows(c,'SELECT s.*,COALESCE(p.excluded,0) excluded FROM video_sources s LEFT JOIN source_policy p ON p.source_id=s.id ORDER BY s.id DESC LIMIT ? OFFSET ?',(limit,(page-1)*limit))
        return rows(c,'SELECT * FROM '+mapping[kind]+' ORDER BY id DESC LIMIT ? OFFSET ?',(limit,(page-1)*limit))
@app.post('/api/v1/admin/categories')
def category_save(d:dict,actor=Depends(admin)):
    name=str(d.get('name','')).strip()[:100]
    if not name: raise HTTPException(422,'Name required')
    with db() as c:
        cid=d.get('id'); vals=(name,str(d.get('name_en',''))[:100],slugify(d.get('slug') or name),d.get('parent_id') or None,str(d.get('description',''))[:2000],validate_url(d.get('cover_url')),int(d.get('sort_order',0)),int(bool(d.get('status',1))))
        if cid:
            if vals[3]==cid: raise HTTPException(422,'Invalid parent')
            c.execute('UPDATE categories SET name=?,name_en=?,slug=?,parent_id=?,description=?,cover_url=?,sort_order=?,status=? WHERE id=?',(*vals,cid))
        else: cid=c.execute('INSERT INTO categories(name,name_en,slug,parent_id,description,cover_url,sort_order,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(*vals,NOW())).lastrowid
        audit(c,actor,'category.save',cid); return {'id':cid}
@app.post('/api/v1/admin/tags')
def tag_save(d:dict,actor=Depends(admin)):
    n=str(d.get('name','')).strip()[:100]
    if not n: raise HTTPException(422,'Name required')
    with db() as c:
        tid=d.get('id'); en=str(d.get('name_en',''))[:100]
        if tid: c.execute('UPDATE tags SET name=?,name_en=? WHERE id=?',(n,en,tid))
        else: tid=c.execute('INSERT INTO tags(name,name_en,slug,created_at) VALUES(?,?,?,?)',(n,en,slugify(n)+'-'+secrets.token_hex(4),NOW())).lastrowid
        audit(c,actor,'tag.save',tid); return {'id':tid}
def domains(value):
    a=value if isinstance(value,list) else str(value or '').split(','); out=[]
    for x in a:
        x=str(x).strip().lower().rstrip('.')
        if not x: continue
        if not re.fullmatch(r'[a-z0-9.-]+',x) or '.' not in x or len(x)>253: raise HTTPException(422,'Invalid allowed domain')
        out.append(x)
    return out
@app.post('/api/v1/admin/providers')
def provider_save(d:dict,actor=Depends(admin)):
    host=domains([d.get('domain','')]); name=str(d.get('name','')).strip()[:100]
    if not host or not name: raise HTTPException(422,'Domain and name required')
    h=host[0]; typ=d.get('source_type','iframe'); allowed=json.dumps(domains(d.get('allowed_domains',[])))
    if typ not in ('iframe','mp4','hls','external'): raise HTTPException(422,'Invalid source type')
    with db() as c:
        pid=d.get('id'); vals=(name,h,str(d.get('embed_template',''))[:2000],typ,allowed,int(bool(d.get('check_enabled',1))),int(bool(d.get('enabled',1))),NOW())
        if pid: c.execute('UPDATE source_providers SET name=?,domain=?,embed_template=?,source_type=?,allowed_domains=?,check_enabled=?,enabled=?,updated_at=? WHERE id=?',(*vals,pid))
        else: pid=c.execute('INSERT INTO source_providers(name,domain,embed_template,source_type,allowed_domains,check_enabled,enabled,updated_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(*vals,NOW())).lastrowid
        for s in rows(c,'SELECT id,source_url FROM video_sources'):
            if urlsplit(s['source_url']).hostname==h: c.execute('UPDATE video_sources SET provider_id=? WHERE id=?',(pid,s['id']))
        audit(c,actor,'provider.save',pid); return {'id':pid}
@app.post('/api/v1/admin/imports')
def import_create(d:dict,actor=Depends(admin)):
    items=d.get('items',[])
    if isinstance(items,str): items=[{'source_url':x.strip()} for x in items.splitlines() if x.strip()]
    if not isinstance(items,list) or not 1<=len(items)<=5000: raise HTTPException(422,'1–5000 items per task')
    with db() as c:
        c.execute('BEGIN IMMEDIATE'); request_id=str(d.get('request_id',''))[:128]
        if request_id:
            existing=one(c,'SELECT task_id FROM import_requests WHERE request_id=?',(request_id,))
            if existing: return {'id':existing['task_id']}
        tid=c.execute('INSERT INTO import_tasks(total,created_at,updated_at) VALUES(?,?,?)',(len(items),NOW(),NOW())).lastrowid
        for item in items:
            if not isinstance(item,dict): item={'source_url':str(item)}
            u=str(item.get('source_url',''))[:4096]; item['title']=str(item.get('title') or urlsplit(u).hostname or 'Untitled video')[:300]
            c.execute('INSERT INTO import_task_items(task_id,source_url,payload,created_at) VALUES(?,?,?,?)',(tid,u,json.dumps(item,ensure_ascii=False),NOW()))
        if request_id: c.execute('INSERT INTO import_requests VALUES(?,?)',(request_id,tid))
        audit(c,actor,'import.create',tid); return {'id':tid}
@app.get('/api/v1/admin/imports/{tid}/items')
def import_items(tid:int,actor=Depends(admin)):
    with db() as c: return rows(c,'SELECT id,source_url,status,video_id,error FROM import_task_items WHERE task_id=? ORDER BY id LIMIT 5000',(tid,))
@app.post('/api/v1/admin/ads')
def ad_save(d:dict,actor=Depends(admin)):
    name=str(d.get('name','')).strip()[:100]; code=str(d.get('ad_code',''))[:50000]; allowed=domains(d.get('allowed_domains',[])); pos=d.get('position','top'); w=int(d.get('width',728)); h=int(d.get('height',90)); device=d.get('device_type','all')
    if not name or not code or not allowed or pos not in ('top','sidebar','below','grid') or device not in ('all','pc','mobile') or not 1<=w<=2000 or not 1<=h<=1000: raise HTTPException(422,'Invalid advertisement; specify trusted domains and dimensions')
    with db() as c:
        aid=d.get('id'); vals=(name,str(d.get('provider','Adsterra'))[:100],pos,code,json.dumps(allowed),w,h,device,int(bool(d.get('enabled',0))),d.get('start_at') or None,d.get('end_at') or None,NOW())
        if aid: c.execute('UPDATE advertisements SET name=?,provider=?,position=?,ad_code=?,allowed_domains=?,width=?,height=?,device_type=?,enabled=?,start_at=?,end_at=?,updated_at=? WHERE id=?',(*vals,aid))
        else: aid=c.execute('INSERT INTO advertisements(name,provider,position,ad_code,allowed_domains,width,height,device_type,enabled,start_at,end_at,updated_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(*vals,NOW())).lastrowid
        audit(c,actor,'ad.save',aid); return {'id':aid}
@app.get('/ad/{aid}',response_class=HTMLResponse)
def ad_frame(aid:int):
    with db() as c: a=one(c,'SELECT * FROM advertisements WHERE id=? AND enabled=1 AND (start_at IS NULL OR start_at<=?) AND (end_at IS NULL OR end_at>=?)',(aid,NOW(),NOW()))
    if not a: raise HTTPException(404)
    allowed=' '.join('https://'+x for x in json.loads(a['allowed_domains'])); csp=f"default-src 'none'; script-src 'unsafe-inline' {allowed}; style-src 'unsafe-inline' {allowed}; img-src data: {allowed}; connect-src {allowed}; frame-src {allowed}; font-src {allowed}; base-uri 'none'; form-action 'none'; sandbox allow-scripts; frame-ancestors 'self'"
    return HTMLResponse('<!doctype html><html><meta charset=utf-8><style>body{margin:0}</style>'+a['ad_code']+'</html>',headers={'Content-Security-Policy':csp,'Cache-Control':'no-store'})
@app.post('/api/v1/admin/reports/{rid}')
def report_resolve(rid:int,d:dict,actor=Depends(admin)):
    state=d.get('status');
    if state not in ('open','resolved','dismissed'): raise HTTPException(422)
    with db() as c: c.execute('UPDATE video_reports SET status=? WHERE id=?',(state,rid)); audit(c,actor,'report.resolve',rid)
    return {'ok':True}
@app.get('/api/v1/admin/settings')
def settings_read(actor=Depends(admin)):
    with db() as c: return {x['key']:x['value'] for x in rows(c,"SELECT * FROM settings WHERE key IN ('site_name','site_url','site_description','seo_title','seo_description','seo_index','search_enabled','search_order')")}
@app.post('/api/v1/admin/settings')
def settings_save(d:dict,actor=Depends(admin)):
    for k in ('seo_index','search_enabled'):
        if k in d and str(d[k]) not in ('0','1'): raise HTTPException(422,k+' must be 0 or 1')
    if 'search_order' in d and d['search_order'] not in ('latest','popular','today','week','month','featured'): raise HTTPException(422,'Invalid search order')
    with db() as c:
        for k in ('site_name','site_url','site_description','seo_title','seo_description','seo_index','search_enabled','search_order'):
            if k in d: c.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(k,validate_url(d[k],True).rstrip('/') if k=='site_url' else str(d[k])[:300]))
        audit(c,actor,'settings.save')
    return {'ok':True}
@app.post('/api/v1/admin/backup')
def backup(actor=Depends(admin)):
    name=make_backup()
    with db() as c: audit(c,actor,'backup.create',name)
    return {'name':name}
@app.get('/api/v1/admin/export')
def export(actor=Depends(admin)):
    with db() as c: data=[get_video(c,v['id'],False) for v in rows(c,'SELECT id FROM videos ORDER BY id LIMIT 100000')]
    return Response(json.dumps(data,ensure_ascii=False),media_type='application/json',headers={'Content-Disposition':'attachment; filename=videohub-export.json'})
@app.get('/robots.txt')
def robots():
    cfg=config(); return PlainTextResponse('User-agent: *\n'+('Disallow: /\n' if cfg.get('seo_index','0')!='1' else 'Disallow: /api/\nDisallow: /ad/\nSitemap: '+cfg['site_url'].rstrip('/')+'/sitemap.xml\n'))
@app.get('/sitemap.xml')
def sitemap(page:int=Query(0,ge=0)):
    cfg=config(); base=cfg['site_url'].rstrip('/'); from urllib.parse import quote
    with db() as c:
        if cfg.get('seo_index','0')!='1': items=[]; n=0
        else:
            n=c.execute('SELECT count(*) FROM sitemap_entries e JOIN videos v ON v.id=e.video_id WHERE '+PUBLIC).fetchone()[0]
            if page==0 and n>10000:
                body=''.join('<sitemap><loc>'+html.escape(base+'/sitemap.xml?page='+str(i))+'</loc></sitemap>' for i in range(1,(n+9999)//10000+1)); return Response('<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+body+'</sitemapindex>',media_type='application/xml')
            items=rows(c,'SELECT v.slug FROM sitemap_entries e JOIN videos v ON v.id=e.video_id WHERE '+PUBLIC+' ORDER BY v.id LIMIT 10000 OFFSET ?',(max(0,page-1)*10000,))
    links=([base+'/'] if cfg.get('seo_index','0')=='1' else [])+[base+'/video/'+quote(x['slug']) for x in items]; return Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+''.join('<url><loc>'+html.escape(x)+'</loc></url>' for x in links)+'</urlset>',media_type='application/xml')
# Fully usable SSR fallback, shared backend; production compose can use Nuxt public UI.
def lang(req): return 'en' if req.query_params.get('lang')=='en' else 'zh'
@app.get('/',response_class=HTMLResponse)
def homepage(req:Request,q:str='',category:str='',tag:str='',sort:str='latest',page:int=Query(1,ge=1)):
    cfg=config(); data=catalog(q,category,tag,sort,page,24); return templates.TemplateResponse(request=req,name='home.html',context={'cfg':cfg,'data':data,'lang':lang(req),'q':q,'category':category,'tag':tag,'sort':sort,'canonical':cfg['site_url'].rstrip('/')+'/'})
@app.get('/video/{slug}',response_class=HTMLResponse)
def watch(slug:str,req:Request):
    cfg=config()
    try: v=public_video(slug)
    except HTTPException:
        with db() as c: red=one(c,'SELECT v.slug FROM redirects r JOIN videos v ON v.id=r.video_id WHERE r.old_slug=? AND '+PUBLIC,(slug,))
        if red: return RedirectResponse('/video/'+red['slug'],301)
        raise
    with db() as c: v['seo']=one(c,'SELECT * FROM video_seo WHERE video_id=?',(v['id'],)) or {}
    return templates.TemplateResponse(request=req,name='video.html',context={'cfg':cfg,'v':v,'lang':lang(req),'canonical':cfg['site_url'].rstrip('/')+'/video/'+v['slug']})
@app.get('/category/{slug}')
def cat_page(slug:str,req:Request): return homepage(req,category=slug,page=1)
@app.get('/tag/{slug}')
def tag_page(slug:str,req:Request): return homepage(req,tag=slug,page=1)
