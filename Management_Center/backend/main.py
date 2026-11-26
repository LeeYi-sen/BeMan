import os,time,secrets,hmac,hashlib,base64,json,re
from contextlib import asynccontextmanager
from fastapi import FastAPI,Request,HTTPException,Depends,Query
from fastapi.responses import FileResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from .store import *
from .client import base_url,request,RemoteError
from .jobs import enqueue,KINDS
@asynccontextmanager
async def lifespan(app): init();yield
app=FastAPI(title='Management Center',version='2.0',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
app.mount('/static',StaticFiles(directory=ROOT/'frontend'),name='static')
def mac(s): return hmac.new(os.environ['MC_MASTER_KEY'].encode(),('session:'+hashlib.sha256(os.environ['MC_PASSWORD'].encode()).hexdigest()+':'+s).encode(),hashlib.sha256).hexdigest()
def session(req):
    try:
        t,s=req.cookies.get('mc_session','').split('.')
        if not hmac.compare_digest(s,mac(t)): return None
        d=json.loads(base64.urlsafe_b64decode(t)); return d if d['exp']>now() else None
    except Exception: return None
def auth(req:Request):
    d=session(req)
    if not d: raise HTTPException(401,'Login required')
    if req.method not in ('GET','HEAD') and not hmac.compare_digest(req.headers.get('X-CSRF-Token',''),d['csrf']): raise HTTPException(403,'CSRF token required')
    return d
@app.middleware('http')
async def headers(req,call_next):
    r=await call_next(req);r.headers['Cache-Control']='no-store';r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY';r.headers['Content-Security-Policy']="default-src 'self';script-src 'self' https://cdn.jsdelivr.net/npm/hls.js@1.5.18/dist/hls.min.js;style-src 'self';img-src 'self' https: http: data:;frame-src https: http:;media-src https: http: blob:;connect-src 'self' https: http:;worker-src 'self' blob:;object-src 'none';base-uri 'none';frame-ancestors 'none';form-action 'self'";return r
@app.exception_handler(ValueError)
async def invalid(req,e): return JSONResponse({'detail':str(e)[:300]},422)
@app.exception_handler(sqlite3.IntegrityError)
async def conflict(req,e): return JSONResponse({'detail':'Duplicate or invalid related record'},409)
@app.exception_handler(RemoteError)
async def remote_error(req,e): return JSONResponse({'detail':str(e),'remote_status':e.status},502)
@app.get('/')
def home(): return FileResponse(ROOT/'frontend/index.html')
@app.get('/healthz')
def health():
    with db() as c: c.execute('SELECT 1')
    return {'status':'ok'}
_attempts={}
@app.post('/api/login')
def login(d:dict,req:Request):
    ip=req.client.host if req.client else 'unknown'; t=now()
    for k in list(_attempts):
        if _attempts[k][0]<t: del _attempts[k]
    until,count=_attempts.get(ip,(t+300,0))
    if count>=10: raise HTTPException(429,'Try later')
    if not hmac.compare_digest(str(d.get('password','')).encode(),os.environ['MC_PASSWORD'].encode()):
        _attempts[ip]=(until,count+1);raise HTTPException(401,'Invalid password')
    _attempts.pop(ip,None); csrf=secrets.token_hex(32); token=base64.urlsafe_b64encode(json.dumps({'exp':now()+43200,'csrf':csrf}).encode()).decode();r=JSONResponse({'csrf':csrf});r.set_cookie('mc_session',token+'.'+mac(token),httponly=True,secure=os.getenv('MC_SECURE_COOKIE','1')=='1',samesite='strict',max_age=43200);return r
@app.get('/api/session')
def who(a=Depends(auth)): return {'csrf':a['csrf']}
@app.post('/api/logout')
def logout(a=Depends(auth)):
    r=JSONResponse({'ok':True});r.delete_cookie('mc_session');return r
@app.get('/api/sites')
def sites(a=Depends(auth)):
    with db() as c: return rows(c,'SELECT id,name,base_url,key_id,region,enabled,created_at,last_seen,last_status,last_error,last_dashboard FROM sites ORDER BY id')
@app.post('/api/sites')
def add_site(d:dict,a=Depends(auth)):
    name=str(d.get('name','')).strip()[:100]; origin=base_url(d.get('base_url',''));kid=str(d.get('key_id','')).strip();secret=str(d.get('secret',''))
    if not name or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}',kid) or len(secret)<32: raise HTTPException(422,'Name, key ID and secret (32+ chars) required')
    with db() as c:
        ident=c.execute('INSERT INTO sites(name,base_url,key_id,secret_enc,region,created_at,enabled) VALUES(?,?,?,?,?,?,?)',(name,origin,kid,encrypt(secret),str(d.get('region',''))[:100],now(),int(bool(d.get('enabled',True))))).lastrowid; audit(c,ident,'site.create')
    return {'id':ident}
@app.put('/api/sites/{sid}')
def edit_site(sid:int,d:dict,a=Depends(auth)):
    with db() as c:
        s=one(c,'SELECT * FROM sites WHERE id=?',(sid,))
        if not s: raise HTTPException(404)
        if one(c,"SELECT id FROM jobs WHERE site_id=? AND status='running'",(sid,)): raise HTTPException(409,'Site has a running task')
        name=str(d.get('name',s['name'])).strip()[:100];origin=base_url(d.get('base_url',s['base_url']));kid=str(d.get('key_id',s['key_id']));secret=str(d.get('secret',''))
        if not name or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}',kid) or (secret and len(secret)<32): raise HTTPException(422,'Invalid site configuration')
        c.execute('UPDATE sites SET name=?,base_url=?,key_id=?,secret_enc=?,region=?,enabled=? WHERE id=?',(name,origin,kid,encrypt(secret) if secret else s['secret_enc'],str(d.get('region',s['region']))[:100],int(bool(d.get('enabled',s['enabled']))),sid));audit(c,sid,'site.edit')
    return {'ok':True}
@app.delete('/api/sites/{sid}')
def delete_site(sid:int,a=Depends(auth)):
    with db() as c:
        if one(c,"SELECT id FROM jobs WHERE site_id=? AND status='running'",(sid,)): raise HTTPException(409,'Site has a running task')
        c.execute('DELETE FROM sites WHERE id=?',(sid,));audit(c,sid,'site.detach')
    return {'ok':True}
def get_site(sid):
    with db() as c: s=one(c,'SELECT * FROM sites WHERE id=? AND enabled=1',(sid,))
    if not s: raise HTTPException(404,'Site unavailable')
    return s
# Strict path/method whitelist: this is not an arbitrary HTTP proxy.
RULES={'GET':[r'/(dashboard|capabilities|videos|sources|categories|tags|providers|ads|settings|rankings|reports|imports|logs|backups|stats|published)',r'/videos/\d+',r'/imports/\d+/items'], 'POST':[r'/(videos|categories|tags|providers|ads|settings|imports|backup)',r'/videos/\d+/sources',r'/sources/\d+/check',r'/reports/\d+'], 'PUT':[r'/(videos|sources)/\d+',r'/videos/\d+/seo',r'/sources/\d+/policy',r'/rankings/(popular|today|week|month)',r'/sitemap'], 'DELETE':[r'/(videos|sources|categories|tags|providers|ads)/\d+']}
@app.post('/api/sites/{sid}/command')
def command(sid:int,d:dict,a=Depends(auth)):
    s=get_site(sid); method=str(d.get('method','GET')).upper(); path=str(d.get('path',''))
    if not any(re.fullmatch(p,path) for p in RULES.get(method,[])): raise HTTPException(422,'Unsupported operation')
    query=d.get('query',{})
    if not isinstance(query,dict) or any(k not in ('page','limit','q','after') for k in query): raise HTTPException(422,'Invalid query')
    if method=='POST' and path=='/imports':
        payload=d.get('data',{})
        if not payload.get('request_id'): raise HTTPException(422,'Import request_id required')
    try: result=request(s,method,path,d.get('data') if method not in ('GET','DELETE') else None,query)
    except RemoteError:
        with db() as c: audit(c,sid,'remote.error',method+' '+path)
        raise
    with db() as c: audit(c,sid,'remote.'+method,path)
    return result
@app.get('/api/jobs')
def jobs(site_id:int=0,a=Depends(auth)):
    with db() as c: return rows(c,'SELECT * FROM jobs WHERE (?=0 OR site_id=?) ORDER BY id DESC LIMIT 200',(site_id,site_id))
@app.post('/api/jobs')
def create_job(d:dict,a=Depends(auth)):
    sid=int(d['site_id']);get_site(sid);kind=str(d.get('kind',''))
    if kind=='distribution': raise HTTPException(422,'Use media distribution endpoint')
    with db() as c: ident=enqueue(c,sid,kind,d.get('payload',{}));audit(c,sid,'job.create',kind)
    return {'id':ident}
@app.get('/api/schedules')
def schedules(site_id:int=0,a=Depends(auth)):
    with db() as c:return rows(c,'SELECT * FROM schedules WHERE (?=0 OR site_id=?) ORDER BY id',(site_id,site_id))
@app.post('/api/schedules')
def schedule(d:dict,a=Depends(auth)):
    sid=int(d['site_id']);get_site(sid);kind=d['kind'];interval=int(d.get('interval_seconds',3600))
    if kind not in KINDS-{'distribution'} or not 60<=interval<=31536000: raise HTTPException(422,'Invalid schedule')
    with db() as c:
        c.execute('INSERT INTO schedules(site_id,kind,payload,interval_seconds,next_run,enabled) VALUES(?,?,?,?,?,?) ON CONFLICT(site_id,kind) DO UPDATE SET payload=excluded.payload,interval_seconds=excluded.interval_seconds,next_run=excluded.next_run,enabled=excluded.enabled',(sid,kind,json.dumps(d.get('payload',{})),interval,now()+interval,int(bool(d.get('enabled',True)))));audit(c,sid,'schedule.save',kind)
    return {'ok':True}
@app.delete('/api/schedules/{ident}')
def delete_schedule(ident:int,a=Depends(auth)):
    with db() as c:c.execute('DELETE FROM schedules WHERE id=?',(ident,))
    return {'ok':True}
@app.get('/api/audit')
def audits(a=Depends(auth)):
    with db() as c:return rows(c,'SELECT * FROM audit ORDER BY id DESC LIMIT 200')
@app.post('/api/backup')
def local_backup(a=Depends(auth)):return {'name':backup()}

from .media import register
register(app,auth)
