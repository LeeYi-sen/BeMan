import json,uuid
from urllib.parse import urlsplit,urlunsplit
from fastapi import Depends,HTTPException,Query
from .store import *
from .jobs import enqueue

def validate(d):
    title=str(d.get('title','')).strip()[:300]
    if not title: raise HTTPException(422,'视频标题必填')
    def url(x,required=False):
        x=str(x or '').strip();p=urlsplit(x)
        if not x and not required:return ''
        if len(x)>4096 or p.scheme not in ('http','https') or not p.hostname or p.username or p.password or any(ord(ch)<33 for ch in x): raise HTTPException(422,'请输入有效的 HTTP(S) 网络地址')
        if p.port not in (None,80,443):raise HTTPException(422,'媒体地址仅支持 80/443 端口')
        host=p.hostname.lower().rstrip('.').encode('idna').decode('ascii')
        if ':' in host:host='['+host+']'
        return urlunsplit((p.scheme,host+((':'+str(p.port)) if p.port and p.port!=(443 if p.scheme=='https' else 80) else ''),p.path or '/',p.query,''))
    src=d.get('sources',[])
    if not isinstance(src,list) or not 1<=len(src)<=50: raise HTTPException(422,'请填写 1–50 条播放源')
    sources=[]
    for x in src:
        t=x.get('source_type','iframe');u=url(x.get('source_url'),True);e=url(x.get('embed_url'))
        if t not in ('iframe','mp4','hls','external') or (e and t!='iframe'): raise HTTPException(422,'播放源类型不正确')
        sources.append({'source_url':u,'source_type':t,'embed_url':e,'quality':str(x.get('quality',''))[:100],'status':int(bool(x.get('status',1)))})
    if len({x['source_url'] for x in sources})!=len(sources): raise HTTPException(422,'播放源重复')
    rights=d.get('rights_status','pending');ref=str(d.get('rights_reference',''))[:2000]
    if rights not in ('pending','authorized','blocked'): raise HTTPException(422,'授权状态无效')
    if rights=='authorized' and not ref.strip(): ref='运营者已确认有权发布（自我声明，非平台核验）'
    tags=d.get('tags',[])
    if not isinstance(tags,list): raise HTTPException(422,'标签格式错误')
    return dict(title=title,title_en=str(d.get('title_en',''))[:300],description=str(d.get('description',''))[:10000],description_en=str(d.get('description_en',''))[:10000],cover_url=url(d.get('cover_url')),duration=max(0,int(d.get('duration',0))),category_name=str(d.get('category_name',''))[:100],tags=list(dict.fromkeys(str(t).strip()[:100] for t in tags if str(t).strip()))[:100],rights_status=rights,rights_reference=ref,sources=sources)

def reserve_sources(c,mid,doc):
    c.execute('DELETE FROM media_source_keys WHERE media_id=?',(mid,))
    for src in doc['sources']:
        existing=one(c,'SELECT media_id FROM media_source_keys WHERE source_url=?',(src['source_url'],))
        if existing:raise HTTPException(409,'播放源已在中央库视频 #'+str(existing['media_id'])+' 中存在')
        c.execute('INSERT INTO media_source_keys VALUES(?,?)',(src['source_url'],mid))

def serialize(c,r):
    return {**r,'document':json.loads(r['document']),'sites':rows(c,'SELECT m.*,s.name,j.status job_status FROM media_site_mappings m JOIN sites s ON s.id=m.site_id LEFT JOIN jobs j ON j.id=m.job_id WHERE media_id=? ORDER BY site_id',(r['id'],))}

def register(app,auth):
    @app.get('/api/media')
    def media(q:str='',page:int=Query(1,ge=1),site_id:int=0,status:str='',a=Depends(auth)):
        conditions=['m.document LIKE ?']; args=['%'+q[:200]+'%']
        if status:
            if status not in ('published','draft','unpublished','frozen','deleted','not_distributed','needs_review'): raise HTTPException(422,'Invalid status')
            clause='ms.media_id=m.id'+(' AND ms.site_id=?' if site_id else '')
            if site_id: args.append(site_id)
            if status=='not_distributed':
                conditions.append('NOT EXISTS(SELECT 1 FROM media_site_mappings ms WHERE '+clause+" AND ms.actual!='not_distributed')")
            elif status=='needs_review':
                conditions.append('EXISTS(SELECT 1 FROM media_site_mappings ms JOIN jobs j ON j.id=ms.job_id WHERE '+clause+" AND j.status='needs_review')")
            else:
                conditions.append('EXISTS(SELECT 1 FROM media_site_mappings ms WHERE '+clause+' AND ms.actual=?)');args.append(status)
        elif site_id:
            conditions.append('EXISTS(SELECT 1 FROM media_site_mappings ms WHERE ms.media_id=m.id AND ms.site_id=?)');args.append(site_id)
        where=' AND '.join(conditions)
        with db() as c:
            total=c.execute('SELECT count(*) FROM media_library m WHERE '+where,args).fetchone()[0]
            return {'total':total,'items':[serialize(c,r) for r in rows(c,'SELECT m.* FROM media_library m WHERE '+where+' ORDER BY m.id DESC LIMIT 30 OFFSET ?',(*args,(page-1)*30))]}
    @app.post('/api/media')
    def create(d:dict,a=Depends(auth)):
        doc=validate(d);raw=json.dumps(doc,ensure_ascii=False)
        with db() as c:
            mid=c.execute('INSERT INTO media_library(media_key,document,created_at,updated_at) VALUES(?,?,?,?)',(uuid.uuid4().hex,raw,now(),now())).lastrowid
            reserve_sources(c,mid,doc);c.execute('INSERT INTO media_revisions VALUES(?,?,?,?)',(mid,1,raw,now()));audit(c,None,'media.create',mid)
            return serialize(c,one(c,'SELECT * FROM media_library WHERE id=?',(mid,)))
    @app.put('/api/media/{mid}')
    def edit(mid:int,d:dict,a=Depends(auth)):
        with db() as c:
            c.execute('BEGIN IMMEDIATE');m=one(c,'SELECT * FROM media_library WHERE id=?',(mid,))
            if not m: raise HTTPException(404)
            previous=json.loads(m['document']);doc=validate({**previous,**d});raw=json.dumps(doc,ensure_ascii=False)
            reserve_sources(c,mid,doc);rev=m['revision']+1;c.execute('UPDATE media_library SET document=?,updated_at=?,revision=? WHERE id=?',(raw,now(),rev,mid));c.execute('INSERT INTO media_revisions VALUES(?,?,?,?)',(mid,rev,raw,now()));audit(c,None,'media.edit',mid)
            return serialize(c,one(c,'SELECT * FROM media_library WHERE id=?',(mid,)))
    @app.post('/api/media/{mid}/distribute')
    def distribute(mid:int,d:dict,a=Depends(auth)):
        action=d.get('action');ids=d.get('site_ids',[])
        if action not in ('publish','sync','unpublish','freeze','unfreeze','delete','restore') or not isinstance(ids,list) or not ids: raise HTTPException(422,'请选择操作和目标站点')
        ids=list(dict.fromkeys(int(x) for x in ids));out=[]
        with db() as c:
            c.execute('BEGIN IMMEDIATE');m=one(c,'SELECT * FROM media_library WHERE id=?',(mid,))
            if not m: raise HTTPException(404)
            doc=json.loads(m['document'])
            if action=='publish' and (doc['rights_status']!='authorized' or not doc['rights_reference'].strip()): raise HTTPException(422,'发布前必须有真实授权依据')
            for sid in ids:
                if not one(c,'SELECT id FROM sites WHERE id=? AND enabled=1',(sid,)): raise HTTPException(422,'站点不可用')
                old=one(c,'SELECT m.*,j.status job_status FROM media_site_mappings m LEFT JOIN jobs j ON j.id=m.job_id WHERE media_id=? AND m.site_id=?',(mid,sid))
                if old and old['job_status'] in ('queued','running','needs_review','failed'): raise HTTPException(409,'该视频在目标站点有未完成任务；请先在任务中心核对或重试')
                if (not old or old['actual']=='not_distributed') and action not in ('publish','sync'): raise HTTPException(409,'尚未分发到目标站点')
                v=(old['version'] if old else 0)+1;prev=old['actual'] if old else 'draft'
                if action=='sync' and prev=='not_distributed':prev='draft'
                if action in ('publish','sync') and prev in ('frozen','deleted'):raise HTTPException(409,'请先解冻或恢复')
                payload={'media_id':mid,'media_key':m['media_key'],'version':v,'action':action,'video':doc,'previous':prev}
                j=enqueue(c,sid,'distribution',payload)
                c.execute('INSERT INTO media_site_mappings(media_id,site_id,version,desired,job_id) VALUES(?,?,?,?,?) ON CONFLICT(media_id,site_id) DO UPDATE SET version=excluded.version,desired=excluded.desired,job_id=excluded.job_id,error=\'\'',(mid,sid,v,action,j));out.append(j)
            audit(c,None,'media.distribute',f'{mid}:{action}');return {'jobs':out}
    @app.post('/api/jobs/{jid}/retry')
    def retry(jid:int,a=Depends(auth)):
        with db() as c:
            c.execute('BEGIN IMMEDIATE');j=one(c,'SELECT * FROM jobs WHERE id=?',(jid,))
            if not j or j['status'] not in ('failed','needs_review'):raise HTTPException(409,'该任务不可重试')
            if j['kind']!='distribution':raise HTTPException(409,'请人工核对普通任务后重新发起')
            p=json.loads(j['payload']);m=one(c,'SELECT * FROM media_site_mappings WHERE media_id=? AND site_id=?',(p['media_id'],j['site_id']))
            if not m or m['job_id']!=jid:raise HTTPException(409,'已存在更新任务')
            c.execute("UPDATE jobs SET status='queued',error='',finished_at=NULL,started_at=NULL WHERE id=?",(jid,));c.execute('UPDATE media_site_mappings SET error=\'\' WHERE media_id=? AND site_id=?',(p['media_id'],j['site_id']));return {'ok':True}
    @app.get('/api/overview')
    def overview(a=Depends(auth)):
        with db() as c:
            return {'media':c.execute('SELECT count(*) FROM media_library').fetchone()[0],'jobs':rows(c,'SELECT status,count(*) count FROM jobs GROUP BY status'),'sites':rows(c,'SELECT id,name,region,base_url,enabled,last_seen,last_status,last_error,last_dashboard FROM sites ORDER BY id')}
