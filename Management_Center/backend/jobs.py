import json,time,datetime,collections,logging,fcntl,concurrent.futures
from .store import *
from .client import request,RemoteError
KINDS={'health','rankings','seo','check_sources','imports','backup','distribution'}
def enqueue(c,site_id,kind,payload=None,schedule_id=None):
    if kind not in KINDS: raise ValueError('Unknown job kind')
    return c.execute('INSERT INTO jobs(site_id,kind,payload,created_at,schedule_id) VALUES(?,?,?,?,?)',(site_id,kind,json.dumps(payload or {}),now(),schedule_id)).lastrowid
def fetch_cursor(site,path):
    after=0
    while True:
        batch=request(site,'GET',path,query={'after':after,'limit':500})
        if not batch: break
        yield from batch; after=batch[-1]['id']
def fetch_pages(site,path):
    page=1
    while True:
        batch=request(site,'GET',path,query={'page':page,'limit':100})
        yield from batch
        if len(batch)<100: break
        page+=1
def execute(site,kind,payload,progress=lambda _:None):
    if kind=='distribution':
        result=request(site,'PUT','/distribution/'+payload['media_key'],{'revision':payload['version'],'action':payload['action'],'video':payload['video']})
        if result.get('stale'): raise ValueError('Remote has a newer revision; reconcile before retry')
        return result
    if kind=='health':
        caps=request(site,'GET','/capabilities'); dashboard=request(site,'GET','/dashboard')
        with db() as c: c.execute('UPDATE sites SET last_dashboard=? WHERE id=?',(json.dumps(dashboard),site['id']))
        return {'capabilities':caps,'dashboard':dashboard}
    if kind=='rankings':
        videos=list(fetch_cursor(site,'/published')); progress(f'{len(videos)} published videos'); ids={v['id'] for v in videos}; counts={k:collections.Counter() for k in ('today','week','month')}; today=datetime.datetime.now(datetime.timezone.utc).date()
        for stat in fetch_cursor(site,'/stats'):
            if stat['video_id'] not in ids: continue
            days=(today-datetime.date.fromisoformat(stat['date'])).days
            for k,n in [('today',1),('week',7),('month',30)]:
                if 0<=days<n: counts[k][stat['video_id']]+=stat['view_count']
        limit=max(1,min(10000,int(payload.get('limit',1000)))); boards={'popular':[v['id'] for v in sorted(videos,key=lambda v:(-v['view_count'],v['id']))[:limit]]}
        for k,ctr in counts.items(): boards[k]=sorted((i for i in ctr if ctr[i]>0),key=lambda i:(-ctr[i],i))[:limit]
        version=time.time_ns()//1000000
        result={}
        for k,v in boards.items():
            result[k]=request(site,'PUT','/rankings/'+k,{'ids':v,'version':version}); progress(f'{len(result)}/4 ranking boards')
        return result
    if kind=='seo':
        videos=list(fetch_cursor(site,'/published')); progress(f'{len(videos)} sitemap entries'); res=request(site,'PUT','/sitemap',{'ids':[v['id'] for v in videos],'version':time.time_ns()//1000000})
        # Optional generation is controlled by the center; do not overwrite manual metadata by default.
        if payload.get('generate_metadata'):
            for i,v in enumerate(videos,1):
                request(site,'PUT',f"/videos/{v['id']}/seo",{'title':v['title'],'title_en':v['title_en'],'description':v['description'][:160],'description_en':v['description_en'][:160]}); progress(f'{i}/{len(videos)} SEO records')
        return res
    if kind=='check_sources':
        limit=max(1,min(500,int(payload.get('limit',30)))); interval=max(60,int(payload.get('min_age',86400))); eligible=[]
        for s in fetch_pages(site,'/sources'):
            if s['status'] and s['provider_id'] and (not s['last_checked_at'] or s['last_checked_at']<=now()-interval): eligible.append(s)
        result=[]
        for s in sorted(eligible,key=lambda s:(s['last_checked_at'] or 0,s['id']))[:limit]:
            r=request(site,'POST',f"/sources/{s['id']}/check"); result.append(r)
            threshold=max(1,min(20,int(payload.get('failure_threshold',3))))
            if r['health_status']=='missing' and r['failure_count']>=threshold:
                request(site,'PUT',f"/sources/{s['id']}/policy",{'excluded':True})
            elif r['health_status']=='reachable' and s.get('excluded'):
                request(site,'PUT',f"/sources/{s['id']}/policy",{'excluded':False})
            progress(f'{len(result)}/{min(limit,len(eligible))} sources'); time.sleep(.25)
        return {'checked':len(result),'results':result}
    if kind=='imports':
        tid=payload.get('task_id'); tasks=[{'id':int(tid),'status':'queued'}] if tid else list(fetch_pages(site,'/imports')); completed=[]
        for task in tasks:
            if task['status'] not in ('queued','running'): continue
            # Remote primitive is transactional and resumable; repeated calls only process queued rows.
            for _ in range(200):
                r=request(site,'POST',f"/imports/{task['id']}/run");
                progress(f"Import {task['id']}: {r['processed']}/{r['total']}")
                if r['status']=='done': break
            completed.append(r)
        return completed
    if kind=='backup': return request(site,'POST','/backup')
    raise ValueError('Unknown job')
def run_job(job):
    with db() as c: site=one(c,'SELECT * FROM sites WHERE id=? AND enabled=1',(job['site_id'],))
    def progress(message):
        with db() as c: c.execute('UPDATE jobs SET progress=? WHERE id=?',(message[:300],job['id']))
    if not site: status='failed'; result={}; error='Site disabled or removed'
    else:
        try: result=execute(site,job['kind'],json.loads(job['payload']),progress); status='done'; error=''
        except Exception as e: status='needs_review'; result={}; error=str(e)[:300]
    with db() as c:
        c.execute('UPDATE jobs SET status=?,result=?,error=?,finished_at=? WHERE id=?',(status,json.dumps(result,ensure_ascii=False),error,now(),job['id']))
        if job['kind']=='distribution':
            p=json.loads(job['payload']); c.execute("UPDATE media_site_mappings SET remote_id=COALESCE(?,remote_id),actual=CASE WHEN ?='done' THEN ? ELSE actual END,error=? WHERE media_id=? AND site_id=? AND version=?",(result.get('id'),status,{'publish':'published','sync':p.get('previous','draft'),'unpublish':'unpublished','freeze':'frozen','unfreeze':'draft','delete':'deleted','restore':'draft'}[p['action']],error,p['media_id'],job['site_id'],p['version']))
        c.execute('UPDATE sites SET last_seen=CASE WHEN ?=\'done\' THEN ? ELSE last_seen END,last_status=?,last_error=? WHERE id=?',(status,now(),'online' if status=='done' else 'error',error,job['site_id']))
        audit(c,job['site_id'],'job.'+status,job['kind'])
def claim():
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        for s in rows(c,'SELECT sc.* FROM schedules sc JOIN sites st ON st.id=sc.site_id WHERE sc.enabled=1 AND st.enabled=1 AND sc.next_run<=?',(now(),)):
            if not one(c,"SELECT id FROM jobs WHERE schedule_id=? AND status IN ('queued','running')",(s['id'],)): enqueue(c,s['site_id'],s['kind'],json.loads(s['payload']),s['id'])
            c.execute('UPDATE schedules SET next_run=? WHERE id=?',(now()+s['interval_seconds'],s['id']))
        job=one(c,"SELECT j.* FROM jobs j JOIN sites s ON s.id=j.site_id WHERE j.status='queued' AND s.enabled=1 AND NOT EXISTS(SELECT 1 FROM jobs r WHERE r.site_id=j.site_id AND r.status='running') ORDER BY j.id LIMIT 1")
        if job: c.execute("UPDATE jobs SET status='running',started_at=? WHERE id=?",(now(),job['id']))
        return job
if __name__=='__main__':
    logging.basicConfig(level=logging.INFO); init()
    with open(DB.parent/'scheduler.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with db() as c: c.execute("UPDATE jobs SET status='needs_review',error='Scheduler interrupted; verify remote result before retry',finished_at=? WHERE status='running'",(now(),))
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures=set()
            while True:
                futures={f for f in futures if not f.done()}
                while len(futures)<4:
                    job=claim()
                    if not job: break
                    futures.add(pool.submit(run_job,job))
                time.sleep(1)
