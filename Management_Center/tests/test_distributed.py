"""Real loopback HTTP: two separate site processes and an independently deployed center."""
import os,sys,subprocess,socket,time,json,sqlite3
from pathlib import Path
import httpx,pytest
ROOT=Path(__file__).resolve().parents[2];CENTER=ROOT/'Management_Center';VH=ROOT/'VideoHub'
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def launch(cwd,env,cmd,procs):
    p=subprocess.Popen([sys.executable,*cmd],cwd=cwd,env={**os.environ,**env},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);procs.append(p);return p
def wait(url):
    for _ in range(100):
        try:
            if httpx.get(url,timeout=.4,trust_env=False).status_code==200:return
        except httpx.HTTPError:pass
        time.sleep(.1)
    raise AssertionError('Service did not start: '+url)
@pytest.fixture
def cluster(tmp_path):
    ps=[]; nodes=[]
    try:
        for i in (1,2):
            p=port();url=f'http://127.0.0.1:{p}';env={'VIDEOHUB_DB':str(tmp_path/f'node{i}/video.db'),'VIDEOHUB_BACKUPS':str(tmp_path/f'node{i}/backups'),'VIDEOHUB_SITE_ID':f'node{i}','VIDEOHUB_API_KEY':f'node{i}','VIDEOHUB_API_SECRET':str(i)*40};proc=launch(VH,env,['-m','uvicorn','backend.main:app','--host','127.0.0.1','--port',str(p)],ps);wait(url+'/healthz');nodes.append((url,proc,env))
        p=port();base=f'http://127.0.0.1:{p}';env={'MC_DB':str(tmp_path/'center/management.db'),'MC_BACKUPS':str(tmp_path/'center/backups'),'MC_PASSWORD':'secure-test-password','MC_MASTER_KEY':'m'*40,'MC_SECURE_COOKIE':'0','MC_ALLOW_HTTP_LOCAL':'1'};mc=launch(CENTER,env,['-m','uvicorn','backend.main:app','--host','127.0.0.1','--port',str(p)],ps);wait(base+'/healthz');worker=launch(CENTER,env,['-m','backend.jobs'],ps)
        with httpx.Client(base_url=base,trust_env=False,timeout=15) as c:
            yield c,nodes,mc,worker,tmp_path,env
    finally:
        for p in reversed(ps):
            if p.poll() is None:p.terminate()
        for p in reversed(ps):
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
def test_two_sites_isolated_and_offline(cluster):
    c,nodes,mc,worker,tmp,env=cluster
    assert c.get('/api/sites').status_code==401
    r=c.post('/api/login',json={'password':env['MC_PASSWORD']});assert r.status_code==200,r.text;c.headers['X-CSRF-Token']=r.json()['csrf']
    ids=[]
    for i,(url,_,se) in enumerate(nodes,1):
        r=c.post('/api/sites',json={'name':f'Site {i}','region':('Europe' if i==1 else 'America'),'base_url':url,'key_id':se['VIDEOHUB_API_KEY'],'secret':se['VIDEOHUB_API_SECRET']});assert r.status_code==200,r.text;ids.append(r.json()['id'])
    assert 'secret_enc' not in c.get('/api/sites').text and '1'*40 not in c.get('/api/sites').text
    with sqlite3.connect(env['MC_DB']) as db:assert db.execute('SELECT secret_enc FROM sites WHERE id=?',(ids[0],)).fetchone()[0]!='1'*40
    def cmd(i,method,path,data=None):
        r=c.post(f'/api/sites/{ids[i]}/command',json={'method':method,'path':path,'data':data});assert r.status_code==200,r.text;return r.json()
    def job(i,kind,payload=None):
        r=c.post('/api/jobs',json={'site_id':ids[i],'kind':kind,'payload':payload or {}});assert r.status_code==200,r.text;return r.json()['id']
    def done(j):
        for _ in range(150):
            r=next(x for x in c.get('/api/jobs').json() if x['id']==j)
            if r['status'] not in ('queued','running'):assert r['status']=='done',r;return r
            time.sleep(.1)
        raise AssertionError('job timeout')
    for i in range(2):done(job(i,'health'))
    v=cmd(0,'POST','/videos',{'title':'Europe only','title_en':'Europe only','rights_status':'authorized','rights_reference':'Owned test fixture','status':1,'sources':[{'source_url':'https://example.com/a.mp4','source_type':'mp4'}]})
    assert cmd(1,'GET','/videos')['total']==0
    assert cmd(0,'GET','/videos')['total']==1
    cmd(0,'POST','/settings',{'site_name':'Europe hub','site_url':'https://europe.example.com','seo_index':'1'})
    cmd(0,'POST','/ads',{'name':'Test ad','ad_code':'<div>fixture</div>','allowed_domains':['example.com'],'position':'top','enabled':1})
    done(job(0,'rankings'));done(job(0,'seo',{'generate_metadata':True}));done(job(0,'backup'))
    imp=cmd(1,'POST','/imports',{'request_id':'same-import','items':['https://example.com/b.mp4','https://example.com/b.mp4']});done(job(1,'imports',{'task_id':imp['id']}));assert cmd(1,'GET','/imports')[0]['duplicate_count']==1
    assert c.post('/api/schedules',json={'site_id':ids[0],'kind':'health','interval_seconds':60}).status_code==200
    with sqlite3.connect(env['MC_DB']) as db:db.execute('UPDATE schedules SET next_run=0');db.commit()
    for _ in range(50):
        if any(j['schedule_id'] and j['status']=='done' for j in c.get('/api/jobs').json()):break
        time.sleep(.15)
    else:pytest.fail('schedule not executed')
    assert c.post('/api/backup').status_code==200
    # One node offline does not stop jobs on the other node.
    nodes[1][1].terminate();nodes[1][1].wait(timeout=5);bad=job(1,'health');good=job(0,'health');done(good)
    for _ in range(50):
        failed=next(x for x in c.get('/api/jobs').json() if x['id']==bad)
        if failed['status']=='needs_review':break
        time.sleep(.1)
    else:pytest.fail('offline state not recorded')
    # Shut down the center entirely. The remaining node continues serving saved content, config, ranks and ad frames.
    worker.terminate();worker.wait(timeout=5);mc.terminate();mc.wait(timeout=5)
    with httpx.Client(base_url=nodes[0][0],trust_env=False) as public:
        assert public.get('/').status_code==200 and 'Europe only' in public.get('/').text
        assert public.get('/api/public/catalog?sort=popular').json()['total']==1
        assert public.get('/api/public/catalog?q=Europe').json()['total']==1
        assert v['slug'] in public.get('/sitemap.xml').text
        assert public.get('/api/public/config').json()['ads'][0]['name']=='Test ad'
        assert public.get('/admin').status_code==404
    for f in (tmp/'center/management.db',tmp/'node1/video.db',tmp/'node2/video.db'):assert f.exists()
    with sqlite3.connect(tmp/'node1/video.db') as db:
        assert not db.execute("SELECT name FROM sqlite_master WHERE name='scheduled_tasks'").fetchone();assert not db.execute("SELECT name FROM sqlite_master WHERE name='sites'").fetchone()
    with sqlite3.connect(tmp/'center/management.db') as db:assert not db.execute("SELECT name FROM sqlite_master WHERE name='videos'").fetchone()

def test_central_library_and_lifecycle(cluster):
    c,nodes,mc,worker,tmp,env=cluster
    r=c.post('/api/login',json={'password':env['MC_PASSWORD']});assert r.status_code==200;c.headers['X-CSRF-Token']=r.json()['csrf']
    ids=[]
    for i,(url,_,se) in enumerate(nodes,1):
        r=c.post('/api/sites',json={'name':f'Site {i}','base_url':url,'key_id':se['VIDEOHUB_API_KEY'],'secret':se['VIDEOHUB_API_SECRET']});assert r.status_code==200,r.text;ids.append(r.json()['id'])
    for i,sid in enumerate(ids):
        r=c.post(f'/api/sites/{sid}/command',json={'method':'POST','path':'/categories','data':{'name':'Film','slug':f'film-existing-{i}'}});assert r.status_code==200,r.text
    doc={'title':'Central original','title_en':'Central original','category_name':'Film','tags':['demo'],'rights_status':'pending','sources':[{'source_url':'https://example.com/owned.mp4','source_type':'mp4'}]}
    r=c.post('/api/media',json=doc);assert r.status_code==200,r.text;m=r.json();mid=m['id'];
    assert c.post('/api/media',json=doc).status_code==409
    assert c.post(f'/api/media/{mid}/distribute',json={'action':'publish','site_ids':ids}).status_code==422
    doc['rights_status']='authorized'
    r=c.put(f'/api/media/{mid}',json=doc);assert r.status_code==200,r.text
    doc['rights_reference']='Owned test fixture'
    assert c.put(f'/api/media/{mid}',json=doc).status_code==200
    del doc['rights_reference']
    r=c.put(f'/api/media/{mid}',json=doc);assert r.status_code==200,r.text
    assert r.json()['document']['rights_reference']=='Owned test fixture'
    def action(name,targets):
        r=c.post(f'/api/media/{mid}/distribute',json={'action':name,'site_ids':targets});assert r.status_code==200,r.text;return r.json()['jobs']
    def wait_jobs(ids,status='done'):
        for _ in range(180):
            jobs={x['id']:x for x in c.get('/api/jobs').json()}
            if all(jobs[x]['status'] not in ('queued','running') for x in ids):
                assert all(jobs[x]['status']==status for x in ids),[jobs[x] for x in ids];return
            time.sleep(.1)
        pytest.fail('timeout')
    def public(i):return httpx.get(nodes[i][0]+'/api/public/catalog',trust_env=False).json()['items']
    wait_jobs(action('publish',ids));assert all(len(public(i))==1 for i in (0,1))
    wait_jobs(action('freeze',[ids[0]]));assert not public(0) and len(public(1))==1
    assert c.get('/api/media',params={'site_id':ids[0],'status':'frozen'}).json()['total']==1
    assert c.get('/api/media',params={'site_id':ids[1],'status':'frozen'}).json()['total']==0
    assert c.post(f'/api/media/{mid}/distribute',json={'action':'publish','site_ids':[ids[0]]}).status_code==409
    wait_jobs(action('unfreeze',[ids[0]]));assert not public(0)
    wait_jobs(action('publish',[ids[0]]));assert len(public(0))==1
    doc['title']='Central revised';doc['sources']=[{'source_url':'https://example.com/new.mp4','source_type':'mp4'}]
    assert c.put(f'/api/media/{mid}',json=doc).status_code==200
    wait_jobs(action('sync',ids));assert all(public(i)[0]['title']=='Central revised' for i in (0,1))
    # Simulate an already-committed request whose acknowledgement was lost, retry exact same revision.
    j=action('publish',[ids[1]])[0];wait_jobs([j]);
    with sqlite3.connect(env['MC_DB']) as con:con.execute("UPDATE jobs SET status='needs_review' WHERE id=?",(j,));con.commit()
    assert c.post(f'/api/jobs/{j}/retry').status_code==200;wait_jobs([j]);assert len(public(1))==1
    wait_jobs(action('delete',[ids[0]]));assert not public(0) and len(public(1))==1
    wait_jobs(action('restore',[ids[0]]));assert not public(0)
    wait_jobs(action('publish',[ids[0]]));assert len(public(0))==1
    overview=c.get('/api/overview').json();assert overview['media']==1
    for i in (1,2):
        with sqlite3.connect(tmp/f'node{i}/video.db') as con:
            assert con.execute('SELECT count(*) FROM videos').fetchone()[0]==1
            assert con.execute("SELECT count(*) FROM categories WHERE name='Film'").fetchone()[0]==1
            assert con.execute('SELECT c.slug FROM videos v JOIN categories c ON c.id=v.category_id').fetchone()[0]==f'film-existing-{i-1}'
            assert con.execute('SELECT source_url FROM video_sources').fetchone()[0]=='https://example.com/new.mp4'
    result=c.get('/api/media').json()['items'][0];assert len(result['sites'])==2 and all(x['actual']=='published' for x in result['sites'])
