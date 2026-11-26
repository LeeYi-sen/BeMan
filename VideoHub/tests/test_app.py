import os, tempfile, pathlib, sqlite3, json, time
import pytest, httpx, hmac, hashlib, secrets
from fastapi.testclient import TestClient
from backend import db as store
from backend.main import app
from backend.worker import process_import
from backend import checker
@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(store,'DB',tmp_path/'video.db'); monkeypatch.setattr(store,'BACKUPS',tmp_path/'backups')
    # modules importing DB by value only use it for diagnostics; route operations use store.db
    import backend.main as main
    monkeypatch.setattr(main,'DB',store.DB)
    monkeypatch.setenv('VIDEOHUB_API_KEY','test'); monkeypatch.setenv('VIDEOHUB_API_SECRET','x'*40)
    with TestClient(app) as c:
        yield c

class Sign(httpx.Auth):
    requires_request_body=True
    def auth_flow(self,req):
        ts=str(int(time.time()));nonce=secrets.token_hex(16);target=req.url.raw_path.decode();msg='\n'.join(['test',ts,nonce,req.method,target,hashlib.sha256(req.content).hexdigest()]);req.headers.update({'X-API-Key':'test','X-Timestamp':ts,'X-Nonce':nonce,'X-Signature':hmac.new(('x'*40).encode(),msg.encode(),hashlib.sha256).hexdigest()});yield req

def auth(c): c.auth=Sign()
def video(c,**kw):
    d={'title':'星空摄影记录','title_en':'Stars documentary','rights_status':'authorized','rights_reference':'Own test material','status':1,'sources':[{'source_url':'https://example.com/clip.mp4','source_type':'mp4'}], 'tags':['星空','space']};d.update(kw)
    r=c.post('/api/v1/admin/videos',json=d);assert r.status_code==200,r.text;return r.json()
def test_auth_and_replay(client):
    c=client;assert c.get('/api/v1/admin/dashboard').status_code==401;assert c.get('/').status_code==200;assert c.get('/admin').status_code==404;assert c.post('/api/login',json={}).status_code==404
    auth(c);r=c.get('/api/v1/admin/dashboard');assert r.status_code==200;c.auth=None
    headers={k:v for k,v in r.request.headers.items() if k.startswith('x-')};assert c.get('/api/v1/admin/dashboard',headers=headers).status_code==409

def test_public_search_bilingual_and_seo(client):
    c=client;auth(c);cat=c.post('/api/v1/admin/categories',json={'name':'纪录片','name_en':'Documentary'}).json()['id'];v=video(c,category_id=cat)
    assert c.get('/api/public/catalog?q=摄影记录').json()['total']==1;assert c.get('/api/public/catalog?q=stars').json()['total']==1;assert c.get('/api/public/catalog?q=星空').json()['total']==1
    assert c.get('/?lang=en').status_code==200 and 'Stars documentary' in c.get('/?lang=en').text
    assert c.get('/video/'+v['slug']).status_code==200;assert v['slug'] not in c.get('/sitemap.xml').text
    assert c.post('/api/v1/admin/settings',json={'seo_index':'1'}).status_code==200;assert c.put('/api/v1/admin/sitemap',json={'ids':[v['id']],'version':1}).status_code==200;assert __import__('urllib.parse',fromlist=['unquote']).unquote(c.get('/sitemap.xml').text).find(v['slug'])>=0
    assert c.get('/category/'+v['category_slug']).status_code==200;assert c.get('/tag/'+v['tags'][0]['slug']).status_code==200

def test_publish_guard_and_duplicate(client):
    c=client;auth(c);assert c.post('/api/v1/admin/videos',json={'title':'No rights','status':1,'sources':[{'source_url':'https://example.org/test.mp4'}]}).status_code==422
    v=video(c);assert c.post('/api/v1/admin/videos',json={'title':'Duplicate','sources':[{'source_url':'https://example.com/clip.mp4'}]}).status_code==409;assert c.get('/api/v1/admin/videos').json()['total']==1
    assert c.delete('/api/v1/admin/videos/'+str(v['id'])).status_code==200;assert c.get('/api/public/video/'+v['slug']).status_code==404

def test_sources_and_views(client):
    c=client;auth(c);v=video(c);vid=v['id'];s=c.post(f'/api/v1/admin/videos/{vid}/sources',json={'source_url':'https://example.net/stream.m3u8','source_type':'hls','priority':3}).json()['id'];p='/api/public/video/'+v['slug'];assert len(c.get(p).json()['sources'])==2
    assert c.put(f'/api/v1/admin/sources/{s}',json={'status':0}).status_code==200;assert len(c.get(p).json()['sources'])==1
    assert c.post(p+'/view').status_code==200;assert c.post(p+'/view').status_code==200;assert c.get(p).json()['view_count']==1
    assert c.post(p+'/report',json={'reason':'copyright'}).status_code==200;assert len(c.get('/api/v1/admin/reports').json())==1

def test_import_worker_and_resume(client):
    c=client;auth(c);r=c.post('/api/v1/admin/imports',json={'items':[{'source_url':'https://example.com/x.mp4','title':'X'},{'source_url':'https://example.com/x.mp4'},{'source_url':'file:///etc/passwd'}]});assert r.status_code==200,r.text
    tid=r.json()['id'];assert process_import(tid);assert process_import(tid);assert process_import(tid);assert not process_import(tid);task=c.get('/api/v1/admin/imports').json()[0];assert (task['created_count'],task['duplicate_count'],task['failed_count'],task['status'])==(1,1,1,'done');assert c.get('/api/public/catalog').json()['total']==0

def test_checker_blocks_private(client,monkeypatch):
    monkeypatch.setattr(checker.socket,'getaddrinfo',lambda *a,**kw:[(2,1,6,'',('127.0.0.1',80))]);with_error=False
    with pytest.raises(ValueError): checker.public_ip('example.com',80)

def test_health_missing_and_recovery(client,monkeypatch):
    c=client;auth(c);v=video(c);sid=v['sources'][0]['id'];assert c.post('/api/v1/admin/providers',json={'name':'Example','domain':'example.com'}).status_code==200
    monkeypatch.setattr(checker,'probe',lambda *a:('missing',404,'HTTP 404'))
    for _ in range(3): r=c.post(f'/api/v1/admin/sources/{sid}/check');assert r.status_code==200
    assert r.json()['health_status']=='missing';assert c.get('/api/public/video/'+v['slug']).json()['sources'];assert c.put(f'/api/v1/admin/sources/{sid}/policy',json={'excluded':True}).status_code==200;assert not c.get('/api/public/video/'+v['slug']).json()['sources']
    monkeypatch.setattr(checker,'probe',lambda *a:('reachable',200,'HTTP reachable; playback unverified'));assert c.post(f'/api/v1/admin/sources/{sid}/check').json()['health_status']=='reachable';assert c.put(f'/api/v1/admin/sources/{sid}/policy',json={'excluded':False}).status_code==200;assert len(c.get('/api/public/video/'+v['slug']).json()['sources'])==1

def test_ads_sandbox_and_backup(client):
    c=client;auth(c);a=c.post('/api/v1/admin/ads',json={'name':'Test','ad_code':'<script>window.x=1</script>','allowed_domains':['ads.example.com'],'position':'top','enabled':1});assert a.status_code==200,a.text
    r=c.get('/ad/'+str(a.json()['id']));assert r.status_code==200;assert 'sandbox allow-scripts' in r.headers['content-security-policy'];assert 'ads.example.com' in r.headers['content-security-policy']
    r=c.post('/api/v1/admin/backup');assert r.status_code==200,r.text;f=store.BACKUPS/r.json()['name'];assert f.exists();assert sqlite3.connect(f).execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    assert c.get('/api/v1/admin/export').status_code==200

def test_settings_and_xss_escape(client):
    c=client;auth(c);assert c.post('/api/v1/admin/settings',json={'site_name':'MyVideo','site_url':'https://example.com'}).status_code==200;assert c.get('/api/v1/admin/settings').json()['site_name']=='MyVideo'
    v=video(c,title='<script>alert(1)</script>');text=c.get('/').text;assert '&lt;script&gt;' in text and '<script>alert(1)</script>' not in text

def test_external_rankings_and_version(client):
    c=client;auth(c);v=video(c);assert c.get('/api/public/catalog?sort=popular').json()['total']==0
    assert c.put('/api/v1/admin/rankings/popular',json={'ids':[v['id']],'version':10}).status_code==200
    assert c.put('/api/v1/admin/rankings/popular',json={'ids':[],'version':9}).status_code==409
    assert c.get('/api/public/catalog?sort=popular').json()['items'][0]['id']==v['id']
    assert c.put(f"/api/v1/admin/videos/{v['id']}/seo",json={'title':'SEO custom'}).status_code==200
    assert 'SEO custom' in c.get('/video/'+v['slug']).text
    assert c.post('/api/v1/admin/settings',json={'search_enabled':'0'}).status_code==200;assert c.get('/api/public/catalog?q=stars').json()['total']==0

def test_import_request_idempotency(client):
    c=client;auth(c);d={'request_id':'import-123','items':['https://example.com/unique.mp4']};a=c.post('/api/v1/admin/imports',json=d);b=c.post('/api/v1/admin/imports',json=d);assert a.json()==b.json();assert len(c.get('/api/v1/admin/imports').json())==1
