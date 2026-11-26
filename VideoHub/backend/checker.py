import socket, ssl, ipaddress, http.client, os, json
from urllib.parse import urlsplit,urljoin
from .db import *
# Connect to the validated numeric address, preserving TLS SNI/Host; no proxy, no redirects to private networks.
def public_ip(host,port):
    ips={x[4][0] for x in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)}
    if not ips or any(not ipaddress.ip_address(x).is_global for x in ips): raise ValueError('Non-public destination blocked')
    return sorted(ips)[0]
class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,ip,port): super().__init__(host,port,timeout=8,context=ssl.create_default_context()); self.ip=ip
    def connect(self): self.sock=self._context.wrap_socket(socket.create_connection((self.ip,self.port),self.timeout),server_hostname=self.host)
def probe(target,allowed):
    for _ in range(4):
        p=urlsplit(url(target)); host=p.hostname; port=p.port or (443 if p.scheme=='https' else 80)
        if host not in allowed: return ('unknown',None,'Domain not approved for health check')
        ip=public_ip(host,port)
        conn=PinnedHTTPS(host,ip,port) if p.scheme=='https' else http.client.HTTPConnection(ip,port,timeout=8)
        try:
            conn.request('HEAD',p.path+('?' + p.query if p.query else ''),headers={'Host':p.netloc,'User-Agent':'VideoHub-LinkCheck/1.0','Accept':'*/*'})
            r=conn.getresponse(); code=r.status; loc=r.getheader('Location'); xfo=(r.getheader('X-Frame-Options') or '').lower(); csp=r.getheader('Content-Security-Policy') or ''
            if code in (301,302,303,307,308) and loc: target=urljoin(target,loc); continue
            if code in (404,410): return ('missing',code,'HTTP '+str(code))
            if 200<=code<300:
                if 'deny' in xfo or 'sameorigin' in xfo or 'frame-ancestors' in csp: return ('reachable',code,'Embedding restriction may apply; playback unverified')
                return ('reachable',code,'HTTP reachable; playback unverified')
            return ('unknown',code,'HTTP '+str(code)+'; playback unverified')
        finally: conn.close()
    return ('unknown',None,'Too many redirects')
def check_source(sid):
    with db() as c: s=one(c,'SELECT s.*,p.domain,p.allowed_domains,p.check_enabled,p.enabled provider_enabled FROM video_sources s LEFT JOIN source_providers p ON p.id=s.provider_id WHERE s.id=?',(sid,))
    if not s: return None
    if not s['domain'] or not s['check_enabled'] or not s['provider_enabled']: result=('unknown',None,'No approved health-check provider')
    else:
        try: result=probe(s['embed_url'] or s['source_url'],{s['domain'],*json.loads(s['allowed_domains'])})
        except (OSError,ValueError,http.client.HTTPException) as e: result=('unknown',None,str(e)[:200])
    state,code,error=result; count=s['failure_count']+1 if state=='missing' else 0
    with db() as c:
        c.execute('UPDATE video_sources SET health_status=?,http_status=?,failure_count=?,last_error=?,last_checked_at=? WHERE id=? AND source_url=? AND embed_url=?',(state,code,count,error,NOW(),sid,s['source_url'],s['embed_url']))
    return {'id':sid,'health_status':state,'http_status':code,'failure_count':count,'last_error':error}
