import os,time,json,secrets,hashlib,hmac,urllib.request,urllib.error,re,ipaddress
from urllib.parse import urlsplit,urlunsplit,urlencode
from .store import decrypt
PREFIX='/api/v1/admin'
class RemoteError(Exception):
    def __init__(self,msg,status=502): super().__init__(msg); self.status=status
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k): return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
# Explicit private LAN networks; do not allow link-local or public HTTP.
LAN_NETWORKS = tuple(ipaddress.ip_network(x) for x in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))

def local_http_host(host):
    if host in ('localhost', '127.0.0.1', '::1'):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in network for network in LAN_NETWORKS)

def base_url(value):
    p=urlsplit(str(value).strip())
    if p.username or p.password or not p.hostname or p.path not in ('','/') or p.query or p.fragment: raise ValueError('Use server origin only, e.g. https://video.example.com')
    if p.scheme!='https':
        if not (os.getenv('MC_ALLOW_HTTP_LOCAL')=='1' and p.scheme=='http' and local_http_host(p.hostname)): raise ValueError('HTTPS required; set MC_ALLOW_HTTP_LOCAL=1 for private LAN IP HTTP testing')
    if p.port is not None and not 1<=p.port<=65535: raise ValueError('Invalid port')
    return urlunsplit((p.scheme,p.netloc,'','',''))
def request(site,method,path,data=None,query=None):
    if not re.fullmatch(r'/[a-z0-9_-]+(?:/[a-z0-9_-]+)*',path): raise ValueError('Invalid API path')
    target=PREFIX+path+('?' + urlencode(query) if query else ''); raw=json.dumps(data,ensure_ascii=False,separators=(',',':')).encode() if data is not None else b''
    ts=str(int(time.time())); nonce=secrets.token_hex(16); kid=site['key_id']; secret=decrypt(site['secret_enc'])
    msg='\n'.join([kid,ts,nonce,method,target,hashlib.sha256(raw).hexdigest()]); sig=hmac.new(secret.encode(),msg.encode(),hashlib.sha256).hexdigest()
    req=urllib.request.Request(base_url(site['base_url'])+target,data=raw if data is not None else None,method=method,headers={'X-API-Key':kid,'X-Timestamp':ts,'X-Nonce':nonce,'X-Signature':sig,'Content-Type':'application/json','Accept':'application/json'})
    # Keep ordinary sequential operations below the default VideoHub API ingress limit.
    time.sleep(.12)
    try:
        with opener.open(req,timeout=45) as response:
            body=response.read(32*1024*1024+1)
            if len(body)>32*1024*1024: raise RemoteError('Remote response too large')
            return json.loads(body)
    except urllib.error.HTTPError as e:
        # Never log auth headers or arbitrary server response bodies.
        raise RemoteError('Remote HTTP '+str(e.code),e.code) from None
    except (OSError,ValueError) as e: raise RemoteError('Remote unavailable or invalid response; verify write result before retrying') from None
