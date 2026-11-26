import hashlib,hmac,os,time,re,sqlite3
from fastapi import HTTPException,Request
from .db import db
async def admin(req:Request):
    key=os.getenv('VIDEOHUB_API_KEY',''); secret=os.getenv('VIDEOHUB_API_SECRET','')
    kid=req.headers.get('X-API-Key',''); ts=req.headers.get('X-Timestamp',''); nonce=req.headers.get('X-Nonce',''); sig=req.headers.get('X-Signature','')
    if not key or len(secret)<32 or not hmac.compare_digest(kid,key): raise HTTPException(401,'API authentication required')
    if not re.fullmatch(r'[0-9]{1,12}',ts) or abs(time.time()-int(ts))>300 or not re.fullmatch(r'[a-f0-9]{32}',nonce): raise HTTPException(401,'Invalid timestamp or nonce')
    body=await req.body()
    if len(body)>16*1024*1024: raise HTTPException(413)
    target=req.scope.get('raw_path',req.url.path.encode()).decode('ascii'); query=req.scope.get('query_string',b'').decode('ascii'); target+=('?'+query) if query else ''
    msg='\n'.join([kid,ts,nonce,req.method,target,hashlib.sha256(body).hexdigest()]); expected=hmac.new(secret.encode(),msg.encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig,expected): raise HTTPException(401,'Invalid signature')
    if req.method not in ('GET','HEAD','OPTIONS') and os.getenv('VIDEOHUB_API_READ_ONLY')=='1': raise HTTPException(403,'Read-only API key')
    with db() as c:
        try:
            c.execute('DELETE FROM api_nonces WHERE created_at<?',(int(time.time())-610,)); c.execute('INSERT INTO api_nonces VALUES(?,?,?)',(kid,nonce,int(time.time())))
        except sqlite3.IntegrityError: raise HTTPException(409,'Replay rejected')
    return kid
