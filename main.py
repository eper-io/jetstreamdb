import os, time, random, hashlib, threading, urllib.request, urllib.parse, ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

# --- Config ---
root = "/data"; retention = 10*60; marker = "dat"; fileExtension = f".{marker}"; sslLocation = marker
MaxFileSize = 128*1024*1024
cluster = "http://localhost:7777"  # legacy for secret indirection
routedCall = "09E3F5F0-1D87-4B54-B57D-8D046D001942"
depthCall = "9D2D182E-0F2D-42D8-911B-071443F8D21C"
nodes = [["http://localhost:7777"],["https://hour.schmied.us"]]
startupTime = time.time()
WriteOnlySecret = "Write only channel to segment "
ReadOnlySecret  = "Read only channel to segment "
AppendOnlySecret = "Append only channel to segment "
instance = str(int(time.time()*1e9)+random.randint(0,1<<30))
client_ctx = ssl.create_default_context(); client_ctx.check_hostname=False; client_ctx.verify_mode=ssl.CERT_NONE

# --- Helpers ---
sha256 = lambda b: hashlib.sha256(b).hexdigest()

def is_valid_hash(p):
    return p.endswith(fileExtension) and len(p)==len(f"/{sha256(b'')}{fileExtension}")

def get_depth(qs):
    try:
        v = urllib.parse.parse_qs(qs).get(depthCall,[""])[0]
        if v=="": return 0
        d=max(0,int(v));
        return min(d,len(nodes)-1)
    except: return 0

def quantum_ok(): time.sleep(0.002)

def quantum_err(): time.sleep(0.002); time.sleep(0.010)

def auth_fail(handler):
    ref=os.getenv("APIKEY","")
    if not ref:
        try: ref=open(os.path.join(root,"apikey"),"r").read().strip()
        except: ref=""
    api=urllib.parse.parse_qs(urllib.parse.urlparse(handler.path).query).get("apikey",[""])[0]
    if ref!=api:
        quantum_err(); handler.send_response(401); handler.end_headers(); return True
    quantum_ok(); return False

def formatted(query, shortName):
    fmt=query.get("format",["*"])[0] or "*"; return fmt.replace("*","%s")% ("/"+shortName)

# --- Storage ops ---

def write_nonvolatile(handler, body):
    # Use parsed path (ignore query) to match Go implementation semantics
    up = urllib.parse.urlparse(handler.path)
    if up.path != "/":
        return
    shortName=f"{sha256(body)}{fileExtension}"; p=os.path.join(root,shortName)
    try:
        with open(p,"xb") as f: f.write(body)
    except: pass
    handler.wfile.write(formatted(handler.q,shortName).encode())

def write_volatile(handler, body):
    up=urllib.parse.urlparse(handler.path)
    if not is_valid_hash(up.path) or len(up.path)<=1: return
    shortName=up.path[1:]; p=os.path.join(root,shortName)
    try: data=open(p,'rb').read()
    except: data=b''
    if f"{sha256(data)}{fileExtension}"==shortName: quantum_err(); return
    if len(data)<120:
        if data.startswith(ReadOnlySecret.encode()): return
        if data.startswith(WriteOnlySecret.encode()):
            secretHash=data[len(WriteOnlySecret):].decode()
            if is_valid_hash(secretHash) and cluster:
                q=up.query
                url=cluster+secretHash+("?"+q if q else "")
                try:
                    req=urllib.request.Request(url,data=body,method="POST"); req.add_header("Content-Type","text/plain")
                    with urllib.request.urlopen(req,context=client_ctx): handler.wfile.write(up.path.encode()); return
                except: return
        if data.startswith(AppendOnlySecret.encode()):
            # Only allow when append=1 is present
            if urllib.parse.parse_qs(up.query).get("append",["0"])[0]!="1": return
            secretHash=data[len(AppendOnlySecret):].decode()
            if is_valid_hash(secretHash) and cluster:
                q=up.query
                url=cluster+secretHash+("?"+q if q else "")
                try:
                    req=urllib.request.Request(url,data=body,method="POST"); req.add_header("Content-Type","text/plain")
                    with urllib.request.urlopen(req,context=client_ctx): handler.wfile.write(up.path.encode()); return
                except: return
    q=handler.q
    setifnot=q.get("setifnot",["0"])[0]=="1"; append=q.get("append",["0"])[0]=="1"
    mode='ab' if append else ('xb' if setifnot else 'wb')
    try:
        with open(p,mode) as f: f.write(body)
    except:
        if setifnot: return
    handler.wfile.write(formatted(q,shortName).encode())

def delete_volatile(handler):
    up=urllib.parse.urlparse(handler.path)
    if not is_valid_hash(up.path) or len(up.path)<=1: return False
    shortName=up.path[1:]; p=os.path.join(root,shortName)
    try: data=open(p,'rb').read()
    except: return False
    if f"{sha256(data)}{fileExtension}"==shortName: quantum_err(); return False
    if len(data)<120 and (data.startswith(ReadOnlySecret.encode()) or data.startswith(WriteOnlySecret.encode()) or data.startswith(AppendOnlySecret.encode())):
        quantum_err(); return False
    try: os.remove(p); return True
    except: return False

def read_store(handler):
    up=urllib.parse.urlparse(handler.path)
    if not is_valid_hash(up.path): handler.send_response(417); handler.end_headers(); return
    p=os.path.join(root,up.path[1:])
    try: data=open(p,'rb').read()
    except: quantum_err(); handler.send_response(404); handler.end_headers(); return
    if len(data)<120:
        if data.startswith(WriteOnlySecret.encode()) or data.startswith(AppendOnlySecret.encode()): handler.send_response(403); handler.end_headers(); return
        if data.startswith(ReadOnlySecret.encode()):
            sh=data[len(ReadOnlySecret):].decode()
            if is_valid_hash(sh) and cluster:
                try:
                    with urllib.request.urlopen(cluster+sh,context=client_ctx) as resp:
                        if resp.status==200: data=resp.read()
                except: handler.send_response(403); handler.end_headers(); return
            else: handler.send_response(403); handler.end_headers(); return
    handler.send_response(200)
    mt=handler.q.get("Content-Type",["application/octet-stream"])[0]
    handler.send_header("Content-Type",mt); handler.send_header("Cache-Control","no-store"); handler.end_headers()
    if handler.q.get("burst",["0"])[0]=="1":
        for raw in data.decode().splitlines():
            line = raw.strip()
            if not line: continue
            # Allow full URLs or plain paths
            if line.startswith("http://") or line.startswith("https://"):
                try:
                    parsed_line = urllib.parse.urlparse(line)
                    candidate = parsed_line.path
                except:
                    candidate = line
            else:
                candidate = line
            if candidate.startswith("/"): candidate = candidate[1:]
            if not candidate: continue
            if not is_valid_hash("/"+candidate):
                continue
            fp = os.path.join(root, candidate)
            try:
                with open(fp,'rb') as f: handler.wfile.write(f.read())
            except:
                pass
    else:
        handler.wfile.write(data)
    if handler.q.get("take",["0"])[0]=="1": delete_volatile(handler)

# --- Replication helpers ---

def depth_group(qs): d=get_depth(qs); return nodes[d] if 0<=d<len(nodes) else []

def fanout(handler, body=None):
    if handler.is_call_routed(): return False
    up=urllib.parse.urlparse(handler.path); qs=up.query; d=get_depth(qs); grp=depth_group(qs)
    if len(grp)<=1: return False
    body_hash=f"{sha256(body if body else b'')}{fileExtension}" if handler.command in ["PUT","POST"] and (up.path=="/" or up.path=="") else None
    remote=None
    for addr in grp:
        b=urllib.parse.urlparse(addr); base=f"{b.scheme or 'http'}://{b.netloc or b.path}"; q=urllib.parse.parse_qs(b.query)
        rq=urllib.parse.parse_qs(qs)
        for k,vs in q.items():
            for v in vs: rq.setdefault(k,[]).append(v)
        rq[routedCall]=[instance]
        fqs=urllib.parse.urlencode([(k,v) for k,vs in rq.items() for v in vs])
        verify_path=up.path
        if body_hash and handler.command in ["PUT","POST"]: verify_path="/"+body_hash
        verify=f"{base}{verify_path}?{fqs}" if fqs else f"{base}{verify_path}"
        try:
            req=urllib.request.Request(verify,method="HEAD")
            with urllib.request.urlopen(req,context=client_ctx,timeout=5) as resp:
                if resp.status==200: remote=f"{base}{up.path}?{fqs}" if fqs else f"{base}{up.path}"
        except: pass
    if not remote: return False
    try:
        data=body if body is not None else None
        req=urllib.request.Request(remote,data=data,method=handler.command)
        with urllib.request.urlopen(req,context=client_ctx,timeout=30) as resp:
            handler.send_response(resp.status); handler.end_headers();
            if handler.command!="HEAD": handler.wfile.write(resp.read())
        return True
    except: return False

def merge_and_bump(base_url, handler):
    uph=urllib.parse.urlparse(handler.path); d=get_depth(uph.query)+1
    u=urllib.parse.urlparse(base_url); base=f"{u.scheme or 'http'}://{u.netloc or u.path}"; q=urllib.parse.parse_qs(u.query); rq=urllib.parse.parse_qs(uph.query)
    for k,vs in rq.items():
        for v in vs: q.setdefault(k,[]).append(v)
    q[depthCall]=[str(d)]
    qs=urllib.parse.urlencode([(k,v) for k,vs in q.items() for v in vs])
    return f"{base}{uph.path}?{qs}" if qs else f"{base}{uph.path}"

def replicate_next(handler, body):
    up=urllib.parse.urlparse(handler.path); d=get_depth(up.query)+1
    if d>=len(nodes): return
    grp=nodes[d]
    if not grp: return
    target=random.choice(grp)
    url=merge_and_bump(target,handler)
    try:
        req=urllib.request.Request(url,data=body,method=handler.command)
        with urllib.request.urlopen(req,context=client_ctx,timeout=10): pass
    except: pass

def delete_next(handler):
    up=urllib.parse.urlparse(handler.path); d=get_depth(up.query)+1
    if d>=len(nodes): return
    grp=nodes[d]
    if not grp: return
    target=random.choice(grp); url=merge_and_bump(target,handler)
    try:
        req=urllib.request.Request(url,method="DELETE")
        with urllib.request.urlopen(req,context=client_ctx,timeout=10): pass
    except: pass

def restore_next(handler):
    up=urllib.parse.urlparse(handler.path); d=get_depth(up.query)+1
    if d>=len(nodes) or time.time()>startupTime+retention or not is_valid_hash(up.path): return
    if os.path.exists(os.path.join(root,up.path[1:])): return
    grp=nodes[d];
    if not grp: return
    target=random.choice(grp); url=merge_and_bump(target,handler)
    try:
        req=urllib.request.Request(url,method="GET")
        with urllib.request.urlopen(req,context=client_ctx,timeout=10) as resp:
            if resp.status==200:
                body=resp.read()
                JetHandler.write_volatile_static(up.path,body) if is_valid_hash(up.path) else JetHandler.write_nonvolatile_static(body)
    except: pass

# --- Handler ---
class JetHandler(BaseHTTPRequestHandler):
    @staticmethod
    def write_volatile_static(pathv, body):
        if not is_valid_hash(pathv) or len(pathv)<=1: return
        p=os.path.join(root,pathv[1:])
        try: data=open(p,'rb').read()
        except: data=b''
        if f"{sha256(data)}{fileExtension}"==pathv[1:]: return
        try:
            with open(p,'wb') as f: f.write(body)
        except: pass
    @staticmethod
    def write_nonvolatile_static(body):
        short=f"{sha256(body)}{fileExtension}"; p=os.path.join(root,short)
        try:
            with open(p,'xb') as f: f.write(body)
        except: pass
    def is_call_routed(self):
        return routedCall in urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
    def do_HEAD(self): self._process(method_only=True)
    def do_GET(self): self._process()
    def do_PUT(self): self._process(write=True)
    def do_POST(self): self._process(write=True)
    def do_DELETE(self): self._process(delete=True)
    def _process(self,write=False,delete=False,method_only=False):
        up=urllib.parse.urlparse(self.path)
        if ".." in up.path or "./" in up.path: self.send_response(400); self.end_headers(); return
        self.q=urllib.parse.parse_qs(up.query)
        if write:
            length=min(int(self.headers.get('Content-Length','0') or '0'),MaxFileSize)
            body=self.rfile.read(length) if length>0 else b''
            if fanout(self,body): return
            if up.path=="/kv": self.send_response(200); self.end_headers(); self.wfile.write(f"/{sha256(body)}{fileExtension}".encode()); return
            if auth_fail(self): return
            self.send_response(200); self.end_headers()
            if is_valid_hash(up.path): write_volatile(self,body)
            else: write_nonvolatile(self,body)
            replicate_next(self,body)
            return
        if delete:
            if not is_valid_hash(up.path): self.send_response(417); self.end_headers(); return
            if auth_fail(self): return
            if delete_volatile(self): self.send_response(200); self.end_headers(); self.wfile.write(up.path.encode())
            else: self.send_response(200); self.end_headers()  # nothing & 200 for error
            delete_next(self); return
        if method_only: # HEAD
            if fanout(self): return
            if not is_valid_hash(up.path): self.send_response(417); self.end_headers(); return
            p=os.path.join(root,up.path[1:])
            if not os.path.exists(p): restore_next(self)
            if not os.path.exists(p): quantum_err(); self.send_response(404); self.end_headers(); return
            quantum_ok(); self.send_response(200); self.end_headers(); return
        # GET
        if fanout(self): return
        restore_next(self)
        if up.path=="/":
            if auth_fail(self): return
            return
        read_store(self)

# --- Maintenance ---

def cleanup():
    while True:
        now=time.time()
        try:
            for v in os.listdir(root):
                if is_valid_hash("/"+v):
                    p=os.path.join(root,v)
                    try:
                        if os.stat(p).st_mtime+retention<now: os.remove(p)
                    except: pass
            time.sleep(retention)
        except: time.sleep(retention)

def setup():
    if not os.path.exists(root):
        try: os.makedirs(root,exist_ok=True)
        except: pass
    threading.Thread(target=cleanup,daemon=True).start()

# --- Run ---
if __name__=="__main__":
    if not os.path.exists(root): root="/tmp"; setup()
    setup(); key=f"/etc/ssl/{sslLocation}.key"; crt=f"/etc/ssl/{sslLocation}.crt"; use_ssl=os.path.exists(key)
    srv=HTTPServer(("",443 if use_ssl else 7777),JetHandler)
    if use_ssl: srv.socket=ssl.wrap_socket(srv.socket,keyfile=key,certfile=crt,server_side=True)
    srv.serve_forever()
