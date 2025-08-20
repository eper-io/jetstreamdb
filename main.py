import os, time, random, hashlib, threading, urllib.request, urllib.parse, ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import socket
import queue
import http.client

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

# --- Config ---
root = "/data"
retention = 10 * 60  # 10 minutes in seconds
marker = "dat"
fileExtension = f".{marker}"
sslLocation = marker
MaxFileSize = 128 * 1024 * 1024
MaxMemSize = 4 * MaxFileSize

# Cluster endpoint
cluster = "http://127.0.0.1:7777"

# Snapshot topology
nodes = [["http://127.0.0.1:7777"], ["https://18.209.57.108:443"]]

# Reliability measures
pinnedIP = {'127.0.0.1': 'localhost', '18.209.57.108': 'hour.schmied.us'}

# Fairly unique instance ID to avoid routing loops.
instance = str(int(time.time() * 1e9) + random.randint(0, 1 << 30))

routedCall = "09E3F5F0-1D87-4B54-B57D-8D046D001942"
depthCall = "9D2D182E-0F2D-42D8-911B-071443F8D21C"

# Pools avoid deadlocks and bottlenecks due to memory allocation.
pool_size = MaxMemSize // MaxFileSize if MaxFileSize > 0 else 0
level1Pool = queue.Queue(maxsize=pool_size)
level2Pool = queue.Queue(maxsize=pool_size)

# The startup time is used to determine if the system is still warming up.
startupTime = time.time()

AppendOnlySecret = "Append only channel to segment "
WriteOnlySecret = "Write only channel to segment "
ReadOnlySecret = "Read only channel to segment "

def request_with_pinned_ip(url, method='GET', data=None, headers=None, timeout=10):
    """
    Make an HTTP/HTTPS request to a URL using a pinned IP for the host, enforcing SNI and Host header.
    """
    parsed = urllib.parse.urlparse(url)
    ip = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    host = pinnedIP.get(ip)
    if not host:
        raise Exception(f"No pinned host for IP: {ip}")
    
    # Reconstruct the path and query to ensure nothing is lost.
    path = urllib.parse.urlunparse(('', '', parsed.path, '', parsed.query, ''))

    req_headers = headers.copy() if headers else {}
    req_headers['Host'] = host
    if method in ('POST', 'PUT') and data is not None:
        req_headers['Content-Length'] = str(len(data))
    else:
        data = None
    
    conn = None
    try:
        if parsed.scheme == 'https':
            # For HTTPS, we connect to the IP, but specify the hostname for TLS SNI
            sock = socket.create_connection((ip, port), timeout=timeout)
            context = ssl.create_default_context()
            ssock = context.wrap_socket(sock, server_hostname=host)
            # We pass the original host to HTTPSConnection for it to use in headers,
            # but the actual connection is already established to the IP.
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
            conn.sock = ssock
        else:
            # For HTTP, it's simpler, just connect to the IP. The Host header is set manually.
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        
        conn.request(method, path, body=data, headers=req_headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        
        class Resp:
            def __init__(self, status, body, headers):
                self.status = status
                self._body = body
                self.headers = headers
            def read(self):
                return self._body
        
        return Resp(resp.status, resp_body, dict(resp.getheaders()))
    finally:
        if conn:
            conn.close()

# --- Helpers ---
sha256 = lambda b: hashlib.sha256(b).hexdigest()

def is_valid_root_hash_extension(p):
    # Path validation is strict, must be /<sha256>.<ext>
    return p.startswith('/') and p.endswith(fileExtension) and len(p) == len(f"/{sha256(b'')}{fileExtension}")

def get_depth(r):
    try:
        qs = urllib.parse.urlparse(r.path).query
        v = urllib.parse.parse_qs(qs).get(depthCall, [""])[0]
        if v == "": return 0
        d = max(0, int(v))
        return min(d, len(nodes) - 1)
    except (ValueError, IndexError):
        return 0

def quantum_ok(): time.sleep(0.002)
def quantum_err(): time.sleep(0.012)

class SilentResponseWriter:
    def __init__(self):
        self.headers = {}
        self.body = bytearray()

    def send_response(self, code):
        pass

    def send_header(self, key, value):
        self.headers[key] = value

    def end_headers(self):
        pass

    def write(self, data):
        self.body.extend(data)
        return len(data)

def auth_fail(handler):
    ref = os.getenv("APIKEY", "")
    if not ref:
        try:
            with open(os.path.join(root, "apikey"), "r") as f:
                ref = f.read().strip()
        except FileNotFoundError:
            ref = ""
    api = handler.q.get("apikey", [""])[0]
    if ref != api:
        quantum_err()
        handler.send_response(401)
        handler.end_headers()
        return True
    quantum_ok()
    return False

def formatted(query, shortName):
    fmt = query.get("format", ["*"])[0] or "*"
    # Replicate Go's strings.Replace with count=1
    return fmt.replace("*", "/" + shortName, 1)

def is_call_routed(r):
    qs = urllib.parse.urlparse(r.path).query
    return routedCall in urllib.parse.parse_qs(qs)

def mark_as_used(handler, file_path):
    chtimes = handler.q.get("chtimes", ["1"])[0]
    if chtimes != "0":
        now = time.time()
        try:
            os.utime(file_path, (now, now))
        except OSError:
            pass

# --- Storage ops ---

def write_nonvolatile(handler, body):
    shortName = f"{sha256(body)}{fileExtension}"
    p = os.path.join(root, shortName)
    try:
        with open(p, "xb") as f:
            f.write(body)
    except FileExistsError:
        pass # If it exists, we're good. Content-addressing means it's the same file.
    handler.wfile.write(formatted(handler.q, shortName).encode())

def write_volatile(handler, body):
    up = urllib.parse.urlparse(handler.path)
    shortName = up.path[1:]
    p = os.path.join(root, shortName)
    
    try:
        data = open(p, 'rb').read()
        # Disallow updating secure hashed segments already stored.
        if f"{sha256(data)}{fileExtension}" == shortName:
            quantum_err()
            return
    except FileNotFoundError:
        data = b''

    if len(data) < 120:
        if data.startswith(ReadOnlySecret.encode()):
            return
        if data.startswith(WriteOnlySecret.encode()):
            secretHash = data[len(WriteOnlySecret):].decode()
            if is_valid_root_hash_extension(secretHash) and cluster:
                url = cluster + secretHash + ("?" + up.query if up.query else "")
                try:
                    request_with_pinned_ip(url, method="PUT", data=body)
                    handler.wfile.write(up.path.encode())
                except Exception:
                    pass
            return
        if data.startswith(AppendOnlySecret.encode()):
            if handler.q.get("append", ["0"])[0] != "1":
                return
            secretHash = data[len(AppendOnlySecret):].decode()
            if is_valid_root_hash_extension(secretHash) and cluster:
                url = cluster + secretHash + ("?" + up.query if up.query else "")
                try:
                    request_with_pinned_ip(url, method="PUT", data=body)
                    handler.wfile.write(up.path.encode())
                except Exception:
                    pass
            return

    setifnot = handler.q.get("setifnot", ["0"])[0] == "1"
    append = handler.q.get("append", ["0"])[0] == "1"
    mode = 'ab' if append else ('xb' if setifnot else 'wb')
    try:
        with open(p, mode) as f:
            f.write(body)
    except FileExistsError:
        if setifnot:
            return # Don't write on setifnot if file exists
    except IOError:
        return # Other write errors
    handler.wfile.write(formatted(handler.q, shortName).encode())

def delete_volatile(handler):
    up = urllib.parse.urlparse(handler.path)
    if not up.path or len(up.path) <= 1:
        return False
    shortName = up.path[1:]
    p = os.path.join(root, shortName)
    try:
        data = open(p, 'rb').read()
        if f"{sha256(data)}{fileExtension}" == shortName:
            quantum_err()
            return False
        if len(data) < 120 and (data.startswith(ReadOnlySecret.encode()) or data.startswith(WriteOnlySecret.encode()) or data.startswith(AppendOnlySecret.encode())):
            quantum_err()
            return False
        os.remove(p)
        return True
    except (FileNotFoundError, OSError):
        return False

def read_store(handler):
    up = urllib.parse.urlparse(handler.path)
    if not is_valid_root_hash_extension(up.path):
        handler.send_response(417)
        handler.end_headers()
        return

    p = os.path.join(root, up.path[1:])
    try:
        data = open(p, 'rb').read()
    except FileNotFoundError:
        quantum_err()
        handler.send_response(404)
        handler.end_headers()
        return

    if len(data) < 120:
        if data.startswith(WriteOnlySecret.encode()) or data.startswith(AppendOnlySecret.encode()):
            handler.send_response(403)
            handler.end_headers()
            return
        if data.startswith(ReadOnlySecret.encode()):
            sh = data[len(ReadOnlySecret):].decode().strip()
            if is_valid_root_hash_extension(sh) and cluster:
                try:
                    resp = request_with_pinned_ip(cluster + sh, method='GET')
                    if resp.status == 200:
                        data = resp.read()
                    else:
                        handler.send_response(403); handler.end_headers(); return
                except Exception:
                    handler.send_response(403); handler.end_headers(); return

    handler.send_response(200)
    mt = handler.q.get("Content-Type", ["application/octet-stream"])[0]
    handler.send_header("Content-Type", mt)
    handler.send_header("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
    handler.send_header("Pragma", "no-cache")
    handler.send_header("Expires", "0")
    handler.end_headers()

    if handler.q.get("burst", ["0"])[0] == "1":
        lines = data.decode(errors='ignore').splitlines()
        for line in lines:
            line = line.strip()
            if is_valid_root_hash_extension(line):
                if cluster:
                    try:
                        print(f"Burst read from cluster: {cluster + line}")
                        resp = request_with_pinned_ip(cluster + line)
                        if resp.status == 200:
                            handler.wfile.write(resp.read())
                    except Exception as e:
                        print(f"Error during burst read: {e}")
                        pass # Ignore errors and continue
    else:
        handler.wfile.write(data)
        mark_as_used(handler, p)

    if handler.q.get("take", ["0"])[0] == "1":
        delete_volatile(handler)

# --- Replication ---

def merge_and_bump(base_url, handler):
    uph = urllib.parse.urlparse(handler.path)
    d = get_depth(handler) + 1
    u = urllib.parse.urlparse(base_url)
    base = f"{u.scheme or 'http'}://{u.netloc or u.path}"
    q = urllib.parse.parse_qs(u.query)
    rq = urllib.parse.parse_qs(uph.query)
    for k, vs in rq.items():
        q.setdefault(k, []).extend(vs)
    q[depthCall] = [str(d)]
    qs = urllib.parse.urlencode([(k, v) for k, vs in q.items() for v in vs], doseq=True)
    return f"{base}{uph.path}?{qs}" if qs else f"{base}{uph.path}"

def backup_to_chain(base_url, handler, body):
    url = merge_and_bump(base_url, handler)
    print(f"Backup to chain: {url}")
    try:
        headers = {k: v for k, v in handler.headers.items() if k.lower() != 'host'}
        request_with_pinned_ip(url, method=handler.command, data=body, headers=headers)
    except Exception:
        pass

def delete_to_chain(base_url, handler):
    url = merge_and_bump(base_url, handler)
    print(f"Delete to chain: {url}")
    try:
        headers = {k: v for k, v in handler.headers.items() if k.lower() != 'host'}
        request_with_pinned_ip(url, method="DELETE", headers=headers)
    except Exception:
        pass

def restore_from_chain(base_url, handler):
    url = merge_and_bump(base_url, handler)
    print(f"Restore from chain: {url}")
    try:
        headers = {k: v for k, v in handler.headers.items() if k.lower() != 'host'}
        resp = request_with_pinned_ip(url, method="GET", headers=headers)
        if resp.status == 200:
            body = resp.read()
            sw = SilentResponseWriter()
            
            class HandlerDouble:
                def __init__(self):
                    self.path = handler.path
                    self.q = handler.q
                    self.wfile = sw
                def send_response(self, code): pass
                def send_header(self, k, v): pass
                def end_headers(self): pass

            if is_valid_root_hash_extension(handler.path):
                write_volatile(HandlerDouble(), body)
            else:
                write_nonvolatile(HandlerDouble(), body)
    except Exception:
        pass

def distributed_address(r, body_hash, cluster_address):
    up = urllib.parse.urlparse(r.path)
    u = urllib.parse.urlparse(cluster_address)
    base = f"{u.scheme or 'http'}://{u.netloc or u.path}"
    
    q = urllib.parse.parse_qs(u.query)
    rq = urllib.parse.parse_qs(up.query)
    for k, vs in rq.items():
        q.setdefault(k, []).extend(vs)
    q[routedCall] = [instance]
    
    qs = urllib.parse.urlencode([(k, v) for k, vs in q.items() for v in vs], doseq=True)
    
    verify_path = up.path
    if r.command in ["PUT", "POST"] and (up.path == "/" or up.path == ""):
        verify_path = "/" + body_hash
        
    verify_address = f"{base}{verify_path}?{qs}" if qs else f"{base}{verify_path}"
    forward_address = f"{base}{up.path}?{qs}" if qs else f"{base}{up.path}"
    
    return verify_address, forward_address

def distributed_check(url):
    try:
        resp = request_with_pinned_ip(url, method="HEAD")
        return resp.status == 200
    except Exception:
        return False

def distributed_call(handler, method, body, url):
    try:
        resp = request_with_pinned_ip(url, method=method, data=body)
        handler.send_response(resp.status)
        for k, v in resp.headers.items():
            handler.send_header(k, v)
        handler.end_headers()
        if method != "HEAD":
            handler.wfile.write(resp.read())
        return True
    except Exception:
        handler.send_response(500)
        handler.end_headers()
        return False

# --- Handler ---

class JetHandler(BaseHTTPRequestHandler):
    def do_HEAD(self): self._process()
    def do_GET(self): self._process()
    def do_PUT(self): self._process()
    def do_POST(self): self._process()
    def do_DELETE(self): self._process()

    def _process(self):
        up = urllib.parse.urlparse(self.path)
        if ".." in up.path or "./" in up.path:
            self.send_response(400); self.end_headers(); return
        
        self.q = urllib.parse.parse_qs(up.query)
        depth = get_depth(self)
        
        if nodes and depth < len(nodes) and len(nodes[depth]) > 1 and not is_call_routed(self):
            self.fulfill_request_by_cluster()
            return

        buffer = level1Pool.get()
        try:
            body = None
            if self.command in ["PUT", "POST"]:
                length = min(int(self.headers.get('Content-Length', '0') or '0'), MaxFileSize)
                if length > 0:
                    body = self.rfile.read(length)
            self.fulfill_request_locally(body)
        finally:
            level1Pool.put(bytearray(MaxFileSize))

    def fulfill_request_locally(self, body):
        if self.command in ["PUT", "POST"]:
            if self.path == "/kv":
                shortName = f"{sha256(body)}{fileExtension}"
                self.send_response(200); self.end_headers()
                self.wfile.write(f"/{shortName}".encode())
                return
            if auth_fail(self): return
            self.send_response(200); self.end_headers()
            if is_valid_root_hash_extension(self.path):
                write_volatile(self, body)
            else:
                write_nonvolatile(self, body)
            
            depth = get_depth(self)
            if (depth + 1) < len(nodes) and nodes[depth + 1]:
                bc = random.choice(nodes[depth + 1])
                backup_to_chain(bc, self, body)
            return

        if self.command == "DELETE":
            if not is_valid_root_hash_extension(self.path):
                self.send_response(417); self.end_headers(); return
            if auth_fail(self): return
            if delete_volatile(self):
                self.send_response(200); self.end_headers()
                self.wfile.write(self.path.encode())
            else:
                self.send_response(200); self.end_headers()

            depth = get_depth(self)
            if (depth + 1) < len(nodes) and nodes[depth + 1]:
                bc = random.choice(nodes[depth + 1])
                delete_to_chain(bc, self)
            return

        depth = get_depth(self)
        next_depth = depth + 1
        if next_depth < len(nodes) and nodes[next_depth] and time.time() < (startupTime + retention) and not is_call_routed(self):
            if self.command in ["HEAD", "GET"] and is_valid_root_hash_extension(self.path):
                p = os.path.join(root, self.path[1:])
                if not os.path.exists(p):
                    rc = random.choice(nodes[next_depth])
                    restore_from_chain(rc, self)

        if self.command == "HEAD":
            if not is_valid_root_hash_extension(self.path):
                self.send_response(417); self.end_headers(); return
            p = os.path.join(root, self.path[1:])
            if os.path.exists(p):
                quantum_ok(); self.send_response(200); self.end_headers()
            else:
                quantum_err(); self.send_response(404); self.end_headers()
            return

        if self.command == "GET":
            if self.path == "/":
                if auth_fail(self): return
                return
            else:
                read_store(self)
                if self.q.get("take", ["0"])[0] == "1":
                    delete_volatile(self)

    def fulfill_request_by_cluster(self):
        buffer = level2Pool.get()
        try:
            body = None
            if self.command in ["PUT", "POST"]:
                length = min(int(self.headers.get('Content-Length', '0') or '0'), MaxFileSize)
                if length > 0:
                    body = self.rfile.read(length)
            
            body_hash = sha256(body if body else b'') + fileExtension
            
            remote_address = ""
            depth = get_depth(self)
            node_list = nodes[depth] if 0 <= depth < len(nodes) else []
            
            for cluster_address in node_list:
                verify_addr, forward_addr = distributed_address(self, body_hash, cluster_address)
                if distributed_check(verify_addr):
                    remote_address = forward_addr
                    break
            
            if remote_address:
                distributed_call(self, self.command, body, remote_address)
            else:
                self.fulfill_request_locally(body)
        finally:
            level2Pool.put(bytearray(MaxFileSize))

# --- Maintenance ---

def cleanup():
    while True:
        now = time.time()
        try:
            files = os.listdir(root)
            for v in files:
                if is_valid_root_hash_extension("/" + v):
                    p = os.path.join(root, v)
                    try:
                        if os.stat(p).st_mtime + retention < now:
                            os.remove(p)
                    except OSError:
                        pass
            
            sleep_duration = retention
            if len(files) > 0:
                # This logic is from the Go version to spread out the load
                sleep_duration = (retention / len(files)) / 10
            time.sleep(max(0.1, sleep_duration))
        except Exception:
            time.sleep(retention)

def setup():
    if not os.path.exists(root):
        try:
            os.makedirs(root, exist_ok=True)
        except OSError:
            pass
    
    for _ in range(pool_size):
        level1Pool.put(bytearray(MaxFileSize))
    
    need_level2 = any(len(grp) > 1 for grp in nodes)
    if need_level2:
        for _ in range(pool_size):
            level2Pool.put(bytearray(MaxFileSize))

    threading.Thread(target=cleanup, daemon=True).start()

# --- Run ---
if __name__ == "__main__":
    if not os.path.exists(root):
        # Fallback for environments where /data is not writable
        if os.access("/tmp", os.W_OK):
            root = "/tmp"
    setup()
    key = f"/etc/ssl/{sslLocation}.key"
    crt = f"/etc/ssl/{sslLocation}.crt"
    use_ssl = os.path.exists(key) and os.path.exists(crt)
    
    port = 443 if use_ssl else 7777
    srv = ThreadingHTTPServer(("", port), JetHandler)
    
    if use_ssl:
        srv.socket = ssl.wrap_socket(srv.socket, keyfile=key, certfile=crt, server_side=True)
    
    print(f"Server starting on port {port}...")
    srv.serve_forever()
