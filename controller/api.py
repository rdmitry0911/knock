"""Bounded HTTPS control endpoint; clients authenticate only their issued profile."""
import fcntl
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
from socketserver import ThreadingMixIn
import sqlite3
import ssl
import threading
import time
import server

MAX_BODY = 65536
APP_ROOT = Path('/usr/local/share/knock-control/app')
APP_TYPES = {
    'app.html':'text/html; charset=utf-8', 'app.webmanifest':'application/manifest+json',
    'style.css':'text/css; charset=utf-8', 'icon.svg':'image/svg+xml',
    **{name:'text/javascript; charset=utf-8' for name in (
        'app.js','bridge.js','browser-client.js','profile-codec.js','transport-config.js',
        'qr.js','sw.js','vendor/jsQR.js')},
    **{f'icon-{size}.png':'image/png' for size in (180,192,512)},
}


class APIHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    server_version = 'KnockControl/2'
    sys_version = ''

    def setup(self):
        self.request.settimeout(5)
        self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        try:
            super().setup()
        except Exception:
            self.request.close()
            raise

    def finish(self):
        try:
            super().finish()
        finally:
            self.request.close()

    def log_message(self, *args):
        pass  # Never log Authorization headers, request bodies or issued secrets.

    def reply(self, status, value):
        payload = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        # An explicit whitelist keeps credentials, configuration and filesystem
        # paths inaccessible. Enrollment secrets exist only in the URL fragment.
        name = 'app.html' if self.path == '/app/' else self.path.removeprefix('/app/')
        if not self.path.startswith('/app/') or name not in APP_TYPES:
            self.reply(404, {'ok':False, 'error':'Unknown endpoint'})
            return
        if not self.server.allow(self.client_address[0]):
            self.reply(429, {'ok':False, 'error':'Request limit exceeded'})
            return
        try:
            payload = (APP_ROOT / name).read_bytes()
        except OSError:
            self.reply(503, {'ok':False, 'error':'Web application is not installed'})
            return
        self.send_response(200)
        self.send_header('Content-Type',APP_TYPES[name])
        self.send_header('Content-Length',str(len(payload)))
        self.send_header('Cache-Control','no-cache')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Permissions-Policy','camera=(self), microphone=(), geolocation=()')
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != '/v1/control':
            self.reply(404, {'ok': False, 'error': 'Unknown endpoint'})
            return
        if not self.server.allow(self.client_address[0]):
            self.reply(429, {'ok': False, 'error': 'Request limit exceeded'})
            return
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not lengths[0].isdigit() or self.headers.get('Transfer-Encoding'):
            self.reply(400, {'ok': False, 'error': 'A single Content-Length is required'})
            return
        length = int(lengths[0])
        if not 1 <= length <= MAX_BODY:
            self.reply(413, {'ok': False, 'error': 'Request too large'})
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.reply(400, {'ok': False, 'error': 'Incomplete request'})
            return
        if len(self.headers.get_all('Authorization', [])) != 1:
            self.reply(401, {'ok': False, 'error': 'Authentication failed'})
            return
        try:
            with open(server.LOCK, 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    ident = server.authenticate(self.headers.get('Authorization'), body)
                except ValueError:
                    self.reply(401, {'ok': False, 'error': 'Authentication failed'})
                    return
                response = server.dispatch(json.loads(body), ident, self.client_address[0])
                response['access_active'] = server.run([server.IPSET,'test',server.set_name(ident),self.client_address[0]],check=False).returncode == 0
            response['observed_ip'] = self.client_address[0]
            self.reply(200, response)
        except (ValueError, UnicodeError):
            self.reply(400, {'ok': False, 'error': 'Operation rejected: refresh status, check editable settings and credential policy'})
        except (OSError, sqlite3.Error, server.subprocess.SubprocessError):
            self.reply(503, {'ok': False, 'error': 'Server operation unavailable'})


class APIServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, address, tls):
        self.tls = tls
        self.slots = threading.BoundedSemaphore(32)
        self.rate_lock = threading.Lock()
        self.rates = {}
        super().__init__(address, APIHandler)

    def allow(self, address):
        bucket = int(time.monotonic() // 60)
        with self.rate_lock:
            self.rates = {key: value for key, value in self.rates.items() if value[0] == bucket}
            if address not in self.rates and len(self.rates) >= 4096:
                return False
            old_bucket, count = self.rates.get(address, (bucket, 0))
            self.rates[address] = (bucket, count + 1)
            return count < 120

    def get_request(self):
        # TLS handshakes run inside bounded workers, not in the accept loop.
        request, address = self.socket.accept()
        request.settimeout(5)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        pass  # Invalid TLS/slow/disconnected clients do not emit secret-bearing traces.


def serve():
    db = server.load()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(server.CERT, server.KEY)
    with APIServer((db['api_bind'], db['api_port']), tls) as endpoint:
        endpoint.serve_forever(poll_interval=.25)
