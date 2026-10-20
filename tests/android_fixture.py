#!/usr/bin/python3
"""Real firewall/pcap fixture for Android AVD tests; run only in a private netns.

The test driver uses a Unix socket; Android ON/OFF reaches the actual UDP capture.
"""
import argparse
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'controller'))
import api
import common
import qr_codec
import server


def main():
    assert os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Use an isolated root network namespace'
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);args=parser.parse_args()
    work=args.directory;work.mkdir(mode=0o700,parents=True,exist_ok=True);work.chmod(0o700)
    server.CONFIG=work/'settings.json';server.DAEMON_CONFIG=work/'knockd.conf';server.REPLAYS=work/'replay.sqlite';server.LOCK=work/'lock';server.CERT=work/'server.crt';server.KEY=work/'server.key'
    server.IPSET=os.environ.get('IPSET_BIN',server.IPSET);server.DAEMON=str(ROOT/'knockd')
    control=work/'control'
    control.write_text('#!/usr/bin/python3\nimport sys,fcntl\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(ROOT/'controller'))+')\nimport server\nserver.CONFIG=Path('+repr(str(server.CONFIG))+')\nserver.REPLAYS=Path('+repr(str(server.REPLAYS))+')\nserver.IPSET='+repr(server.IPSET)+'\nwith open('+repr(str(server.LOCK))+',"a") as lock:\n fcntl.flock(lock,fcntl.LOCK_EX)\n server.access_ice(*sys.argv[2:])\n');control.chmod(0o700);server.CONTROL=str(control)
    if server.CONFIG.exists():db=server.load();ident=next(iter(db['profiles']))
    else:
        db=server.init_server('203.0.113.1','lo',18443,'203.0.113.1')
        ident=server.issue(db,'Android emulator',[23456],[23456,23458],15,60)
    db['activated']=True
    common.atomic_write(server.CONFIG,json.dumps(db));common.atomic_write(server.DAEMON_CONFIG,server.render(db));server.firewall(db)
    def export_profile():
        current={**server.export_bundle(server.load(),ident),'stun_server':'stun:203.0.113.1:34780'}
        common.atomic_write(work/'bundle.json',json.dumps(current));common.atomic_write(work/'enrollment.txt',qr_codec.enrollment_url(current));qr_codec.write_qr(current,work/'enrollment.png')
        return current
    bundle=export_profile()
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(server.CERT,server.KEY);api.APP_ROOT=ROOT/'dist/web-app'
    api_requests=[]
    class Handler(api.APIHandler):
        def do_POST(self):api_requests.append(self.path);super().do_POST()
    endpoint=None
    def open_api():
        nonlocal endpoint
        if endpoint is None:
            endpoint=api.APIServer(('203.0.113.1',18443),tls);endpoint.RequestHandlerClass=Handler
            threading.Thread(target=endpoint.serve_forever,daemon=True).start()
    def close_api():
        nonlocal endpoint
        if endpoint is not None:endpoint.shutdown();endpoint.server_close();endpoint=None
    class Protected(BaseHTTPRequestHandler):
        def do_GET(self):
            payload=b'<!doctype html><title>Protected service OK</title><p>Protected service OK</p>'
            self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
        def log_message(self,*args):pass
    listeners=[]
    for port in (23456,23458):
        listener=ThreadingHTTPServer(('203.0.113.1',port),Protected);listeners.append(listener);threading.Thread(target=listener.serve_forever,daemon=True).start()
    stop=threading.Event();stun=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);stun.bind(('203.0.113.1',34780));stun.settimeout(.2)
    leaks=[];captures=[];packets=[]
    def discovery():
        while not stop.is_set():
            try:data,peer=stun.recvfrom(2048)
            except socket.timeout:continue
            if len(data)<20 or data[:2]!=b'\x00\x01':continue
            if b'KNI1' in data:leaks.append(True);continue
            address=bytes(a^b for a,b in zip(socket.inet_aton(peer[0]),b'\x21\x12\xa4\x42'))
            stun.sendto(b'\x01\x01\x00\x0c'+data[4:20]+b'\x00\x20\x00\x08\x00\x01'+struct.pack('!H',peer[1]^0x2112)+address,peer)
    threading.Thread(target=discovery,daemon=True).start()
    raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));raw.bind(('lo',0));raw.settimeout(.2)
    def capture():
        while not stop.is_set():
            try:b=raw.recv(65535)
            except socket.timeout:continue
            if len(b)<42 or b[23]!=17:continue
            off=14+(b[14]&15)*4
            if int.from_bytes(b[off+2:off+4],'big')!=bundle['settings']['base']:continue
            payload=b[off+8:];pos=payload.find(b'KNI1')
            if pos<0:continue
            token=payload[pos:pos+165].decode('ascii',errors='replace');source=socket.inet_ntoa(b[26:30])
            try:action,_,_=common.verify_ice_token(server.export_bundle(server.load(),ident),token,source)
            except ValueError:continue
            captures.append({'source':source,'action':action,'bytes':len(payload)});packets.append(payload)
    threading.Thread(target=capture,daemon=True).start()
    def start_daemon():return subprocess.Popen([str(ROOT/'knockd'),'-c',str(server.DAEMON_CONFIG)],stdout=(work/'daemon.log').open('a'),stderr=subprocess.STDOUT)
    daemon=start_daemon();server.active=lambda:daemon.poll() is None
    def service_operation(op):
        assert op=='reload';daemon.send_signal(signal.SIGHUP)
    server.service_operation=service_operation;open_api()
    (work/'control.sock').unlink(missing_ok=True)
    management=socket.socket(socket.AF_UNIX);management.bind(str(work/'control.sock'));management.listen(1);management.settimeout(.5)
    def status():
        sources=sorted({p['source'] for p in captures})
        return {'ok':True,'api_open':endpoint is not None,'api_requests':len(api_requests),'captures':captures,'grants':{ip:server.grant_active(ident,ip) for ip in sources},'stun_secret_leaks':len(leaks),'daemon_alive':daemon.poll() is None,'knock_udp_listener':any(int(r.split()[1].split(':')[1],16)==bundle['settings']['base'] for r in Path('/proc/net/udp').read_text().splitlines()[1:])}
    def shutdown(*_):stop.set()
    signal.signal(signal.SIGTERM,shutdown);common.atomic_write(work/'ready.json',json.dumps({'ok':True,'profile_id':ident,'url':bundle['server_url'],'base':bundle['settings']['base']}))
    try:
        while not stop.is_set():
            try:conn,_=management.accept()
            except socket.timeout:continue
            with conn:
                q=json.loads(conn.recv(8192));op=q['op']
                if op=='close-api':close_api()
                elif op=='open-api':open_api()
                elif op=='export-profile':export_profile()
                elif op=='restart-daemon':daemon.terminate();daemon.wait(timeout=5);daemon=start_daemon();time.sleep(.3)
                elif op=='replay':
                    payload=next(p for p in reversed(packets) if b'KNI1' in p and p[p.find(b'KNI1')+28:p.find(b'KNI1')+29]==b'O')
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:udp.bind(('203.0.113.1',0));udp.sendto(payload,('203.0.113.1',bundle['settings']['base']))
                    time.sleep(.3)
                elif op=='stop':stop.set()
                elif op!='status':raise ValueError('Unknown test operation')
                try:conn.sendall(json.dumps(status()).encode())
                except (BrokenPipeError,ConnectionResetError):pass
    finally:
        stop.set();daemon.terminate();daemon.wait(timeout=5);close_api();management.close();stun.close();raw.close()
        for listener in listeners:listener.shutdown();listener.server_close()


if __name__=='__main__':main()
