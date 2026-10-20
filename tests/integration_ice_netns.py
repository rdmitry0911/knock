#!/usr/bin/python3
"""Browser UI -> closed UDP port -> libpcap -> durable controller -> kernel firewall.

Run with sudo -E unshare --net python3 tests/integration_ice_netns.py.
Uses disposable namespaces and real Chromium/Firefox extension UI.
ICE_FIREFOX_PWA selects the Firefox mobile-size web client instead.
Firefox sandbox exceptions, when needed for root/unshare, apply only to tests.
The bootstrap static HTTPS listener is closed before the ON/OFF checks.
"""
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'controller'))
import common
import server


def main():
    if os.geteuid() or os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
        raise SystemExit('Requires root in an isolated network namespace')
    def run(*args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,**kw)
    run('ip','link','set','lo','up');run('ip','link','add','wan','type','bridge');run('ip','addr','add','203.0.113.1/24','dev','wan');run('ip','link','set','wan','up')
    namespaces=[subprocess.Popen(['unshare','--net','sleep','600']) for _ in range(4)]
    clients=[];daemon=None;stop=threading.Event();captures={};noise_count=[0];discovery_leaks=[]
    with tempfile.TemporaryDirectory(prefix='knock-ice-netns-') as temporary:
        tmp=Path(temporary)
        try:
            time.sleep(.1)
            for i,p in enumerate(namespaces[:2]):
                nat=str(namespaces[i+2].pid);client=str(p.pid);name='peer'+str(i);outer='outer'+str(i);inner='inner'+str(i);eth='eth'+str(i)
                run('ip','link','add',name,'type','veth','peer','name',outer);run('ip','link','set',name,'master','wan');run('ip','link','set',name,'up');run('ip','link','set',outer,'netns',nat)
                run('ip','link','add',inner,'type','veth','peer','name',eth);run('ip','link','set',inner,'netns',nat);run('ip','link','set',eth,'netns',client)
                def ns(pid,*cmd):return run('nsenter','-t',pid,'-n',*cmd)
                ns(nat,'ip','link','set','lo','up');ns(nat,'ip','addr','add',f'203.0.113.{i+2}/24','dev',outer);ns(nat,'ip','link','set',outer,'up');ns(nat,'ip','addr','add',f'10.230.{i+1}.1/24','dev',inner);ns(nat,'ip','link','set',inner,'up');ns(nat,'sysctl','-w','net.ipv4.ip_forward=1')
                ns(nat,'iptables','-t','nat','-A','POSTROUTING','-o',outer,'-j','SNAT','--to-source',f'203.0.113.{i+2}')
                ns(client,'ip','link','set','lo','up');ns(client,'ip','addr','add',f'10.230.{i+1}.2/24','dev',eth);ns(client,'ip','link','set',eth,'up');ns(client,'ip','route','add','default','via',f'10.230.{i+1}.1')
            server.CONFIG=tmp/'settings.json';server.DAEMON_CONFIG=tmp/'knockd.conf';server.REPLAYS=tmp/'replay.sqlite';server.IPSET=os.environ.get('IPSET_BIN',server.IPSET)
            control=tmp/'control';control.write_text('#!/usr/bin/python3\nimport sys,fcntl\nsys.path.insert(0,'+repr(str(ROOT/'controller'))+')\nimport server\nfrom pathlib import Path\nserver.CONFIG=Path('+repr(str(server.CONFIG))+')\nserver.REPLAYS=Path('+repr(str(server.REPLAYS))+')\nserver.IPSET='+repr(server.IPSET)+'\nwith open('+repr(str(tmp/'lock'))+',"a") as lock:\n fcntl.flock(lock,fcntl.LOCK_EX)\n server.access_ice(*sys.argv[2:])\n');control.chmod(0o700);server.CONTROL=str(control)
            db={'schema':2,'activated':True,'interface':'wan','api_bind':'203.0.113.1','api_port':18443,'server_url':'https://203.0.113.1:18443','knock_host':'203.0.113.1','certificate_sha256':'a'*64,'protected_ports':[],'profiles':{}}
            ident=server.issue(db,'Shared ICE',[23456],[23456],10,60);common.atomic_write(server.CONFIG,json.dumps(db));common.atomic_write(server.DAEMON_CONFIG,server.render(db));server.firewall(db)
            def start_daemon():
                return subprocess.Popen([str(ROOT/'knockd'),'-c',str(server.DAEMON_CONFIG)],stdout=(tmp/'daemon.log').open('a'),stderr=subprocess.STDOUT)
            daemon=start_daemon();time.sleep(.3)
            # A normal STUN server used only to discover each test client's IPv4.
            stun=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);stun.bind(('203.0.113.1',34780));stun.settimeout(.2)
            def stun_server():
                while not stop.is_set():
                    try:data,peer=stun.recvfrom(2048)
                    except socket.timeout:continue
                    if len(data)<20 or data[:2]!=b'\x00\x01':continue
                    if b'KNI1' in data:discovery_leaks.append(True);continue
                    address=bytes(a^b for a,b in zip(socket.inet_aton(peer[0]),b'\x21\x12\xa4\x42'))
                    response=b'\x01\x01\x00\x0c'+data[4:20]+b'\x00\x20\x00\x08\x00\x01'+struct.pack('!H',peer[1]^0x2112)+address
                    time.sleep(float(os.environ.get('ICE_STUN_DELAY','0')))
                    stun.sendto(response,peer)
            threading.Thread(target=stun_server,daemon=True).start()
            capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));capture.bind(('wan',0));capture.settimeout(.2)
            def capture_packets():
                while not stop.is_set():
                    try:data=capture.recv(65535)
                    except socket.timeout:continue
                    if len(data)<42 or data[23]!=17:continue
                    off=14+(data[14]&15)*4;port=int.from_bytes(data[off+2:off+4],'big');payload=data[off+8:]
                    if port!=db['profiles'][ident]['settings']['base'] or payload[:2]!=b'\x00\x01':continue
                    offset=20
                    while offset+4<=len(payload):
                        kind,n=struct.unpack('!HH',payload[offset:offset+4]);value=payload[offset+4:offset+4+n]
                        if kind==6 and value.startswith(b'KNI1') and len(value)>=166:
                            captures[(socket.inet_ntoa(data[26:30]),chr(value[28]))]=payload
                        offset+=4+(n+3)//4*4
            threading.Thread(target=capture_packets,daemon=True).start()
            # Protected TCP echo, with real established sockets across OFF.
            echo=socket.socket();echo.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);echo.bind(('203.0.113.1',23456));echo.listen(32);echo.settimeout(.2)
            def peer(sock):
                with sock:
                    try:
                        while data:=sock.recv(1024):sock.sendall(data)
                    except OSError:pass
            def accept():
                while not stop.is_set():
                    try:conn,_=echo.accept();threading.Thread(target=peer,args=(conn,),daemon=True).start()
                    except socket.timeout:pass
            threading.Thread(target=accept,daemon=True).start()
            cert=tmp/'cert';key=tmp/'key';run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=203.0.113.1')
            class Static(SimpleHTTPRequestHandler):
                def __init__(self,*args,**kw):super().__init__(*args,directory=str(ROOT/'dist'),**kw)
                def translate_path(self,path):return super().translate_path('/web-app/app.html' if path=='/app/' else path.replace('/app/','/web-app/',1))
                def log_message(self,*args):pass
            web=ThreadingHTTPServer(('203.0.113.1',18443),Static);tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key);web.socket=tls.wrap_socket(web.socket,server_side=True)
            threading.Thread(target=web.serve_forever,daemon=True).start()
            node=os.environ.get('NODE_BINARY','node')
            for i,engine in enumerate(('chromium','firefox')):
                bundle={**server.export_bundle(db,ident),'stun_server':'stun:203.0.113.1:34780'}
                path=tmp/(engine+'.json');path.write_text(json.dumps(bundle));config=tmp/(engine+'-config.json');config.write_text(json.dumps({'bundle':bundle,'bundle_file':str(path),'service':23456}))
                command=[node,str(ROOT/'tests/ice-browser-runner.mjs'),engine,str(config)] if i==0 or os.environ.get('ICE_FIREFOX_PWA') else ['/usr/bin/python3',str(ROOT/'tests/ice-firefox-extension.py'),str(config)]
                client=subprocess.Popen(['nsenter','-t',str(namespaces[i].pid),'-n',*command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(tmp/(engine+'.log')).open('w'),text=True)
                clients.append(client);line=client.stdout.readline();assert line and json.loads(line)['ready'],(tmp/(engine+'.log')).read_text()
            web.shutdown();web.server_close()
            run('iptables','-I','INPUT','1','-p','tcp','--dport','18443','-j','DROP')
            def rpc(i,op,**fields):
                c=clients[i];c.stdin.write(json.dumps({'op':op,**fields})+'\n');c.stdin.flush();line=c.stdout.readline();assert line,(tmp/('chromium' if i==0 else 'firefox')).as_posix();result=json.loads(line);assert 'error' not in result,result;return result
            def granted(i):return server.grant_active(ident,f'203.0.113.{i+2}')
            if not os.environ.get('ICE_QUIET'):rpc(0,'noise-start')
            for i in (0,1):
                assert not rpc(i,'tcp')['reachable'];sent=rpc(i,'on');assert sent['apiRequests']==0
                assert granted(i) and rpc(i,'tcp')['reachable'],{'client':i,'daemon_exit':daemon.poll(),'captured':list(captures),'browser':sent['debug']}
            assert rpc(0,'hold')['reachable'];assert rpc(0,'off')['apiRequests']==0
            assert not granted(0) and not rpc(0,'held')['reachable'] and granted(1) and rpc(1,'tcp')['reachable']
            captured=captures[('203.0.113.2','O')];rpc(0,'raw',packet=base64.b64encode(captured).decode());time.sleep(.2);assert not granted(0)
            daemon.terminate();daemon.wait(timeout=5);daemon=start_daemon();time.sleep(.3)
            rpc(0,'raw',packet=base64.b64encode(captured).decode());time.sleep(.3);assert not granted(0),'Replay after daemon restart'
            delayed=rpc(0,'token',source='203.0.113.2',delta=-1000)['token'];rpc(0,'off');rpc(0,'send-token',token=delayed);assert not granted(0),'Old ON after newer OFF'
            for bad in (rpc(0,'token',source='203.0.113.3')['token'],rpc(0,'token',source='203.0.113.2',revision=2)['token']):rpc(0,'send-token',token=bad);assert not granted(0)
            rpc(0,'on');rpc(0,'close-stream');rpc(1,'on')
            for _ in range(12):assert rpc(1,'tcp')['reachable'];time.sleep(1)
            assert not granted(0) and granted(1);rpc(1,'off');assert not granted(1)
            if os.environ.get('ICE_DETACH'):
                for i in (0,1):
                    rpc(i,'on-detached');assert granted(i) and rpc(i,'tcp')['reachable'],'ON did not survive closing popup'
                    rpc(i,'off-detached');assert not granted(i),'OFF did not survive closing popup'
            for i in (0,1):
                result=rpc(i,'stop');assert result['apiRequests']==0 and result['errors']==[];noise_count[0]+=result['noise_packets']
            assert not any(int(row.split()[1].split(':')[1],16)==db['profiles'][ident]['settings']['base'] for row in Path('/proc/net/udp').read_text().splitlines()[1:]),'Knock UDP socket is listening'
            assert not discovery_leaks,'Secret-bearing token sent to discovery STUN server'
            report={'result':'PASS','firefox_test_sandbox_disabled':bool(os.environ.get('MOZ_DISABLE_SOCKET_PROCESS_SANDBOX')),'engines':['Chromium extension MV3','Firefox MV2 extension (desktop engine)' if not os.environ.get('ICE_FIREFOX_PWA') else 'Firefox PWA mobile viewport'],'noise_packets':noise_count[0],'popup_close_tested':bool(os.environ.get('ICE_DETACH')),'stun_delay_seconds':float(os.environ.get('ICE_STUN_DELAY','0')),'checks':['real browser UI ICE with automatic STUN source discovery; no API requests and closed HTTPS port','shared profile, two source namespaces; OFF blocks established connection without affecting the other IP','captured STUN replay rejected before and after daemon restart','late ON cannot supersede newer OFF; wrong source and revision rejected','protected activity refreshes only its source; other source expires when idle','no listening UDP socket on the knock port']}
            out=Path(os.environ.get('ICE_REPORT','dist/openwrt/browser-ice-test-report.json'));out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
        except Exception:
            for (source,action),payload in captures.items():
                offset=20
                while offset+4<=len(payload):
                    kind,n=struct.unpack('!HH',payload[offset:offset+4]);value=payload[offset+4:offset+4+n]
                    if kind==6:
                        try:common.verify_ice_token(server.export_bundle(db,ident),value.split(b':')[0].decode(),source);print('Captured token validates:',source,action,len(payload),file=sys.stderr)
                        except ValueError as e:print('Captured token rejected:',str(e),file=sys.stderr)
                    offset+=4+(n+3)//4*4
            print((tmp/'daemon.log').read_text()[-3000:] if (tmp/'daemon.log').exists() else '',file=sys.stderr)
            for name in ('chromium','firefox'):
                p=tmp/(name+'.log')
                if p.exists():print(p.read_text()[-3000:],file=sys.stderr)
            raise
        finally:
            stop.set()
            if daemon:daemon.terminate();daemon.wait(timeout=5)
            for p in clients:
                if p.poll() is None:
                    try:p.stdin.write('{\"op\":\"stop\"}\n');p.stdin.flush();p.wait(timeout=8)
                    except (OSError,subprocess.TimeoutExpired):pass
            for p in clients+namespaces:
                if p.poll() is not None:continue
                p.terminate()
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()


if __name__=='__main__':main()
