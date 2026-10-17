#!/usr/bin/python3
"""Real multi-credential TLS API, pcap, iptables/ipset and idle activity test.
ONLY run inside a separate network namespace:
 sudo unshare --net python3 tests/integration_netns.py
IPSET_BIN/LD_LIBRARY_PATH may point to locally extracted ipset packages.
"""
import copy
import base64
import http.client
import secrets
import fcntl
import json
import os
from pathlib import Path
import random
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
import common
import native
import server
import api


def main():
    if os.geteuid() or os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
        raise SystemExit('Root in a separate network namespace is required')
    subprocess.run(['/usr/sbin/ip','link','set','lo','up'],check=True)
    server.IPSET=os.environ.get('IPSET_BIN',server.IPSET)
    stop=threading.Event();total=[0];listeners=[]
    def echo_peer(peer):
        peer.settimeout(.2)
        with peer:
            while not stop.is_set():
                try:
                    data=peer.recv(1024)
                    if not data:return
                    peer.sendall(data)
                except socket.timeout:pass
                except OSError:return
    def accept(listener):
        while not stop.is_set():
            try:
                peer,_=listener.accept();threading.Thread(target=echo_peer,args=(peer,),daemon=True).start()
            except socket.timeout:pass
            except OSError:return
    for port in (23456,23457,23458):
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',port));listener.listen(100);listener.settimeout(.1)
        listeners.append(listener);threading.Thread(target=accept,args=(listener,),daemon=True).start()
    def reachable(port):
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=.25) as peer:
                peer.sendall(b'ok');return peer.recv(2)==b'ok'
        except OSError:return False
    with tempfile.TemporaryDirectory(prefix='knock-netns-v2-') as directory:
        tmp=Path(directory)
        server.CONFIG=tmp/'settings.json';server.DAEMON_CONFIG=tmp/'knockd.conf';server.LOCK=tmp/'lock'
        server.CERT=tmp/'server.crt';server.KEY=tmp/'server.key';server.REPLAYS=tmp/'replays.sqlite'
        db=server.init_server('127.0.0.1','lo',8443,'127.0.0.1')
        a=server.issue(db,'Alice',[23456],[23456,23458],10,60)
        b=server.issue(db,'Bob',[23457],[23457],10,60)
        db['profiles'][a]['settings']['protocols']=['tcp','udp','tcp','udp','udp','tcp']
        db['activated']=True
        helper=tmp/'access.py'
        helper.write_text("import sys,fcntl\nfrom pathlib import Path\nsys.path.insert(0,"+repr(str(ROOT/'controller'))+")\nimport server\nserver.CONFIG=Path("+repr(str(server.CONFIG))+")\nserver.IPSET="+repr(server.IPSET)+"\nwith open("+repr(str(server.LOCK))+",'a') as lock:\n fcntl.flock(lock,fcntl.LOCK_EX)\n server.access(*sys.argv[1:])\n")
        original_render=server.render
        def render(data):return original_render(data).replace('/usr/local/sbin/knock-control',f'/usr/bin/python3 -I {helper}')
        common.atomic_write(server.CONFIG,json.dumps(db));common.atomic_write(server.DAEMON_CONFIG,render(db));server.firewall(db)
        diagnostic=(tmp/'daemon.log').open('w+')
        daemon=subprocess.Popen([str(ROOT/'knockd'),'-v','-c',str(server.DAEMON_CONFIG)],stdout=diagnostic,stderr=diagnostic)
        original_run=server.run
        def run(args,**kwargs):
            if args[0]=='/usr/bin/systemctl':
                if 'reload' in args:daemon.send_signal(signal.SIGHUP)
                return subprocess.CompletedProcess(args,0 if daemon.poll() is None else 1,'','')
            if args[0]=='/usr/local/sbin/knockd':args=[str(ROOT/'knockd'),*args[1:]]
            return original_run(args,**kwargs)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(server.CERT,server.KEY)
        endpoint=api.APIServer(('127.0.0.1',8443),tls)
        api_thread=threading.Thread(target=endpoint.serve_forever,daemon=True);api_thread.start()
        ca=common.client_bundle(server.export_bundle(db,a));cb=common.client_bundle(server.export_bundle(db,b))
        ca['public_ip']=cb['public_ip']='127.0.0.1'
        def knock(bundle,action):return native.knock(native.transport_config(bundle),action)
        bases=[profile['settings']['base'] for profile in db['profiles'].values()]
        def noise():
            rng=random.Random(42)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                while not stop.is_set():
                    for _ in range(100):
                        payload=b'KNC1'+rng.randbytes(56) if total[0]%7==0 else rng.randbytes(rng.randrange(1,100))
                        sock.sendto(payload,('127.0.0.1',rng.choice(bases)+rng.randrange(256)))
                        total[0]+=1
                    time.sleep(.01)
        started=time.monotonic()
        try:
            with patch.object(server,'run',side_effect=run),patch.object(server,'render',side_effect=render):
                time.sleep(.3);assert daemon.poll() is None
                threading.Thread(target=noise,daemon=True).start()
                time.sleep(2);assert not reachable(23456) and not reachable(23457),'Noise authorized access'
                # Full valid sequence with a bad current-window HMAC.
                def forged(*args,**kwargs):
                    proof=common.confirmation(*args,**kwargs);return proof[:-1]+bytes([proof[-1]^1])
                with patch.object(native,'confirmation',side_effect=forged):knock(ca,'open')
                time.sleep(.3);assert not reachable(23456),'Forged signature authorized access'
                proofs=[]
                def capture(*args,**kwargs):
                    proof=common.confirmation(*args,**kwargs);proofs.append(proof);return proof
                with patch.object(native,'confirmation',side_effect=capture):knock(ca,'open')
                knock(cb,'open');time.sleep(.3)
                assert reachable(23456) and reachable(23457),'Legitimate profiles failed under noise'
                # Real application traffic keeps Alice active beyond idle_timeout.
                # Bob has only noise/API traffic and must expire independently.
                with socket.create_connection(('127.0.0.1',23456),timeout=1) as stream:
                    for _ in range(7):
                        stream.sendall(b'ping');assert stream.recv(4)==b'ping','Active stream expired'
                        native.remote(cb,'status')
                        time.sleep(2)
                    assert reachable(23456),'Alice activity did not refresh idle timeout'
                    assert not reachable(23457),'Bob idle timeout was refreshed by noise/API traffic'
                    knock(cb,'open');time.sleep(.3);assert reachable(23457)
                    knock(ca,'close');time.sleep(.3)
                    assert not reachable(23456) and reachable(23457),'Manual off affected another profile'
                    stream.settimeout(.4)
                    try:
                        stream.sendall(b'ping');blocked=stream.recv(4)!=b'ping'
                    except OSError:blocked=True
                    assert blocked,'Manual off left established protected traffic allowed'
                with patch.object(native,'confirmation',return_value=proofs[0]):knock(ca,'open')
                time.sleep(.3);assert not reachable(23456),'Replay reopened access'
                # Browser HTTPS transport uses the same sequence and proof, and
                # affects the same real per-profile kernel sets under noise.
                def browser_request(bundle,action):
                    cfg=native.transport_config(bundle)['settings'];now=time.time()
                    return {'action':'browser-'+action,
                        'sequence':[list(item) for item in common.sequence(cfg,action,'127.0.0.1',now=now)],
                        'confirmation':base64.b64encode(common.confirmation(cfg,action,'127.0.0.1',now=now)).decode()}
                def browser_send(bundle,request):
                    body=json.dumps(request).encode();stamp=str(int(time.time()));nonce=secrets.token_hex(16)
                    signature=common.api_signature(bundle['secret'],stamp,nonce,body)
                    connection=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),timeout=5)
                    try:
                        connection.request('POST','/v1/control',body,{'Authorization':f"Knock {bundle['profile_id']}:{stamp}:{nonce}:{signature}",'Content-Type':'application/json'})
                        response=connection.getresponse();value=json.loads(response.read())
                        if response.status!=200 or not value.get('ok'):raise ValueError('Browser request rejected')
                        return value
                    finally:connection.close()
                browser_open=browser_request(ca,'open')
                browser_send(ca,browser_open)
                assert reachable(23456) and reachable(23457),'Browser ON failed or affected Bob'
                browser_send(ca,browser_request(ca,'close'))
                assert not reachable(23456) and reachable(23457),'Browser OFF failed or affected Bob'
                try:browser_send(ca,browser_open);raise AssertionError('Browser proof replay authorized access')
                except ValueError:pass
                # A profile cannot configure another identity or escape its policy.
                try:native.remote({**ca,'profile_id':b},'status');raise AssertionError('Cross-profile authentication succeeded')
                except ValueError:pass
                try:native.remote(ca,'configure',{'ports':[22]});raise AssertionError('Policy escape succeeded')
                except ValueError:pass
                bob_before=copy.deepcopy(server.load()['profiles'][b])
                result=native.remote(ca,'configure',{'ports':[23458],'idle_timeout':12})
                ca['settings']=result['settings'];ca['revision']=result['revision']
                assert daemon.poll() is None,'Hot reload stopped the daemon'
                assert server.load()['profiles'][b]==bob_before,'Alice changed Bob settings'
                assert reachable(23457),'Alice configure removed Bob grant'
                knock(ca,'open');time.sleep(.3)
                assert reachable(23458) and not reachable(23456),'Updated profile ports were not applied'
                # Revocation immediately rejects API and knocks while preserving Bob.
                with open(server.LOCK,'a') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX)
                    changed=server.load();changed['profiles'][a]['revoked']=True;changed['profiles'][a]['enabled']=False
                    server.publish(changed,[a])
                try:native.remote(ca,'status');raise AssertionError('Revoked API credential accepted')
                except ValueError:pass
                assert not reachable(23458) and reachable(23457),'Revocation crossed profile boundary'
                assert daemon.poll() is None
                # All credentials can be revoked without killing the worker;
                # issuing a new server-side secret wakes the empty BPF filter.
                with open(server.LOCK,'a') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX)
                    empty=server.load();empty['profiles'][b]['revoked']=True;empty['profiles'][b]['enabled']=False
                    server.publish(empty,[b])
                time.sleep(.3);assert daemon.poll() is None,'Empty profile set killed worker'
                with open(server.LOCK,'a') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX)
                    restored=server.load();c=server.issue(restored,'Charlie',[23457],[23457],10,60)
                    server.publish(restored,[c])
                cc=common.client_bundle(server.export_bundle(restored,c));cc['public_ip']='127.0.0.1'
                # ExecReload sends SIGHUP asynchronously. Let the new range's
                # BPF filter become active before sending its first sequence.
                time.sleep(.3)
                knock(cc,'open');time.sleep(.3);assert reachable(23457),'New credential failed after empty profile reload'
                print(json.dumps({'result':'PASS','noise_packets':total[0],'elapsed_seconds':round(time.monotonic()-started,2),
                  'checks':['noise cannot authorize','forged signature rejected','two server-issued secrets','mixed TCP/UDP open',
                    'application traffic refreshes idle timeout','idle expires despite noise/API','manual off blocks existing traffic',
                    'manual off preserves other profile','replay rejected','browser HTTPS ON/OFF and proof replay rejection','HTTPS identity and policy isolation',
                    'configure hot reload preserves other settings and grant','revocation isolates own profile','zero-profile reload and recovery']},indent=2))
        except Exception:
            diagnostic.flush();diagnostic.seek(0)
            lines=diagnostic.read().splitlines()
            print('\n'.join(lines[-100:]))
            raise
        finally:
            stop.set();endpoint.shutdown();endpoint.server_close();api_thread.join(timeout=2)
            daemon.terminate()
            try:daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
            for listener in listeners:listener.close()

if __name__=='__main__':main()
