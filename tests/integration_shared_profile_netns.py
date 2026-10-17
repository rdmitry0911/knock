#!/usr/bin/python3
"""Two real IPv4 clients sharing one issued profile, in an isolated netns.

sudo unshare --net python3 tests/integration_shared_profile_netns.py
The clients bind 127.0.0.2 and 127.0.0.3; the server is 127.0.0.1.
Only systemd control and installed helper paths are adapted for the test.
Native client code, TLS, pcap, TCP/UDP and kernel iptables/ipset remain real.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import random
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
import api
import common
import native
import server

HOST='127.0.0.1'
CLIENTS=('127.0.0.2','127.0.0.3')
OUTSIDER='127.0.0.4'
PORT=23456


def main():
    if os.geteuid() or os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
        raise SystemExit('Root in a separate network namespace is required')
    subprocess.run(['/usr/sbin/ip','link','set','lo','up'],check=True)
    server.IPSET=os.environ.get('IPSET_BIN',server.IPSET)
    stop=threading.Event();noise_count=[0];checks=[]
    listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind((HOST,PORT));listener.listen(32);listener.settimeout(.2)

    def echo(peer):
        with peer:
            peer.settimeout(.2)
            while not stop.is_set():
                try:
                    data=peer.recv(1024)
                    if not data:return
                    peer.sendall(data)
                except socket.timeout:pass
                except OSError:return

    def accept():
        while not stop.is_set():
            try:
                peer,_=listener.accept();threading.Thread(target=echo,args=(peer,),daemon=True).start()
            except socket.timeout:pass
            except OSError:return

    threading.Thread(target=accept,daemon=True).start()

    def connect(source):
        return socket.create_connection((HOST,PORT),timeout=.5,source_address=(source,0))

    def ping(stream):
        stream.sendall(b'ping');assert stream.recv(4)==b'ping','Protected echo stream failed'

    def reachable(source):
        try:
            with connect(source) as stream:ping(stream)
            return True
        except OSError:return False

    def blocked(stream):
        try:ping(stream)
        except (OSError,AssertionError):return True
        return False

    with tempfile.TemporaryDirectory(prefix='knock-shared-profile-') as directory:
        tmp=Path(directory)
        server.CONFIG=tmp/'settings.json';server.DAEMON_CONFIG=tmp/'knockd.conf';server.LOCK=tmp/'lock'
        server.CERT=tmp/'server.crt';server.KEY=tmp/'server.key';server.REPLAYS=tmp/'replays.sqlite'
        db=server.init_server(HOST,'lo',8443,HOST)
        ident=server.issue(db,'Shared profile',[PORT],[PORT],10,60)
        db['profiles'][ident]['settings']['protocols']=['tcp','udp','tcp','udp','udp','tcp']
        db['activated']=True
        # Export exactly once: both clients receive identical server credentials.
        bundle=common.client_bundle(server.export_bundle(db,ident))
        clients={source:copy.deepcopy(bundle) for source in CLIENTS}
        assert clients[CLIENTS[0]]==clients[CLIENTS[1]]
        helper=tmp/'access.py'
        helper.write_text("import sys,fcntl\nfrom pathlib import Path\nsys.path.insert(0,"+repr(str(ROOT/'controller'))+")\nimport server\nserver.CONFIG=Path("+repr(str(server.CONFIG))+")\nserver.IPSET="+repr(server.IPSET)+"\nwith open("+repr(str(server.LOCK))+",'a') as lock:\n fcntl.flock(lock,fcntl.LOCK_EX)\n server.access(*sys.argv[1:])\n")
        original_render=server.render
        def render(data):return original_render(data).replace('/usr/local/sbin/knock-control',f'/usr/bin/python3 -I {helper}')
        common.atomic_write(server.CONFIG,json.dumps(db));common.atomic_write(server.DAEMON_CONFIG,render(db))
        server.firewall(db)
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
        endpoint=api.APIServer((HOST,8443),tls)
        api_thread=threading.Thread(target=endpoint.serve_forever,daemon=True);api_thread.start()
        # Bind only native client sockets, using a thread-local source. Server
        # sockets and the socket module itself remain untouched.
        local=threading.local()
        def client_socket(*args,**kwargs):
            sock=socket.socket(*args,**kwargs);sock.bind((local.source,0));return sock
        native_sockets=SimpleNamespace(socket=client_socket,getaddrinfo=socket.getaddrinfo,
            AF_INET=socket.AF_INET,SOCK_DGRAM=socket.SOCK_DGRAM,SOCK_STREAM=socket.SOCK_STREAM)

        def native_action(source,action):
            local.source=source
            config=native.transport_config(clients[source]);config['public_ip']=source
            return native.knock(config,action)

        def request(source,action,**fields):
            cfg=clients[source]
            body=json.dumps({'action':action,**fields},separators=(',',':')).encode()
            stamp=str(int(time.time()));nonce=secrets.token_hex(16)
            signature=common.api_signature(cfg['secret'],stamp,nonce,body)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
            connection=http.client.HTTPSConnection(HOST,8443,context=context,timeout=5,source_address=(source,0))
            try:
                connection.connect()
                assert hmac.compare_digest(hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest(),cfg['server_certificate_sha256'])
                connection.request('POST','/v1/control',body,{'Content-Type':'application/json',
                    'Authorization':f"Knock {ident}:{stamp}:{nonce}:{signature}"})
                response=connection.getresponse();value=json.loads(response.read())
                if response.status!=200 or not value.get('ok'):raise ValueError('API request rejected')
                assert value['observed_ip']==source,'API did not use actual peer IP'
                return value
            finally:connection.close()

        def browser_action(source,action):
            status=request(source,'status');cfg={**status['settings'],'secret':bundle['secret']};now=time.time()
            sequence=[list(item) for item in common.sequence(cfg,action,status['observed_ip'],now=now)]
            proof=base64.b64encode(common.confirmation(cfg,action,status['observed_ip'],now=now)).decode()
            return request(source,'browser-'+action,sequence=sequence,confirmation=proof)

        def granted(source):
            return original_run([server.IPSET,'test',server.set_name(ident),source],check=False).returncode==0

        def wait_grants(expected):
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                if all(granted(source)==value for source,value in zip(CLIENTS,expected)):return
                time.sleep(.03)
            raise AssertionError('Unexpected grants: '+str({source:granted(source) for source in CLIENTS}))

        def simultaneous(action,operation):
            barrier=threading.Barrier(2)
            def invoke(source):barrier.wait(timeout=5);return operation(source,action)
            with ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(invoke,CLIENTS))

        def noise():
            rng=random.Random(42);base=bundle['settings']['base']
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                # Noise shares the idle client's IP during the native case.
                sock.bind((CLIENTS[1],0))
                while not stop.is_set():
                    for _ in range(100):
                        sock.sendto(b'KNC1'+rng.randbytes(56),(HOST,base+rng.randrange(256)));noise_count[0]+=1
                    stop.wait(.01)

        started=time.monotonic()
        try:
            with patch.object(server,'run',side_effect=run),patch.object(server,'render',side_effect=render),patch.object(native,'socket',native_sockets):
                time.sleep(.3);assert daemon.poll() is None
                threading.Thread(target=noise,daemon=True).start()
                assert not any(reachable(source) for source in (*CLIENTS,OUTSIDER))
                for transport,operation,active,idle in (
                        ('native TCP/UDP',native_action,CLIENTS[0],CLIENTS[1]),
                        ('browser HTTPS',browser_action,CLIENTS[1],CLIENTS[0])):
                    simultaneous('open',operation);wait_grants((True,True))
                    with connect(CLIENTS[0]) as first,connect(CLIENTS[1]) as second:
                        ping(first);ping(second)
                        operation(CLIENTS[0],'close');wait_grants((False,True))
                        assert blocked(first),'OFF left its own established stream open'
                        ping(second)
                        operation(CLIENTS[0],'open');wait_grants((True,True))
                        operation(CLIENTS[1],'close');wait_grants((True,False))
                        assert blocked(second),'OFF left the second established stream open'
                        assert reachable(CLIENTS[0]) and not reachable(CLIENTS[1])
                    simultaneous('open',operation);wait_grants((True,True))
                    with connect(active) as stream:
                        ping(stream)
                        # No protected-service probes of the idle IP in this
                        # interval: only API and knock noise, neither is activity.
                        deadline=time.monotonic()+12.5
                        while time.monotonic()<deadline:
                            ping(stream)
                            request(idle,'status')
                            time.sleep(.5)
                        assert granted(active),'Activity failed to refresh its own IP'
                        assert not granted(idle),'One client refreshed the other IP lease'
                        assert not reachable(idle) and not reachable(OUTSIDER)
                        assert request(active,'status')['access_active'] is True
                        assert request(idle,'status')['access_active'] is False
                        operation(idle,'open');wait_grants((True,True));ping(stream)
                    simultaneous('close',operation);wait_grants((False,False))
                    checks.append(transport+': concurrent ON, both OFF directions, established-stream isolation, per-IP idle expiry and status')
                    print('PASS: '+checks[-1],flush=True)
                # Sharing a profile means sharing settings. A change updates both
                # views; an out-of-date client cannot silently overwrite it.
                simultaneous('open',browser_action);wait_grants((True,True))
                first=request(CLIENTS[0],'status');second=request(CLIENTS[1],'status')
                assert first['settings']==second['settings'] and first['revision']==second['revision']
                updated=request(CLIENTS[0],'configure',revision=first['revision'],settings={'idle_timeout':12})
                wait_grants((False,False))
                assert request(CLIENTS[1],'status')['settings']['idle_timeout']==12
                try:request(CLIENTS[1],'configure',revision=second['revision'],settings={'idle_timeout':20})
                except ValueError:pass
                else:raise AssertionError('Stale shared-profile settings overwrote the new revision')
                assert request(CLIENTS[1],'status')['revision']==updated['revision']
                checks.append('shared settings are explicit; stale revision rejected; configuration changes reset all grants of that profile')
                print(json.dumps({'result':'PASS','same_issued_profile':True,'source_ips':CLIENTS,
                    'noise_packets':noise_count[0],'elapsed_seconds':round(time.monotonic()-started,2),'checks':checks},indent=2))
        except Exception:
            diagnostic.flush();diagnostic.seek(0);print('\n'.join(diagnostic.read().splitlines()[-80:]))
            raise
        finally:
            stop.set();endpoint.shutdown();endpoint.server_close();api_thread.join(timeout=2)
            daemon.terminate()
            try:daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
            diagnostic.close();listener.close()


if __name__=='__main__':main()
