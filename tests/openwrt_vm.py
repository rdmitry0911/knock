#!/usr/bin/python3
"""Install and test the APK in a fresh QEMU OpenWrt VM, including a reboot.

Requires qemu-system-x86_64, ssh/scp and an official ext4 combined image (.img.gz).
SSH/API forwards use loopback; ICE uses temporary UDP/TCP forwards on a host IPv4.
No host firewall or network setup is changed.
"""
import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import shlex
import ssl
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
import common
import native
from openwrt_cli import check_cli
from openwrt_rules import check_rules
from openwrt_ice import check_ice

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image',type=Path,required=True)
parser.add_argument('--package',type=Path,required=True)
parser.add_argument('--upgrade-from',type=Path,help='First install an older APK to verify upgrade of its persisted includes')
parser.add_argument('--report',type=Path,default=ROOT/'dist/openwrt/vm-test-report.json')
parser.add_argument('--probe',type=Path,help='Native network test probe built with build-openwrt.py --test-tools')
parser.add_argument('--ice-only',action='store_true',help='Run focused ICE checks after basic installation')
parser.add_argument('--tcg',action='store_true',help='Use software emulation instead of KVM')
args=parser.parse_args();results=[]
probe_path=args.probe or args.package.parent/'openwrt-probe'
if not probe_path.is_file():parser.error('Build the native probe with scripts/build-openwrt.py --test-tools')

def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
ssh_port,api_port,service_port=port(),port(),port()

def record(value):results.append(value);print(json.dumps(value,ensure_ascii=False),flush=True)

def echo_ok():
    try:
        with socket.create_connection(('127.0.0.1',service_port),timeout=.6) as stream:
            stream.sendall(b'ok');return stream.recv(2)==b'ok'
    except OSError:return False

with tempfile.TemporaryDirectory(prefix='knock-openwrt-vm-') as directory:
    work=Path(directory);disk=work/'disk.img'
    if args.image.suffix=='.gz':
        with gzip.open(args.image,'rb') as source,disk.open('wb') as target:shutil.copyfileobj(source,target)
    else:shutil.copy2(args.image,disk)
    ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=no',
         '-o','UserKnownHostsFile='+str(work/'known_hosts'),'-p',str(ssh_port),'root@127.0.0.1']
    def remote(command,check=True,timeout=90,input=None):
        result=subprocess.run([*ssh,command],capture_output=True,text=True,timeout=timeout,input=input)
        if check and result.returncode:raise RuntimeError('Guest command failed: '+command+'\n'+result.stdout+'\n'+result.stderr)
        return result
    def copy(source,target):
        subprocess.run(['scp','-O','-q','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(work/'known_hosts'),
            '-P',str(ssh_port),str(source),'root@127.0.0.1:'+target],check=True,capture_output=True)
    def ready(previous_boot=None):
        end=time.monotonic()+100
        while time.monotonic()<end:
            if vm.poll() is not None:raise RuntimeError('QEMU exited: '+(work/'console.log').read_text(errors='replace')[-3000:])
            result=remote('cat /proc/sys/kernel/random/boot_id',check=False,timeout=5)
            if result.returncode==0 and result.stdout.strip() and result.stdout.strip()!=previous_boot:return result.stdout.strip()
            time.sleep(.5)
        raise TimeoutError('OpenWrt SSH did not become ready')
    command=['qemu-system-x86_64','-name','knock-control-package-test','-m','768','-smp','2',
        '-drive','file='+str(disk)+',format=raw,if=virtio','-display','none','-serial','file:'+str(work/'console.log'),'-monitor','none',
        '-qmp','unix:'+str(work/'qmp.sock')+',server=on,wait=off',
        '-netdev',f'user,id=lan,net=192.168.1.0/24,host=192.168.1.2,hostfwd=tcp:127.0.0.1:{ssh_port}-192.168.1.1:22',
        '-device','virtio-net-pci,netdev=lan,mac=52:54:00:12:34:01',
        '-netdev',f'user,id=wan,hostfwd=tcp:127.0.0.1:{api_port}-:{api_port},hostfwd=tcp:127.0.0.1:{service_port}-:{service_port}',
        '-device','virtio-net-pci,netdev=wan,mac=52:54:00:12:34:02',
        '-object','filter-dump,id=icecap,netdev=wan,file='+str(work/'wan.pcap')]
    command+=['-accel','tcg'] if args.tcg else ['-enable-kvm','-cpu','host']
    with (work/'qemu.log').open('w') as log:
        vm=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            boot_id=ready();board=json.loads(remote('ubus call system board').stdout)
            assert 'QEMU' in board['model'] and board['release']['target']=='x86/64'
            record({'phase':'boot','result':'PASS','release':board['release'],'kernel':board['kernel'],'model':board['model']})
            assert remote('command -v python3',check=False).returncode!=0,'Expected a fresh image without Python'
            if args.upgrade_from:
                copy(args.upgrade_from,'/tmp/knock-control-old.apk')
                remote('apk update && apk add --allow-untrusted /tmp/knock-control-old.apk',timeout=180)
                preserved=remote('sha256sum /etc/config/knock-control').stdout.split()[0]
                remote('cat /etc/knock-control/firewall.nft')
            copy(args.package,'/tmp/knock-control.apk')
            assert remote('sha256sum /tmp/knock-control.apk').stdout.split()[0]==hashlib.sha256(args.package.read_bytes()).hexdigest()
            install=remote('apk update && apk add --allow-untrusted /tmp/knock-control.apk',timeout=180)
            (work/'install.log').write_text(install.stdout+'\n'+install.stderr)
            assert remote('apk info -e knock-control').returncode==0
            if args.upgrade_from:
                assert remote('sha256sum /etc/config/knock-control').stdout.split()[0]==preserved
                assert 'knock_control_forward' in remote('cat /etc/knock-control/firewall.nft').stdout
                remote('fw4 check')
                record({'phase':'upgrade','result':'PASS','from':args.upgrade_from.name,'checks':['standard UCI configuration preserved','legacy firewall include regenerated before fw4 reload']})
            before_cli=remote('sha256sum /etc/config/knock-control /etc/config/firewall').stdout
            cli_check=check_cli(lambda arguments:remote('knock-control '+shlex.join(arguments),check=False))
            assert remote('sha256sum /etc/config/knock-control /etc/config/firewall').stdout==before_cli
            assert remote('test ! -e /etc/knock-control/server.key').returncode==0
            record({'phase':'cli','result':'PASS','checks':[cli_check]})
            record({'phase':'install','result':'PASS','package':args.package.name,'sha256':hashlib.sha256(args.package.read_bytes()).hexdigest(),
                'checks':['APK installed in clean OpenWrt image','all dependencies resolved by apk from official repositories']})
            assert remote('command -v python3',check=False).returncode!=0,'Native APK pulled in Python'
            assert remote('test ! -d /usr/lib/knock-control').returncode==0,'Python server files were packaged'
            copy(probe_path,'/tmp/openwrt-probe');remote('chmod 700 /tmp/openwrt-probe')
            def probe(**request):return json.loads(remote('/tmp/openwrt-probe',input=json.dumps(request)+'\n',timeout=130).stdout)
            def ctl(*command):return json.loads(remote('knock-control '+shlex.join(map(str,command))).stdout)
            assert remote('uci -q get knock-control.main.initialized').stdout.strip()=='0'
            ctl('init','--public-host','127.0.0.1','--interface','eth1','--api-port',api_port)
            assert remote('uci -q get knock-control.main.initialized').stdout.strip()=='1'
            assert remote('ls -ln /etc/config/knock-control').stdout.startswith('-rw-------')
            assert remote('test ! -e /etc/knock-control/settings.json').returncode==0
            shared=ctl('issue','--name','Shared','--ports',service_port,'--idle-timeout',10,'--max-idle-timeout',60,
                '--out','/root/shared.json','--qr-out','/root/shared.png')
            other_port=service_port+1
            assert other_port!=api_port
            other=ctl('issue','--name','Other','--ports',other_port,'--idle-timeout',10,'--out','/root/other.json')
            ctl('activate')
            for name in ('knock-control-firewall','knock-control-api','knock-control'):
                remote('/etc/init.d/'+name+' enable')
            # Echo and all guest-side clients are C too: no test-only Python.
            echo_request=work/'echo.json';echo_request.write_text(json.dumps({'op':'echo','ports':[service_port,other_port]})+'\n')
            copy(echo_request,'/root/echo.json')
            def start_echo():remote('/tmp/openwrt-probe < /root/echo.json > /tmp/echo.log 2>&1 &')
            start_echo();time.sleep(.5)
            copy_back=['scp','-O','-q','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile='+str(work/'known_hosts'),'-P',str(ssh_port)]
            subprocess.run([*copy_back,'root@127.0.0.1:/root/shared.png',str(work/'shared.png')],check=True,capture_output=True)
            assert (work/'shared.png').read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
            assert remote('ls -ln /root/shared.png').stdout.startswith('-rw-------')
            remote('fw4 check')
            rules=json.loads(remote('nft -j list chain inet fw4 input').stdout)['nftables']
            first=next(entry['rule'] for entry in rules if 'rule' in entry)
            assert first['expr'][0]['jump']['target']=='knock_control_input'
            record({'phase':'prepare','result':'PASS','checks':['no Python before or after APK install',
                'native C initialization and profile issuance','offline QR PNG and private permissions',
                'dedicated uhttpd API and procd daemon','fw4 syntax and protection hook before established accept']})
            if args.ice_only:
                record({'phase':'browser-ice','result':'PASS','checks':check_ice(remote,ctl,work/'qmp.sock',service_port,echo_ok)})
                raise SystemExit(0)
            # QEMU forwards this host request through the VM's WAN interface.
            # The exact issued URL is valid in both the VM and the host.
            profile=common.client_bundle(json.loads(remote('cat /root/shared.json').stdout))
            status=native.remote(profile,'status');assert status['observed_ip']=='10.0.2.2'
            assert status['access_active'] is False and not echo_ok()
            # Read actual installed catalog/module files through the VM's uhttpd.
            locales=('en','ru','de','fr','es','pt_BR','zh_CN','ja','ar','hi')
            for resource in [*(f'_locales/{locale}/messages.json' for locale in locales),'i18n.js','ice-operation.js']:
                connection=http.client.HTTPSConnection('127.0.0.1',api_port,context=ssl._create_unverified_context(),timeout=5)
                try:
                    connection.connect()
                    assert hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()==profile['server_certificate_sha256']
                    connection.request('GET','/app/'+resource);response=connection.getresponse();content=response.read()
                    assert response.status==200,(resource,response.status)
                    if resource.endswith('.json'):assert json.loads(content)['extensionName']['message']=='Knock Control'
                finally:connection.close()
            record({'phase':'localized-web-app','result':'PASS','locales':list(locales),'checks':['Installed catalogs and localization/ICE modules served by real uhttpd']})
            def browser(action):
                status=native.remote(profile,'status');cfg={**status['settings'],'secret':profile['secret']};now=time.time()
                payload={'action':'browser-'+action,'sequence':[list(item) for item in common.sequence(cfg,action,status['observed_ip'],now=now)],
                    'confirmation':base64.b64encode(common.confirmation(cfg,action,status['observed_ip'],now=now)).decode()}
                body=json.dumps(payload,separators=(',',':')).encode();stamp=str(int(time.time()));nonce=os.urandom(16).hex()
                signature=common.api_signature(profile['secret'],stamp,nonce,body)
                connection=http.client.HTTPSConnection('127.0.0.1',api_port,context=ssl._create_unverified_context(),timeout=5)
                try:
                    connection.connect()
                    assert hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()==profile['server_certificate_sha256']
                    connection.request('POST','/v1/control',body,{'Content-Type':'application/json','Authorization':f"Knock {profile['profile_id']}:{stamp}:{nonce}:{signature}"})
                    response=connection.getresponse();value=json.loads(response.read());assert response.status==200 and value['ok'];return value
                finally:connection.close()
            browser('open');assert echo_ok()
            with socket.create_connection(('127.0.0.1',service_port),timeout=.7) as stream:
                stream.sendall(b'ok');assert stream.recv(2)==b'ok';browser('close')
                try:stream.sendall(b'ok');blocked=stream.recv(2)!=b'ok'
                except OSError:blocked=True
                assert blocked,'WAN established connection survived OFF'
            assert not echo_ok() and native.remote(profile,'status')['access_active'] is False
            record({'phase':'wan','result':'PASS','observed_ip':'10.0.2.2','checks':['real WAN default-deny','signed HTTPS ON opens protected service','OFF blocks existing WAN stream','OFF closes new WAN connections']})
            # Forward only the derived knock ports through QEMU's WAN NIC;
            # packets are captured by the packaged daemon on eth1.
            with socket.socket(socket.AF_UNIX) as qmp:
                qmp.connect(str(work/'qmp.sock'));stream=qmp.makefile('rwb');json.loads(stream.readline())
                def qmp_command(execute,arguments=None):
                    stream.write((json.dumps({'execute':execute,**({'arguments':arguments} if arguments else {})})+'\n').encode());stream.flush()
                    while True:
                        value=json.loads(stream.readline())
                        if 'error' in value:raise AssertionError(value)
                        if 'return' in value:return value['return']
                qmp_command('qmp_capabilities');forwards={}
                def forward(target,proto):
                    key=(target,proto)
                    if key not in forwards:
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM) as allocation:
                            allocation.bind(('127.0.0.1',0));host_port=allocation.getsockname()[1]
                        output=qmp_command('human-monitor-command',{'command-line':f'hostfwd_add wan {proto}:127.0.0.1:{host_port}-:{target}'})
                        assert not output,output
                        forwards[key]=host_port
                    return forwards[key]
                status=native.remote(profile,'status');profile['revision']=status['revision']
                updated=native.remote(profile,'configure',{'protocols':['tcp','udp','tcp','udp','udp','tcp']})
                profile['settings']=updated['settings'];time.sleep(.3)
                def knocks(action,captured=None):
                    cfg={**profile['settings'],'secret':profile['secret']};now=time.time()
                    sequence=common.sequence(cfg,action,'10.0.2.2',now=now) if captured is None else captured[0]
                    proof=common.confirmation(cfg,action,'10.0.2.2',now=now) if captured is None else captured[1]
                    for target,proto in sequence:
                        destination=('127.0.0.1',forward(target,proto))
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM) as client:
                            if proto=='udp':client.sendto(b'\0',destination)
                            else:client.settimeout(.2);client.connect(destination);time.sleep(.1)
                        time.sleep(.12)
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:client.sendto(proof,('127.0.0.1',forward(cfg['base'],'udp')))
                    time.sleep(.4)
                    return sequence,proof
                captured=knocks('open');assert echo_ok(),'Native WAN knocks did not open access'
                with socket.create_connection(('127.0.0.1',service_port),timeout=.7) as connection:
                    connection.sendall(b'ok');assert connection.recv(2)==b'ok';knocks('close')
                    try:connection.sendall(b'ok');blocked=connection.recv(2)!=b'ok'
                    except OSError:blocked=True
                    assert blocked,'Native WAN OFF left established traffic open'
                assert not echo_ok();knocks('open',captured);assert not echo_ok(),'Native WAN replay reopened access'
            record({'phase':'native-wan','result':'PASS','checks':['mixed TCP/UDP knocks captured on WAN eth1','native ON opens service','native OFF blocks existing WAN traffic','captured native proof replay is rejected']})
            # Move packet capture to loopback only inside this disposable VM;
            # native WAN capture was exercised above.
            remote('uci set knock-control.main.interface=lo && uci commit knock-control && /etc/init.d/knock-control reload && /etc/init.d/knock-control restart')
            time.sleep(.5)
            A,B,OTHER='127.0.0.2','127.0.0.3','127.0.0.4'
            other_profile=common.client_bundle(json.loads(remote('cat /root/other.json').stdout))
            def signed(ip,action,credential=None,**fields):
                credential=credential or profile;body=json.dumps({'action':action,**fields},separators=(',',':')).encode()
                stamp=str(int(time.time()));nonce=os.urandom(16).hex();signature=common.api_signature(credential['secret'],stamp,nonce,body)
                return {'op':'https','ip':ip,'port':api_port,'pin':credential['server_certificate_sha256'],'body':body.decode(),
                    'authorization':f"Knock {credential['profile_id']}:{stamp}:{nonce}:{signature}"}
            def request(ip,action,credential=None,**fields):
                value=probe(**signed(ip,action,credential,**fields));assert value['status']==200,value
                result=json.loads(value['body']);assert result['ok'] and result['observed_ip']==ip;return result
            def proof(ip,action,credential=None):
                credential=credential or profile;status=request(ip,'status',credential);cfg={**status['settings'],'secret':credential['secret']};now=time.time()
                return {'sequence':[list(item) for item in common.sequence(cfg,action,ip,now=now)],
                    'confirmation':base64.b64encode(common.confirmation(cfg,action,ip,now=now)).decode(),'base':cfg['base']}
            def browser_local(ip,action,credential=None):
                fields=proof(ip,action,credential);fields.pop('base');return request(ip,'browser-'+action,credential,**fields)
            def native_local(ip,action):return probe(op='knock',ip=ip,**proof(ip,action))
            def granted(ip,ident=None):
                ident=ident or profile['profile_id'];return remote(f"printf 'get element inet fw4 kc_{ident} {{ {ip} }}\\n' | nft -f -",check=False).returncode==0
            def reachable(ip,port=service_port):return probe(op='tcp',ip=ip,port=port)['reachable']
            def until(predicate):
                end=time.monotonic()+8
                while time.monotonic()<end:
                    if predicate():return
                    time.sleep(.1)
                raise AssertionError('Expected state did not become ready')
            checks=[]
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                noise=pool.submit(probe,op='noise',ip=B,base=profile['settings']['base'],seconds=30)
                def pair(action,method):
                    tasks=[pool.submit(method,ip,action) for ip in (A,B)]
                    for task in tasks:task.result()
                for name,method in (('native mixed TCP/UDP',native_local),('signed browser HTTPS',browser_local)):
                    pair('open',method);until(lambda:granted(A) and granted(B))
                    assert reachable(A) and reachable(B)
                    method(A,'close');until(lambda:not granted(A))
                    assert not reachable(A) and granted(B) and reachable(B)
                    pair('close',method);until(lambda:not granted(A) and not granted(B))
                    checks.append(name+': same-profile ON from two IPs; OFF preserves the other IP')
                pair('open',browser_local)
                stream=pool.submit(probe,op='stream',ip=A,port=service_port,seconds=16)
                deadline=time.monotonic()+12
                while time.monotonic()<deadline:request(B,'status');time.sleep(.5)
                assert granted(A) and not granted(B),'Idle timeouts are not per IP'
                assert not reachable(B)
                assert stream.result()['reachable']
                checks.append('protected TCP traffic refreshes its own lease; idle IP expires despite API and knock noise')
                browser_local(OTHER,'open',other_profile);assert reachable(OTHER,other_port)
                def daemon_pid():return json.loads(remote('ubus call service list \'{"name":"knock-control"}\'').stdout)['knock-control']['instances']['daemon']['pid']
                before=daemon_pid();status=request(A,'status')
                request(A,'configure',revision=status['revision'],settings={'idle_timeout':12})
                assert not granted(A) and granted(OTHER,other_profile['profile_id'])
                time.sleep(.3);assert daemon_pid()==before
                checks.append('configuration flushes only its own profile and hot-reloads the same daemon PID')
                browser_local(A,'open');browser_local(B,'open');remote('/etc/init.d/firewall reload')
                assert granted(A) and granted(B)
                browser_local(A,'close');assert not granted(A) and granted(B)
                checks.append('firewall4 reload retains unexpired leases; OFF still works')
                captured=signed(A,'status');assert probe(**captured)['status']==200
                assert probe(**captured)['status']==401
                invalid=proof(A,'open');invalid.pop('base');invalid['sequence'][0][0]+=1
                assert probe(**signed(A,'browser-open',**invalid))['status']==400
                status=request(A,'status')
                assert probe(**signed(A,'configure',revision=status['revision'],settings={'ports':[1]}))['status']==400
                assert probe(**signed(A,'configure',revision=status['revision']-1,settings={'idle_timeout':15}))['status']==400
                static=probe(op='https',ip=A,port=api_port,pin=profile['server_certificate_sha256'],method='GET',url='/app/')
                assert static['status']==200 and 'Content-Security-Policy:' in static['headers']
                assert probe(op='https',ip=A,port=api_port,pin=profile['server_certificate_sha256'],method='GET',url='/app/../../etc/knock-control/settings.json')['status'] in (400,404)
                checks.append('API nonce replay, incomplete proof, policy escape, stale revision and static path escape are rejected')
                noise_result=noise.result();assert noise_result['packets']>10000
            record({'phase':'native-no-python','result':'PASS','noise_packets':noise_result['packets'],'checks':checks})
            # Administrative paths in the new native implementation must keep
            # issued credentials and rollback guarantees of the Python version.
            browser_local(OTHER,'open',other_profile)
            ctl('revoke',other_profile['profile_id'])
            assert not granted(OTHER,other_profile['profile_id']) and not reachable(OTHER,other_port)
            assert probe(**signed(OTHER,'status',other_profile))['status']==401
            assert remote('knock-control export '+other_profile['profile_id']+' --out /tmp/revoked.json',check=False).returncode!=0
            hashes='sha256sum /etc/config/knock-control /etc/knock-control/knockd.conf /etc/knock-control/server.crt /etc/knock-control/server.key'
            before=remote(hashes).stdout
            remote('openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/new.key -out /tmp/new.crt -days 1 -subj /CN=rollback-test')
            assert remote('knock-control tls --cert /tmp/new.crt --key /etc/knock-control/server.key',check=False).returncode!=0
            assert remote(hashes).stdout==before,'Mismatched TLS key changed persistent state'
            stub=work/'reject-service';stub.write_text('#!/bin/sh\nexit 1\n');copy(stub,'/tmp/reject-service')
            remote('cp /etc/init.d/knock-control-api /tmp/api.init && cp /tmp/reject-service /etc/init.d/knock-control-api && chmod 755 /etc/init.d/knock-control-api')
            rejected=remote('knock-control tls --cert /tmp/new.crt --key /tmp/new.key',check=False)
            remote('cp /tmp/api.init /etc/init.d/knock-control-api && chmod 755 /etc/init.d/knock-control-api')
            assert rejected.returncode!=0 and remote(hashes).stdout==before,'Failed TLS restart did not roll back'
            ctl('tls','--cert','/etc/knock-control/server.crt','--key','/etc/knock-control/server.key')
            until(lambda:request(A,'status')['ok'])
            # Force nft failure without altering the live ruleset, then ensure
            # the database and generated daemon configuration are restored.
            before=remote(hashes).stdout;status=request(A,'status')
            remote('mv /usr/sbin/nft /tmp/nft-real && cp /tmp/reject-service /usr/sbin/nft && chmod 755 /usr/sbin/nft')
            rejected=probe(**signed(A,'configure',revision=status['revision'],settings={'idle_timeout':15}))
            remote('rm /usr/sbin/nft && mv /tmp/nft-real /usr/sbin/nft')
            assert rejected['status']==400 and remote(hashes).stdout==before,'Failed nft transaction did not roll back'
            assert request(A,'status')['revision']==status['revision']
            record({'phase':'native-admin','result':'PASS','checks':['revocation removes grants and blocks authentication/export',
                'TLS key mismatch is rejected before mutation','TLS restart failure restores certificates and database',
                'valid TLS installation restarts dedicated API','nft failure restores profile database and daemon configuration']})
            # Exercise the real JSON -> UCI migration with live profiles and
            # replay journal. Certificates and client exports must stay valid.
            snapshot=probe(op='database');legacy=work/'legacy.json';legacy.write_text(json.dumps(snapshot))
            before_export=ctl('export',profile['profile_id'],'--out','/tmp/before-client.json')
            old_export=remote('cat /tmp/before-client.json').stdout
            replay_migration=signed(A,'status');assert probe(**replay_migration)['status']==200
            copy(legacy,'/etc/knock-control/settings.json');remote('chmod 600 /etc/knock-control/settings.json')
            copy(ROOT/'packaging/openwrt/files/knock-control.config','/etc/config/knock-control');remote('chmod 600 /etc/config/knock-control')
            remote('knock-control migrate')
            assert probe(op='database')==snapshot
            assert remote('test ! -e /etc/knock-control/settings.json && test -s /etc/knock-control/settings.json.pre-uci').returncode==0
            ctl('export',profile['profile_id'],'--out','/tmp/after-client.json')
            assert remote('cat /tmp/after-client.json').stdout==old_export
            assert probe(**replay_migration)['status']==401
            assert remote("sysupgrade -l | sed -n '\\|^/etc/config/knock-control$|p'").stdout.strip()=='/etc/config/knock-control'
            record({'phase':'uci','result':'PASS','checks':['native UCI configuration and private permissions',
                'uci set/commit and init reload apply settings','JSON migration retains profiles, client exports and durable nonces',
                'configuration is included in sysupgrade backups']})
            secret_hash=remote('sha256sum /etc/config/knock-control').stdout.split()[0]
            reboot_replay=signed(A,'status');assert probe(**reboot_replay)['status']==200
            remote('reboot',check=False);boot_id=ready(boot_id)
            copy(probe_path,'/tmp/openwrt-probe');remote('chmod 700 /tmp/openwrt-probe');start_echo()
            until(lambda:request(A,'status')['ok']);assert not granted(A) and not granted(B)
            assert not reachable(A);assert probe(**reboot_replay)['status']==401
            browser_local(A,'open');assert reachable(A);browser_local(A,'close')
            assert remote('command -v python3',check=False).returncode!=0
            record({'phase':'postboot','result':'PASS','checks':['credentials and settings survive reboot','API and daemon autostart without Python',
                'live leases are closed after reboot','API replay journal survives reboot','ON/OFF works after reboot']})
            assert remote('sha256sum /etc/config/knock-control').stdout.split()[0]==secret_hash
            # Removing/reinstalling the APK must not destroy issued credentials.
            copy(args.package,'/tmp/knock-control.apk')
            remote('apk del knock-control && apk add --allow-untrusted /tmp/knock-control.apk',timeout=120)
            assert remote('sha256sum /etc/config/knock-control').stdout.split()[0]==secret_hash
            assert native.remote(profile,'status')['profile_id']==profile['profile_id']
            remote('fw4 check')
            record({'phase':'reinstall','result':'PASS','checks':['package removal/reinstall retains generated credentials and settings','API works after reinstall','firewall4 configuration validates']})
            record({'phase':'named-rules','result':'PASS','checks':check_rules(remote,copy,ctl,work,api_port)})
            record({'phase':'browser-ice','result':'PASS','checks':check_ice(remote,ctl,work/'qmp.sock',service_port,echo_ok)})
            report={'result':'PASS','image':args.image.name,'image_sha256':hashlib.sha256(args.image.read_bytes()).hexdigest(),
                'architecture':'x86_64','virtualization':'QEMU TCG' if args.tcg else 'QEMU KVM','phases':results}
            args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
            shutil.copy2(work/'install.log',args.report.parent/'vm-install.log')
            print('PASS: '+str(args.report),flush=True)
        except Exception:
            shutil.copy2(work/'wan.pcap','/tmp/knock-ice-vm-wan.pcap')
            print(remote('cat /tmp/echo.log; ps w; nft list chain inet fw4 knock_control_input',check=False).stdout,file=sys.stderr)
            print(remote('logread | tail -40',check=False).stdout,file=sys.stderr)
            raise
        finally:
            vm.terminate()
            try:vm.wait(timeout=5)
            except subprocess.TimeoutExpired:vm.kill();vm.wait()
