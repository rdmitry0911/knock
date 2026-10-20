#!/usr/bin/python3
"""Check a native installation on an inactive OpenWrt router over SSH.

All temporary profiles, TLS listeners and captured knocks use a private /tmp
directory and loopback. No production profiles/firewall rules are activated.
Build --test-tools with the target SDK first. Python runs only on this host.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
import common
import server
from test_openwrt_native import decode_native_png
from openwrt_cli import check_cli

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--host',required=True,help='SSH destination, e.g. root@192.168.64.1')
parser.add_argument('--artifacts',type=Path,required=True)
parser.add_argument('--report',type=Path,required=True)
args=parser.parse_args()
ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8',args.host]
def remote(command,input=None,check=True):
    result=subprocess.run([*ssh,command],input=input,text=True,capture_output=True,timeout=90)
    if check and result.returncode:raise RuntimeError('Remote test failed: '+command+'\n'+result.stdout+'\n'+result.stderr)
    return result
def copy(source,target):subprocess.run(['scp','-O','-q','-o','BatchMode=yes',str(source),args.host+':'+target],capture_output=True,check=True)
def probe(**request):return json.loads(remote('/tmp/knock-native-selftest/probe',json.dumps(request)+'\n').stdout)
def ctl(*command):return json.loads(remote('/tmp/knock-native-selftest/control '+shlex.join(map(str,command))).stdout)

prefix='/tmp/knock-native-selftest'
remote('test ! -e /etc/knock-control/settings.json && test ! -e '+prefix)
initialized=remote('uci -q get knock-control.main.initialized').stdout.strip()
assert initialized in ('0','1')
assert initialized=='0' or remote('uci -q get knock-control.main.activated').stdout.strip()=='0'
assert remote('/etc/init.d/knock-control running',check=False).returncode!=0
before=remote('sha256sum /etc/config/firewall').stdout.split()[0]
uci_before=remote('sha256sum /etc/config/knock-control').stdout.split()[0]
assert remote('ls -ln /etc/config/knock-control').stdout.startswith('-rw-------')
assert remote("sysupgrade -l | sed -n '\\|^/etc/config/knock-control$|p'").stdout.strip()=='/etc/config/knock-control'
assert remote('command -v python3',check=False).returncode!=0,'Python is still installed'
cli_check=check_cli(lambda arguments:remote('knock-control '+shlex.join(arguments),check=False))
assert remote('sha256sum /etc/config/knock-control').stdout.split()[0]==uci_before
if initialized=='0':assert remote('test ! -e /etc/knock-control/server.key').returncode==0
board=json.loads(remote('ubus call system board').stdout)
remote('mkdir -m 700 '+prefix)
pids=[];checks=[cli_check]
try:
    for name,target in [('openwrt-probe','probe'),('openwrt-native-unit','unit'),('openwrt-selftest-control','control')]:
        copy(args.artifacts/name,prefix+'/'+target)
    remote('chmod 700 '+prefix+'/probe '+prefix+'/unit '+prefix+'/control')
    used={int(row.split()[1].split(':')[1],16) for row in remote('cat /proc/net/tcp').stdout.splitlines()[1:]}
    port=next(p for p in range(48143,49000) if p not in used)
    ctl('init','--public-host','127.0.0.1','--interface','lo','--bind','127.0.0.1','--api-port',port)
    issued=ctl('issue','--name','Native ARM test','--ports',port+1,'--idle-timeout',10,
        '--out',prefix+'/profile.json','--qr-out',prefix+'/profile.png')
    profile=common.client_bundle(json.loads(remote('cat '+prefix+'/profile.json').stdout))
    ctl('qr',issued['profile_id'],'--out',prefix+'/profile.svg')
    terminal=remote(prefix+'/control qr '+issued['profile_id']+' --terminal').stdout
    assert terminal.startswith('\x1b[30;47m')
    checks.append('native ARM initialization, issuance, export and PNG/SVG/terminal QR without Python')
    with tempfile.TemporaryDirectory(prefix='knock-router-test-') as temporary:
        work=Path(temporary)
        subprocess.run(['scp','-O','-q','-o','BatchMode=yes',args.host+':'+prefix+'/profile.png',str(work/'profile.png')],capture_output=True,check=True)
        decoded=common.client_bundle(__import__('qr_codec').decode_enrollment(decode_native_png(work/'profile.png')))
        assert decoded['profile_id']==profile['profile_id'] and decoded['secret']==profile['secret']
        checks.append('PNG decodes with the exact offline jsQR decoder shipped in browser clients')
        # Cross-language fixture: Python produces signed requests, native C
        # verifies them, including durable replay rejection and RFC vectors.
        db=probe(op='database',state_dir=prefix);db['activated']=True
        db['rules']={'ping':{'type':'input','protocol':'icmp','icmp_type':'echo-request'},
                     'udp_range':{'type':'input','protocol':'udp','ports':['31000-31002']}}
        db['profiles'][profile['profile_id']]['settings']['rules']=['ping','udp_range']
        db['profiles'][profile['profile_id']]['policy']['allowed_rules']=['ping','udp_range']
        cfg=server.config_for(db,db['profiles'][profile['profile_id']]);now=time.time();ip='127.0.0.2';nonce=os.urandom(16)
        def proof(config):return {'action':'browser-open','sequence':[list(item) for item in common.sequence(config,'open',ip,now=now)],
            'confirmation':base64.b64encode(common.confirmation(config,'open',ip,now=now,nonce=nonce)).decode()}
        body=json.dumps(proof(cfg),separators=(',',':'));stamp=str(int(now));api_nonce=os.urandom(16).hex()
        signature=common.api_signature(profile['secret'],stamp,api_nonce,body.encode())
        fixture={'db':db,'id':profile['profile_id'],'ip':ip,'body':body,
            'authorization':f"Knock {profile['profile_id']}:{stamp}:{api_nonce}:{signature}",
            'ice_token':common.ice_token(server.export_bundle(db,profile['profile_id']),'open',ip,now=now),
            'request':proof(cfg),'request_no_ip':proof({**cfg,'ip_protection':False}),'proof_nonce':nonce.hex()}
        (work/'fixture.json').write_text(json.dumps(fixture));copy(work/'fixture.json',prefix+'/fixture.json')
        remote('mkdir -m 700 '+prefix+'/unit-state')
        remote(prefix+'/unit '+prefix+'/unit-state '+prefix+'/fixture.json')
        checks.append('cross-compiled C TOTP, HMAC, ICE/STUN parser, source binding, replay/order and persistent SQLite tests')
        # Dedicated TLS process on loopback. Existing LuCI uhttpd is untouched.
        remote('mkdir -p '+prefix+'/http/cgi-bin')
        (work/'cgi').write_text('#!/bin/sh\nexec '+prefix+'/control http\n');copy(work/'cgi',prefix+'/http/cgi-bin/control')
        remote('chmod 755 '+prefix+'/http/cgi-bin/control')
        command=['/usr/sbin/uhttpd','-f','-s',f'127.0.0.1:{port}','-C',prefix+'/server.crt','-K',prefix+'/server.key',
            '-h',prefix+'/http','-x','/cgi-bin','-E','/cgi-bin/control','-D','-S','-n','4','-N','8','-t','30','-T','5','-k','0']
        pids.append(int(remote(shlex.join(command)+' > '+prefix+'/uhttpd.log 2>&1 & echo $!').stdout.strip()))
        time.sleep(.3)
        def signed(action='status'):
            body=json.dumps({'action':action},separators=(',',':'));stamp=str(int(time.time()));nonce=os.urandom(16).hex()
            signature=common.api_signature(profile['secret'],stamp,nonce,body.encode())
            return {'op':'https','ip':ip,'port':port,'pin':profile['server_certificate_sha256'],
                'body':body,'authorization':f"Knock {profile['profile_id']}:{stamp}:{nonce}:{signature}"}
        captured=signed();response=probe(**captured);assert response['status']==200
        assert json.loads(response['body'])['access_active'] is False
        assert probe(**captured)['status']==401
        static=probe(op='https',ip=ip,port=port,pin=profile['server_certificate_sha256'],method='GET',url='/app/')
        assert static['status']==200 and 'Content-Security-Policy:' in static['headers']
        checks.append('real uhttpd HTTPS, certificate pin, signed API, replay rejection and PWA/security headers')
        # Raw libpcap daemon uses harmless marker commands, never nft mutations.
        marker=prefix+'/markers'
        config='[options]\n Interface = lo\n UseSyslog\n'
        for action in ('open','close'):
            config+=f"[{profile['profile_id']}.{action}]\n totp = {profile['secret']}, 30, {cfg['base']}, on, tcp, udp, tcp, udp, udp, tcp\n seq_timeout = 10\n tcpflags = syn,!ack,!rst\n command = printf '{action} %IP%\\n' >> {marker}\n"
        (work/'capture.conf').write_text(config);copy(work/'capture.conf',prefix+'/capture.conf')
        remote('/usr/sbin/knock-control-daemon --check --config '+prefix+'/capture.conf')
        pids.append(int(remote('/usr/sbin/knock-control-daemon -c '+prefix+'/capture.conf > '+prefix+'/daemon.log 2>&1 & echo $!').stdout.strip()))
        time.sleep(.3);cfg['protocols']=['tcp','udp','tcp','udp','udp','tcp']
        def knocks(action,source=ip,packet=None):
            now=time.time()
            packet=packet or {'sequence':[list(item) for item in common.sequence(cfg,action,source,now=now)],
                'confirmation':base64.b64encode(common.confirmation(cfg,action,source,now=now)).decode()}
            probe(op='knock',ip=source,base=cfg['base'],**packet);time.sleep(.3);return packet
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            noise=pool.submit(probe,op='noise',ip='127.0.0.3',base=cfg['base'],seconds=5)
            captured=knocks('open');knocks('close');knocks('open',packet=captured)
            assert remote('cat '+marker).stdout.splitlines()==['open '+ip,'close '+ip]
            noise_result=noise.result();assert noise_result['packets']>10000
        checks.append('real ARM libpcap mixed TCP/UDP ON/OFF under random traffic; replayed proof rejected')
    assert remote('test ! -e /etc/knock-control/settings.json').returncode==0
    assert remote('sha256sum /etc/config/firewall').stdout.split()[0]==before
    assert remote('sha256sum /etc/config/knock-control').stdout.split()[0]==uci_before
    checks.append('standard UCI configuration has mode 0600, remains unchanged during tests and is included in sysupgrade backups')
    packages=sorted(args.artifacts.glob('knock-control-*.apk'),key=lambda path:path.stat().st_mtime)
    package=packages[-1]
    report={'result':'PASS','target':args.host,'board':board,'runtime':'native C + dedicated uhttpd; no Python',
        'package':package.name,'package_sha256':hashlib.sha256(package.read_bytes()).hexdigest(),
        'configuration':'/etc/config/knock-control','configuration_format':'UCI',
        'checks':checks,'noise_packets':noise_result['packets'],'production_initialized':initialized=='1','protected_ports_activated':False,
        'firewall_config_sha256':before}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print('PASS: '+str(args.report))
finally:
    for pid in reversed(pids):remote('kill '+str(pid),check=False)
    remote('rm -rf '+prefix)
