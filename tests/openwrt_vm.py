#!/usr/bin/python3
"""Install and test the APK in a fresh QEMU OpenWrt VM, including a reboot.

Requires qemu-system-x86_64, ssh/scp and an official ext4 combined image (.img.gz).
SSH forwards use loopback; ICE uses temporary UDP/TCP forwards on a host IPv4.
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
            def ctl(*command):return json.loads(remote('knock-control '+shlex.join(map(str,command))).stdout)
            previous=None
            if args.upgrade_from:
                copy(args.upgrade_from,'/tmp/knock-control-old.apk')
                remote('apk update && apk add --allow-untrusted /tmp/knock-control-old.apk',timeout=180)
                ctl('init','--public-host','127.0.0.1','--interface','eth1','--api-port','8443')
                issued=ctl('issue','--name','Preserved profile','--ports',service_port,'--idle-timeout','10','--out','/root/old.json')
                ctl('activate');time.sleep(1)
                previous=json.loads(remote('cat /root/old.json').stdout)
                listeners=remote('cat /proc/net/tcp /proc/net/tcp6').stdout
                assert any(int(row.split()[1].split(':')[1],16)==8443 and row.split()[3]=='0A' for row in listeners.splitlines() if len(row.split())>3 and ':' in row.split()[1]),'Old API not running before upgrade'
            copy(args.package,'/tmp/knock-control.apk')
            install=remote('apk update && apk add --allow-untrusted /tmp/knock-control.apk',timeout=180)
            (work/'install.log').write_text(install.stdout+install.stderr)
            assert remote('command -v python3',check=False).returncode!=0
            for command in ('serve','http','tls'):
                assert remote('knock-control '+command,check=False).returncode!=0
            for path in ('/etc/init.d/knock-control-api','/usr/share/knock-control/http/cgi-bin/control','/usr/share/knock-control/app'):
                assert remote('test ! -e '+path).returncode==0,path
            if not previous:
                ctl('init','--public-host','127.0.0.1','--interface','eth1')
                assert remote('test ! -e /etc/knock-control/server.key').returncode==0
                issued=ctl('issue','--name','Knock only','--ports',service_port,'--idle-timeout','10','--out','/root/current.json','--qr-out','/root/profile.png')
                ctl('activate')
            else:
                ctl('export',issued['profile_id'],'--out','/root/current.json')
                current=json.loads(remote('cat /root/current.json').stdout)
                assert current['secret']==previous['secret'] and current['revision']==previous['revision']
                record({'phase':'upgrade','result':'PASS','checks':['Active HTTPS API stopped and its init/CGI removed','Credential secret and revision preserved','Existing v2 profiles remain usable with new ICE client']})
            listeners=remote('cat /proc/net/tcp /proc/net/tcp6').stdout
            assert not any(int(row.split()[1].split(':')[1],16)==8443 and row.split()[3]=='0A' for row in listeners.splitlines() if len(row.split())>3 and ':' in row.split()[1])
            assert remote("uci -q get knock-control.main.api_port",check=False).returncode!=0
            assert 'tcp dport 8443 accept' not in remote('nft list chain inet fw4 knock_control_input').stdout
            remote('fw4 check')
            copy(probe_path,'/tmp/openwrt-probe');remote('chmod 700 /tmp/openwrt-probe')
            remote('cat > /root/echo.json',input=json.dumps({'op':'echo','ports':[service_port]})+'\n')
            def start_echo():remote('/tmp/openwrt-probe < /root/echo.json > /tmp/echo.log 2>&1 &')
            start_echo();time.sleep(.5)
            record({'phase':'knock-only-install','result':'PASS','sha256':hashlib.sha256(args.package.read_bytes()).hexdigest(),'checks':['No Python, HTTP API, CGI, bundled web client or TLS generation','No TCP 8443 listener or unconditional firewall accept','Standard UCI config, native daemon and firewall4 check']})
            record({'phase':'browser-ice','result':'PASS','checks':check_ice(remote,ctl,work/'qmp.sock',service_port,echo_ok)})
            before=remote('sha256sum /etc/config/knock-control').stdout
            remote('/etc/init.d/knock-control enable && /etc/init.d/knock-control-firewall enable')
            remote('reboot',check=False);boot_id=ready(boot_id)
            assert remote('sha256sum /etc/config/knock-control').stdout==before
            deadline=time.monotonic()+40
            while remote('/etc/init.d/knock-control running',check=False).returncode:
                assert time.monotonic()<deadline,'Daemon did not autostart'
                time.sleep(.5)
            assert remote('test ! -e /etc/init.d/knock-control-api').returncode==0
            record({'phase':'reboot','result':'PASS','checks':['UCI credentials survive reboot','Daemon autostarts without API']})
            copy(args.package,'/tmp/knock-control.apk')
            remote('apk del knock-control && apk add --allow-untrusted /tmp/knock-control.apk',timeout=120)
            assert remote('sha256sum /etc/config/knock-control').stdout==before
            remote('fw4 check')
            record({'phase':'reinstall','result':'PASS','checks':['Credentials survive removal and reinstall','API remains absent']})
            report={'result':'PASS','version':'4.0.3','image':args.image.name,'image_sha256':hashlib.sha256(args.image.read_bytes()).hexdigest(),'architecture':'x86_64','virtualization':'QEMU KVM','phases':results}
            args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n')
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
