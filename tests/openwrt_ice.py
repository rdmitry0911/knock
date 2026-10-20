"""Actual Chrome/Firefox ICE packets -> installed OpenWrt daemon/controller/nft."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]


def check_ice(remote,ctl,qmp_path,service_port,echo_ok):
    # Keep management bound to loopback throughout: UDP knocking does not need it.
    issued=ctl('issue','--name','ICE WAN','--ports',service_port,'--idle-timeout','10','--out','/root/ice.json')
    remote("uci set knock-control.main.interface='eth1' && uci set knock-control.main.api_bind='127.0.0.1' && uci commit knock-control && /etc/init.d/knock-control reload && /etc/init.d/knock-control restart")
    ctl('export',issued['profile_id'],'--out','/root/ice.json');bundle=json.loads(remote('cat /root/ice.json').stdout)
    base=bundle['settings']['base'];ident=bundle['profile_id']
    assert not any(int(row.split()[1].split(':')[1],16)==base for row in remote('cat /proc/net/udp').stdout.splitlines()[1:])
    addresses=json.loads(subprocess.run(['ip','-j','-4','addr','show'],text=True,capture_output=True,check=True).stdout)
    bind=os.environ.get('ICE_VM_BIND') or next(a['local'] for link in addresses for a in link['addr_info'] if a['scope']=='global')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as allocation:allocation.bind((bind,0));port=allocation.getsockname()[1]
    with socket.socket(socket.AF_UNIX) as qmp:
        qmp.connect(str(qmp_path));stream=qmp.makefile('rwb');json.loads(stream.readline())
        def command(execute,arguments=None):
            stream.write((json.dumps({'execute':execute,**({'arguments':arguments} if arguments else {})})+'\n').encode());stream.flush()
            while True:
                value=json.loads(stream.readline())
                if 'error' in value:raise AssertionError(value)
                if 'return' in value:return value['return']
        command('qmp_capabilities')
        assert not command('human-monitor-command',{'command-line':f'hostfwd_add wan udp:{bind}:{port}-:{base}'})
        with socket.socket() as allocation:allocation.bind((bind,0));tcp_port=allocation.getsockname()[1]
        assert not command('human-monitor-command',{'command-line':f'hostfwd_add wan tcp:{bind}:{tcp_port}-:{service_port}'})
        def echo_ok():
            try:
                with socket.create_connection((bind,tcp_port),timeout=.6) as sock:
                    sock.sendall(b'ok');return sock.recv(2)==b'ok'
            except OSError:return False
        def granted():return remote(f'nft get element inet fw4 kc_{ident} {{ {bind} }}',check=False).returncode==0
        for engine in ('chromium','firefox'):
            node=os.environ.get('NODE_BINARY','node')
            process=subprocess.Popen([node,str(ROOT/'tests/ice-vm-browser.mjs'),engine],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
            try:
                def send(action='open',token=None):
                    process.stdin.write(json.dumps({'bundle':bundle,'action':action,'host':bind,'port':port,'source':bind,**({'token':token} if token else {})})+'\n');process.stdin.flush()
                    line=process.stdout.readline();assert line,'Browser transport exited';return json.loads(line)['token']
                captured=send();assert granted() and echo_ok(),engine+' ICE ON failed'
                send('close');assert not granted() and not echo_ok(),engine+' ICE OFF failed'
                remote('/etc/init.d/knock-control restart');time.sleep(.3)
                send(token=captured);assert not granted(),engine+' replay reopened access after restart'
            finally:
                if process.poll() is None:
                    process.stdin.write('{"stop":true}\n');process.stdin.flush()
                    process.stdin.close()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
    return ['real Chromium and Firefox ICE over WAN UDP forwarding with management bound to loopback',
            'installed daemon + C controller + nftables ON/OFF; no UDP listener on knock port',
            'captured ICE ON remains rejected after daemon restart by durable SQLite journal']
