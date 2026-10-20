#!/usr/bin/python3
"""Real routed IPv4 TCP/UDP/ICMP and DNAT checks in disposable namespaces.

sudo -E unshare --net python3 tests/integration_rules_netns.py --backend iptables
For native nft rendering set KNOCK_NATIVE_UNIT and use --backend native-nft.
All interfaces, firewall rules and child network namespaces are private.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
import common
import server


def echo_services():
    def udp(sock):
        while True:
            data,addr=sock.recvfrom(2048);sock.sendto(data,addr)
    def peer(sock):
        with sock:
            try:
                while data:=sock.recv(2048):sock.sendall(data)
            except OSError:pass
    def tcp(sock):
        while True:
            conn,_=sock.accept();threading.Thread(target=peer,args=(conn,),daemon=True).start()
    for proto,ports in ((socket.SOCK_STREAM,[12345,30000,30001,30002,30003,32000,32002]),
                        (socket.SOCK_DGRAM,[5556,31000,31001,31002,31003,4567,33000,33002,34000,34002])):
        for port in ports:
            sock=socket.socket(socket.AF_INET,proto);sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.bind(('0.0.0.0',port))
            if proto==socket.SOCK_STREAM:sock.listen(32)
            threading.Thread(target=tcp if proto==socket.SOCK_STREAM else udp,args=(sock,),daemon=True).start()


def client():
    held={}
    for line in sys.stdin:
        q=json.loads(line);result=False
        try:
            op=q.get('op','check');key=q.get('key','flow')
            if op=='close':
                sock=held.pop(key)
                if sock.type==socket.SOCK_STREAM:sock.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
                sock.close();result=True
            elif q['protocol']=='icmp':
                result=subprocess.run(['ping','-n','-c','1','-W','1','-I',q['source'],q['host']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
            else:
                if op=='held':sock=held[key]
                else:
                    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if q['protocol']=='tcp' else socket.SOCK_DGRAM)
                    sock.settimeout(.35);sock.bind((q['source'],0));sock.connect((q['host'],q['port']))
                    if op=='hold':held[key]=sock
                sock.send(b'knock-test');result=sock.recv(1024)==b'knock-test'
                if op=='check':sock.close()
        except OSError:pass
        print(json.dumps(result),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend',choices=('iptables','nft','native-nft'),required=True)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    if os.geteuid() or os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
        raise SystemExit('Requires root in a separate network namespace')
    def run(*command,**kw):return subprocess.run(list(command),check=True,capture_output=True,text=True,**kw)
    run('ip','link','set','lo','up')
    # Keep namespaces alive without named mounts or changes to /run/netns.
    namespaces=[subprocess.Popen(['unshare','--net','sleep','600']) for _ in range(2)]
    children=[];records=[]
    try:
        time.sleep(.1)
        for index,(name,network) in enumerate((('wan','10.231.0'),('lan','10.232.0'))):
            pid=str(namespaces[index].pid)
            run('ip','link','add',name,'type','veth','peer','name',name+'peer')
            run('ip','link','set',name+'peer','netns',pid)
            run('ip','addr','add',network+'.1/24','dev',name);run('ip','link','set',name,'up')
            def ns(*cmd):return run('nsenter','-t',pid,'-n',*cmd)
            ns('ip','link','set','lo','up');ns('ip','addr','add',network+'.2/24','dev',name+'peer')
            if index==0:
                for suffix in (3,4):ns('ip','addr','add',network+f'.{suffix}/24','dev',name+'peer')
            ns('ip','link','set',name+'peer','up');ns('ip','route','add','default','via',network+'.1')
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
        echo_services()
        internal=subprocess.Popen(['nsenter','-t',str(namespaces[1].pid),'-n',sys.executable,__file__,'--echo'])
        children.append(internal)
        rpc=subprocess.Popen(['nsenter','-t',str(namespaces[0].pid),'-n',sys.executable,__file__,'--client'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        children.append(rpc)
        def check(source,proto,port=0,host='10.231.0.1',op='check',key='flow'):
            q={'source':f'10.231.0.{source}','protocol':proto,'port':port,'host':host,'op':op,'key':key}
            rpc.stdin.write(json.dumps(q)+'\n');rpc.stdin.flush()
            line=rpc.stdout.readline();assert line,'Client process exited'
            return json.loads(line)
        with tempfile.TemporaryDirectory(prefix='knock-rules-') as tmp:
            server.CONFIG=Path(tmp)/'settings.json';server.IPSET=os.environ.get('IPSET_BIN',server.IPSET)
            db={'schema':2,'activated':True,'interface':'wan','api_bind':'0.0.0.0','api_port':8443,
                'server_url':'https://example.org:8443','knock_host':'example.org','certificate_sha256':'a'*64,
                'profiles':{},'protected_ports':[], 'rules':{
                    'tcp_range':{'type':'input','protocol':'tcp','ports':['30000-30002']},
                    'udp_range':{'type':'input','protocol':'udp','ports':['31000-31002']},
                    'ping':{'type':'input','protocol':'icmp','icmp_type':'echo-request'},
                    'ssh_lan':{'type':'dnat','protocol':'tcp','ports':['2222'],'dest_ip':'10.232.0.2','dest_port':12345},
                    'udp_lan':{'type':'dnat','protocol':'udp','ports':['5555'],'dest_ip':'10.232.0.2','dest_port':5556},
                    'dnat_tcp_range':{'type':'dnat','protocol':'tcp','ports':['32000-32002'],'dest_ip':'10.232.0.2'},
                    'dnat_udp_range':{'type':'dnat','protocol':'udp','ports':['33000-33002'],'dest_ip':'10.232.0.2'},
                    'routed':{'type':'forward','protocol':'udp','ports':['4567','34000-34002'],'dest_ip':'10.232.0.2'},
                    'routed_ping':{'type':'forward','protocol':'icmp','icmp_type':'echo-request','dest_ip':'10.232.0.2'}}}
            ident=server.issue(db,'Shared',[],[],10,60,rules=list(db['rules']))
            other=server.issue(db,'Other',[],[],10,60,rules=['tcp_range'])
            common.atomic_write(server.CONFIG,json.dumps(db))
            if args.backend=='iptables':
                server.firewall(db)
                # Simulate a permissive established-flow policy behind our guards.
                run('iptables','-A','FORWARD','-m','conntrack','--ctstate','ESTABLISHED','-j','ACCEPT')
            else:
                if args.backend=='native-nft':
                    content=run(os.environ['KNOCK_NATIVE_UNIT'],'--firewall',str(server.CONFIG)).stdout
                else:
                    import nft_backend
                    content=nft_backend.render(db)
                hooks='chain input { type filter hook input priority 0; policy accept; jump knock_control_input; ct state established accept; }\nchain output { type filter hook output priority 0; policy accept; jump knock_control_output; }\nchain forward { type filter hook forward priority 0; policy accept; jump knock_control_forward; ct state established accept; }\n'
                run('nft','-f','-',input='table inet fw4 {\n'+content+hooks+'}\n')
                server.OPENWRT=True
            time.sleep(.3)
            def access(action,source,profile=ident):
                return server.access('access-'+action,profile,server.credential_tag(db['profiles'][profile]),f'10.231.0.{source}')
            services=[('tcp',30000,'10.231.0.1'),('tcp',30002,'10.231.0.1'),('udp',31000,'10.231.0.1'),('udp',31002,'10.231.0.1'),('icmp',0,'10.231.0.1'),('tcp',2222,'10.231.0.1'),('udp',5555,'10.231.0.1'),('udp',4567,'10.232.0.2')]
            services.extend((proto,port,host) for proto,ports,host in (
                ('tcp',[32000,32002],'10.231.0.1'),('udp',[33000,33002],'10.231.0.1'),
                ('udp',[34000,34002],'10.232.0.2'),('icmp',[0],'10.232.0.2')) for port in ports)
            for proto,port,host in services:assert not check(2,proto,port,host),('Initially open',proto,port)
            access('open',2);access('open',3);access('open',4,other)
            for source in (2,3):
                for proto,port,host in services:assert check(source,proto,port,host),('ON failed',source,proto,port)
            assert check(4,'tcp',30000) and not check(4,'udp',31000) and not check(4,'tcp',2222)
            # Inclusive bounds; unrelated ports remain governed by the existing firewall.
            assert check(4,'tcp',30003) and check(4,'udp',31003)
            records.append('TCP/UDP inclusive ranges, ICMP, routed UDP and translated TCP/UDP DNAT')
            assert check(2,'tcp',2222,op='hold',key='tcp')
            assert check(2,'udp',5555,op='hold',key='udp')
            access('close',2)
            assert not check(2,'tcp',op='held',key='tcp') and not check(2,'udp',op='held',key='udp')
            for proto,port,host in services:assert not check(2,proto,port,host),('OFF failed',proto,port)
            assert check(3,'tcp',2222) and check(3,'udp',5555) and check(4,'tcp',30000)
            records.append('OFF blocks established TCP and UDP NAT flows; shared-secret second IP and overlapping profile unaffected')
            access('open',2);access('open',3)
            # Terminate the deliberately blocked TCP flow after reopening, so its
            # retransmissions do not count as genuine activity during the idle check.
            assert check(2,'tcp',op='close',key='tcp') and check(2,'udp',op='close',key='udp')
            # Only Bob's protected UDP traffic refreshes Bob. Alice sends unrelated noise.
            for _ in range(12):
                assert check(3,'udp',5555)
                for _ in range(50):check(2,'udp',31003)
                time.sleep(1)
            assert not check(2,'tcp',2222) and not check(2,'udp',5555) and not check(2,'icmp')
            assert check(3,'udp',5555)
            access('close',3)
            assert not check(3,'udp',5555)
            records.append('UDP activity refreshes only its source lease; unrelated noise does not defeat idle timeout')
            result={'ok':True,'backend':args.backend,'checks':records}
            if args.report:args.report.write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result),flush=True)
    finally:
        for p in reversed(children+namespaces):
            p.terminate()
        for p in children+namespaces:
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()


if __name__=='__main__':
    if '--echo' in sys.argv:
        echo_services();threading.Event().wait()
    elif '--client' in sys.argv:client()
    else:main()
