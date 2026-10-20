"""Exercise installed C controller rules in routed guest namespaces (no Python guest)."""
import base64
import concurrent.futures
import json
import os
import shlex
import time
import common


def check_rules(remote, copy, ctl, work, api_port):
    # These are disposable test dependencies, not dependencies of the APK.
    remote('apk add ip-full kmod-veth',timeout=180)
    remote('ip netns add kcclient && ip netns add kchost')
    for inter,peer,ns,subnet in (('kcwan','kcclient0','kcclient','10.231.0'),('kclan','kchost0','kchost','10.232.0')):
        remote(f'ip link add {inter} type veth peer name {peer} && ip link set {peer} netns {ns}')
        remote(f'ip addr add {subnet}.1/24 dev {inter} && ip link set {inter} up')
        remote(f'ip -n {ns} link set lo up && ip -n {ns} addr add {subnet}.2/24 dev {peer} && ip -n {ns} link set {peer} up && ip -n {ns} route add default via {subnet}.1')
    remote('ip -n kcclient addr add 10.231.0.3/24 dev kcclient0')
    remote("uci set firewall.@defaults[0].flow_offloading='1' && uci add_list firewall.@zone[0].device='kclan' && uci add_list firewall.@zone[1].device='kcwan' && uci commit firewall && /etc/init.d/firewall reload")
    remote('nft list flowtable inet fw4 ft')
    names=[]
    for name,args in (
        ('range_tcp',['--type','input','--protocol','tcp','--ports','30000-30002']),
        ('range_udp',['--type','input','--protocol','udp','--ports','31000-31002']),
        ('ping',['--type','input','--protocol','icmp']),
        ('dnat_tcp',['--type','dnat','--protocol','tcp','--ports','2222','--dest-ip','10.232.0.2','--dest-port','12345']),
        ('dnat_udp',['--type','dnat','--protocol','udp','--ports','5555','--dest-ip','10.232.0.2','--dest-port','5556']),
        ('routed_udp',['--type','forward','--protocol','udp','--ports','4567','--dest-ip','10.232.0.2'])):
        ctl('rule-set',name,*args,'--interface','kcwan');names.append(name)
    issued=ctl('issue','--name','Rule list','--rules',','.join(names),'--idle-timeout','10','--out','/root/rules.json','--qr-out','/root/rules.png')
    ident=issued['profile_id']
    profile=json.loads(remote('cat /root/rules.json').stdout)
    assert profile['settings']['ports']==[] and profile['settings']['rules']==names
    # Real UCI edits can select a rule subset; a service reload applies the policy.
    remote(f"uci set knock-control.{ident}.idle_timeout='12' && uci commit knock-control && /etc/init.d/knock-control reload")
    assert json.loads(remote('knock-control rules').stdout)['dnat_tcp']['dest_port']==12345
    remote('fw4 check')
    for op,ports,ns in (('echo',[30000,30002],None),('udp-echo',[31000,31002],None),('echo',[12345],'kchost'),('udp-echo',[5556,4567],'kchost')):
        path=work/('rules-'+op+('-host' if ns else '')+'.json');path.write_text(json.dumps({'op':op,'ports':ports})+'\n')
        target='/tmp/'+path.name;copy(path,target)
        remote((f'ip netns exec {ns} ' if ns else '')+f'/tmp/openwrt-probe < {target} > {target}.log 2>&1 &')
    time.sleep(.4)
    def probe(**q):
        return json.loads(remote('ip netns exec kcclient /tmp/openwrt-probe',input=json.dumps(q)+'\n',timeout=60).stdout)
    def api(source,action,**extra):
        body=json.dumps({'action':action,**extra},separators=(',',':'));stamp=str(int(time.time()));nonce=os.urandom(16).hex()
        auth=f'Knock {ident}:{stamp}:{nonce}:'+common.api_signature(profile['secret'],stamp,nonce,body.encode())
        r=probe(op='https',ip=f'10.231.0.{source}',host='10.231.0.1',port=api_port,pin=profile['server_certificate_sha256'],authorization=auth,body=body)
        return r['status'],json.loads(r['body'])
    def access(source,action):
        code,status=api(source,'status');assert code==200
        cfg={**status['settings'],'secret':profile['secret']};ip=f'10.231.0.{source}';now=time.time()
        code,result=api(source,'browser-'+action,
            sequence=[list(x) for x in common.sequence(cfg,action,ip,now=now)],
            confirmation=base64.b64encode(common.confirmation(cfg,action,ip,now=now)).decode())
        assert code==200 and result['access_active']==(action=='open')
    def reachable(source,op,port,host='10.231.0.1',**extra):
        return probe(op=op,ip=f'10.231.0.{source}',host=host,port=port,**extra)['reachable']
    assert not reachable(2,'tcp',2222) and not reachable(2,'udp',5555)
    assert remote('ip netns exec kcclient ping -c 1 -W 1 -I 10.231.0.2 10.231.0.1',check=False).returncode!=0
    access(2,'open');access(3,'open')
    for op,port,host in (('tcp',30000,'10.231.0.1'),('tcp',30002,'10.231.0.1'),('udp',31000,'10.231.0.1'),('udp',31002,'10.231.0.1'),('tcp',2222,'10.231.0.1'),('udp',5555,'10.231.0.1'),('udp',4567,'10.232.0.2')):
        assert reachable(2,op,port,host),(op,port)
    remote('ip netns exec kcclient ping -c 1 -W 1 -I 10.231.0.2 10.231.0.1')
    # A credential may choose its rule list but cannot add another target or rule.
    _,status=api(2,'status')
    code,_=api(2,'configure',revision=status['revision'],settings={'rules':['not_allowed']})
    assert code==400
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        tcp=pool.submit(reachable,2,'stream',2222,seconds=15)
        udp=pool.submit(reachable,2,'udp-stream',5555,seconds=15)
        time.sleep(1.5);access(2,'close')
        assert not tcp.result(timeout=20) and not udp.result(timeout=20)
    assert reachable(3,'tcp',2222) and reachable(3,'udp',5555)
    access(2,'open');access(3,'open')
    # Keep Bob active with UDP, leave Alice idle. API status must not renew her lease.
    for _ in range(8):
        assert reachable(3,'udp',5555)
        assert api(2,'status')[0]==200
        time.sleep(2)
    assert not reachable(2,'udp',5555) and reachable(3,'udp',5555)
    access(3,'close');assert not reachable(3,'udp',5555)
    remote('ip netns del kcclient && ip netns del kchost')
    return ['installed C rule-set CLI and UCI bindings; rule-only profile and QR export',
            'routed namespaces: inclusive TCP/UDP ranges, ICMP and TCP/UDP DNAT with port translation',
            'OFF blocks established TCP/UDP NAT streams; second source using same profile survives',
            'client cannot select unauthorized rules; per-IP UDP activity and idle expiry; API does not refresh lease',
            'software flow offloading enabled: protection precedes flow offload and established accepts']
