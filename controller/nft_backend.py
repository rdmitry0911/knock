"""OpenWrt firewall4 backend: per-IP leases ahead of established-flow accepts.

Only our named chains and sets inside inet fw4 are modified. The persistent
include recreates missing sets after a reboot; a normal fw4 reload can retain
existing unexpired elements. IP leases are never written into that include.
"""
import json
from pathlib import Path
import server
import rules as named_rules
from common import atomic_write

NFT='/usr/sbin/nft'
RULES=Path('/etc/knock-control/firewall.nft')
INPUT='knock_control_input'
OUTPUT='knock_control_output'


def nft(text, *, check=True):
    return server.run([NFT,'-f','-'],text=text,check=check)


def contains(ident, source):
    return nft(f'get element inet fw4 {server.set_name(ident)} {{ {source} }}\n',check=False).returncode==0


def flush(ident):
    name=server.set_name(ident)
    if server.run([NFT,'list','set','inet','fw4',name],check=False).returncode==0:
        nft(f'flush set inet fw4 {name}\n')


def set_definition(profile):
    return ('{ type ipv4_addr; flags dynamic,timeout; '
            f'timeout {profile["settings"]["idle_timeout"]}s; size 4096; }}')


def rules(db):
    incoming=[];outgoing=[]
    if db.get('activated',False):
        for ident,profile in sorted(db['profiles'].items()):
            if profile['revoked'] or not profile['enabled']:continue
            cfg=server.config_for(db,profile)
            if not cfg['ports']:continue
            ports='{ '+', '.join(map(str,cfg['ports']))+' }'
            name=server.set_name(ident);timeout=cfg['idle_timeout']
            incoming += [f'tcp dport {ports} ct state established ip saddr @{name} update @{name} {{ ip saddr timeout {timeout}s }}',
                         f'tcp dport {ports} ip saddr @{name} accept']
            outgoing.append(f'tcp sport {ports} ct state established ip daddr @{name} update @{name} {{ ip daddr timeout {timeout}s }}')
        extra=named_rules.nft_rules(db)
        incoming.extend(extra['input']);outgoing.extend(extra['output'])
        if db['protected_ports']:
            incoming.append('meta nfproto ipv4 tcp dport { '+', '.join(map(str,sorted(set(db['protected_ports']))))+' } drop')
    return incoming,outgoing


def render(db):
    incoming,outgoing=rules(db)
    lines=['# Managed by knock-control. Live IP leases are intentionally not persisted.']
    if db.get('activated',False):
        for ident,profile in sorted(db['profiles'].items()):
            lines.append(f'set {server.set_name(ident)} '+set_definition(profile))
    extra=named_rules.nft_rules(db)
    for chain,entries in ((INPUT,incoming),(OUTPUT,outgoing),('knock_control_forward',extra['forward']),('knock_control_prerouting',['type nat hook prerouting priority -101; policy accept;',*extra['prerouting']])):
        lines += [f'chain {chain} {{',*('    '+rule for rule in entries),'}']
    return '\n'.join(lines)+'\n'


def prepare(db):
    atomic_write(RULES,render(db))


def firewall(db):
    old=RULES.read_text() if RULES.exists() else None
    prepare(db)
    try:
        reload=server.run([NFT,'list','chain','inet','fw4','knock_control_forward'],check=False).returncode!=0
        if any(r['type']!='input' for r in db.get('rules',{}).values()):
            reload=reload or server.run([NFT,'list','flowtable','inet','fw4','ft'],check=False).returncode==0
        if reload:
            # First activation installs the include into the live fw4 ruleset.
            # fw4 itself never calls a controller that could wait on its lock.
            server.service_operation('reload','firewall.service')
        listing=json.loads(server.run([NFT,'-j','list','table','inet','fw4']).stdout)
        sets={entry['set']['name'] for entry in listing['nftables'] if 'set' in entry}
        incoming,outgoing=rules(db)
        commands=[]
        if db.get('activated',False):
            for ident,profile in sorted(db['profiles'].items()):
                name=server.set_name(ident)
                if name not in sets:commands.append(f'add set inet fw4 {name} '+set_definition(profile))
        for chain,entries in ((INPUT,incoming),(OUTPUT,outgoing)):
            commands += [f'flush chain inet fw4 {chain}',*(f'add rule inet fw4 {chain} {rule}' for rule in entries)]
        for suffix,entries in named_rules.nft_rules(db).items():
            if suffix in ('input','output'):continue
            chain='knock_control_'+suffix
            commands += [f'flush chain inet fw4 {chain}',*(f'add rule inet fw4 {chain} {rule}' for rule in entries)]
        nft('\n'.join(commands)+'\n')  # One atomic transaction; other IP leases survive.
    except (ValueError,OSError,server.subprocess.SubprocessError):
        if old is not None:atomic_write(RULES,old)
        raise


def access(action,profile,source):
    ident=profile['id'];name=server.set_name(ident)
    if action not in ('access-open','access-close'):raise ValueError('Invalid access action')
    commands=[]
    if contains(ident,source):commands.append(f'delete element inet fw4 {name} {{ {source} }}')
    if action=='access-open':
        commands.append(f'add element inet fw4 {name} {{ {source} timeout {profile["settings"]["idle_timeout"]}s }}')
    if commands:nft('\n'.join(commands)+'\n')
    return {'ok':True}
