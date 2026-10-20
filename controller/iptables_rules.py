"""Render named rules for iptables/ipset without interpolating shell code."""
from rules import selected


def matches(rule, interface, direction='ORIGINAL'):
    proto, kind = rule['protocol'], rule['type']
    inter = rule.get('interface', interface)
    head = f'-{"i" if direction == "ORIGINAL" else "o"} {inter} -p {proto}'
    if kind != 'input':
        head += f' -m conntrack --ctdir {direction}'
        if kind == 'dnat':
            head += ' --ctstate DNAT'
        else:
            head += f' --ctorigdst {rule["dest_ip"]}'
    if proto == 'icmp':
        yield head + (' --icmp-type '+('echo-request' if direction == 'ORIGINAL' else 'echo-reply') if rule['icmp_type'] != 'any' else '')
    else:
        for entry in rule['ports']:
            port = entry.replace('-', ':')
            yield head + (' --dport ' if kind == 'input' else ' --ctorigdstport ') + port


def render(db, chain):
    incoming, outgoing, forward, nat = [], [], [], []
    for ident, p in sorted(db['profiles'].items()):
        if p['revoked'] or not p['enabled']:
            continue
        name, timeout = 'kc_'+ident, p['settings']['idle_timeout']
        def grant(target, match, side, accept=True):
            target.append(f'{match} -m set --match-set {name} {side} -j SET --add-set {name} {side} --exist --timeout {timeout}')
            if accept:
                target.append(f'{match} -m set --match-set {name} {side} -j ACCEPT')
        for r in selected(db, p):
            if r['type'] == 'input':
                for match in matches(r, db['interface']):
                    grant(incoming, match, 'src')
                for match in matches(r, db['interface']):
                    reply = match.replace('-i ', '-o ', 1).replace('--dport ', '--sport ')
                    if r['protocol'] == 'icmp':
                        reply = reply.replace('echo-request', 'echo-reply')
                    grant(outgoing, reply+' -m conntrack --ctstate ESTABLISHED', 'dst', False)
            else:
                for direction, side in (('ORIGINAL', 'src'), ('REPLY', 'dst')):
                    for match in matches(r, db['interface'], direction):
                        if r['type'] == 'dnat':
                            match += f' -{"d" if direction == "ORIGINAL" else "s"} {r["dest_ip"]}'
                            if 'dest_port' in r:
                                match += f' --{"dport" if direction == "ORIGINAL" else "sport"} {r["dest_port"]}'
                        grant(forward, match, side)
                if r['type'] == 'dnat':
                    direct = {**r, 'type': 'input'}
                    dest = r['dest_ip'] + (':'+str(r['dest_port']) if 'dest_port' in r else '')
                    for match in matches(direct, db['interface']):
                        nat.append(f'{match} -m addrtype --dst-type LOCAL -m set --match-set {name} src -j DNAT --to-destination {dest}')
    for r in db.get('rules', {}).values():
        if r['type'] in ('input', 'dnat'):
            incoming.extend(m+' -j DROP' for m in matches({**r, 'type':'input'}, db['interface']))
        if r['type'] != 'input':
            for direction in ('ORIGINAL', 'REPLY'):
                forward.extend(m+' -j DROP' for m in matches(r, db['interface'], direction))
    return incoming, outgoing, forward, nat
