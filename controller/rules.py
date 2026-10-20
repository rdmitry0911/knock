"""Server-owned IPv4 firewall rules shared by profiles, never shell commands."""
import ipaddress
import re


def rule_names(value):
    if not isinstance(value, list) or len(value) > 64 or any(
        not isinstance(s, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,31}', s) for s in value
    ) or len(set(value)) != len(value):
        raise ValueError('Use up to 64 distinct rule names (letters, digits, underscore)')
    return value.copy()


def normalize(value):
    if not isinstance(value, dict) or set(value) - {'type', 'protocol', 'ports', 'dest_ip', 'dest_port', 'icmp_type', 'interface'}:
        raise ValueError('Invalid rule fields')
    kind, proto = value.get('type', 'input'), value.get('protocol', 'tcp')
    if kind not in ('input', 'forward', 'dnat') or proto not in ('tcp', 'udp', 'icmp'):
        raise ValueError('Rule type: input/forward/dnat; protocol: tcp/udp/icmp')
    result = {'type': kind, 'protocol': proto}
    if 'interface' in value:
        if not isinstance(value['interface'], str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', value['interface']):
            raise ValueError('Invalid rule interface')
        result['interface'] = value['interface']
    if proto == 'icmp':
        if kind == 'dnat' or 'ports' in value or 'dest_port' in value:
            raise ValueError('ICMP has no ports or DNAT')
        it = value.get('icmp_type', 'echo-request')
        if it not in ('any', 'echo-request'):
            raise ValueError('ICMP type must be any or echo-request')
        result['icmp_type'] = it
    else:
        if 'icmp_type' in value:
            raise ValueError('icmp_type requires ICMP')
        entries = value.get('ports')
        if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
            raise ValueError('Use 1..32 ports or inclusive ranges per rule')
        result['ports'] = []
        for entry in entries:
            s = str(entry) if type(entry) is int else entry
            if not isinstance(s, str) or not re.fullmatch(r'[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?', s):
                raise ValueError('Port must be 1..65535 or START-END')
            bounds = list(map(int, s.split('-')))
            if not 1 <= bounds[0] <= bounds[-1] <= 65535:
                raise ValueError('Invalid port range')
            if s not in result['ports']:
                result['ports'].append(s)
    if kind != 'input':
        address = ipaddress.IPv4Address(value.get('dest_ip', ''))
        if address.is_multicast or address.is_unspecified or str(address) == '255.255.255.255':
            raise ValueError('Destination must be a unicast IPv4 address')
        result['dest_ip'] = str(address)
    elif 'dest_ip' in value:
        raise ValueError('dest_ip requires forward or dnat')
    if 'dest_port' in value:
        p = value['dest_port']
        if kind != 'dnat' or len(result['ports']) != 1 or '-' in result['ports'][0] or type(p) is not int or not 1 <= p <= 65535:
            raise ValueError('Port translation requires one DNAT port; ranges keep their ports')
        result['dest_port'] = p
    return result


def validate(db):
    rules = db.get('rules', {})
    if not isinstance(rules, dict) or len(rules) > 128:
        raise ValueError('Maximum 128 named rules')
    bases = [p['settings']['base'] for p in db['profiles'].values()]
    for name, value in rules.items():
        rule_names([name])
        rule = normalize(value)
        # Protecting transport or management ports would make recovery impossible.
        if rule['type'] != 'forward' and rule['protocol'] != 'icmp':
            for entry in rule['ports']:
                a, b = int(entry.split('-')[0]), int(entry.split('-')[-1])
                if rule['protocol'] == 'tcp' and a <= db['api_port'] <= b or any(a <= base+255 and b >= base for base in bases):
                    raise ValueError('Rule overlaps the API or knock ports')
        rules[name] = rule
    entries=list(rules.values())
    for i, left in enumerate(entries):
        if left['protocol']=='icmp' or left['type']=='forward':continue
        for right in entries[i+1:]:
            if right['protocol']!=left['protocol'] or right['type']=='forward' or 'dnat' not in (left['type'],right['type']):continue
            if left.get('interface',db['interface'])!=right.get('interface',db['interface']):continue
            overlap=any(int(a.split('-')[0])<=int(b.split('-')[-1]) and int(b.split('-')[0])<=int(a.split('-')[-1]) for a in left['ports'] for b in right['ports'])
            if overlap and (left['type']!=right['type'] or (left.get('dest_ip'),left.get('dest_port'))!=(right.get('dest_ip'),right.get('dest_port'))):
                raise ValueError('Conflicting input/DNAT mappings on the same interface and ports')
    for p in db['profiles'].values():
        if 'rules' in p['settings'] or 'allowed_rules' in p['policy']:
            p['settings'].setdefault('rules', [])
            p['policy'].setdefault('allowed_rules', [])
        selected = rule_names(p['settings'].get('rules', []))
        allowed = rule_names(p['policy'].get('allowed_rules', []))
        if not set(selected) <= set(allowed) <= set(rules):
            raise ValueError('Unknown rule or rule outside profile policy')


def selected(db, profile):
    return [db['rules'][name] for name in profile['settings'].get('rules', [])]


def nft_match(rule, interface, direction='original'):
    """Match both directions using conntrack's original tuple for forwarded flows."""
    inter = rule.get('interface', interface)
    proto, kind = rule['protocol'], rule['type']
    if kind == 'input':
        head = f'iifname "{inter}" '
        if proto == 'icmp':
            return head + 'meta nfproto ipv4 meta l4proto icmp' + (' icmp type echo-request' if rule['icmp_type'] != 'any' else '')
        return head + proto + ' dport { ' + ', '.join(rule['ports']) + ' }'
    head = f'{"iifname" if direction == "original" else "oifname"} "{inter}" ct direction {direction} meta l4proto {proto} '
    if kind == 'dnat':
        head += 'ct status dnat '
    else:
        head += f'ct original ip daddr {rule["dest_ip"]} '
    if proto != 'icmp':
        head += 'ct original proto-dst { ' + ', '.join(rule['ports']) + ' }'
    elif rule['icmp_type'] != 'any':
        head += 'icmp type ' + ('echo-request' if direction == 'original' else 'echo-reply')
    return head.strip()


def nft_rules(db):
    out = {k: [] for k in ('input', 'output', 'forward', 'prerouting')}
    if not db.get('activated'):
        return out
    for ident, profile in sorted(db['profiles'].items()):
        if profile['revoked'] or not profile['enabled']:
            continue
        timeout, name = profile['settings']['idle_timeout'], 'kc_'+ident
        for rule in selected(db, profile):
            if rule['type'] == 'input':
                match = nft_match(rule, db['interface'])
                source = 'ip saddr'
                out['input'] += [f'{match} {source} @{name} update @{name} {{ {source} timeout {timeout}s }} accept']
                # Replies refresh a lease only while it still exists.
                inter = rule.get('interface', db['interface'])
                if rule['protocol'] != 'icmp':
                    reply = f'oifname "{inter}" {rule["protocol"]} sport {{ '+', '.join(rule['ports'])+' } ct state established'
                else:
                    reply = f'oifname "{inter}" meta nfproto ipv4 meta l4proto icmp ct state established'
                out['output'].append(f'{reply} ip daddr @{name} update @{name} {{ ip daddr timeout {timeout}s }}')
            else:
                for direction in ('original', 'reply'):
                    match = nft_match(rule, db['interface'], direction)
                    if rule['type'] == 'dnat':
                        match += f' {"ip daddr" if direction == "original" else "ip saddr"} {rule["dest_ip"]}'
                        if 'dest_port' in rule:
                            match += f' {rule["protocol"]} {"dport" if direction == "original" else "sport"} {rule["dest_port"]}'
                    source = 'ct original ip saddr'
                    out['forward'].append(f'{match} {source} @{name} update @{name} {{ {source} timeout {timeout}s }} accept')
                if rule['type'] == 'dnat':
                    inter = rule.get('interface', db['interface'])
                    dest = rule['dest_ip'] + (':'+str(rule['dest_port']) if 'dest_port' in rule else '')
                    out['prerouting'].append(f'iifname "{inter}" fib daddr type local {rule["protocol"]} dport {{ '+', '.join(rule['ports'])+f' }} ip saddr @{name} dnat ip to {dest}')
    # All accepts precede all guards, so overlapping profile permissions form a union.
    for rule in db.get('rules', {}).values():
        if rule['type'] == 'input':
            out['input'].append(nft_match(rule, db['interface'])+' drop')
        elif rule['type'] == 'dnat':
            direct = {**rule, 'type': 'input'}
            out['input'].append(nft_match(direct, db['interface'])+' drop')
        if rule['type'] != 'input':
            for direction in ('original', 'reply'):
                out['forward'].append(nft_match(rule, db['interface'], direction)+' drop')
    return out
