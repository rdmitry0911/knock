"""Shared validation, RFC 6238 TOTP and authenticated knock transport."""
import base64
import struct
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
from pathlib import Path
import re
import tempfile
import time


def integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{name}: expected integer {low}..{high}')
    return value


def settings(value):
    if not isinstance(value, dict):
        raise ValueError('settings must be an object')
    result = {}
    interface = value.get('interface', 'eth0')
    if not isinstance(interface, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', interface):
        raise ValueError('Invalid network interface')
    result['interface'] = interface
    secret = value.get('secret', '').replace(' ', '').upper() if isinstance(value.get('secret'), str) else ''
    if not re.fullmatch(r'[A-Z2-7]{32}', secret):
        raise ValueError('secret: use a 32-character Base32 Google Authenticator secret')
    result['secret'] = secret
    for name, default, low, high in [('period', 30, 30, 30), ('base', 20000, 1024, 65280),
                                    ('idle_timeout', 600, 10, 86400), ('seq_timeout', 10, 1, 60)]:
        result[name] = integer(value.get(name, default), low, high, name)
    protocols = value.get('protocols', ['udp'] * 6)
    if not isinstance(protocols, list) or not 3 <= len(protocols) <= 20 or any(p not in ('tcp', 'udp') for p in protocols):
        raise ValueError('Use 3..20 TCP/UDP protocols')
    result['protocols'] = protocols
    protection = value.get('ip_protection', True)
    if type(protection) is not bool:
        raise ValueError('ip_protection must be boolean')
    result['ip_protection'] = protection
    count = len(protocols)
    if result['seq_timeout'] <= count * .25 or result['period'] <= count * .25 + .5:
        raise ValueError('Increase seq_timeout/period for the chosen sequence length')
    ports = value.get('ports', [22])
    if not isinstance(ports, list) or len(ports) > 15 or not ports and 'rules' not in value:
        raise ValueError('Use 1..15 protected TCP ports or a named rule list')
    result['ports'] = sorted(set(integer(p, 1, 65535, 'port') for p in ports))
    if 'rules' in value:
        from rules import rule_names
        result['rules'] = rule_names(value['rules'])
    if any(result['base'] <= p <= result['base'] + 255 for p in result['ports']):
        raise ValueError('Protected ports must be outside the knock range')
    if 'profile_id' in value:
        result['profile_id'] = profile_id(value['profile_id'])
    return result


def public_settings(value):
    return {k: v for k, v in value.items() if k != 'secret'}


def totp(secret, now=None):
    """RFC 6238 / Google Authenticator: SHA1, 6 digits, 30 seconds."""
    key = base64.b32decode(secret.upper())
    step = int(time.time() if now is None else now) // 30
    digest = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff
    return f'{value % 1000000:06d}'


def sequence(config, action, ip='', now=None, code=None):
    config = settings(config)
    if action not in ('open', 'close'):
        raise ValueError('Invalid knock action')
    if code is None:
        code = totp(config['secret'], now)
    if not isinstance(code, str) or not re.fullmatch(r'[0-9]{6}', code):
        raise ValueError('Enter a six-digit Google Authenticator code')
    source = str(ipaddress.IPv4Address(ip)) if config['ip_protection'] else '-'
    # RFC 6238 defines the code; this versioned mapping defines the knock transport.
    door = config['profile_id'] + '.' + action if config.get('profile_id') else action
    message = f'knock-control:v1:{door}:{source}:{code}'.encode('ascii')
    digest = hashlib.sha256(message).digest()
    return [(config['base'] + byte, proto) for byte, proto in zip(digest, config['protocols'])]


def confirmation(config, action, ip, now=None, code=None, nonce=None):
    config = settings(config)
    current = int(time.time() if now is None else now) // 30
    step = current
    if code is not None:
        matching = [s for s in (current, current-1, current+1) if totp(config['secret'], s*30) == code]
        if not matching:
            raise ValueError('Authenticator code is invalid or expired')
        step = matching[0]
    nonce = secrets.token_bytes(16) if nonce is None else nonce
    source = str(ipaddress.IPv4Address(ip)) if config['ip_protection'] else '-'
    counter = struct.pack('>Q', step)
    door = config['profile_id'] + '.' + action if config.get('profile_id') else action
    message = b'knock-control:confirm:v1:' + counter + nonce + door.encode('ascii') + b':' + source.encode('ascii')
    tag = hmac.new(base64.b32decode(config['secret']), message, hashlib.sha256).digest()
    return b'KNC1' + counter + nonce + tag


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    return json.loads(Path(path).read_text())


PROFILE_ID = re.compile(r'[0-9a-f]{24}')


def profile_id(value):
    if not isinstance(value, str) or not PROFILE_ID.fullmatch(value):
        raise ValueError('Invalid profile ID')
    return value


def ice_token(bundle, action, source, *, now=None, nonce=None, issued_ms=None, target=None):
    if action not in ('open', 'close'): raise ValueError('Invalid ICE action')
    now = time.time() if now is None else now
    source = str(ipaddress.IPv4Address(source))
    nonce = secrets.token_hex(16) if nonce is None else nonce
    if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{32}',nonce): raise ValueError('Invalid ICE nonce')
    issued_ms = int(now*1000) if issued_ms is None else integer(issued_ms,0,2**53-1,'issued_ms')
    version = 1 if target is None else 2
    if target is not None:
        target = ipaddress.IPv4Address(target)
        if not 0 < int(target) >> 24 < 224: raise ValueError('Invalid access IPv4')
    clock = f'{int(now)//30:016x}' if target is None else f'{int(now)//30:08x}{int(target):08x}'
    prefix = 'KNI'+str(version)+profile_id(bundle['profile_id'])+('O' if action=='open' else 'C')+f'{bundle["revision"]:08x}'+clock+f'{issued_ms:016x}'+nonce
    ip = source if bundle['settings']['ip_protection'] else '-'
    signature=hmac.new(base64.b32decode(bundle['secret']),f'knock-control:ice:v{version}:{prefix}:{ip}'.encode('ascii'),hashlib.sha256).hexdigest()
    return prefix+signature


def verify_ice_token(bundle, token, source, *, now=None):
    now=time.time() if now is None else now
    if not isinstance(token,str) or not re.fullmatch(r'KNI[12][0-9a-f]{24}[OC][0-9a-f]{136}',token): raise ValueError('Invalid ICE token')
    target=ice_target(token,source) if token.startswith('KNI2') else None
    step,issued=int(token[37:45 if target else 53],16),int(token[53:69],16)
    if token[4:28]!=bundle['profile_id'] or int(token[29:37],16)!=bundle['revision'] or abs(int(now)//30-step)>1 or abs(int(now*1000)-issued)>60000:
        raise ValueError('Expired or replaced ICE credential')
    action='open' if token[28]=='O' else 'close'
    expected=ice_token(bundle,action,source,now=step*30,nonce=token[69:101],issued_ms=issued,target=target)
    if not hmac.compare_digest(token,expected): raise ValueError('Invalid ICE authentication')
    return action,token[69:101],issued


def ice_target(token, source):
    if not token.startswith('KNI2'): return source
    target=ipaddress.IPv4Address(int(token[45:53],16))
    if not 0 < int(target) >> 24 < 224: raise ValueError('Invalid access IPv4')
    return str(target)


def ice_proof_ports(token, base):
    ports=[]
    for i in range(6):
        offset=int(token[101+i*2:103+i*2],16)%255
        while base+1+offset in ports: offset=(offset+1)%255
        ports.append(base+1+offset)
    return ports


def client_bundle(value):
    from urllib.parse import urlsplit
    if not isinstance(value,dict) or value.get('format') not in ('knock-control-client-v2','knock-control-client-v3'):
        raise ValueError('Import a client file issued by the server')
    ident=profile_id(value.get('profile_id'))
    legacy=value['format']=='knock-control-client-v2'
    legacy_url=value.get('server_url','') if legacy else ''
    if not isinstance(legacy_url,str):raise ValueError('Invalid legacy profile URL')
    parsed=urlsplit(legacy_url)
    if legacy and (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment):
        raise ValueError('Invalid legacy profile URL')
    if not isinstance(value.get('settings'),dict):raise ValueError('Client settings must be an object')
    config=settings({**value['settings'],'secret':value.get('secret'),'profile_id':ident})
    host=value.get('knock_host',parsed.hostname)
    if not isinstance(host,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}',host):raise ValueError('Invalid knock host')
    name=value.get('name',ident)
    if not isinstance(name,str) or not 1<=len(name)<=80 or any(ord(c)<32 for c in name):raise ValueError('Invalid profile name')
    result={'format':'knock-control-client-v3','profile_id':ident,'name':name,'knock_host':host,
            'secret':config['secret'],'settings':public_settings(config),'ice_version':1,
            'public_ip':str(ipaddress.IPv4Address(value['public_ip'])) if value.get('public_ip') else '',
            'revision':integer(value.get('revision',1),1,2147483647,'revision')}
    for key in ('ice_host','ice_source','access_source'):
        if value.get(key):result[key]=str(ipaddress.IPv4Address(value[key]))
    if 'stun_server' in value:
        if not isinstance(value['stun_server'],str) or not re.fullmatch(r'stun:[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}:[0-9]{1,5}',value['stun_server']):raise ValueError('Invalid STUN server')
        integer(int(value['stun_server'].rsplit(':',1)[1]),1,65535,'STUN port');result['stun_server']=value['stun_server']
    return result


def atomic_write_bytes(path, data, mode=0o600):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,temporary=tempfile.mkstemp(dir=path.parent,prefix='.'+path.name)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode);stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
