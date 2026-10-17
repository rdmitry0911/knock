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
    if not isinstance(ports, list) or not 1 <= len(ports) <= 15:
        raise ValueError('Use 1..15 protected TCP ports')
    result['ports'] = sorted(set(integer(p, 1, 65535, 'port') for p in ports))
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
EDITABLE = frozenset(('ports', 'idle_timeout', 'protocols', 'seq_timeout', 'ip_protection'))


def profile_id(value):
    if not isinstance(value, str) or not PROFILE_ID.fullmatch(value):
        raise ValueError('Invalid profile ID')
    return value


def api_signature(secret, timestamp, nonce, body):
    message = f'knock-control:api:v2:POST:/v1/control:{timestamp}:{nonce}:'.encode('ascii') + hashlib.sha256(body).hexdigest().encode('ascii')
    return hmac.new(base64.b32decode(secret), message, hashlib.sha256).hexdigest()


def client_bundle(value):
    from urllib.parse import urlsplit
    if not isinstance(value, dict) or value.get('format') != 'knock-control-client-v2':
        raise ValueError('Import a client file issued by the server')
    ident = profile_id(value.get('profile_id'))
    url = value.get('server_url', '')
    if not isinstance(url, str):
        raise ValueError('Invalid HTTPS server URL')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Server URL must be https://host:port')
    try:
        integer(parsed.port or 443, 1, 65535, 'API port')
    except ValueError:
        raise ValueError('Invalid API port') from None
    pin = value.get('server_certificate_sha256', '')
    if not isinstance(pin, str) or not re.fullmatch(r'[0-9a-f]{64}', pin):
        raise ValueError('Server certificate fingerprint is required')
    if not isinstance(value.get('settings'), dict):
        raise ValueError('Client settings must be an object')
    config = settings({**value.get('settings', {}), 'secret': value.get('secret'), 'profile_id': ident})
    host = value.get('knock_host', parsed.hostname)
    if not isinstance(host, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', host):
        raise ValueError('Invalid knock host')
    name = value.get('name', ident)
    if not isinstance(name, str) or not 1 <= len(name) <= 80 or any(ord(ch) < 32 for ch in name):
        raise ValueError('Invalid profile name')
    ip = value.get('public_ip', '')
    ip = str(ipaddress.IPv4Address(ip)) if ip else ''
    return {'format': 'knock-control-client-v2', 'profile_id': ident, 'name': name,
            'server_url': url.rstrip('/'), 'server_certificate_sha256': pin,
            'knock_host': host, 'secret': config['secret'], 'settings': public_settings(config),
            'public_ip': ip, 'revision': integer(value.get('revision', 1), 1, 2147483647, 'revision')}


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
