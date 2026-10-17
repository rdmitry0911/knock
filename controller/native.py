#!/usr/bin/python3
"""Per-user Native Messaging bridge for server-issued credentials."""
import errno
import hashlib
import hmac
import http.client
import ipaddress
import json
from pathlib import Path
import secrets
import select
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlsplit, urlencode, quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import EDITABLE, api_signature, atomic_write, client_bundle, confirmation, public_settings, read_json, sequence, settings

STORE = Path.home() / '.config/knock-control/profiles.json'
LIMIT = 65536


def store_load():
    if not STORE.exists():
        return {'version':2,'active':None,'profiles':{}}
    value = read_json(STORE)
    if not isinstance(value, dict) or value.get('version') != 2 or not isinstance(value.get('profiles'), dict):
        raise ValueError('Import a server-issued credential into the new client')
    return value


def key_for(bundle):
    return hashlib.sha256((bundle['server_url']+':'+bundle['profile_id']).encode()).hexdigest()[:32]


def save_store(value):
    atomic_write(STORE, json.dumps(value, indent=2)+'\n')


def active_profile(store):
    cfg = store['profiles'].get(store['active'])
    if not cfg:
        raise ValueError('Import and select a server-issued client file')
    return client_bundle(cfg)


def safe_profile(cfg):
    return {key: value for key, value in cfg.items() if key != 'secret'}


def remote(config, action, changes=None):
    parsed = urlsplit(config['server_url'])
    # A server-issued SHA256 leaf certificate pin is checked BEFORE sending
    # any authenticated HTTP request. Self-signed bootstrap needs no shared CA.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context, timeout=15)
    request = {'action': action}
    if action == 'configure':
        if not isinstance(changes, dict) or set(changes)-EDITABLE:
            raise ValueError('Only profile settings can be changed')
        request.update(settings=changes, revision=config['revision'])
    body = json.dumps(request, sort_keys=True, separators=(',',':')).encode('utf-8')
    try:
        connection.connect()
        certificate = connection.sock.getpeercert(binary_form=True)
        if not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), config['server_certificate_sha256']):
            raise ValueError('Server certificate differs from the issued client file')
        timestamp, nonce = str(int(time.time())), secrets.token_hex(16)
        signature = api_signature(config['secret'], timestamp, nonce, body)
        authorization = f"Knock {config['profile_id']}:{timestamp}:{nonce}:{signature}"
        connection.request('POST','/v1/control',body,{'Authorization':authorization,'Content-Type':'application/json'})
        result = connection.getresponse()
        payload = result.read(LIMIT+1)
        if len(payload)>LIMIT:
            raise ValueError('Server response too large')
        response = json.loads(payload)
        if not isinstance(response,dict) or not response.get('ok') or result.status != 200:
            raise ValueError(response.get('error','Server operation failed') if isinstance(response,dict) else 'Invalid server response')
        if response.get('profile_id') != config['profile_id']:
            raise ValueError('Server returned a different profile')
        return response
    finally:
        connection.close()


def transport_config(bundle):
    return {'host':bundle['knock_host'], 'public_ip':bundle['public_ip'],
            'settings':settings({**bundle['settings'],'secret':bundle['secret'],'profile_id':bundle['profile_id']})}


def knock(config, action, code=None):
    cfg = config['settings']
    if cfg['ip_protection'] and not config['public_ip']:
        raise ValueError('Specify the public IPv4 seen by this server')
    # Resolve once: all packets in a sequence must hit the SAME IPv4 address.
    address = socket.getaddrinfo(config['host'], None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    count = len(cfg['protocols'])
    duration = count * .25 + .5
    if duration >= cfg['period']:
        raise ValueError('OTP period is too short for this sequence')
    remaining = cfg['period'] - time.time() % cfg['period']
    if remaining < duration:
        time.sleep(remaining + .05)
    stamp = time.time()
    proof = confirmation(cfg, action, config['public_ip'], now=stamp, code=code)
    ports = sequence(cfg, action, config['public_ip'], now=stamp, code=code)
    for port, proto in ports:
        if proto == 'udp':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b'\x00', (address, port))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setblocking(False)
                code = sock.connect_ex((address, port))
                if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.ECONNREFUSED):
                    raise OSError(code, 'TCP knock failed')
                # Give the kernel time to transmit the SYN, then close before retransmission.
                select.select([], [sock], [], .1)
        time.sleep(.15)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(proof, (address, cfg['base']))
    return {'ok': True, 'sent': len(ports) + 1, 'message': 'Последовательность отправлена; получение сервером не подтверждено.'}


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError('Request must be an object')
    action = request.get('action')
    store = store_load()
    if action == 'load':
        cfg = active_profile(store) if store['active'] else None
        return {'ok':True, 'profile':safe_profile(cfg) if cfg else None, 'active':store['active'],
                'profiles':[{'key':key,'name':value['name'],'server_url':value['server_url']} for key,value in store['profiles'].items()]}
    if action == 'import':
        from qr_codec import decode_enrollment
        value=request.get('bundle')
        cfg = decode_enrollment(value) if isinstance(value,str) else client_bundle(value)
        key = key_for(cfg)
        store['profiles'][key] = cfg
        store['active'] = key
        save_store(store)
        return {'ok':True, 'profile':safe_profile(cfg)}
    if action == 'select':
        if request.get('key') not in store['profiles']:
            raise ValueError('Unknown client profile')
        store['active'] = request['key']
        save_store(store)
        return {'ok':True}
    cfg = active_profile(store)
    if action == 'save':
        ip = request.get('public_ip','')
        cfg['public_ip'] = str(ipaddress.IPv4Address(ip)) if ip else ''
        store['profiles'][store['active']] = cfg
        save_store(store)
        return {'ok':True}
    if action == 'pairing':
        uri = 'otpauth://totp/'+quote('Knock Control:'+cfg['name'],safe='')+'?'+urlencode({'secret':cfg['secret'],'issuer':'Knock Control','algorithm':'SHA1','digits':'6','period':'30'})
        return {'ok':True,'uri':uri,'secret':cfg['secret']}
    if action in ('status','configure'):
        response = remote(cfg, action, request.get('settings'))
        cfg['settings'] = public_settings(settings({**response['settings'],'secret':cfg['secret'],'profile_id':cfg['profile_id']}))
        cfg['revision'] = response['revision']
        if not cfg['public_ip'] and response.get('observed_ip'):
            cfg['public_ip'] = str(ipaddress.IPv4Address(response['observed_ip']))
        store['profiles'][store['active']] = cfg
        save_store(store)
        return {**response,'profile':safe_profile(cfg)}
    if action in ('open','close'):
        if not cfg['public_ip']:
            response = remote(cfg,'status')
            cfg['public_ip'] = str(ipaddress.IPv4Address(response['observed_ip']))
            cfg['settings'] = response['settings']
            cfg['revision'] = response['revision']
            store['profiles'][store['active']] = cfg
            save_store(store)
        return knock(transport_config(cfg),action,request.get('code') or None)
    raise ValueError('Unknown client action')


def read_exact(stream, length):
    chunks = bytearray()
    while len(chunks)<length:
        block=stream.read(length-len(chunks))
        if not block: raise EOFError('Truncated Native Messaging frame')
        chunks.extend(block)
    return bytes(chunks)


def main():
    while True:
        first=sys.stdin.buffer.read(1)
        if not first: return
        try:
            length=struct.unpack('=I', first+read_exact(sys.stdin.buffer,3))[0]
            if not 1<=length<=LIMIT: return
            response=dispatch(json.loads(read_exact(sys.stdin.buffer,length)))
        except EOFError:
            return
        except (ValueError,OSError,http.client.HTTPException) as exc:
            response={'ok':False,'error':str(exc) if isinstance(exc,ValueError) else type(exc).__name__+': операция не выполнена'}
        payload=json.dumps(response,ensure_ascii=False).encode('utf-8')
        sys.stdout.buffer.write(struct.pack('=I',len(payload))+payload)
        sys.stdout.buffer.flush()


if __name__=='__main__': main()
