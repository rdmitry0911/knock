"""Offline QR enrollment: server-issued profile URL, PNG/SVG and terminal output."""
import base64
import json
from pathlib import Path
import struct
import zlib
from urllib.parse import urlsplit, parse_qs
from common import client_bundle

PREFIX = 'kc2_'


def enrollment_url(bundle):
    bundle = client_bundle(bundle)
    # Compact transport keeps one whole profile in one camera-readable QR.
    cfg = bundle['settings']
    compact = {'v':2,'u':bundle['server_url'],'f':bundle['server_certificate_sha256'],
               'i':bundle['profile_id'],'n':bundle['name'],'k':bundle['secret'],
               'h':bundle['knock_host'],'r':bundle['revision'],
               's':[cfg['base'],cfg['ports'],cfg['idle_timeout'],
                    ''.join('t' if p=='tcp' else 'u' for p in cfg['protocols']),
                    cfg['seq_timeout'],int(cfg['ip_protection'])]}
    if 'rules' in cfg: compact['s'].append(cfg['rules'])
    if 'ice_version' in bundle:compact['w']=bundle['ice_version']
    encoded = base64.urlsafe_b64encode(json.dumps(compact,ensure_ascii=False,separators=(',',':')).encode()).decode().rstrip('=')
    return bundle['server_url']+'/app/#import='+PREFIX+encoded


def decode_enrollment(text):
    if not isinstance(text,str) or len(text)>8192:
        raise ValueError('Invalid enrollment QR')
    if text.lstrip().startswith('{'):
        return client_bundle(json.loads(text))
    parsed = urlsplit(text)
    if parsed.scheme!='https' or parsed.path!='/app/' or parsed.username or parsed.password or parsed.query:
        raise ValueError('Use a Knock Control enrollment QR')
    values=parse_qs(parsed.fragment)
    tokens=values.get('import',[])
    if len(tokens)!=1 or not tokens[0].startswith(PREFIX):
        raise ValueError('Use a Knock Control enrollment QR')
    token=tokens[0][len(PREFIX):]
    try:
        value=json.loads(base64.b64decode(token+'='*((-len(token))%4),altchars=b'-_',validate=True))
        cfg=value['s']
        if value['v']!=2 or not isinstance(cfg,list) or len(cfg) not in (6,7) or cfg[5] not in (0,1) or not isinstance(cfg[3],str) or any(p not in 'tu' for p in cfg[3]):
            raise ValueError()
        bundle=client_bundle({'format':'knock-control-client-v2','server_url':value['u'],
            'server_certificate_sha256':value['f'],'profile_id':value['i'],'name':value['n'],
            'secret':value['k'],'knock_host':value['h'],'revision':value['r'],**({'ice_version':value['w']} if 'w' in value else {}),
            'settings':{'base':cfg[0],'ports':cfg[1],'idle_timeout':cfg[2],
                        'protocols':['tcp' if p=='t' else 'udp' for p in cfg[3]],
                        'seq_timeout':cfg[4],'ip_protection':bool(cfg[5]), **({'rules':cfg[6]} if len(cfg)==7 else {})}})
    except (ValueError,KeyError,TypeError,IndexError):
        raise ValueError('Invalid enrollment QR') from None
    if parsed.netloc!=urlsplit(bundle['server_url']).netloc:
        raise ValueError('QR destination differs from its profile server')
    return bundle


def png_bytes(matrix, scale=6, border=4):
    size=(matrix.get_size()+border*2)*scale
    rows=[]
    for y in range(size):
        row=bytes(0 if matrix.get_module(x//scale-border,y//scale-border) else 255 for x in range(size))
        rows.append(b'\x00'+row)
    def chunk(kind,data):
        return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',size,size,8,0,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows),9))+chunk(b'IEND',b'')


def write_qr(bundle, path):
    from vendor.qrcodegen import QrCode
    matrix=QrCode.encode_text(enrollment_url(bundle),QrCode.Ecc.MEDIUM)
    path=Path(path)
    if path.suffix.lower()=='.png':
        data=png_bytes(matrix)
    elif path.suffix.lower()=='.svg':
        size=matrix.get_size()+8
        modules=' '.join(f'M{x+4},{y+4}h1v1h-1z' for y in range(matrix.get_size()) for x in range(matrix.get_size()) if matrix.get_module(x,y))
        data=(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size*6}" height="{size*6}"><rect width="100%" height="100%" fill="white"/><path d="{modules}" fill="black"/></svg>').encode()
    else:
        raise ValueError('QR output must be .png or .svg')
    from common import atomic_write_bytes
    atomic_write_bytes(path,data)


def terminal_qr(bundle):
    from vendor.qrcodegen import QrCode
    matrix=QrCode.encode_text(enrollment_url(bundle),QrCode.Ecc.MEDIUM)
    size=matrix.get_size()+8
    chars={(False,False):' ',(True,False):'▀',(False,True):'▄',(True,True):'█'}
    lines=[]
    for y in range(0,size,2):
        lines.append(''.join(chars[(matrix.get_module(x-4,y-4),matrix.get_module(x-4,y-3))] for x in range(size)))
    # Explicit black/white makes the terminal QR independent of its color theme.
    return '\x1b[30;47m'+'\n'.join(lines)+'\x1b[0m\n'
