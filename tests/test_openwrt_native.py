"""Optional host build tests for the OpenWrt C controller.

Run with KNOCK_NATIVE_UNIT=/path/to/compiled/openwrt_native_unit.
The standard Linux suite skips this when native OpenWrt dev libraries are absent.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'controller'))
import common
import qr_codec
import server

def decode_native_png(path):
    """Decode our grayscale PNG through the same offline jsQR used by clients."""
    image=Path(path).read_bytes();offset=8;compressed=bytearray();width=height=None
    assert image[:8]==b'\x89PNG\r\n\x1a\n'
    while offset<len(image):
        size=struct.unpack('>I',image[offset:offset+4])[0]
        kind=image[offset+4:offset+8];data=image[offset+8:offset+8+size]
        assert zlib.crc32(kind+data)&0xffffffff==struct.unpack('>I',image[offset+8+size:offset+12+size])[0]
        if kind==b'IHDR':
            width,height,depth,color,*_=struct.unpack('>IIBBBBB',data);assert depth==8 and color==0
        if kind==b'IDAT':compressed.extend(data)
        offset+=size+12
    raw=zlib.decompress(compressed);rgba=bytearray()
    for y in range(height):
        row=raw[y*(width+1):(y+1)*(width+1)];assert row[0]==0
        for pixel in row[1:]:rgba.extend((pixel,pixel,pixel,255))
    decoder=Path(__file__).resolve().parents[1]/'extension/vendor/jsQR.js'
    script='const fs=require("fs"),qr=require(process.argv[1]),p=JSON.parse(fs.readFileSync(0,"utf8")); const result=qr(new Uint8ClampedArray(Buffer.from(p.rgba,"base64")),p.width,p.height);if(!result)process.exit(1);process.stdout.write(result.data);'
    return subprocess.run([os.environ.get('NODE_BINARY','node'),'-e',script,str(decoder)],
        input=json.dumps({'width':width,'height':height,'rgba':base64.b64encode(rgba).decode()}),
        capture_output=True,text=True,check=True).stdout

@unittest.skipUnless(os.environ.get('KNOCK_NATIVE_UNIT'),'Set KNOCK_NATIVE_UNIT to the native test binary')
class NativeOpenWrt(unittest.TestCase):
    def test_python_protocol_and_database_compatibility(self):
        self.check_compatibility(False)

    def test_named_rules_uci_qr_and_protocol_compatibility(self):
        self.check_compatibility(True)

    def check_compatibility(self, named):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            db={'schema':2,'activated':True,'interface':'lo','api_bind':'127.0.0.1',
                'api_port':18443,'server_url':'https://example.org:18443','knock_host':'example.org',
                'certificate_sha256':'0'*64,'protected_ports':[],'profiles':{}}
            if named:
                db['rules']={
                    'ssh_lan':{'type':'dnat','protocol':'tcp','ports':['2222'],'dest_ip':'192.168.1.10','dest_port':22},
                    'udp_range':{'type':'input','protocol':'udp','ports':['30000-30003','5353']},
                    'ping':{'type':'input','protocol':'icmp','icmp_type':'echo-request'},
                    'routed':{'type':'forward','protocol':'udp','dest_ip':'192.168.1.20','ports':['9000-9010']}}
                ident=server.issue(db,"Phone ' Ω spare", [], [], 10, 60, rules=list(db['rules']))
            else:
                ident=server.issue(db,"Phone ' Ω spare", [23456], [23456,23457], 10, 60)
            profile=db['profiles'][ident];cfg=server.config_for(db,profile)
            ip='127.0.0.2';now=time.time();nonce=secrets.token_bytes(16)
            def request(config):return {'action':'browser-open',
                'sequence':[list(pair) for pair in common.sequence(config,'open',ip,now=now)],
                'confirmation':base64.b64encode(common.confirmation(config,'open',ip,now=now,nonce=nonce)).decode()}
            body=json.dumps(request(cfg),separators=(',',':'));stamp=str(int(now));api_nonce=secrets.token_hex(16)
            signature=common.api_signature(profile['secret'],stamp,api_nonce,body.encode())
            fixture={'db':db,'id':ident,'ip':ip,'body':body,
                'ice_token':common.ice_token(server.export_bundle(db,ident),'open',ip,now=now),
                'authorization':f'Knock {ident}:{stamp}:{api_nonce}:{signature}',
                'request':request(cfg),'request_no_ip':request({**cfg,'ip_protection':False}),
                'proof_nonce':nonce.hex()}
            (root/'fixture.json').write_text(json.dumps(fixture))
            subprocess.run([os.environ['KNOCK_NATIVE_UNIT'],directory,str(root/'fixture.json')],check=True)
            exported=json.loads((root/'profile.json').read_text())
            self.assertEqual(exported,server.export_bundle(db,ident))
            decoded=qr_codec.decode_enrollment((root/'enrollment.txt').read_text())
            expected=common.client_bundle(exported);expected['settings']['interface']='eth0'
            self.assertEqual(decoded,expected)
            self.assertEqual((root/'knockd.conf').read_text(),server.render(db).replace('/usr/local/sbin/knock-control','/usr/sbin/knock-control'))
            self.assertTrue((root/'profile.png').read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
            self.assertEqual(decode_native_png(root/'profile.png'),(root/'enrollment.txt').read_text())
            self.assertEqual((root/'profile.png').stat().st_mode&0o777,0o600)
            self.assertIn("config server 'main'",(root/'knock-control').read_text())
            self.assertEqual((root/'knock-control').stat().st_mode&0o777,0o600)
            self.assertFalse((root/'settings.json').exists())
            self.assertEqual(json.loads((root/'settings.json.pre-uci').read_text()),db)
            # Same schema and nonce rows can be used by either implementation.
            with sqlite3.connect(root/'api-replays.sqlite3') as connection:
                self.assertEqual(connection.execute('SELECT profile,nonce FROM nonces WHERE profile=?',(ident,)).fetchall(),[(ident,api_nonce)])
            if named:
                self.assertIn('ct original ip saddr @kc_'+ident,(root/'firewall.nft').read_text())
                self.assertIn("config rule 'ssh_lan'",(root/'knock-control').read_text())
            else:
                self.assertIn('ct state established ip saddr @kc_'+ident,(root/'firewall.nft').read_text())

if __name__=='__main__':unittest.main()
