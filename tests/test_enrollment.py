import base64
import json
import hashlib
from pathlib import Path
import stat
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
import common
import native
import qr_codec
import server
from test_controller import database

class EnrollmentTests(unittest.TestCase):

    def test_initialization_and_export_need_no_tls_or_listener(self):
        with tempfile.TemporaryDirectory() as tmp,patch.multiple(server,CONFIG=Path(tmp)/'settings.json',DAEMON_CONFIG=Path(tmp)/'knockd.conf'),patch.object(server,'run') as run:
            db=server.init_server('127.0.0.1','lo');ident=server.issue(db,'Local',[8443],[8443])
            bundle=server.export_bundle(db,ident);run.assert_not_called()
            self.assertNotIn('api_port',db);self.assertNotIn('server_url',bundle);self.assertNotIn('server_certificate_sha256',bundle)
            self.assertEqual(bundle['format'],'knock-control-client-v3')
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()),['knockd.conf','settings.json'])

    def test_v2_json_and_qr_upgrade_without_https_dependency(self):
        db,ident,_=database();bundle=server.export_bundle(db,ident)
        legacy={**bundle,'format':'knock-control-client-v2','server_url':'https://example.org:8443','server_certificate_sha256':'a'*64,'transport':'https'}
        legacy.pop('ice_version')
        for invalid in (None,{},[]):
            with self.assertRaises(ValueError):common.client_bundle({**legacy,'server_url':invalid})
        self.assertEqual(common.client_bundle(legacy),common.client_bundle(bundle))
        cfg=bundle['settings'];compact={'v':2,'u':legacy['server_url'],'f':'a'*64,'i':ident,'n':bundle['name'],'k':bundle['secret'],'h':bundle['knock_host'],'r':bundle['revision'],'w':1,
            's':[cfg['base'],cfg['ports'],cfg['idle_timeout'],''.join('t' if p=='tcp' else 'u' for p in cfg['protocols']),cfg['seq_timeout'],int(cfg['ip_protection'])]}
        token=base64.urlsafe_b64encode(json.dumps(compact).encode()).decode().rstrip('=');url=legacy['server_url']+'/app/#import=kc2_'+token
        restored=qr_codec.decode_enrollment(url);self.assertEqual(restored['secret'],bundle['secret']);self.assertEqual(restored['format'],'knock-control-client-v3')
        with self.assertRaises(ValueError):qr_codec.decode_enrollment(url.replace('https://example.org:8443/','https://other.org/'))

    def test_full_profile_round_trip_unicode_and_native_import(self):
        db,a,_=database();db['profiles'][a]['name']='Alice phone Ω'
        bundle=server.export_bundle(db,a)
        text=qr_codec.enrollment_url(bundle)
        restored=qr_codec.decode_enrollment(text)
        for key in ('profile_id','name','secret','knock_host','revision','ice_host'):
            self.assertEqual(restored[key],bundle[key])
        for key in ('base','ports','protocols','ip_protection','seq_timeout','idle_timeout'):
            self.assertEqual(restored['settings'][key],bundle['settings'][key])
        self.assertNotIn(bundle['secret'],text.split('#')[0])
        self.assertEqual(qr_codec.decode_enrollment(json.dumps(bundle))['secret'],bundle['secret'])

    def test_wrong_destination_and_non_enrollment_are_rejected(self):
        db,a,_=database();text=qr_codec.enrollment_url(server.export_bundle(db,a))
        for bad in ('otpauth://totp/foo?secret=ABC',text.replace('knock-control://import/','knock-control://other/'),text+'!',text.replace('kc3_','kc2_')):
            with self.subTest(text=bad[:60]),self.assertRaises(ValueError):qr_codec.decode_enrollment(bad)

    def test_qr_images_are_private_offline_files(self):
        db,a,_=database();bundle=server.export_bundle(db,a)
        with tempfile.TemporaryDirectory() as tmp:
            for ext in ('png','svg'):
                path=Path(tmp)/('profile.'+ext);qr_codec.write_qr(bundle,path)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                if ext=='png':self.assertTrue(path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
                else:self.assertIn('<svg',path.read_text())
            with self.assertRaises(ValueError):qr_codec.write_qr(bundle,Path(tmp)/'bad.jpg')
