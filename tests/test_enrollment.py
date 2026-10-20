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
    def test_tls_rotation_validates_pair_pins_leaf_and_rolls_back_failed_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            with patch.multiple(server,CONFIG=folder/'settings.json',DAEMON_CONFIG=folder/'knockd.conf',CERT=folder/'server.crt',KEY=folder/'server.key'):
                db=server.init_server('127.0.0.1','lo',8443,'127.0.0.1')
                old_cert=server.CERT.read_text();old_db=server.CONFIG.read_text()
                fresh_cert=folder/'fresh.crt';fresh_key=folder/'fresh.key'
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(fresh_key),'-out',str(fresh_cert),'-days','1','-subj','/CN=127.0.0.1'],capture_output=True,check=True)
                leaf=fresh_cert.read_text()
                with self.assertRaises(ssl.SSLError):server.install_tls(db,fresh_cert,server.KEY)
                self.assertEqual(server.CERT.read_text(),old_cert);self.assertEqual(server.CONFIG.read_text(),old_db)
                fresh_cert.write_text(leaf+old_cert)
                with patch.object(server,'run') as run:
                    server.install_tls(db,fresh_cert,fresh_key)
                    run.assert_called_once_with(['/usr/bin/systemctl','restart','knock-control-api.service'])
                self.assertEqual(db['certificate_sha256'],hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf)).hexdigest())
                self.assertEqual(stat.S_IMODE(server.KEY.stat().st_mode),0o600)
                saved_cert=server.CERT.read_bytes();saved_key=server.KEY.read_bytes();saved_db=server.CONFIG.read_bytes()
                with patch.object(server,'run',side_effect=[subprocess.CalledProcessError(1,['systemctl']),None]),self.assertRaises(subprocess.CalledProcessError):
                    server.install_tls(db,fresh_cert,fresh_key)
                self.assertEqual(server.CERT.read_bytes(),saved_cert);self.assertEqual(server.KEY.read_bytes(),saved_key);self.assertEqual(server.CONFIG.read_bytes(),saved_db)

    def test_full_profile_round_trip_unicode_and_native_import(self):
        db,a,_=database();db['profiles'][a]['name']='Alice phone Ω'
        bundle=server.export_bundle(db,a)
        text=qr_codec.enrollment_url(bundle)
        restored=qr_codec.decode_enrollment(text)
        for key in ('server_url','server_certificate_sha256','profile_id','name','secret','knock_host','revision'):
            self.assertEqual(restored[key],bundle[key])
        for key in ('base','ports','protocols','ip_protection','seq_timeout','idle_timeout'):
            self.assertEqual(restored['settings'][key],bundle['settings'][key])
        self.assertNotIn(bundle['secret'],text.split('#')[0])
        with tempfile.TemporaryDirectory() as tmp,patch.object(native,'STORE',Path(tmp)/'native.json'):
            native.dispatch({'action':'import','bundle':text})
            self.assertEqual(native.dispatch({'action':'load'})['profile']['profile_id'],a)
        self.assertEqual(qr_codec.decode_enrollment(json.dumps(bundle))['secret'],bundle['secret'])

    def test_wrong_destination_and_non_enrollment_are_rejected(self):
        db,a,_=database();text=qr_codec.enrollment_url(server.export_bundle(db,a))
        for bad in ('otpauth://totp/foo?secret=ABC',text.replace('https://localhost:8443/','https://example.com/'),text+'!',text.replace('kc2_','kc3_')):
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

    def test_browser_proof_binds_profile_action_address_sequence_and_time(self):
        db,a,b=database();cfg=server.config_for(db,db['profiles'][a]);now=int(time.time());source='192.0.2.7'
        proof=common.confirmation(cfg,'open',source,now=now)
        request={'action':'browser-open','confirmation':base64.b64encode(proof).decode(),
                 'sequence':[list(item) for item in common.sequence(cfg,'open',source,now=now)]}
        with tempfile.TemporaryDirectory() as tmp,patch.object(server,'REPLAYS',Path(tmp)/'replays.sqlite'),patch.object(server,'load',return_value=db),patch.object(server,'access') as access,patch.object(server,'active',return_value=True):
            for bad,ident,address in (({**request,'action':'browser-close'},a,source),
                    (request,b,source),(request,a,'192.0.2.8'),({**request,'sequence':request['sequence'][:-1]},a,source),
                    ({**request,'confirmation':base64.b64encode(common.confirmation(cfg,'open',source,now=now-120)).decode()},a,source)):
                with self.assertRaises(ValueError):server.dispatch(bad,ident,address)
            access.assert_not_called()
            result=server.dispatch(request,a,source)
            self.assertEqual(result['profile_id'],a)
            access.assert_called_once_with('access-open',a,server.credential_tag(db['profiles'][a]),source)
            with self.assertRaises(ValueError):server.dispatch(request,a,source)
            access.reset_mock();db['profiles'][a]['policy']['allow_browser_transport']=False
            with self.assertRaises(ValueError):server.dispatch(request,a,source)
            access.assert_not_called()
