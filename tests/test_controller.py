import base64
import copy
import io
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
import common
import native
import server
import api

CFG=common.settings({'secret':'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'})


def database():
    db={'schema':2,'activated':True,'interface':'lo','api_port':8443,'api_bind':'127.0.0.1',
        'server_url':'https://localhost:8443','knock_host':'127.0.0.1','certificate_sha256':'a'*64,
        'protected_ports':[],'profiles':{}}
    alice=server.issue(db,'Alice',[23456],[23456,23458],10,60)
    bob=server.issue(db,'Bob',[23457],[23457],20,120)
    return db,alice,bob


class ControllerTests(unittest.TestCase):
    def test_rfc_totp_and_distinct_profile_domains(self):
        self.assertEqual(common.totp(CFG['secret'],59),'287082')
        db,a,b=database()
        ca=server.config_for(db,db['profiles'][a]);cb={**ca,'profile_id':b}
        self.assertNotEqual(common.sequence(ca,'open','192.0.2.1',now=1700000000),common.sequence(cb,'open','192.0.2.1',now=1700000000))
        self.assertNotEqual(common.confirmation(ca,'open','192.0.2.1',now=1700000000,nonce=bytes(16)),common.confirmation(cb,'open','192.0.2.1',now=1700000000,nonce=bytes(16)))
        with self.assertRaises(ValueError):common.confirmation(CFG,'open','192.0.2.1',now=1700000000,code='000000')

    def test_server_generates_distinct_base32_credentials_and_ranges(self):
        db,a,b=database()
        self.assertNotEqual(db['profiles'][a]['secret'],db['profiles'][b]['secret'])
        self.assertEqual(len(base64.b32decode(db['profiles'][a]['secret'])),20)
        self.assertNotEqual(db['profiles'][a]['settings']['base'],db['profiles'][b]['settings']['base'])
        with self.assertRaises(ValueError): server.issue(db,'Bad',[8443],[8443])
        with self.assertRaises(ValueError): server.issue(db,'Bad',[db['profiles'][a]['settings']['base']],[db['profiles'][a]['settings']['base']])

    def test_validation_rejects_invalid_client_and_settings(self):
        db,a,_=database();bundle=server.export_bundle(db,a)
        for key,value in [('secret','bad'),('server_url','http://localhost'),('profile_id','../root'),('server_certificate_sha256',''),('settings',None)]:
            with self.subTest(key=key),self.assertRaises(ValueError):common.client_bundle({**bundle,key:value})
        for key,value in [('idle_timeout',True),('base',65535),('protocols',['icmp']),('ports',[22,'80'])]:
            with self.subTest(key=key),self.assertRaises(ValueError):common.settings({**CFG,key:value})

    def test_import_multiple_profiles_select_and_never_return_secret(self):
        db,a,b=database()
        with tempfile.TemporaryDirectory() as tmp,patch.object(native,'STORE',Path(tmp)/'profiles.json'):
            native.dispatch({'action':'import','bundle':server.export_bundle(db,a)})
            first=native.key_for(server.export_bundle(db,a))
            native.dispatch({'action':'import','bundle':server.export_bundle(db,b)})
            self.assertEqual(len(native.dispatch({'action':'load'})['profiles']),2)
            native.dispatch({'action':'select','key':first})
            result=native.dispatch({'action':'load'})
            self.assertEqual(result['profile']['profile_id'],a)
            self.assertNotIn(db['profiles'][a]['secret'],json.dumps(result))
            self.assertEqual(stat.S_IMODE(native.STORE.stat().st_mode),0o600)
            with self.assertRaises(ValueError):native.dispatch({'action':'generate'})
            with self.assertRaises(ValueError):native.dispatch({'action':'stop'})

    def test_profile_policy_and_identity_cannot_be_overridden(self):
        db,a,b=database()
        with patch.object(server,'load',return_value=copy.deepcopy(db)),patch.object(server,'publish') as publish:
            for request in ({'action':'configure','revision':1,'settings':{'ports':[22]}},
                            {'action':'configure','revision':1,'settings':{'idle_timeout':61}},
                            {'action':'configure','revision':1,'settings':{'secret':'A'*32}},
                            {'action':'configure','revision':1,'settings':{'profile_id':b}},
                            {'action':'status','profile_id':b}, {'action':'stop'}, {'action':'disable'}):
                with self.subTest(request=request),self.assertRaises(ValueError):server.dispatch(request,a)
            publish.assert_not_called()

    def test_change_only_own_profile_and_reject_stale_revision(self):
        db,a,b=database();bob=copy.deepcopy(db['profiles'][b])
        with patch.object(server,'load',return_value=db),patch.object(server,'publish') as publish,patch.object(server,'active',return_value=True):
            result=server.dispatch({'action':'configure','revision':1,'settings':{'ports':[23458],'idle_timeout':30}},a)
            self.assertEqual(result['revision'],2)
            self.assertEqual(db['profiles'][b],bob)
            self.assertEqual(publish.call_args.args[1],[a])
            with self.assertRaises(ValueError):server.dispatch({'action':'configure','revision':1,'settings':{'idle_timeout':20}},a)
            self.assertNotIn('secret',result['settings'])

    def test_fixed_settings_policy(self):
        db,a,_=database();db['profiles'][a]['policy']['can_configure']=False
        with patch.object(server,'load',return_value=db),self.assertRaises(ValueError):server.dispatch({'action':'configure','revision':1,'settings':{'idle_timeout':20}},a)

    def test_auth_signature_replay_persists_and_cross_profile_rejected(self):
        db,a,b=database();body=b'{"action":"status"}';timestamp=str(int(time.time()));nonce=secrets.token_hex(16)
        signature=common.api_signature(db['profiles'][a]['secret'],timestamp,nonce,body)
        header=f'Knock {a}:{timestamp}:{nonce}:{signature}'
        with tempfile.TemporaryDirectory() as tmp,patch.object(server,'REPLAYS',Path(tmp)/'replays.sqlite'),patch.object(server,'load',return_value=db):
            self.assertEqual(server.authenticate(header,body),a)
            with self.assertRaises(ValueError):server.authenticate(header,body)
            with self.assertRaises(ValueError):server.authenticate(header.replace(a,b),body)
            with self.assertRaises(ValueError):server.authenticate(header,body+b' ')
            db['profiles'][a]['revoked']=True
            with self.assertRaises(ValueError):server.authenticate(header,body)

    def test_firewall_has_independent_sets_and_real_activity_refresh(self):
        db,a,b=database()
        with patch.object(server,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
            server.firewall(db)
        text=next(call.kwargs['text'] for call in run.call_args_list if call.args[0][0]==server.RESTORE)
        self.assertIn('--noflush',next(call.args[0] for call in run.call_args_list if call.args[0][0]==server.RESTORE))
        for ident in (a,b):self.assertIn(server.set_name(ident),text)
        self.assertIn('--ctstate ESTABLISHED',text)
        self.assertIn('--add-set '+server.set_name(a)+' src --exist --timeout 10',text)
        self.assertIn('--add-set '+server.set_name(a)+' dst --exist --timeout 10',text)
        self.assertLess(text.index('-j ACCEPT'),text.index('-j DROP'))
        self.assertNotIn('--ctstate ESTABLISHED,RELATED -j RETURN',text)
        db['profiles'][a]['revoked']=True
        with patch.object(server,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:server.firewall(db)
        text=next(call.kwargs['text'] for call in run.call_args_list if call.args[0][0]==server.RESTORE)
        self.assertNotIn('--match-set '+server.set_name(a),text)
        self.assertIn('23456',text)  # revoked ports remain protected
        self.assertIn('--match-set '+server.set_name(b),text)

    def test_access_uses_only_own_set_and_rejects_stale_or_revoked_key(self):
        db,a,b=database();tag=server.credential_tag(db['profiles'][a])
        with patch.object(server,'load',return_value=db),patch.object(server,'run') as run:
            server.access('access-open',a,tag,'192.0.2.1')
            self.assertEqual(run.call_args.args[0],[server.IPSET,'add',server.set_name(a),'192.0.2.1','timeout','10','-exist'])
            server.access('access-close',a,tag,'192.0.2.1')
            self.assertEqual(run.call_args.args[0][2],server.set_name(a))
            with self.assertRaises(ValueError):server.access('access-open',a,'0'*16,'192.0.2.1')
            with self.assertRaises(ValueError):server.access('access-open',b,tag,'192.0.2.1')
            db['profiles'][a]['revoked']=True
            with self.assertRaises(ValueError):server.access('access-open',a,tag,'192.0.2.1')

    def test_generated_multi_profile_config_validates_with_daemon(self):
        db,a,b=database()
        with tempfile.NamedTemporaryFile(mode='w') as config:
            config.write(server.render(db));config.flush()
            subprocess.run([str(ROOT/'knockd'),'--check','--config',config.name],check=True)
        self.assertIn('['+a+'.open]',server.render(db));self.assertIn('['+b+'.close]',server.render(db))

    def test_publish_preserves_other_grants_and_hot_reloads(self):
        db,a,b=database()
        with tempfile.TemporaryDirectory() as tmp,patch.object(server,'CONFIG',Path(tmp)/'settings.json'),patch.object(server,'DAEMON_CONFIG',Path(tmp)/'knockd.conf'),patch.object(server,'active',return_value=True),patch.object(server,'firewall'),patch.object(server,'run',return_value=subprocess.CompletedProcess([],0,'','')) as run:
            common.atomic_write(server.CONFIG,json.dumps(db));common.atomic_write(server.DAEMON_CONFIG,server.render(db))
            server.publish(db,[a])
            commands=[call.args[0] for call in run.call_args_list]
            self.assertIn([server.IPSET,'flush',server.set_name(a)],commands)
            self.assertNotIn([server.IPSET,'flush',server.set_name(b)],commands)
            self.assertIn(['/usr/bin/systemctl','reload',server.SERVICE],commands)
            self.assertFalse(any('stop' in command for command in commands))

    def test_publish_failure_restores_database_and_rules(self):
        db,a,b=database();updated=copy.deepcopy(db);updated['profiles'][a]['settings']['idle_timeout']=30
        with tempfile.TemporaryDirectory() as tmp,patch.object(server,'CONFIG',Path(tmp)/'settings.json'),patch.object(server,'DAEMON_CONFIG',Path(tmp)/'knockd.conf'),patch.object(server,'active',return_value=True),patch.object(server,'firewall') as fw:
            common.atomic_write(server.CONFIG,json.dumps(db));common.atomic_write(server.DAEMON_CONFIG,server.render(db))
            failed=[False]
            def run(args,**kw):
                if 'reload' in args and not failed[0]:failed[0]=True;raise ValueError('reload failed')
                return subprocess.CompletedProcess(args,0,'','')
            with patch.object(server,'run',side_effect=run),self.assertRaises(ValueError):server.publish(updated,[a])
            self.assertEqual(common.read_json(server.CONFIG),db)
            self.assertEqual(fw.call_args.args[0],db)

    def test_native_frames_and_limits(self):
        body=json.dumps({'action':'load'}).encode();frame=struct.pack('=I',len(body))+body
        with tempfile.TemporaryDirectory() as home:
            env={**os.environ,'HOME':home}
            result=subprocess.run([sys.executable,str(ROOT/'controller/native.py')],input=frame*2,capture_output=True,env=env,check=True)
            stream=io.BytesIO(result.stdout)
            for _ in range(2):
                size=struct.unpack('=I',stream.read(4))[0]
                self.assertEqual(json.loads(stream.read(size))['profile'],None)
            for data in (struct.pack('=I',99999999),b'\x01\x00',struct.pack('=I',20)+b'{}'):
                self.assertEqual(subprocess.run([sys.executable,str(ROOT/'controller/native.py')],input=data,capture_output=True,env=env,check=True).stdout,b'')

    def test_https_real_tls_pin_authentication_and_own_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            with patch.multiple(server,CONFIG=folder/'settings.json',DAEMON_CONFIG=folder/'knockd.conf',CERT=folder/'server.crt',KEY=folder/'server.key',LOCK=folder/'lock',REPLAYS=folder/'replays.sqlite'):
                with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
                db=server.init_server('127.0.0.1','lo',port,'127.0.0.1')
                a=server.issue(db,'Alice',[23456],[23456,23458],10,60);b=server.issue(db,'Bob',[23457],[23457],20,120)
                common.atomic_write(server.CONFIG,json.dumps(db))
                tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(server.CERT,server.KEY)
                endpoint=api.APIServer(('127.0.0.1',port),tls)
                thread=threading.Thread(target=endpoint.serve_forever,daemon=True);thread.start()
                def run(args,**kw):
                    if args[0]=='/usr/local/sbin/knockd':return subprocess.run([str(ROOT/'knockd'),*args[1:]],capture_output=True,text=True,check=True)
                    return subprocess.CompletedProcess(args,0,'','')
                try:
                    with patch.object(server,'run',side_effect=run):
                        ca=common.client_bundle(server.export_bundle(db,a));cb=common.client_bundle(server.export_bundle(db,b))
                        result=native.remote(ca,'status');self.assertEqual(result['profile_id'],a);self.assertNotIn('secret',json.dumps(result))
                        self.assertNotIn(b,json.dumps(result));self.assertEqual(result['observed_ip'],'127.0.0.1')
                        with self.assertRaises(ValueError):native.remote({**ca,'server_certificate_sha256':'0'*64},'status')
                        with self.assertRaises(ValueError):native.remote({**ca,'profile_id':b},'status')
                        result=native.remote(ca,'configure',{'idle_timeout':30});self.assertEqual(result['settings']['idle_timeout'],30)
                        self.assertEqual(native.remote(cb,'status')['settings']['idle_timeout'],20)
                        with self.assertRaises(ValueError):native.remote(ca,'configure',{'ports':[22]})
                finally:
                    endpoint.shutdown();endpoint.server_close();thread.join(timeout=2)

if __name__=='__main__':unittest.main()
