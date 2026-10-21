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

CFG=common.settings({'secret':'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'})


def database():
    db={'schema':2,'activated':True,'interface':'lo','knock_host':'127.0.0.1','protected_ports':[],'profiles':{}}
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
        self.assertIn(server.issue(db,'Service on old API port',[8443],[8443]),db['profiles'])
        with self.assertRaises(ValueError): server.issue(db,'Bad',[db['profiles'][a]['settings']['base']],[db['profiles'][a]['settings']['base']])

    def test_validation_rejects_invalid_client_and_settings(self):
        db,a,_=database();bundle=server.export_bundle(db,a)
        for key,value in [('secret','bad'),('knock_host','../bad'),('profile_id','../root'),('ice_host','not-an-ip'),('settings',None)]:
            with self.subTest(key=key),self.assertRaises(ValueError):common.client_bundle({**bundle,key:value})
        for key,value in [('idle_timeout',True),('base',65535),('protocols',['icmp']),('ports',[22,'80'])]:
            with self.subTest(key=key),self.assertRaises(ValueError):common.settings({**CFG,key:value})






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



if __name__=='__main__':unittest.main()
