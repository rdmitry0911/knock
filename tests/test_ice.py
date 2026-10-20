import base64
import copy
import json
import secrets
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import common
import server
from test_controller import database,ROOT


class IceTests(unittest.TestCase):
    def test_browser_python_token_compatibility_and_binding(self):
        db,ident,_=database();bundle=server.export_bundle(db,ident);now=1700000000;source='192.0.2.7'
        token=common.ice_token(bundle,'open',source,now=now,nonce='00'*16)
        codec='data:text/javascript;base64,'+base64.b64encode((ROOT/'extension/profile-codec.js').read_bytes()).decode()
        js_source=(ROOT/'extension/browser-client.js').read_text().replace("'./profile-codec.js'",json.dumps(codec))
        module='data:text/javascript;base64,'+base64.b64encode(js_source.encode()).decode()
        script='import {webcrypto} from "node:crypto";globalThis.crypto=webcrypto;const {makeIceToken}=await import('+json.dumps(module)+');let s="";for await(const c of process.stdin)s+=c;const b=JSON.parse(s);process.stdout.write(await makeIceToken(b,"open","192.0.2.7",1700000000000,new Uint8Array(16)));'
        result=subprocess.run(['node','--input-type=module','-e',script],input=json.dumps(bundle),text=True,capture_output=True,check=True).stdout
        self.assertEqual(result,token);self.assertEqual(len(token),165)
        self.assertEqual(common.verify_ice_token(bundle,token,source,now=now)[0],'open')
        for modified,ip,at,profile in ((token,'192.0.2.8',now,bundle),(token,source,now+90,bundle),
            (token[:28]+'C'+token[29:],source,now,bundle),(token,source,now,{**bundle,'revision':2}),
            (token[:-1]+('0' if token[-1]!='0' else '1'),source,now,bundle)):
            with self.assertRaises(ValueError):common.verify_ice_token(profile,modified,ip,now=at)

    def test_durable_replay_and_command_order_per_source(self):
        db,ident,_=database();bundle=server.export_bundle(db,ident);now=time.time();tag=server.credential_tag(db['profiles'][ident])
        with tempfile.TemporaryDirectory() as tmp,patch.object(server,'load',return_value=db),patch.object(server,'REPLAYS',Path(tmp)/'replay.db'),patch.object(server,'access') as access:
            on=common.ice_token(bundle,'open','192.0.2.1',now=now,issued_ms=int(now*1000)-10)
            off=common.ice_token(bundle,'close','192.0.2.1',now=now,issued_ms=int(now*1000))
            late=common.ice_token(bundle,'open','192.0.2.1',now=now,issued_ms=int(now*1000)-5)
            server.access_ice(ident,tag,'192.0.2.1',on);server.access_ice(ident,tag,'192.0.2.1',off)
            for token in (on,off,late):
                with self.assertRaises(ValueError):server.access_ice(ident,tag,'192.0.2.1',token)
            self.assertEqual(access.call_count,2)
            # Each invocation opens a fresh SQLite connection, just like a daemon restart.
            second=common.ice_token(bundle,'open','192.0.2.2',now=now,issued_ms=int(now*1000)-5)
            server.access_ice(ident,tag,'192.0.2.2',second)
            self.assertEqual(access.call_count,3)
            db['profiles'][ident]['policy']['allow_browser_transport']=False
            with self.assertRaises(ValueError):server.access_ice(ident,tag,'192.0.2.2',second)
