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
    def test_split_address_token_matches_browser_and_authenticates_target(self):
        db,ident,_=database();bundle=server.export_bundle(db,ident);now=1700000000
        token=common.ice_token(bundle,'open','192.0.2.7',target='198.51.100.9',now=now,nonce='00'*16)
        codec='data:text/javascript;base64,'+base64.b64encode((ROOT/'extension/profile-codec.js').read_bytes()).decode()
        client='data:text/javascript;base64,'+base64.b64encode((ROOT/'extension/browser-client.js').read_text().replace("'./profile-codec.js'",json.dumps(codec)).encode()).decode()
        ice='data:text/javascript;base64,'+base64.b64encode((ROOT/'extension/ice-client.js').read_bytes()).decode()
        script='import {webcrypto} from "node:crypto";globalThis.crypto=webcrypto;const {makeIceToken}=await import('+json.dumps(client)+');const {tcpProofPorts}=await import('+json.dumps(ice)+');let s="";for await(const c of process.stdin)s+=c;const b=JSON.parse(s),token=await makeIceToken(b,"open","192.0.2.7",1700000000000,new Uint8Array(16),1700000000000,"198.51.100.9");process.stdout.write(JSON.stringify({token,ports:tcpProofPorts(token,b.settings.base)}));'
        result=json.loads(subprocess.run(['node','--input-type=module','-e',script],input=json.dumps(bundle),text=True,capture_output=True,check=True).stdout)
        self.assertEqual(result['token'],token);self.assertEqual(len(token),165)
        self.assertEqual(result['ports'],common.ice_proof_ports(token,bundle['settings']['base']))
        self.assertEqual(len(set(result['ports'])),6)
        self.assertEqual(common.ice_target(token,'192.0.2.7'),'198.51.100.9')
        self.assertEqual(common.verify_ice_token(bundle,token,'192.0.2.7',now=now)[0],'open')
        for bad,source in ((token,'192.0.2.8'),(token[:45]+'c633640a'+token[53:],'192.0.2.7')):
            with self.assertRaises(ValueError):common.verify_ice_token(bundle,bad,source,now=now)
        for target in ('0.0.0.0','224.0.0.1','255.255.255.255'):
            with self.assertRaises(ValueError):common.ice_token(bundle,'open','192.0.2.7',target=target)

    def test_split_commands_are_ordered_by_access_ip_across_udp_changes(self):
        db,ident,_=database();bundle=server.export_bundle(db,ident);now=time.time();stamp=int(now*1000);tag=server.credential_tag(db['profiles'][ident])
        with tempfile.TemporaryDirectory() as temporary,patch.object(server,'load',return_value=db),patch.object(server,'REPLAYS',Path(temporary)/'replay.db'),patch.object(server,'access') as access:
            def send(source,target,action,issued):
                token=common.ice_token(bundle,action,source,target=target,now=now,issued_ms=issued)
                server.access_ice(ident,tag,source,token)
            send('192.0.2.1','198.51.100.8','open',stamp-2)
            send('192.0.2.2','198.51.100.8','close',stamp)
            with self.assertRaises(ValueError):send('192.0.2.1','198.51.100.8','open',stamp-1)
            send('192.0.2.1','198.51.100.9','open',stamp-1)
            self.assertEqual([call.args[-1] for call in access.call_args_list],['198.51.100.8','198.51.100.8','198.51.100.9'])

    def test_queued_command_keeps_requested_profile_when_selection_changes(self):
        db,alice,bob=database()
        bundles=[server.export_bundle(db,ident) for ident in (alice,bob)]
        codec='data:text/javascript;base64,'+base64.b64encode((ROOT/'extension/profile-codec.js').read_bytes()).decode()
        source=(ROOT/'extension/browser-client.js').read_text().replace("'./profile-codec.js'",json.dumps(codec))
        module='data:text/javascript;base64,'+base64.b64encode(source.encode()).decode()
        script='''import {webcrypto} from 'node:crypto';globalThis.crypto=webcrypto;
const {dispatch}=await import(MODULE);
let input='';for await(const chunk of process.stdin)input+=chunk;
const [alice,bob]=JSON.parse(input),store=new Map();
globalThis.localStorage={getItem:key=>store.get(key),setItem:(key,value)=>store.set(key,value)};

await dispatch({action:'import',bundle:alice});const a=await dispatch({action:'load'});
await dispatch({action:'import',bundle:bob});const b=await dispatch({action:'load'});
const pinned=await dispatch({action:'load',key:a.active});
const proof=await dispatch({action:'ice-proof',key:a.active,operation:'open',source:'192.0.2.7'});
const current=await dispatch({action:'load'}),updated=await dispatch({action:'load',key:a.active});
process.stdout.write(JSON.stringify({token:proof.token,pinned:pinned.profile.profile_id,
current:current.profile.profile_id,activeUnchanged:current.active===b.active,
aliceUpdated:updated.profile.last_ice_ms>0,bobUntouched:!current.profile.last_ice_ms}));
'''.replace('MODULE',json.dumps(module))
        result=json.loads(subprocess.run(['node','--input-type=module','-e',script],input=json.dumps(bundles),text=True,capture_output=True,check=True).stdout)
        self.assertEqual(result['pinned'],alice)
        self.assertEqual(result['current'],bob)
        self.assertTrue(result['activeUnchanged'] and result['aliceUpdated'] and result['bobUntouched'])
        self.assertEqual(common.verify_ice_token(bundles[0],result['token'],'192.0.2.7')[0],'open')
        with self.assertRaises(ValueError):common.verify_ice_token(bundles[1],result['token'],'192.0.2.7')

    def test_profile_deletion_is_local_and_removed_profile_cannot_sign(self):
        db,alice,bob=database();bundles=[server.export_bundle(db,i) for i in (alice,bob)]
        codec='data:text/javascript;base64,'+base64.b64encode((ROOT/'extension/profile-codec.js').read_bytes()).decode()
        source=(ROOT/'extension/browser-client.js').read_text().replace("'./profile-codec.js'",json.dumps(codec))
        module='data:text/javascript;base64,'+base64.b64encode(source.encode()).decode()
        script='''import {webcrypto} from 'node:crypto';globalThis.crypto=webcrypto;
const {dispatch}=await import(MODULE);let input='';for await(const c of process.stdin)input+=c;
const [alice,bob]=JSON.parse(input),store=new Map();let network=0;
globalThis.fetch=()=>{network++;throw new Error('Network must not be used');};
globalThis.localStorage={getItem:k=>store.get(k),setItem:(k,v)=>store.set(k,v)};
await dispatch({action:'import',bundle:alice});const a=await dispatch({action:'load'});
await dispatch({action:'import',bundle:bob});const b=await dispatch({action:'load'});
// Re-importing a v2 copy replaces the same profile instead of duplicating it.
await dispatch({action:'import',bundle:{...alice,format:'knock-control-client-v2',server_url:'https://127.0.0.1:8443',server_certificate_sha256:'a'.repeat(64)}});
if((await dispatch({action:'load'})).profiles.length!==2)throw new Error('Duplicate legacy profile');
await dispatch({action:'select',key:b.active});await dispatch({action:'remove',key:a.active});
const remaining=await dispatch({action:'load'});let rejected=0;
for(const request of [{action:'ice-proof',key:a.active,operation:'open',source:'192.0.2.7'},{action:'status'},{action:'configure',settings:{}},{action:'save-transport',connection:{}}]){
try{await dispatch(request);}catch{rejected++;}}
await dispatch({action:'remove',key:b.active});const empty=await dispatch({action:'load'});
process.stdout.write(JSON.stringify({network,rejected,remaining:remaining.profile.profile_id,active:empty.active,count:empty.profiles.length,profile:empty.profile}));
'''.replace('MODULE',json.dumps(module))
        result=json.loads(subprocess.run(['node','--input-type=module','-e',script],input=json.dumps(bundles),text=True,capture_output=True,check=True).stdout)
        self.assertEqual(result,{'network':0,'rejected':4,'remaining':bob,'active':None,'count':0,'profile':None})

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
