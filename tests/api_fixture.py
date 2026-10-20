#!/usr/bin/python3
"""Unprivileged HTTPS fixture for browser tests. Firewall/systemd are stubs."""
import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'controller'))
import api
import common
import server
import qr_codec

parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);args=parser.parse_args()
tmp=args.directory;tmp.mkdir(parents=True,exist_ok=True)
server.CONFIG=tmp/'settings.json';server.DAEMON_CONFIG=tmp/'knockd.conf';server.LOCK=tmp/'lock'
server.CERT=tmp/'server.crt';server.KEY=tmp/'server.key';server.REPLAYS=tmp/'replays.sqlite'
with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
db=server.init_server('127.0.0.1','lo',port,'127.0.0.1')
a=server.issue(db,'Alice',[23456],[23456,23458],10,60)
b=server.issue(db,'Bob',[23457],[23457],20,120)
db['rules']={'ping':{'type':'input','protocol':'icmp'},
             'udp_range':{'type':'input','protocol':'udp','ports':['31000-31002']}}
phone=server.issue(db,'Rules',[],[],10,60,rules=['ping'],allowed_rules=['ping','udp_range'])
db['activated']=True
def legacy_bundle(database,ident):
    bundle=server.export_bundle(database,ident);bundle.pop('ice_version',None);return bundle
common.atomic_write(server.CONFIG,json.dumps(db))
common.atomic_write(tmp/'alice.json',json.dumps(legacy_bundle(db,a)))
common.atomic_write(tmp/'bob.json',json.dumps(legacy_bundle(db,b)))
common.atomic_write(tmp/'rules.json',json.dumps(legacy_bundle(db,phone)))
qr_codec.write_qr(legacy_bundle(db,phone),tmp/'rules.png')
qr_codec.write_qr(legacy_bundle(db,a),tmp/'alice.png')
qr_codec.write_qr(legacy_bundle(db,b),tmp/'bob.png')
common.atomic_write(tmp/'alice-url.txt',qr_codec.enrollment_url(legacy_bundle(db,a)))
api.APP_ROOT=ROOT/'dist/web-app'
# Functional UI suites use many browser contexts behind one loopback IP.
api.APIServer.allow=lambda self,address: True
original_run=server.run
grants=set()

def run(command,**kwargs):
    if command[0]=='/usr/local/sbin/knockd':return original_run([str(ROOT/'knockd'),*command[1:]],**kwargs)
    code=0
    if command[0]==server.IPSET:
        if command[1]=='add':grants.add(tuple(command[2:4]))
        elif command[1]=='del':grants.discard(tuple(command[2:4]))
        elif command[1]=='test':code=0 if tuple(command[2:4]) in grants else 1
        elif command[1]=='flush':grants.difference_update({grant for grant in grants if grant[0]==command[2]})
    return subprocess.CompletedProcess(command,code,'','')
server.run=run
tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(server.CERT,server.KEY)
with api.APIServer(('127.0.0.1',port),tls) as endpoint:
    common.atomic_write(tmp/'ready.json',json.dumps({'port':port}))
    endpoint.serve_forever()
