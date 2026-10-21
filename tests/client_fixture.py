#!/usr/bin/python3
"""Standalone static client hosting for browser tests; no control API."""
import argparse
import json
from pathlib import Path
import sys
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'controller'))
import common,server,qr_codec
p=argparse.ArgumentParser();p.add_argument('directory',type=Path);args=p.parse_args();tmp=args.directory;tmp.mkdir(parents=True,exist_ok=True)
server.CONFIG=tmp/'settings.json';server.DAEMON_CONFIG=tmp/'knockd.conf'
db=server.init_server('127.0.0.1','lo')
for name,port in [('Alice',23456),('Bob',23457)]:
 ident=server.issue(db,name,[port],[port],10,60);bundle=server.export_bundle(db,ident)
 common.atomic_write(tmp/(name.lower()+'.json'),json.dumps(bundle));qr_codec.write_qr(bundle,tmp/(name.lower()+'.png'))
 common.atomic_write(tmp/(name.lower()+'-url.txt'),qr_codec.enrollment_url(bundle))
class Static(SimpleHTTPRequestHandler):
 def __init__(self,*a,**kw):super().__init__(*a,directory=str(ROOT/'dist/web-app'),**kw)
 def do_GET(self):
  if self.path=='/':self.path='/app.html'
  super().do_GET()
 def log_message(self,*a):pass
with ThreadingHTTPServer(('127.0.0.1',0),Static) as endpoint:
 common.atomic_write(tmp/'ready.json',json.dumps({'origin':'http://127.0.0.1:'+str(endpoint.server_port)}));endpoint.serve_forever()
