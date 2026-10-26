#!/usr/bin/python3
"""JSON RPC peer using the real Firefox MV2 extension (desktop engine)."""
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

ROOT=Path(__file__).resolve().parents[1]
config=json.loads(Path(sys.argv[1]).read_text());bundle=config['bundle']
UUID='22222222-2222-4222-8222-222222222222'
with tempfile.TemporaryDirectory(prefix='ice-firefox-driver-') as temporary:
    with socket.socket() as allocation:allocation.bind(('127.0.0.1',0));port=allocation.getsockname()[1]
    def request(method,path,data=None):
        q=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=None if data is None else json.dumps(data).encode(),method=method,headers={'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(q,timeout=30) as response:value=json.load(response)['value']
        except urllib.error.HTTPError as error:raise RuntimeError(error.read().decode()) from None
        if isinstance(value,dict) and value.get('error'):raise RuntimeError(str(value))
        return value
    with open(Path(temporary)/'driver.log','w') as log:
        process=subprocess.Popen([os.environ.get('GECKODRIVER','geckodriver'),'--port',str(port),'--allow-system-access'],stdout=log,stderr=log)
        session=None
        try:
            for _ in range(100):
                try:request('GET','/status');break
                except OSError:time.sleep(.05)
            options={'args':['-headless'],'prefs':{'extensions.webextensions.uuids':json.dumps({'knock-control-mobile@local':UUID})}}
            if os.environ.get('FIREFOX_BIN'):options['binary']=os.environ['FIREFOX_BIN']
            session=request('POST','/session',{'capabilities':{'alwaysMatch':{'browserName':'firefox','moz:firefoxOptions':options}}})['sessionId'];base='/session/'+session
            request('POST',base+'/moz/addon/install',{'path':str(ROOT/'dist/firefox-mobile'),'temporary':True})
            def evaluate(source):return request('POST',base+'/execute/sync',{'script':source,'args':[]})
            def message(text):
                for _ in range(260):
                    value=evaluate("return document.querySelector('#message')?.textContent??''")
                    if text in value:return value
                    time.sleep(.05)
                raise RuntimeError(value)
            def element(selector):return request('POST',base+'/element',{'using':'css selector','value':selector})['element-6066-11e4-a52e-4f735466cecf']
            request('POST',base+'/url',{'url':f'moz-extension://{UUID}/app.html'})
            message('Import a server-issued JSON profile')
            request('POST',base+'/element/'+element('#import-file')+'/value',{'text':config['bundle_file']})
            message('Profile imported')
            request('POST',base+'/execute/async',{'script':"""
              const done=arguments[arguments.length-1];
              const watch=owner=>{const original=owner.fetch.bind(owner);owner.fetch=(input,...args)=>{if(String(input?.url??input).includes('/v1/control'))owner.iceApiRequests=(owner.iceApiRequests??0)+1;return original(input,...args);};};
              browser.runtime.getBackgroundPage().then(bg=>{bg.iceApiRequests=0;watch(bg);done(true);});
            """,'args':[]})
            def api_count():return request('POST',base+'/execute/async',{'script':'const done=arguments[arguments.length-1];browser.runtime.getBackgroundPage().then(bg=>done(bg.iceApiRequests??0));','args':[]})
            print(json.dumps({'ready':True}),flush=True)
            for line in sys.stdin:
                q=json.loads(line)
                try:
                    if q['op'] in ('on','off','on-detached','off-detached'):
                        action='on' if q['op'].startswith('on') else 'off';request('POST',base+'/element/'+element('#open' if action=='on' else '#close')+'/click',{})
                        if q['op'].endswith('-detached'):
                            time.sleep(.1);request('POST',base+'/url',{'url':'about:blank'});time.sleep(8.5 if config.get('split') else 5.5);request('POST',base+'/url',{'url':f'moz-extension://{UUID}/popup.html'});message('Press ON')
                        else:message('knock '+('ON' if action=='on' else 'OFF')+' sent')
                        result={'sent':True,'apiRequests':api_count(),'errors':[],'debug':[]}
                    elif q['op']=='tcp':
                        try:
                            with socket.create_connection((bundle['knock_host'],config['service']),timeout=.5) as stream:
                                stream.sendall(b'ping');reachable=stream.recv(4)==b'ping'
                        except OSError:reachable=False
                        result={'reachable':reachable}
                    elif q['op']=='stop':print(json.dumps({'ok':True,'apiRequests':api_count(),'errors':[],'noise_packets':0}),flush=True);break
                    else:raise RuntimeError('Unsupported test operation')
                    print(json.dumps(result),flush=True)
                except Exception as error:
                    log.flush();shutil.copy2(Path(temporary)/'driver.log','/tmp/knock-ice-firefox-driver.log')
                    print(json.dumps({'error':str(error)}),flush=True)
        finally:
            log.flush();shutil.copy2(Path(temporary)/'driver.log','/tmp/knock-ice-firefox-driver.log')
            if session:
                try:request('DELETE','/session/'+session)
                except Exception:pass
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
