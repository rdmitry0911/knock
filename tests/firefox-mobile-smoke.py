#!/usr/bin/python3
"""Real Firefox event-page profile management; no network permissions.
Uses the desktop engine, not an Android device. The test copy is pregranted
only the fixture origin; production obtains that permission on the ON click.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
ROOT=Path(__file__).resolve().parents[1]
UUID='22222222-2222-4222-8222-222222222222'

with tempfile.TemporaryDirectory(prefix='knock-firefox-mobile-') as directory:
    home=Path(directory);env={**os.environ,'HOME':str(home)}
    extension=home/'extension';shutil.copytree(ROOT/'dist/firefox-mobile',extension)
    fixture=subprocess.Popen(['/usr/bin/python3',str(ROOT/'tests/client_fixture.py'),str(home/'server')],env=env,stdout=subprocess.DEVNULL)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    def request(method,path,data=None):
        req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=None if data is None else json.dumps(data).encode(),method=method,headers={'Content-Type':'application/json'})
        try:response=urllib.request.urlopen(req,timeout=25)
        except urllib.error.HTTPError as error:raise AssertionError(error.read().decode()) from None
        with response:
            value=json.load(response)['value']
            if isinstance(value,dict) and value.get('error'):raise AssertionError(value)
            return value
    with open(home/'driver.log','w') as log:
        driver=subprocess.Popen([os.environ.get('GECKODRIVER','geckodriver'),'--port',str(port),'--allow-system-access'],env=env,stdout=log,stderr=log)
        session=None
        try:
            for _ in range(200):
                if (home/'server/ready.json').exists():break
                assert fixture.poll() is None;time.sleep(.05)
            for _ in range(100):
                try:request('GET','/status');break
                except OSError:time.sleep(.05)
            prefs={'extensions.webextensions.uuids':json.dumps({'knock-control-mobile@local':UUID})}
            options={'args':['-headless'],'prefs':prefs}
            if os.environ.get('FIREFOX_BIN'):options['binary']=os.environ['FIREFOX_BIN']
            session=request('POST','/session',{'capabilities':{'alwaysMatch':{'browserName':'firefox','acceptInsecureCerts':True,'moz:firefoxOptions':options}}})['sessionId'];base='/session/'+session
            request('POST',base+'/moz/addon/install',{'path':str(extension),'temporary':True})
            def evaluate(source):return request('POST',base+'/execute/sync',{'script':source,'args':[]})
            def until(source,predicate=lambda v:bool(v)):
                for _ in range(200):
                    value=evaluate(source)
                    if predicate(value):return value
                    time.sleep(.05)
                raise AssertionError(str(value))
            def message(text):until("return document.querySelector('#message')?.textContent??''",lambda v:text in v)
            def element(selector):return request('POST',base+'/element',{'using':'css selector','value':selector})['element-6066-11e4-a52e-4f735466cecf']
            def click(selector):request('POST',base+'/element/'+element(selector)+'/click',{})
            def image(name):
                request('POST',base+'/element/'+element('#import-file')+'/value',{'text':str(home/'server'/name)})
                message('Profile imported')
            request('POST',base+'/url',{'url':f'moz-extension://{UUID}/app.html'})
            message('Import a server-issued JSON profile');image('alice.json')
            assert evaluate("return document.querySelectorAll('#status,#settings-panel,#connection-panel').length")==0
            request('POST',base+'/refresh',{});message('Press ON')
            click('#add-profile');image('bob.json')
            assert evaluate("return document.querySelector('#profiles').selectedOptions[0].textContent")=='Bob'
            click('#delete-profile');request('POST',base+'/alert/dismiss',{})
            assert evaluate("return document.querySelector('#profiles').options.length")==2
            click('#delete-profile');request('POST',base+'/alert/accept',{})
            until("return document.querySelector('#profiles').selectedOptions[0]?.textContent",lambda v:v=='Alice')
            request('POST',base+'/refresh',{});message('Press ON')
            assert evaluate("return document.querySelector('#profiles').options.length")==1
            click('#delete-profile');request('POST',base+'/alert/accept',{})
            until("return !document.querySelector('#import-panel').hidden")
            print('PASS: Firefox extension: import/select/delete, cancellation, fallback, empty store, persistence; no settings/status/host permissions')
        except Exception:
            print((home/'driver.log').read_text()[-4000:]);raise
        finally:
            if session:
                try:request('DELETE','/session/'+session)
                except OSError:pass
            driver.terminate();fixture.terminate()
            for process in (driver,fixture):
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
