#!/usr/bin/python3
"""Firefox + real Native Messaging + real pinned HTTPS (unprivileged API fixture).
GECKODRIVER=/path/geckodriver FIREFOX_BIN=/path/firefox python3 tests/firefox-smoke.py
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

ROOT=Path(__file__).resolve().parents[1]
UUID='11111111-1111-4111-8111-111111111111'


def main():
    with tempfile.TemporaryDirectory(prefix='knock-firefox-v2-') as directory:
        home=Path(directory);env={**os.environ,'HOME':str(home),'XDG_CONFIG_HOME':str(home/'.config')}
        subprocess.run(['/usr/bin/python3',str(ROOT/'scripts/install-native.py'),'--firefox'],env=env,check=True,stdout=subprocess.DEVNULL)
        fixture=subprocess.Popen(['/usr/bin/python3',str(ROOT/'tests/api_fixture.py'),str(home/'server')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
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
                for _ in range(100):
                    if (home/'server/ready.json').exists():break
                    assert fixture.poll() is None,'API fixture failed';time.sleep(.05)
                alice=json.loads((home/'server/alice.json').read_text())
                for _ in range(100):
                    try:request('GET','/status');break
                    except OSError:time.sleep(.05)
                options={'args':['-headless'],'prefs':{'extensions.webextensions.uuids':json.dumps({'knock-control@local':UUID})}}
                if os.environ.get('FIREFOX_BIN'):options['binary']=os.environ['FIREFOX_BIN']
                session=request('POST','/session',{'capabilities':{'alwaysMatch':{'browserName':'firefox','moz:firefoxOptions':options}}})['sessionId'];base='/session/'+session
                request('POST',base+'/moz/addon/install',{'path':str(ROOT/'dist/firefox'),'temporary':True})
                def evaluate(source):return request('POST',base+'/execute/sync',{'script':source,'args':[]})
                def until(source,predicate=lambda value:bool(value),message='Browser did not reach expected state'):
                    for _ in range(200):
                        value=evaluate(source)
                        if predicate(value):return value
                        time.sleep(.05)
                    raise AssertionError(message+': '+str(value))
                def wait_message(text):return until("return document.querySelector('#message').textContent",lambda value:text in value)
                def import_file(name):
                    element=request('POST',base+'/element',{'using':'css selector','value':'#import-file'})
                    ident=element['element-6066-11e4-a52e-4f735466cecf']
                    request('POST',base+'/element/'+ident+'/value',{'text':str(home/'server'/name)})
                    wait_message('профиль импортирован')
                def refresh():
                    evaluate("document.querySelector('#refresh').click()");wait_message('получены с сервера')
                request('POST',base+'/url',{'url':f'moz-extension://{UUID}/options.html'})
                wait_message('Импортируйте JSON-файл');assert not evaluate("return !!document.querySelector('#generate')")
                import_file('alice.json');refresh()
                assert evaluate("return document.querySelector('[name=public_ip]').value")=='127.0.0.1'
                evaluate("document.querySelector('[name=idle_timeout]').value='15';document.querySelector('form').requestSubmit()")
                wait_message('Настройки этого секрета применены')
                evaluate("document.querySelector('#pairing').click()")
                until("return document.querySelector('#pairing-secret').textContent",lambda value:value==alice['secret'])
                evaluate("document.querySelector('#hide-pairing').click()")
                import_file('bob.json');refresh()
                assert evaluate("return document.querySelector('[name=idle_timeout]').value")=='20'
                evaluate("const s=document.querySelector('#profiles');s.value=[...s.options].find(o=>o.textContent.startsWith('Alice')).value;s.dispatchEvent(new Event('change'))")
                wait_message('Профиль выбран');refresh()
                assert evaluate("return document.querySelector('[name=idle_timeout]').value")=='15'
                request('POST',base+'/url',{'url':f'moz-extension://{UUID}/popup.html'})
                until("return document.querySelector('#server').textContent.includes('Alice') && !document.querySelector('#open').disabled")
                evaluate("document.querySelector('#open').click()")
                wait_message('Последовательность отправлена')
                store=json.loads((home/'.config/knock-control/profiles.json').read_text());assert len(store['profiles'])==2
                print('PASS: Firefox import/select server-issued profiles, isolated settings via real pinned HTTPS, Google Authenticator, Native Messaging and signed knocks')
            except Exception:
                log.flush();print((home/'driver.log').read_text()[-4000:]);raise
            finally:
                if session:
                    try:request('DELETE','/session/'+session)
                    except OSError:pass
                driver.terminate();fixture.terminate()
                for process in (driver,fixture):
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()

if __name__=='__main__':main()
