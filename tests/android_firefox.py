#!/usr/bin/python3
"""Firefox Android APK: real extension and PWA UI against Android network fixture."""
import base64
import json
from pathlib import Path
import socket
import os
import re
import subprocess
import threading
from xml.etree import ElementTree
import sys
import time
import urllib.request
import urllib.error

work=Path(sys.argv[1]);session=json.loads(Path(sys.argv[2]).read_text())['value']['sessionId'];mode=sys.argv[3]
ROOT=Path(__file__).resolve().parents[1];url='http://127.0.0.1:4444/session/'+session

def request(method,path,data=None):
    q=urllib.request.Request(url+path,data=None if data is None else json.dumps(data).encode(),method=method,headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(q,timeout=35) as response:value=json.load(response)['value']
    except urllib.error.HTTPError as error:raise RuntimeError(error.read().decode()) from None
    if isinstance(value,dict) and value.get('error'):raise RuntimeError(str(value))
    return value

def evaluate(script,*args):return request('POST','/execute/sync',{'script':script,'args':list(args)})
def element(selector):return request('POST','/element',{'using':'css selector','value':selector})['element-6066-11e4-a52e-4f735466cecf']
def click(selector):request('POST','/element/'+element(selector)+'/click',{})
def localized(text,values=None):
    lang=evaluate('return document.documentElement.lang')
    catalog=json.loads((ROOT/'extension/_locales'/lang.replace('-','_')/'messages.json').read_text())
    key=2166136261
    for byte in text.encode():key=((key^byte)*16777619)&0xffffffff
    translated=catalog.get('m_'+format(key,'x'),{}).get('message',text)
    return re.sub(r'\{(\w+)\}',lambda m:str((values or {}).get(m[1],m[0])),translated)
def message(text,values=None):
    text=localized(text,values)
    for _ in range(180):
        value=evaluate("return document.querySelector('#message')?.textContent??''")
        if text in value:return value
        time.sleep(.1)
    raise AssertionError(value)
def rpc(op):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(str(work/'control.sock'));sock.sendall(json.dumps({'op':op}).encode());chunks=[]
        while b:=sock.recv(65536):chunks.append(b)
        return json.loads(b''.join(chunks))
def granted():return any(rpc('status')['grants'].values())

bundle=json.loads((work/'bundle.json').read_text());request('POST','/timeouts',{'pageLoad':8000,'script':10000})
# Use a profile-local trust anchor for the disposable lab's HTTPS origin.
certificate=''.join((work/'server.crt').read_text().splitlines()[1:-1])
request('POST','/moz/context',{'context':'chrome'})
try:evaluate('const db=Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);db.addCertFromBase64(arguments[0],"C,,");',certificate)
finally:request('POST','/moz/context',{'context':'content'})
rpc('open-api');checks=[]
handles=request('GET','/window/handles')
# Android may show its native home screen while closing restored tabs; retain them.
request('POST','/window',{'handle':handles[-1]}) if handles else request('POST','/window/new',{'type':'tab'})
if mode=='extension':
    handles=request('GET','/window/handles')
    if handles:
        request('POST','/window',{'handle':handles[0]});request('POST','/window/new',{'type':'tab'})
    encoded=base64.b64encode((ROOT/'dist/knock-control-firefox-mobile.unsigned.xpi').read_bytes()).decode()
    adb=os.environ.get('ADB_BIN','adb')
    # Firefox can wait for its native confirmation before completing addon/install.
    done=threading.Event()
    def confirm_added():
        while not done.wait(.5):
            subprocess.run([adb,'shell','uiautomator','dump','/sdcard/knock-ui.xml'],capture_output=True,check=True)
            xml=subprocess.check_output([adb,'shell','cat','/sdcard/knock-ui.xml'],text=True)
            nodes=list(ElementTree.fromstring(xml).iter('node'))
            if not any('Knock Control was added' in n.get('text','') for n in nodes):continue
            node=next(n for n in nodes if n.get('text')=='OK');x1,y1,x2,y2=map(int,re.findall(r'\d+',node.get('bounds')))
            subprocess.run([adb,'shell','input','tap',str((x1+x2)//2),str((y1+y2)//2)],check=True)
            return
    confirmation=threading.Thread(target=confirm_added,daemon=True);confirmation.start()
    try:
        installed=request('POST','/moz/addon/install',{'addon':encoded,'temporary':True})
        confirmation.join(timeout=6)
    finally:done.set();confirmation.join(timeout=5)
    print('Installed temporary Android extension:',installed,flush=True)
    handles=request('GET','/window/handles');assert handles,'No Android browser tab';request('POST','/window',{'handle':handles[-1]})
    client='moz-extension://22222222-2222-4222-8222-222222222222/app.html'
    request('POST','/url',{'url':client})
    for _ in range(100):
        value=evaluate("return document.querySelector('#message')?.textContent??''")
        if value:break
        time.sleep(.1)
    if evaluate("return document.querySelector('#import-panel').hidden"):click('#add-profile')
    click('#import-panel details summary')
    evaluate("document.querySelector('#import-text').value=arguments[0]",(work/'enrollment.txt').read_text());click('#import-button');message('Profile imported. Press ON.')
    checks.append('Original unsigned release XPI temporarily installed in real Firefox Android; QR text imported')
else:
    request('POST','/url',{'url':'about:blank'})
    request('POST','/url',{'url':(work/'enrollment.txt').read_text()});message('Profile imported. Press ON.');client=bundle['server_url']+'/app/'
    assert evaluate('return location.hash')=='';checks.append('QR enrollment link imported and secret fragment removed')
click('#connection-panel summary');evaluate("document.querySelector('[name=stun_server]').value=arguments[0]",bundle['stun_server']);click('#connection-form button');message('Connection saved on this device.')
request('POST','/refresh',{});message('Press ON.');checks.append('Profile persists after page reload')
if mode=='pwa':
    request('POST','/execute/async',{'script':'const done=arguments[arguments.length-1];navigator.serviceWorker.ready.then(()=>done(true));','args':[]})
    request('POST','/url',{'url':'about:blank'});request('POST','/url',{'url':client});message('Press ON.')
    assert evaluate('return !!navigator.serviceWorker.controller'),'PWA service worker is not controlling its page'
    checks.append('Service worker activated and controls saved application')
ua=evaluate('return navigator.userAgent');print(json.dumps({'phase':'import','mode':mode,'user_agent':ua}),flush=True)
client_handle=request('GET','/window');service_handle=request('POST','/window/new',{'type':'tab'})['handle']
def switch(handle):request('POST','/window',{'handle':handle})
def reachable():
    switch(service_handle)
    try:
        request('POST','/url',{'url':'http://203.0.113.1:23456/?t='+str(time.time_ns())});return request('GET','/title')=='Protected service OK'
    except RuntimeError:return False
    finally:
        request('POST','/url',{'url':'about:blank'});switch(client_handle)
def action(which):
    switch(client_handle);click('#'+which);message('Signed UDP knock {operation} sent. No server response was requested.',{'operation':'ON' if which=='open' else 'OFF'});return rpc('status')

assert not granted() and not reachable(),'Service already open before ON'
before=rpc('close-api')
if mode=='pwa':
    request('POST','/url',{'url':'about:blank'});request('POST','/url',{'url':client});message('Press ON.');checks.append('PWA opens from saved shell with stored profile while HTTPS server is stopped')
on=action('open');assert any(on['grants'].values()) and reachable(),'Firefox Android ICE ON failed'
print(json.dumps({'phase':'on','mode':mode,'grants':on['grants']}),flush=True)
action('close');assert not granted() and not reachable(),'Firefox Android ICE OFF failed'
checks.append('ON/OFF opens/closes actual protected HTTP service with HTTPS management listener closed')
rpc('restart-daemon');rpc('replay');assert not granted(),'Captured ON replay reopened access';checks.append('Captured ON replay rejected after daemon restart')
action('open');time.sleep(17);assert not granted() and not reachable(),'Idle timeout failed';checks.append('Idle lease expires without protected traffic')
after=rpc('status');assert after['api_requests']==before['api_requests'] and not after['knock_udp_listener'] and not after['stun_secret_leaks'] and after['daemon_alive']
rpc('open-api');click('#status')
if mode=='extension':
    subprocess.run([adb,'shell','uiautomator','dump','/sdcard/knock-ui.xml'],capture_output=True,check=True)
    xml=subprocess.check_output([adb,'shell','cat','/sdcard/knock-ui.xml'],text=True)
    for n in ElementTree.fromstring(xml).iter('node'):
        if n.get('text')=='Allow':
            x1,y1,x2,y2=map(int,re.findall(r'\d+',n.get('bounds')))
            subprocess.run([adb,'shell','input','tap',str((x1+x2)//2),str((y1+y2)//2)],check=True)
            break
disabled=localized('Access disabled')
for _ in range(120):
    if disabled in evaluate("return document.querySelector('#state').textContent"):break
    time.sleep(.1)
else:raise AssertionError('Signed status failed')
checks.append('Signed HTTPS status works in Firefox Android')
(work/('firefox-'+mode+'-android.png')).write_bytes(base64.b64decode(request('GET','/screenshot')))
result={'result':'PASS','browser':'Firefox Android','mode':mode,'interface_language':evaluate('return document.documentElement.lang'),'user_agent':ua,'checks':checks,'api_requests_during_ice':after['api_requests']-before['api_requests'],'knock_udp_listener':after['knock_udp_listener'],'certificate_exception':'Fixture CA installed only in the disposable Firefox NSS profile; WebDriver acceptInsecureCerts also enabled','extension_installation':'temporary debugging install; permanent Firefox installation still requires Mozilla signature' if mode=='extension' else None}
(work/('firefox-'+mode+'-report.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
