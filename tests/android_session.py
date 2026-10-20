#!/usr/bin/python3
"""Create a Firefox Android WebDriver session after Chrome checks have finished."""
import argparse
import json
from pathlib import Path
import urllib.request

parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
parser.add_argument('--url',default='http://127.0.0.1:4444');parser.add_argument('--device',default='emulator-5554')
args=parser.parse_args()
capabilities={'capabilities':{'alwaysMatch':{'browserName':'firefox','acceptInsecureCerts':True,'moz:firefoxOptions':{'androidPackage':'org.mozilla.firefox','androidDeviceSerial':args.device,'prefs':{'extensions.webextensions.uuids':json.dumps({'knock-control-mobile@local':'22222222-2222-4222-8222-222222222222'})}}}}}
request=urllib.request.Request(args.url+'/session',data=json.dumps(capabilities).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=150) as response:value=json.load(response)
args.out.write_text(json.dumps(value));args.out.chmod(0o600)
print('Firefox Android',value['value']['capabilities']['browserVersion'],'WebDriver session ready')
