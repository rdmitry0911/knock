#!/usr/bin/python3
"""Install per-user Linux native manifests after loading the browser extension."""
import argparse
import json
from pathlib import Path
import re
import shlex
import shutil

parser = argparse.ArgumentParser()
parser.add_argument('--chrome-id', help='32-character ID from chrome://extensions')
parser.add_argument('--firefox', action='store_true')
args = parser.parse_args()
if not args.chrome_id and not args.firefox:
    parser.error('Specify --chrome-id ID and/or --firefox')
if args.chrome_id and not re.fullmatch('[a-p]{32}', args.chrome_id):
    parser.error('Invalid Chrome extension ID')
root = Path(__file__).resolve().parents[1]
destination = Path.home() / '.local/lib/knock-control'
destination.mkdir(parents=True, exist_ok=True, mode=0o700)
for file in ('common.py', 'native.py', 'qr_codec.py'):
    shutil.copy2(root / 'controller' / file, destination / file)
wrapper = destination / 'native-host'
wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 -I ' + shlex.quote(str(destination / 'native.py')) + '\n')
wrapper.chmod(0o700)
manifest = {'name': 'org.knock.control', 'description': 'Knock Control local bridge',
            'path': str(wrapper), 'type': 'stdio'}
locations = []
if args.chrome_id:
    chrome = {**manifest, 'allowed_origins': [f'chrome-extension://{args.chrome_id}/']}
    for folder in ('.config/google-chrome/NativeMessagingHosts', '.config/chromium/NativeMessagingHosts', '.config/microsoft-edge/NativeMessagingHosts'):
        locations.append((Path.home() / folder, chrome))
if args.firefox:
    locations.append((Path.home() / '.mozilla/native-messaging-hosts',
                      {**manifest, 'allowed_extensions': ['knock-control@local']}))
for folder, value in locations:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'org.knock.control.json'
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)
    print(path)
