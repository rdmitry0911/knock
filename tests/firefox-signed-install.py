#!/usr/bin/env python3
"""Verify permanent installation and restart with a stock Firefox release."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.error
import urllib.request
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--signed', type=Path, required=True)
parser.add_argument('--unsigned', type=Path, required=True)
parser.add_argument('--driver-url', default='http://127.0.0.1:4455')
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
with zipfile.ZipFile(args.signed) as archive:
    manifest = json.loads(archive.read('manifest.json'))
ident = manifest['browser_specific_settings']['gecko']['id']
assert 'nativeMessaging' not in manifest['permissions']

def request(method, path, data=None):
    req = urllib.request.Request(args.driver_url + path,
        data=None if data is None else json.dumps(data).encode(), method=method,
        headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)['value']
    except urllib.error.HTTPError as error:
        raise RuntimeError(error.read().decode()) from None

with tempfile.TemporaryDirectory(prefix='knock-signed-firefox-') as temporary:
    profile = Path(temporary) / 'profile'
    profile.mkdir()
    session = None
    def start():
        global session
        result = request('POST', '/session', {'capabilities': {'alwaysMatch': {
            'browserName': 'firefox', 'moz:firefoxOptions': {
                'binary': str(args.binary.resolve()), 'args': ['-headless', '-profile', str(profile)],
                'prefs': {'xpinstall.signatures.required': True}}}}})
        session = result['sessionId']
        request('POST', f'/session/{session}/moz/context', {'context': 'chrome'})
        enforced = request('POST', f'/session/{session}/execute/sync', {
            'script': 'return Services.prefs.getBoolPref("xpinstall.signatures.required");', 'args': []})
        assert enforced is True
        return result['capabilities']['browserVersion']

    def addon():
        return request('POST', f'/session/{session}/execute/async', {'script': '''
            const done = arguments[arguments.length - 1];
            const {AddonManager} = ChromeUtils.importESModule("resource://gre/modules/AddonManager.sys.mjs");
            AddonManager.getAddonByID(arguments[0]).then(a => done(a ? {
                id:a.id, version:a.version, isActive:a.isActive, appDisabled:a.appDisabled,
                userDisabled:a.userDisabled, temporarilyInstalled:a.temporarilyInstalled,
                signedState:a.signedState, expectedSignedState:AddonManager.SIGNEDSTATE_SIGNED
            } : null));''', 'args': [ident]})

    def check(state):
        assert state and state['isActive'] and not state['appDisabled'] and not state['userDisabled'], state
        assert not state['temporarilyInstalled'], state
        assert state['signedState'] == state['expectedSignedState'], state
        assert state['version'] == manifest['version'], state

    try:
        version = start()
        try:
            request('POST', f'/session/{session}/moz/addon/install', {
                'path': str(args.unsigned.resolve()), 'temporary': False})
        except RuntimeError as error:
            assert 'sign' in str(error).lower(), str(error)
        else:
            raise AssertionError('Unsigned XPI unexpectedly installed permanently')
        assert addon() is None
        installed = request('POST', f'/session/{session}/moz/addon/install', {
            'path': str(args.signed.resolve()), 'temporary': False})
        assert installed == ident
        before = addon()
        check(before)
        request('DELETE', f'/session/{session}')
        session = None
        assert start() == version
        after = addon()
        check(after)
        report = {'result': 'PASS', 'browser': 'Official Mozilla Firefox release',
            'browser_version': version, 'platform': 'Linux x86_64',
            'xpi_sha256': hashlib.sha256(args.signed.read_bytes()).hexdigest(),
            'checks': ['Signature enforcement enabled', 'Unsigned XPI rejected for permanent installation',
                'Mozilla-signed browser-only XPI permanently installed',
                'Extension active and signature valid after restarting Firefox with the same profile'],
            'before_restart': before, 'after_restart': after,
            'installation': 'Geckodriver permanent addon installation; no signature bypass or temporary install',
            'scope': 'Installation/signature/persistence test; transport functionality is verified separately'}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)
    finally:
        if session:
            request('DELETE', f'/session/{session}')
