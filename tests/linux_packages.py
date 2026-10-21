#!/usr/bin/python3
"""Verify installed packages inside a disposable root and network namespace.

Dependencies must already be installed. Run in an empty test root with /proc
mounted and loopback up. Never run against an existing server configuration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', choices=('deb', 'rpm'), required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Use an isolated network namespace'
    assert not Path('/etc/knock-control/settings.json').exists(), 'Use a fresh disposable test root'
    package = str(args.package.resolve())
    install = ['dpkg', '-i', package] if args.format == 'deb' else ['rpm', '-Uvh', package]
    run(*install)
    config = Path('/etc/knock-control/settings.json')
    assert not config.exists(), 'Installation must not generate credentials'
    assert not Path('/etc/systemd/system/multi-user.target.wants/knock-control.service').exists()
    assert not Path('/usr/lib/knock-control/api.py').exists()
    assert not Path('/usr/lib/systemd/system/knock-control-api.service').exists()
    control = '/usr/sbin/knock-control'
    run(control, '--help')
    assert json.loads(run(control, 'init', '--public-host', '127.0.0.1', '--interface', 'lo').stdout)['ok']
    assert json.loads(run(control, 'issue', '--name', 'Package test', '--ports', '23456',
                          '--out', '/tmp/package-profile.json', '--qr-out', '/tmp/package-profile.png').stdout)['ok']
    bundle = json.loads(Path('/tmp/package-profile.json').read_text())
    assert bundle['format'] == 'knock-control-client-v3'
    assert 'server_url' not in bundle and 'certificate_sha256' not in bundle
    assert Path('/tmp/package-profile.png').read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
    daemon_config = Path('/etc/knock-control/knockd.conf')
    assert '/usr/sbin/knock-control access-ice ' in daemon_config.read_text()
    assert '/usr/local/' not in daemon_config.read_text()
    run('/usr/sbin/knock-control-daemon', '--check', '--config', str(daemon_config))
    run('systemd-analyze', 'verify', '/usr/lib/systemd/system/knock-control.service',
        '/usr/lib/systemd/system/knock-control-firewall.service')
    sys.path.insert(0, '/usr/lib/knock-control')
    import common
    import server
    assert server.CONTROL == control and server.DAEMON == '/usr/sbin/knock-control-daemon'
    # No systemd PID 1 in this chroot: activate the local test configuration and
    # launch the real daemon directly. This does not simulate a boot test.
    db = json.loads(config.read_text())
    db['activated'] = True
    common.atomic_write(config, json.dumps(db))
    run(control, 'firewall')
    ident = bundle['profile_id']
    set_name = server.set_name(ident)

    def member():
        return run(server.IPSET, 'test', set_name, '127.0.0.1', check=False).returncode == 0

    def packet(action):
        token = common.ice_token(bundle, action, '127.0.0.1')
        value = (token + ':packageTest').encode()
        attribute = struct.pack('!HH', 6, len(value)) + value + b'\0' * (-len(value) % 4)
        return b'\x00\x01' + struct.pack('!H', len(attribute)) + b'\x21\x12\xa4\x42' + os.urandom(12) + attribute

    def send(payload):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.sendto(payload, ('127.0.0.1', bundle['settings']['base']))

    def wait_member(expected):
        deadline = time.monotonic() + 5
        while member() != expected and time.monotonic() < deadline:
            time.sleep(.05)
        assert member() == expected, 'Installed daemon/controller failed ON/OFF'

    log = Path('/tmp/knock-package-daemon.log')
    with log.open('w') as stream:
        daemon = subprocess.Popen(['/usr/sbin/knock-control-daemon', '-c', str(daemon_config)],
                                  stdout=stream, stderr=subprocess.STDOUT)
        try:
            time.sleep(.4)
            assert daemon.poll() is None
            on = packet('open')
            send(on)
            wait_member(True)
            time.sleep(.02)
            send(packet('close'))
            wait_member(False)
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)
        # Captured ON must stay rejected after a new daemon/controller process.
        daemon = subprocess.Popen(['/usr/sbin/knock-control-daemon', '-c', str(daemon_config)],
                                  stdout=stream, stderr=subprocess.STDOUT)
        try:
            time.sleep(.4)
            send(on)
            time.sleep(.5)
            assert not member(), 'Replay accepted after restart'
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)
    journal = Path('/var/lib/knock-control/api-replays.sqlite3')
    assert journal.is_file() and journal.stat().st_mode & 0o777 == 0o600
    before = json.loads(config.read_text()), journal.read_bytes()
    if args.format == 'rpm':
        run('rpm', '-Uvh', '--replacepkgs', package)
        run('rpm', '-e', 'knock-control')
    else:
        run(*install)
        run('dpkg', '--purge', 'knock-control')
    assert json.loads(config.read_text()) == before[0] and journal.read_bytes() == before[1]
    assert not Path(control).exists()
    assert run('/usr/sbin/iptables', '-C', 'INPUT', '-j', 'KNOCK_CONTROL', check=False).returncode == 0
    run(*install)
    assert json.loads(config.read_text()) == before[0] and journal.read_bytes() == before[1]
    assert json.loads(run(control, 'list').stdout)[0]['id'] == ident
    report = {
        'result': 'PASS', 'package_format': args.format, 'package': args.package.name,
        'sha256': hashlib.sha256(args.package.read_bytes()).hexdigest(),
        'distribution': Path('/etc/os-release').read_text(),
        'architecture': os.uname().machine,
        'checks': ['Native package manager installed package and ran lifecycle scripts',
                   'No automatic credentials, service enablement, HTTP API or management listener',
                   'Installed CLI initializes/issues v3 JSON and QR PNG; generated daemon config validates',
                   'Installed systemd units pass systemd-analyze verify',
                   'Real installed packet daemon -> installed Python callback -> kernel iptables/ipset ON/OFF',
                   'Captured ON replay rejected after daemon restart',
                   'Reinstall and removal preserve credentials, revisions and durable replay journal',
                   'Removal retains firewall protection; reinstall uses retained credentials'],
        'limitations': ['Disposable chroot and isolated kernel network namespace; not a booted VM',
                        'Systemd units verified statically; systemd PID 1 and reboot not exercised'],
    }
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS:', args.format, args.package.name)


if __name__ == '__main__':
    main()
