#!/usr/bin/python3
"""Install the Linux package payload into a disposable staging directory."""
import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]


def stage(destination, daemon):
    def install(source, target, mode=0o644):
        path = destination / target.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, path)
        path.chmod(mode)
        return path

    install(daemon, '/usr/sbin/knock-control-daemon', 0o755)
    for name in ('common.py', 'server.py', 'qr_codec.py', 'rules.py', 'iptables_rules.py', 'vendor/qrcodegen.py'):
        path = install(ROOT / 'controller' / name, '/usr/lib/knock-control/' + name)
        if name == 'server.py':
            text = path.read_text()
            for old, new in (('/usr/local/sbin/knock-control', '/usr/sbin/knock-control'),
                             ('/usr/local/sbin/knockd', '/usr/sbin/knock-control-daemon')):
                assert text.count(old) == 1, 'Controller path template changed: ' + old
                text = text.replace(old, new)
            path.write_text(text)
    install(ROOT / 'packaging/linux/knock-control', '/usr/sbin/knock-control', 0o755)
    install(ROOT / 'packaging/linux/maint.sh', '/usr/lib/knock-control/package-maint.sh')
    for name in ('knock-control.service', 'knock-control-firewall.service'):
        path = install(ROOT / 'packaging' / name, '/usr/lib/systemd/system/' + name)
        text = path.read_text().replace('/usr/local/sbin/knock-control', '/usr/sbin/knock-control')
        text = text.replace('/usr/local/sbin/knockd', '/usr/sbin/knock-control-daemon')
        if name == 'knock-control.service':
            text = text.replace('[Unit]\n', '[Unit]\nConditionPathExists=/etc/knock-control/settings.json\n', 1)
        path.write_text(text)
    for name in ('COPYING', 'THIRD_PARTY.json'):
        install(ROOT / name, '/usr/share/doc/knock-control/' + name)
    install(ROOT / 'doc/LINUX_PACKAGES.md', '/usr/share/doc/knock-control/README.md')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dest', required=True, type=Path)
    parser.add_argument('--daemon', required=True, type=Path)
    args = parser.parse_args()
    stage(args.dest, args.daemon)
