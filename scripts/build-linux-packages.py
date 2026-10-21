#!/usr/bin/python3
"""Build native deb or rpm packages; run on the intended distribution family."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '4.0.3'
RELEASE = '2'


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def source_archive(output):
    # Explicit source paths exclude dist, browser credentials and local secrets.
    paths = [ROOT / 'COPYING', ROOT / 'THIRD_PARTY.json', ROOT / 'doc/LINUX_PACKAGES.md']
    for directory in ('src', 'controller', 'packaging/linux'):
        paths.extend(p for p in (ROOT / directory).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts
                     and p.suffix in ('.c', '.h', '.py', '.sh', '.spec'))
    paths.extend(ROOT / 'packaging' / name for name in ('knock-control.service', 'knock-control-firewall.service'))
    paths.extend([ROOT / 'packaging/linux/knock-control', ROOT / 'scripts/build-linux-packages.py'])
    paths.append(ROOT / 'tests/linux_packages.py')
    with tarfile.open(output, 'w:gz') as archive:
        for path in sorted(set(paths)):
            archive.add(path, f'knock-control-{VERSION}/' + str(path.relative_to(ROOT)))


def deb(work, output):
    daemon = work / 'knock-control-daemon'
    run('cc', '-O2', '-g', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
        '-fPIE', '-pie', '-Wl,-z,relro,-z,now', '-o', str(daemon),
        str(ROOT / 'src/knockd.c'), str(ROOT / 'src/list.c'), '-lpcap', '-lcrypto')
    run('strip', '--strip-unneeded', str(daemon))
    stage = work / 'debian/knock-control'
    run('python3', str(ROOT / 'packaging/linux/stage.py'), '--dest', str(stage), '--daemon', str(daemon))
    control = stage / 'DEBIAN'
    control.mkdir()
    arch = run('dpkg', '--print-architecture')
    (work / 'debian').mkdir(exist_ok=True)
    (work / 'debian/control').write_text('Source: knock-control\nSection: net\nPriority: optional\nMaintainer: Dmitry R <29107637+rdmitry0911@users.noreply.github.com>\n\nPackage: knock-control\nArchitecture: any\nDescription: Authenticated emergency access\n')
    deps = run('dpkg-shlibdeps', '-O', '-e' + str(stage / 'usr/sbin/knock-control-daemon'), cwd=work).removeprefix('shlibs:Depends=')
    (control / 'control').write_text(f'''Package: knock-control
Version: {VERSION}-{RELEASE}
Architecture: {arch}
Maintainer: Dmitry R <29107637+rdmitry0911@users.noreply.github.com>
Section: net
Priority: optional
Homepage: https://github.com/rdmitry0911/knock
Depends: {deps}, python3 (>= 3.9), iptables, ipset, systemd
Installed-Size: {sum(p.stat().st_size for p in stage.rglob('*') if p.is_file()) // 1024}
Description: Authenticated emergency access with browser ON/OFF
 Server-issued profiles and signed ICE knocks open per-address firewall grants
 with traffic-based idle expiry. No HTTP API or management listener is installed.
''')
    scripts = {
        'postinst': '. /usr/lib/knock-control/package-maint.sh\nif [ "$1" = configure ]; then knock_configure; fi\n',
        'prerm': '. /usr/lib/knock-control/package-maint.sh\ncase "$1" in remove|deconfigure) knock_remove ;; esac\n',
        'postrm': 'if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi\n',
    }
    for name, body in scripts.items():
        path = control / name
        path.write_text('#!/bin/sh\nset -eu\n' + body)
        path.chmod(0o755)
    artifact = output / f'knock-control_{VERSION}-{RELEASE}_{arch}.deb'
    run('dpkg-deb', '--build', '--root-owner-group', str(stage), str(artifact))
    print(artifact)


def rpm(work, output):
    for name in ('SOURCES', 'SPECS', 'BUILD', 'BUILDROOT', 'RPMS', 'SRPMS'):
        (work / name).mkdir()
    source_archive(work / 'SOURCES' / f'knock-control-{VERSION}-linux{RELEASE}.tar.gz')
    spec = work / 'SPECS/knock-control.spec'
    shutil.copy2(ROOT / 'packaging/linux/knock-control.spec', spec)
    subprocess.run(['rpmbuild', '-ba', '--define', '_topdir ' + str(work), str(spec)], check=True)
    for directory in ('RPMS', 'SRPMS'):
        for path in (work / directory).rglob('*.rpm'):
            shutil.copy2(path, output / path.name)
            print(output / path.name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', required=True, choices=('deb', 'rpm', 'source'))
    parser.add_argument('--output', type=Path, default=ROOT / f'dist/linux/{VERSION}-{RELEASE}')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.format == 'source':
        path = args.output / f'knock-control-{VERSION}-linux{RELEASE}.tar.gz'
        source_archive(path)
        print(path)
    else:
        with tempfile.TemporaryDirectory(prefix='knock-linux-build-') as directory:
            (deb if args.format == 'deb' else rpm)(Path(directory), args.output)
