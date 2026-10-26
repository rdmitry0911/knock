#!/usr/bin/python3
"""Cross-build the native C OpenWrt package with an official SDK."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sdk',type=Path,required=True)
parser.add_argument('--jobs',type=int,default=4)
parser.add_argument('--output-dir',type=Path,default=ROOT/'dist/openwrt')
parser.add_argument('--prepare-only',action='store_true')
parser.add_argument('--test-tools',action='store_true',help='Also cross-build the native VM probe and protocol test (not installed in the APK)')
args=parser.parse_args();sdk=args.sdk.resolve()
if not (sdk/'include/package.mk').is_file():parser.error('Expected an extracted OpenWrt SDK')
if args.jobs<1:parser.error('--jobs must be positive')
package=sdk/'package/knock-control'
if package.exists():shutil.rmtree(package)
shutil.copytree(ROOT/'packaging/openwrt',package)
source=package/'src';source.mkdir()
for directory in ('src',):
    shutil.copytree(ROOT/directory,source/directory,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
shutil.copy2(ROOT/'COPYING',source/'COPYING')
if args.prepare_only:
    print(package)
    raise SystemExit(0)
def run(*command):subprocess.run(command,cwd=sdk,check=True)
run('./scripts/feeds','install','libpcap','libopenssl','libjson-c','libsqlite3','libqrencode','libuci','zlib','firewall4','nftables-json')
config=sdk/'.config'
# The SDK defaults enable every package and OpenSSL engine, including kernel
# modules that are unrelated to our binary. Select just the needed build here.
config.write_text('CONFIG_ALL=n\nCONFIG_ALL_NONSHARED=n\nCONFIG_ALL_KMODS=n\n'
                  'CONFIG_PACKAGE_knock-control=m\nCONFIG_PACKAGE_libpcap=m\n'
                  'CONFIG_PACKAGE_libopenssl=m\nCONFIG_PACKAGE_libopenssl-afalg=n\n'
                  'CONFIG_PACKAGE_libopenssl-devcrypto=n\nCONFIG_PACKAGE_libopenssl-padlock=n\n'
                  'CONFIG_PACKAGE_libjson-c=m\nCONFIG_PACKAGE_libsqlite3=m\n'
                  'CONFIG_PACKAGE_libqrencode=m\nCONFIG_PACKAGE_libuci=m\nCONFIG_PACKAGE_zlib=m\n')
run('make','defconfig')
run('make','package/knock-control/clean','NO_DEPS=1')
# Build link dependencies; Firewall packages resolve from official feeds.
run('make',f'-j{args.jobs}','package/feeds/base/libpcap/compile','package/feeds/base/openssl/compile',
    'package/feeds/base/libjson-c/compile','package/feeds/packages/sqlite3/compile',
    'package/feeds/packages/qrencode/compile','package/feeds/base/uci/compile','package/feeds/base/zlib/compile','V=s')
run('make',f'-j{args.jobs}','package/knock-control/compile','NO_DEPS=1','V=s')
output=args.output_dir.resolve();output.mkdir(parents=True,exist_ok=True)
found=[]
for suffix in ('apk','ipk'):
    for archive in (sdk/'bin/packages').rglob('knock-control*.'+suffix):
        target=output/archive.name;shutil.copy2(archive,target);found.append(target);print(target)
if not found:raise SystemExit('SDK did not produce a knock-control package')
if args.test_tools:
    toolchain=next((sdk/'staging_dir').glob('toolchain-*'))
    compiler=next((toolchain/'bin').glob('*-gcc'))
    target=next((sdk/'staging_dir').glob('target-*'))
    build_env={**os.environ,'PATH':str(toolchain/'bin')+os.pathsep+os.environ['PATH'],
               'STAGING_DIR':str(target)}
    for name,source in [('openwrt-probe',ROOT/'tests/openwrt_probe.c'),
                        ('openwrt-native-unit',ROOT/'tests/openwrt_native_unit.c'),
                        ('openwrt-selftest-control',ROOT/'packaging/openwrt/control.c')]:
        extra=['-DKNC_STATE_DIR="/tmp/knock-native-selftest"'] if name=='openwrt-selftest-control' else []
        subprocess.run([str(compiler),'-Os','-std=gnu11','-Wall','-Wextra','-Werror',
            '-I'+str(target/'usr/include'),'-L'+str(target/'usr/lib'),
            '-Wl,-rpath-link,'+str(target/'usr/lib'),*extra,str(source),
            '-o',str(output/name),'-ljson-c','-lsqlite3','-lqrencode','-luci','-lssl','-lcrypto','-lz'],
            env=build_env,check=True)
(output/'SHA256SUMS').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n'
    for path in sorted(output.iterdir()) if path.suffix in ('.apk','.ipk')))
