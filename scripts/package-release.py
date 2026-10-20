#!/usr/bin/python3
"""Package reviewable sources and browser artifacts; never include local credentials."""
import hashlib
from pathlib import Path
import subprocess
import zipfile
root=Path(__file__).resolve().parents[1]
subprocess.run(['/usr/bin/python3',str(root/'scripts/package-extension.py')],check=True)
dist=root/'dist';version='3.0.0'
files=[]
for directory in ('src','controller','extension','packaging','scripts','tests','doc'):
    for path in (root/directory).rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts and (path.suffix in ('.py','.sh','.cgi','.config','.js','.json','.html','.css','.png','.svg','.webmanifest','.LICENSE','.c','.h','.mjs','.in','.1','.init','.nft') or path.name=='Makefile'):
            files.append(path)
for name in ('README.md','README_RU.md','COPYING','THIRD_PARTY.json','Makefile.am','configure.ac','knockd.conf','knockd.sh','ChangeLog','TODO'):
    if (root/name).is_file():files.append(root/name)
output=dist/f'knock-control-{version}-source.zip'
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(files):archive.write(path,Path(f'knock-control-{version}')/path.relative_to(root))
    for path in sorted(dist.glob('knock-control-*')):
        if path.is_file() and (path.name.endswith('.unsigned.xpi') or path.name.endswith('.zip')) and path!=output and '-source' not in path.name:
            archive.write(path,Path(f'knock-control-{version}')/'packages'/path.name)
    if (dist/'openwrt').exists():
        for path in sorted((dist/'openwrt').rglob('*')):
            if path.is_file() and (path.suffix in ('.apk','.ipk') or path.name=='SHA256SUMS' or
                    (path.parent==dist/'openwrt' and path.suffix in ('.json','.log'))):
                archive.write(path,Path(f'knock-control-{version}')/'packages/openwrt'/path.relative_to(dist/'openwrt'))
artifacts=sorted([p for p in dist.glob('knock-control-*') if p.is_file()])
(dist/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in artifacts))
print(output)
