#!/usr/bin/python3
"""Build one ICE/HTTPS extension per browser and the universal web application."""
import json
from pathlib import Path
import shutil
import zipfile

root = Path(__file__).resolve().parents[1]
dist = root / 'dist'
dist.mkdir(exist_ok=True)
# Remove retired helper variants so a reused dist cannot ship them accidentally.
for retired in ('chromium', 'firefox'):
    shutil.rmtree(dist / retired, ignore_errors=True)
    for suffix in ('.zip', '.unsigned.xpi'):
        (dist / f'knock-control-{retired}{suffix}').unlink(missing_ok=True)
source = root / 'extension'
web_files = ('app.html','app.js','bridge.js','browser-client.js','ice-client.js','profile-codec.js',
             'transport-config.js','qr.js','sw.js','style.css','app.webmanifest','i18n.js','ice-operation.js','_locales',
             'icon.svg','icon-48.png','icon-180.png','icon-192.png','icon-512.png','vendor/jsQR.js','vendor/jsQR.LICENSE')
icons = {str(size):f'icon-{size}.png' for size in (16,32,48,96,128)}

def archive_tree(directory, name):
    with zipfile.ZipFile(dist / name, 'w', zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(directory.rglob('*')):
            if file.is_file():
                archive.write(file, file.relative_to(directory))

def gecko(ident, mobile=False):
    value = {'gecko':{'id':ident,'strict_min_version':'142.0',
                     'data_collection_permissions':{'required':['none']}}}
    if mobile:
        value['gecko_android'] = {'strict_min_version':'142.0'}
    return value

for variant in ('chromium-browser','firefox-mobile','web-app'):
    output = dist / variant
    if output.exists():
        shutil.rmtree(output)
    output.mkdir()
    if variant == 'web-app':
        for name in web_files:
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source / name, target) if (source/name).is_dir() else shutil.copy2(source / name, target)
    else:
        shutil.copytree(source, output, dirs_exist_ok=True)
    shutil.copy2(root / 'THIRD_PARTY.json',output / 'THIRD_PARTY.json')
    if variant in ('web-app','chromium-browser','firefox-mobile'):
        (output / 'transport-config.js').write_text("export const MODE = 'browser';\n")
    if variant == 'web-app':
        archive_tree(output,'knock-control-web-app.zip')
        print(output)
        continue
    manifest = json.loads((source / 'manifest.json').read_text())
    manifest['version'] = '3.1.1'
    manifest['icons'] = icons
    if variant == 'chromium-browser':
        manifest.update({'permissions':['storage','offscreen'], 'optional_host_permissions':['https://*/*'],
            'background':{'service_worker':'background.js','type':'module'},
            'action':{'default_title':'__MSG_extensionName__','default_popup':'popup.html','default_icon':icons},
            'options_ui':{'page':'app.html','open_in_tab':True}})
    elif variant == 'firefox-mobile':
        shutil.copy2(source/'background-firefox.js',output/'background.js')
        for chromium_file in ('chromium-ice.js','offscreen.js','offscreen.html','background-firefox.js'):
            (output/chromium_file).unlink(missing_ok=True)
        # Firefox uses the same popup on desktop and Android; camera import has a full view.
        manifest = {'manifest_version':2,'name':'__MSG_extensionName__','version':'3.1.1','default_locale':'en',
            'description':manifest['description'],'icons':icons,'permissions':['storage'],
            'optional_permissions':['https://*/*'],
            'background':{'scripts':['background.js'],'type':'module','persistent':False},
            'browser_action':{'default_title':'__MSG_extensionName__','default_popup':'popup.html','default_icon':icons},
            'options_ui':{'page':'app.html','open_in_tab':True},
            'content_security_policy':"script-src 'self'; object-src 'none'",
            'browser_specific_settings':gecko('knock-control-mobile@local',True)}
    (output / 'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    archive_tree(output,f'knock-control-{variant}.zip')
    if variant.startswith('firefox'):
        shutil.copy2(dist / f'knock-control-{variant}.zip',dist / f'knock-control-{variant}.unsigned.xpi')
    print(output)
