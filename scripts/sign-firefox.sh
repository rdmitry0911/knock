#!/bin/sh
# Run explicitly to submit the prepared source to Mozilla for unlisted signing.
set -eu
cd "$(dirname "$0")/.."
: "${WEB_EXT_API_KEY:?Set WEB_EXT_API_KEY from addons.mozilla.org}"
: "${WEB_EXT_API_SECRET:?Set WEB_EXT_API_SECRET from addons.mozilla.org}"
if [ "$#" -ne 0 ]; then
    echo 'Usage: scripts/sign-firefox.sh (one Firefox extension for desktop and Android)' >&2
    exit 1
fi
command -v web-ext >/dev/null
python3 scripts/package-extension.py
knock_sign_source=$(mktemp -d "${TMPDIR:-/tmp}/knock-firefox-sign.XXXXXX")
trap 'rm -rf "$knock_sign_source"' EXIT HUP INT TERM
cp -R dist/firefox-mobile/. "$knock_sign_source/"
web-ext sign --no-config-discovery --source-dir "$knock_sign_source" --artifacts-dir dist/signed-firefox-mobile --channel unlisted
KNOCK_SIGN_SOURCE="$knock_sign_source" python3 - <<'PY'
import json
import os
from pathlib import Path
import shutil
import zipfile
manifest = json.loads((Path(os.environ['KNOCK_SIGN_SOURCE']) / 'manifest.json').read_text())
matches = []
for path in Path('dist/signed-firefox-mobile').glob('*.xpi'):
    with zipfile.ZipFile(path) as archive:
        signed = json.loads(archive.read('manifest.json'))
        if signed['version'] == manifest['version'] and signed['browser_specific_settings']['gecko']['id'] == manifest['browser_specific_settings']['gecko']['id']:
            assert 'META-INF/mozilla.rsa' in archive.namelist()
            matches.append(path)
if len(matches) != 1:
    raise SystemExit('Expected exactly one Mozilla-signed XPI for this version')
target = Path('dist') / ('knock-control-firefox-' + manifest['version'] + '.xpi')
shutil.copy2(matches[0], target)
print(target)
PY
