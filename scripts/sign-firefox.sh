#!/bin/sh
# Run explicitly to submit the prepared source to Mozilla for unlisted signing.
set -eu
cd "$(dirname "$0")/.."
: "${WEB_EXT_API_KEY:?Set WEB_EXT_API_KEY from addons.mozilla.org}"
: "${WEB_EXT_API_SECRET:?Set WEB_EXT_API_SECRET from addons.mozilla.org}"
variant=${1:-firefox-mobile}
case "$variant" in firefox|firefox-mobile) ;; *) echo 'Choose firefox or firefox-mobile' >&2; exit 1 ;; esac
command -v web-ext >/dev/null
python3 scripts/package-extension.py
exec web-ext sign --no-config-discovery --source-dir "dist/$variant" --artifacts-dir "dist/signed-$variant" --channel unlisted
