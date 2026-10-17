#!/bin/sh
# Use the same TOTP implementation as the extension; no embedded/demo secrets.
set -eu
exec /usr/bin/python3 "$(dirname "$0")/controller/client.py" "$@"
