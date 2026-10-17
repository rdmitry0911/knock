#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
./scripts/build.sh
cc -g -Wall -Wextra -Wno-unused-parameter -fsanitize=address,undefined -fno-omit-frame-pointer ${PCAP_CFLAGS:-} -o tests/test_knockd tests/test_knockd.c src/list.c ${PCAP_LIBS:--lpcap} -lcrypto
ASAN_OPTIONS=detect_leaks=1 tests/test_knockd
python3 -m unittest discover -s tests -p 'test_*.py' -v
for file in extension/*.js; do node --input-type=module --check < "$file"; done
python3 scripts/package-extension.py
