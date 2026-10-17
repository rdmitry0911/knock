#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Standard build: install libpcap-dev and libssl-dev first.
# PCAP_CFLAGS/PCAP_LIBS can point to locally extracted development packages.
cc ${CFLAGS:--O2 -g -Wall -Wextra -Wno-unused-parameter} ${PCAP_CFLAGS:-} -o knockd src/knockd.c src/list.c ${PCAP_LIBS:--lpcap} -lcrypto
cc ${CFLAGS:--O2 -g -Wall -Wextra} -o knock src/knock.c
