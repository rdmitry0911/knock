# 4.1.0 verification

Tested on 2026-10-26. This release handles networks where a browser's UDP ICE
packets and protected TCP connections arrive from different public IPv4 addresses.
Update both server and browser; existing credentials and profile revisions remain
usable. See the [wire protocol and trust boundary](SPLIT_IP_TRANSPORT.md).

## Browser and firewall behavior

- [Split-address integration](v4.1.0-split-ice-report.json): actual Chromium MV3
  and Firefox MV2 extension UI, distinct UDP/TCP NAT addresses, two clients sharing
  one credential, 2,577,500 noisy UDP packets, ON/OFF, established connection
  closure, independent idle expiry, durable replay rejection, command ordering and
  transmission after closing the popup. The isolated fixture pins access-IP
  discovery; STUN discovery runs in the fixture.
- [Live IP discovery](v4.1.0-ip-discovery-report.json): fresh Chromium and Firefox
  extension contexts returned an IPv4 using the external HTTPS discovery path,
  with no host permissions. No credentials were loaded for this check.
- [Proof regression](v4.1.0-proof-regression-report.json): the pre-hardening
  development binary accepted a blind port sweep; the final strict sequence
  rejects the same 2,040 SYN packets. UDP alone, TCP alone and an unrelated address
  hint do not grant access.
- [Legacy transport](v4.1.0-legacy-ice-report.json): same-address KNI1 remains
  functional. No open management listener is required by either transport.
- [Mozilla signature](v4.1.0-firefox-signature-report.json): stock Firefox 158.0.1
  rejects the unsigned package and permanently installs the signed 4.1.0 XPI,
  which remains active after restart with signature enforcement enabled.
- [Popup/localization](v4.1.0-localization-report.json): ten packaged languages,
  English fallback, toolbar popup, persistent JSON import and profile deletion;
  desktop QR remains hidden. No settings/status interface is included.

The Python/protocol suite passed 29 tests, including cross-language Python,
JavaScript and native OpenWrt C token/QR compatibility. The packet-parser C suite
and native controller checks passed with AddressSanitizer/UndefinedBehaviorSanitizer.
Firefox sandbox exceptions used for root network-namespace tests are test-only;
the signature test used a stock desktop installation.

## Packages

- [OpenWrt QEMU/KVM](v4.1.0-openwrt-vm-report.json): OpenWrt 25.12.5 x86_64,
  upgrade from 4.0.3, installed C daemon/controller, actual Chromium and Firefox
  packets, KNI1 and KNI2, nftables ON/OFF, replay rejection after restart,
  reboot/autostart and reinstall. Profile secrets/revisions survive.
- [DEB](v4.1.0-linux-deb-report.json) and
  [RPM](v4.1.0-linux-rpm-report.json): native builds and installation/lifecycle
  checks on disposable Ubuntu 22.04 and Rocky Linux 9 roots with isolated kernel
  networking. Installed daemon/controller ON/OFF and replay protection pass.
  These chroot checks do not exercise systemd PID 1 or reboot.
- OpenWrt airoha/an7581 APK is built separately using its target SDK. Server
  packages retain configuration and replay journals and install no port 8443 API.

The historical full Proxmox 8/9 VM evidence belongs to 4.0.3-2; see
[its report](PROXMOX_TESTING.md). No new full Proxmox VM or Android emulator run
is claimed for 4.1.0. The user's macOS/network end-to-end confirmation requires
installing the new signed XPI; isolated split-address regression success does not
by itself establish the result on that particular network.
