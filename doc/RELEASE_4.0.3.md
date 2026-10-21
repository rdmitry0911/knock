# Knock Control 4.0.3 verification

Only ON, OFF and local profile import/selection/deletion remain in the browser.
Status, remote configuration, connection forms, HTTPS fallback and host permissions
are removed. The server no longer contains the HTTP API, CGI, TLS setup or
web-app hosting. New v3 profiles are self-contained; legacy v2 JSON/QR imports
are accepted. A deleted local profile does not revoke a server credential.

- 27 unit/protocol tests passed, including native C with ASan/UBSan (leak checking
  disabled for the process-lifetime/longjmp-based unit harness), profile deletion,
  removed-profile signing rejection, old-profile normalization, QR round trips
  and validation without TLS. Old HTTP-only tests were retired with the API.
- Chromium rendered all ten languages, imported/deleted profiles, checked cancel,
  fallback selection, persistence and the empty store. No settings/status UI or
  HTTPS host permissions remain. Actual toolbar opening also passed.
  [Report](v4-localization-popup-report.json), [popup](popup-v4.png).
- Real Chromium/Firefox ICE passed with the visible UI destroyed during delayed
  STUN, two source IPs sharing one credential, idle expiry, replay rejection and
  over 1.5 million noise packets. Isolated root namespace tests used browser test
  sandbox exceptions; released clients do not disable sandboxing.
  [Report](v4-ice-report.json).
- The final x86_64 APK passed both clean installation and upgrade from an active
  3.1.1 server in official OpenWrt 25.12.5 QEMU. Upgrade stopped the HTTPS API,
  removed its init/CGI, preserved credential secrets/revisions and removed the
  unconditional 8443 firewall grant. Both paths passed real Firefox/Chromium ICE,
  reboot/autostart and reinstall. No Python, HTTP listener, web client or TLS
  generation is installed. The ARM64/Airoha package is cross-built, not installed
  on physical hardware for this release.
  [Clean install](v4-openwrt-clean-report.json), [upgrade](v4-openwrt-upgrade-report.json).

Mozilla signing and permanent restart are checked in [stock Firefox](v4-firefox-signature-report.json). Actual Android 15 APKs are checked separately in the [Android report](v4-android-report.json).
