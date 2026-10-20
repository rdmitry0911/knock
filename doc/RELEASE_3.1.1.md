# Knock Control 3.1.1 verification

This version adds ten packaged interface languages, English source text, a
compact toolbar popup, the owner's Mozilla profile icon and desktop JSON import.
QR/camera import remains available on mobile. ICE transmission runs in an
extension background document so closing the popup does not abort it. Queued
commands retain their originally selected profile.

- 33 Python tests passed, including JavaScript/Python token compatibility,
  per-profile command binding, enrollment, translation catalogs and native C
  controller/protocol checks. Native tests used ASan and UBSan; leak checking was
  disabled for the process-lifetime/longjmp-based test harness.
- Mozilla web-ext lint: zero errors, notices or warnings. Mozilla-signed 3.1.1
  installed permanently in stock Firefox 158.0.1 with signature enforcement and
  remained active after restart; an unsigned permanent install was rejected.
  See [signature report](firefox-signed-install-report.json).
- Chromium rendered all ten locales and English fallback, checked Arabic RTL,
  desktop JSON import, QR hiding, saved profiles and actual toolbar popup opening.
  See [localization report](localization-popup-test-report.json) and
  [popup screenshot](popup-desktop.png).
- Chromium and Firefox real ICE/firewall tests passed with delayed STUN while
  destroying the visible UI during ON/OFF, two source IPs sharing a profile,
  replay rejection and idle expiry under over 1.5 million noise packets. These
  isolated root network namespace runs disabled the Firefox test sandbox;
  released code does not change browser sandbox settings.
  See [ICE report](popup-ice-test-report.json).
- Official OpenWrt 25.12.5 x86_64 in QEMU installed the 3.1.1-r1 APK and resolved
  dependencies. Upgrade from 3.0.0-r6, UCI migration, all ten language files over
  real uhttpd, real WAN/named rules, Firefox/Chromium ICE, reboot and reinstall
  passed. OpenWrt runs without Python. The Airoha/AN7581 ARM64 package was
  cross-built with the matching SDK; this release was not installed on physical
  ARM hardware. See [VM report](openwrt-vm-test-report.json).

Android APK and permanent signed Firefox installation results are documented
separately in [Android testing](ANDROID_TESTING.md) and
[browser installation](BROWSER_INSTALLATION_RU.md).
