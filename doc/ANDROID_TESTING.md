# Android emulator verification

Verified on 2026-10-20 against release `v3.0.0-r6`, production commit
`a8800eae591eacb3a58c12ddf4bafc85b9e3ea42`:

| Android 15 / API 35 / x86_64, KVM | Result |
|---|---|
| Chrome APK 124.0.6367.219 (system image), web app | PASS |
| Firefox APK 158.0.1 (Mozilla release), temporary original release XPI | PASS |
| Firefox APK 158.0.1, web app | PASS |

All three verified enrollment import/persistence, real protected-service access
with ICE ON/OFF while HTTPS was stopped, idle expiry, replay rejection after
daemon restart, and signed HTTPS status. Both web apps reopened from their saved
cache with HTTPS stopped. Chrome also changed the profile configuration and used
the new revision for ICE. Each ICE stage issued zero API requests and had no
listening knock UDP socket. Android browser sandboxing stayed enabled.
See the [machine-readable report](android-emulator-test-report.json) and
supplemental `knock-control-android-test-evidence.zip` on the
[release page](https://github.com/rdmitry0911/knock/releases/tag/v3.0.0-r6).

The Android checks use a real Android AVD and Android APKs, with the native
packet daemon, signed controller callbacks, iptables/ipset and protected HTTP
listeners in a disposable Linux network namespace. A Unix socket controls the
test fixture; it is separate from the application's HTTPS API. The checks stop
the HTTPS listener before ICE ON/OFF and verify access through the browser.

Components:

- `tests/android_lab.py`: start a dedicated AVD and ADB in a private namespace.
- `tests/android_fixture.py`: real server/firewall/STUN fixture, with no production profiles.
- `tests/android_chrome.mjs`: Chrome Android through Playwright Android/CDP.
- `tests/android_session.py`: Firefox Android WebDriver session.
- `tests/android_firefox.py`: original release XPI installed temporarily, or the mobile web app.

Use an installed Android SDK, a dedicated Google APIs x86_64 AVD containing
Chrome, KVM, an official x86_64 Firefox Android APK, geckodriver, Node.js 22+
and Playwright. The host also needs the ordinary Linux daemon/firewall build
dependencies described in README_RU.md. Do not run firewall fixtures outside
an isolated network namespace; both the launcher and fixture check this.

For SDK/AVD setup see the [Android emulator command-line documentation](https://developer.android.com/studio/run/emulator-commandline).
Firefox APKs are available from [Mozilla's archive](https://archive.mozilla.org/pub/fenix/releases/).

Example launcher (keep it running in one terminal):

```sh
export ANDROID_SDK_ROOT=/path/to/android-sdk
export ANDROID_AVD_HOME=/path/to/test-avds
sudo --preserve-env=ANDROID_SDK_ROOT,ANDROID_AVD_HOME unshare --net \
  python3 tests/android_lab.py --directory /tmp/knock-android-lab --avd knock-api35
```

Use the PID in `/tmp/knock-android-lab/pid` to enter the same namespace in another
terminal with `sudo nsenter -t PID -n bash`. All commands below run there, from
the repository root. Wait for `adb shell getprop sys.boot_completed` to return
`1`. Ensure Wi-Fi is connected (`adb shell cmd wifi connect-network AndroidWifi open`
for this AVD); cached pages can load even when Android has no network. Install the Firefox APK with `adb install -r /path/firefox.apk`, and finish
its first-run welcome screens in the dedicated AVD. Native permission prompts
are part of the real browser UI; temporary extension installation confirms its
native “added” dialog, and the HTTPS status test grants the requested host access.

```sh
python3 tests/android_fixture.py /tmp/knock-android-lab/fixture > /tmp/android-fixture.log 2>&1 &
# Wait for fixture/ready.json. Build browser artifacts first if dist is absent.
PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs node tests/android_chrome.mjs /tmp/knock-android-lab/fixture
# Chrome changes the profile revision; export the current enrollment for Firefox.
python3 - <<'PY'
import json, socket
with socket.socket(socket.AF_UNIX) as connection:
    connection.connect('/tmp/knock-android-lab/fixture/control.sock')
    connection.sendall(json.dumps({'op': 'export-profile'}).encode())
    while connection.recv(65536):
        pass
PY
geckodriver --allow-system-access --port 4444 > /tmp/android-geckodriver.log 2>&1 &
python3 tests/android_session.py --out /tmp/knock-android-lab/session.json
ADB_BIN=/path/to/android-sdk/platform-tools/adb python3 tests/android_firefox.py \
  /tmp/knock-android-lab/fixture /tmp/knock-android-lab/session.json extension
ADB_BIN=/path/to/android-sdk/platform-tools/adb python3 tests/android_firefox.py \
  /tmp/knock-android-lab/fixture /tmp/knock-android-lab/session.json pwa
```

If a prior test configured the profile, re-export the fixture's current profile
and enrollment URL before importing it into another client: clients must use the
current revision. Test outputs contain JSON reports and screenshots, while the
fixture directory contains temporary secrets and must stay private. Only reports
and screenshots with an empty import field belong in published evidence.

The lab uses a self-signed test certificate. Chrome accepts it only in its
disposable test process. Firefox WebDriver enables `acceptInsecureCerts`; the web
app test additionally imports the fixture CA into its disposable NSS profile
(the current driver does this for either mode). This does not
change TLS handling in released clients. The Firefox XPI is a temporary debug
installation, not a Mozilla-signed permanent installation. An emulator run is
not verification on physical phones, other Android versions or Safari/iOS.
These runs imported enrollment URL/text, not a camera/gallery image, and did not
test adding a launcher icon. Chrome is the exact system image version above,
not a claim about the latest Chrome release. For permanent browser installation
see the [Mozilla signing and installation guide](BROWSER_INSTALLATION_RU.md).
