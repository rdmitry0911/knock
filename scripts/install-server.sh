#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then echo 'Run with sudo on the target Linux server' >&2; exit 1; fi
for binary in /usr/sbin/ipset /usr/sbin/iptables /usr/sbin/iptables-restore /usr/bin/python3 /usr/bin/systemctl /usr/bin/openssl; do
    if [ ! -x "$binary" ]; then echo "Missing $binary" >&2; exit 1; fi
done
if [ ! -x ./knockd ]; then echo 'Build knockd with scripts/build.sh first' >&2; exit 1; fi
install -d -m 755 /usr/local/lib/knock-control
install -d -m 700 /etc/knock-control
install -m 644 controller/common.py controller/server.py controller/api.py controller/qr_codec.py controller/rules.py controller/iptables_rules.py /usr/local/lib/knock-control/
install -d -m 755 /usr/local/lib/knock-control/vendor
install -m 644 controller/vendor/qrcodegen.py /usr/local/lib/knock-control/vendor/
python3 scripts/package-extension.py
install -d -m 755 /usr/local/share/knock-control/app
cp -R dist/web-app/. /usr/local/share/knock-control/app/
find /usr/local/share/knock-control/app -type d -exec chmod 755 {} +
find /usr/local/share/knock-control/app -type f -exec chmod 644 {} +
install -m 755 knockd /usr/local/sbin/knockd
cat > /usr/local/sbin/knock-control <<'WRAPPER'
#!/bin/sh
exec /usr/bin/python3 -I /usr/local/lib/knock-control/server.py "$@"
WRAPPER
chmod 755 /usr/local/sbin/knock-control
install -m 644 packaging/knock-control.service packaging/knock-control-firewall.service packaging/knock-control-api.service /etc/systemd/system/
systemctl daemon-reload
echo 'Installed. Initialize with: sudo knock-control init --public-host HOST --interface INTERFACE'
echo 'Issue client files with knock-control issue, distribute them, then run knock-control activate.'
echo 'Enable boot: sudo systemctl enable knock-control.service knock-control-firewall.service knock-control-api.service'
