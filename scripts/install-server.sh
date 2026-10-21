#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then echo 'Run with sudo on the target Linux server' >&2; exit 1; fi
for binary in /usr/sbin/ipset /usr/sbin/iptables /usr/sbin/iptables-restore /usr/bin/python3 /usr/bin/systemctl; do
    if [ ! -x "$binary" ]; then echo "Missing $binary" >&2; exit 1; fi
done
if [ ! -x ./knockd ]; then echo 'Build knockd with scripts/build.sh first' >&2; exit 1; fi
install -d -m 755 /usr/local/lib/knock-control
install -d -m 700 /etc/knock-control /var/lib/knock-control
install -m 644 controller/common.py controller/server.py controller/qr_codec.py controller/rules.py controller/iptables_rules.py /usr/local/lib/knock-control/
install -d -m 755 /usr/local/lib/knock-control/vendor
install -m 644 controller/vendor/qrcodegen.py /usr/local/lib/knock-control/vendor/
# An upgrade must stop and disable the retired API before removing its unit.
if [ -f /etc/systemd/system/knock-control-api.service ]; then
    systemctl disable --now knock-control-api.service
    rm -f /etc/systemd/system/knock-control-api.service
fi
rm -f /usr/local/lib/knock-control/api.py
rm -rf /usr/local/share/knock-control/app
install -m 755 knockd /usr/local/sbin/knockd
cat > /usr/local/sbin/knock-control <<'WRAPPER'
#!/bin/sh
exec /usr/bin/python3 -I /usr/local/lib/knock-control/server.py "$@"
WRAPPER
chmod 755 /usr/local/sbin/knock-control
install -m 644 packaging/knock-control.service packaging/knock-control-firewall.service /etc/systemd/system/
systemctl daemon-reload
if [ -f /etc/knock-control/settings.json ]; then /usr/local/sbin/knock-control migrate; fi
echo 'Installed. Initialize with: sudo knock-control init --public-host HOST --interface INTERFACE'
echo 'Issue client files with knock-control issue, distribute them, then run knock-control activate.'
echo 'Enable boot: sudo systemctl enable knock-control.service knock-control-firewall.service'
