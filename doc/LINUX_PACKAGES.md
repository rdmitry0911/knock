# Linux server packages

The `v4.0.3` release also provides native x86_64 server packages:

- `knock-control_4.0.3-2_amd64.deb`: built on Ubuntu 22.04; Debian 12+ and Ubuntu 22.04+.
- `knock-control-4.0.3-2.el9.x86_64.rpm`: built on Rocky Linux 9; EL9-compatible systems.
- A source RPM and a Linux packaging source archive accompany these binaries.

These are server packages. Browser extensions remain separate release assets.
Existing OpenWrt APKs are unchanged; this does not add an Alpine Linux package.

Install the matching file with dependency resolution:

```sh
sudo apt install ./knock-control_4.0.3-2_amd64.deb
# Or, on an EL9-compatible distribution:
sudo dnf install ./knock-control-4.0.3-2.el9.x86_64.rpm
```

The packages install the administrator command as `/usr/sbin/knock-control`,
the private packet daemon as `/usr/sbin/knock-control-daemon`, Python modules
under `/usr/lib/knock-control`, and systemd units under `/usr/lib/systemd/system`.
They do not place files in `/usr/local` or replace a distribution's `knockd` binary.
They use iptables/ipset and require kernel support for ipset and the SET target.
An existing firewall manager must preserve the Knock Control chains.

Use revision **4.0.3-2** for Proxmox and other iptables-legacy systems. Revision
4.0.3-1 installed successfully in a Proxmox 8 VM but its systemd firewall unit
failed: legacy iptables-restore needs `CAP_NET_RAW` as well as `CAP_NET_ADMIN`.
Revision 2 adds that capability; it does not add a listener or change credentials.
Original revision 1 assets remain available for traceability. Browser extensions
and OpenWrt packages are unchanged. Full VM verification has a separate
[Proxmox guide](PROXMOX_TESTING.md).

Installation does not generate credentials, enable services or open ports.
Initialize locally, substituting the public IPv4 and interface:

```sh
sudo /usr/sbin/knock-control init --public-host 203.0.113.10 --interface eth0
sudo /usr/sbin/knock-control issue --name laptop --ports 22 --out /root/laptop.json
sudo /usr/sbin/knock-control activate
sudo systemctl enable knock-control.service knock-control-firewall.service
```

Import the issued JSON into the browser, then use ON/OFF. Use the local CLI for
rules, timeouts and revocation, as described in the main guide. No HTTPS API,
TLS certificate, web hosting or management listener is installed.

Configuration is generated in `/etc/knock-control/` and the durable replay journal
is in `/var/lib/knock-control/`. Package reinstall/upgrade preserves them.
Removal, including deb purge, deliberately retains credentials and replay state;
it stops the daemon without removing existing firewall protection. Remove these
directories manually only when retiring the server. Firewall rules remain until
the administrator removes them or the firewall is rebuilt.

For migration from the manual source installer, stop the old daemon and disable
the old API before installing. Back up the two directories above. Remove the
old `knock-control.service` and `knock-control-firewall.service` overrides from
`/etc/systemd/system`, run `systemctl daemon-reload`, and use the explicit
`/usr/sbin/knock-control` path: `/usr/local/sbin/knock-control` can otherwise take
precedence in PATH. Package installation migrates an existing configuration
without replacing its secrets. Retired API units are disabled when systemd is
running; the packages do not delete administrator-owned source installations.

Build natively using Python 3.9+ and the following tools:

```sh
# Ubuntu/Debian build dependencies:
sudo apt install gcc binutils libpcap-dev libssl-dev dpkg-dev python3
python3 scripts/build-linux-packages.py --format deb

# EL9 build dependencies:
sudo dnf --enablerepo=crb install gcc rpm-build libpcap-devel openssl-devel python3
python3 scripts/build-linux-packages.py --format rpm

# Source archive for the same packaging:
python3 scripts/build-linux-packages.py --format source
```

Run builds inside a disposable environment for the oldest intended target
distribution. Dependency versions are derived from its native libraries; a
binary built on a newer distribution is not automatically compatible with older
systems. The source archive and SRPM include the bundled QR library and license.

Verification reports accompany the release and are stored as
`doc/linux2-deb-install-report.json` and `doc/linux2-rpm-install-report.json`.
Both packages were installed with their native package manager in disposable
Ubuntu 22.04 / Rocky Linux 9.8 roots and isolated kernel network namespaces.
The installed packet daemon and Python callback performed real signed ICE
ON/OFF against kernel iptables/ipset; a captured ON remained rejected after a
daemon restart. Initialization, JSON/PNG issuance, unit verification, reinstall,
removal and credential/replay preservation also passed. Systemd PID 1 and reboot
were not exercised in these chroot checks. Other distributions/architectures
were not installed in this run.

To repeat installation checks, provide a fresh disposable root with runtime
dependencies installed, `/dev` and `/proc` mounted, and an isolated network
namespace with loopback up. Inside that root run:

```sh
python3 tests/linux_packages.py --format deb --package /path/package.deb --report /tmp/report.json
# Or use --format rpm --package /path/package.rpm.
```

The test refuses existing configurations and the host network namespace. It
creates temporary credentials, modifies only its namespace's firewall and tests
package removal. Run it only in a disposable root, never on a live server.
