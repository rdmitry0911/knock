# Proxmox VE DEB verification

Use **knock-control 4.0.3-2** on Proxmox VE. The original `4.0.3-1` DEB
installed but failed to activate in the Proxmox 8 VM. Its firewall unit allowed
only `CAP_NET_ADMIN`; Proxmox uses iptables-legacy, which also needs
`CAP_NET_RAW`. A transient systemd unit reproduced exit status 2 without that
capability and success with it, using identical saved firewall rules. The
revision 2 unit adds `CAP_NET_RAW` while retaining `NoNewPrivileges=true`.
See the [original failure report](proxmox-original-deb-failure.json).

The corrected DEB is checked in full QEMU/KVM VMs containing actual Proxmox VE
packages, their own Proxmox kernels and systemd PID 1:

| Node | Kernel | Base |
|---|---|---|
| Proxmox VE / pve-manager 8.4.21 | 6.8.12-43-pve | Debian 12 |
| Proxmox VE / pve-manager 9.2.21 | 7.0.14-25-pve | Debian 13 |

The reports record exact package/image checksums, `pveversion -v`, runtime
dependencies and completed phases:

- [Proxmox 8 report](proxmox8-vm-report.json)
- [Proxmox 9 report](proxmox9-vm-report.json)

The test installs the DEB through apt, checks that installation does not create
credentials or start the server, initializes a profile and exports JSON/PNG.
The administrator activates the real systemd firewall and packet daemon units.
Chromium and Firefox then send real signed WebRTC ICE packets to the guest:
the Proxmox HTTPS UI on TCP 8006 must be blocked before ON, reachable after ON
and blocked after OFF. A captured ON must remain rejected after a daemon
restart. The same access checks run with the datacenter and node classic
`pve-firewall` enabled and after a full reboot. Credentials must survive reboot
and apt reinstall; both Knock Control units must autostart after reboot.

The test's classic firewall policy for unrelated input/output is ACCEPT so SSH
can administer the disposable guest. It explicitly checks `enabled/running`
status and the `PVEFW-INPUT` hook. This is not a claim about arbitrary custom
Proxmox firewall rules, clusters, guest VM/container workloads, IPv6 or the
alternative Proxmox nftables firewall. Browser packets are tested from the
host over QEMU user-network forwards; no host firewall changes are made.
Only the probe accepts the disposable PVE UI's self-signed TLS certificate.
Knock Control itself still has no HTTP API or management listener.

Install or upgrade with the revision 2 release asset:

```sh
sudo apt install ./knock-control_4.0.3-2_amd64.deb
sudo /usr/sbin/knock-control activate
sudo systemctl enable knock-control.service knock-control-firewall.service
```

For a new server, run `init` and `issue` before `activate`, as described in the
[Linux guide](LINUX_PACKAGES.md). Existing profiles and secrets are retained.
The revision 1 assets stay unchanged for traceability. OpenWrt and browser
packages are unaffected by this Linux systemd correction.
For Linux server source builds, use the supplemental `knock-control-4.0.3-linux2.tar.gz`
or the updated repository. The original full `4.0.3-source.zip` predates this
systemd fix and remains unchanged as a historical release artifact.

To reproduce, install QEMU/KVM, `cloud-localds`, SSH and Node/Playwright on a
test machine. Build/download the browser web-app payload into `dist/web-app`
and set `PLAYWRIGHT_MODULE` to Playwright's module path. Download official
[Debian 12](https://cloud.debian.org/images/cloud/bookworm/latest/) and
[Debian 13](https://cloud.debian.org/images/cloud/trixie/latest/)
`genericcloud-amd64.qcow2` images, checking their published SHA512 sums. Obtain
the official Proxmox public repository keyrings:

- [Bookworm keyring](https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg)
- [Trixie keyring](https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg)

```sh
python3 tests/proxmox_vm.py --major 8 \
  --image /path/debian-12.qcow2 --keyring /path/proxmox-bookworm.gpg \
  --package /path/knock-control_4.0.3-2_amd64.deb \
  --work /tmp/knock-test-pve8 --report /tmp/proxmox8-report.json
# Repeat with --major 9 and the Debian 13 / Trixie inputs.
```

The runner installs actual `proxmox-ve` and `proxmox-default-kernel` packages
from the appropriate official no-subscription repository. It handles the
cloud image's GRUB disk selection and restores its disposable SSH key after
Proxmox moves authorized keys into pmxcfs. `--resume` reuses only the same
disposable test disk and resets its test credentials. It must not target a
production disk. Work directories contain private test profiles and SSH keys;
publish only the JSON reports, not work directories, disks or complete logs.
