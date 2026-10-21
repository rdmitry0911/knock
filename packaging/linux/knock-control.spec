Name:           knock-control
Version:        4.0.3
Release:        1%{?dist}
Summary:        Authenticated emergency access with browser ON/OFF
License:        GPL-2.0-or-later AND MIT
URL:            https://github.com/rdmitry0911/knock
Source0:        knock-control-%{version}-linux.tar.gz
BuildRequires:  gcc
BuildRequires:  libpcap-devel
BuildRequires:  openssl-devel
BuildRequires:  python3 >= 3.9
Requires:       python3 >= 3.9
Requires:       iptables
Requires:       ipset
Requires:       systemd
Requires:       coreutils
Requires(post): python3 >= 3.9
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Server-issued TOTP profiles and authenticated ICE knocks open per-address
firewall grants with traffic-based idle expiry. Includes a Python administrator
CLI and systemd units. No HTTP API or management listener is installed.

%prep
%setup -q -n knock-control-%{version}

%build
%{__cc} %{optflags} -fPIE -pie -Wl,-z,relro,-z,now -o knock-control-daemon src/knockd.c src/list.c -lpcap -lcrypto

%install
python3 packaging/linux/stage.py --dest %{buildroot} --daemon knock-control-daemon

%post
. /usr/lib/knock-control/package-maint.sh
knock_configure

%preun
if [ "$1" -eq 0 ]; then
    . /usr/lib/knock-control/package-maint.sh
    knock_remove
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi

%files
/usr/sbin/knock-control
/usr/sbin/knock-control-daemon
/usr/lib/knock-control/
/usr/lib/systemd/system/knock-control.service
/usr/lib/systemd/system/knock-control-firewall.service
%doc /usr/share/doc/knock-control/README.md
%doc /usr/share/doc/knock-control/THIRD_PARTY.json
%license /usr/share/doc/knock-control/COPYING

%changelog
* Wed Oct 21 2026 Dmitry R <29107637+rdmitry0911@users.noreply.github.com> - 4.0.3-1
- Package the knock-only server with local profile administration.
