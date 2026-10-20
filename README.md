## knock: A port-knocking implementation

Download browser extensions, the web app and architecture-specific OpenWrt APKs from [release v3.0.0-r6](https://github.com/rdmitry0911/knock/releases/tag/v3.0.0-r6). **Firefox XPI archives are unsigned and cannot be permanently installed in standard Firefox.** Chrome/Edge ZIPs require unpacking and developer mode. See [installation and Mozilla signing instructions (Russian)](doc/BROWSER_INSTALLATION_RU.md).

This fork includes **Knock Control**, a controlled emergency access mechanism for
sensitive services normally blocked from the public internet. It includes a
Chrome/Firefox extension, mobile QR import, an installable web app, a Linux native
bridge and an HTTPS controller for server-issued client credentials. Each credential
has its own rule policy: named TCP/UDP ports and ranges, ICMP, routed access and DNAT forwarding. Grants and traffic-based idle timeouts are independent
for each source IPv4, including clients sharing the same credential. New managed configurations use RFC 6238 TOTP
(Google Authenticator) and an authenticated UDP confirmation. See
[setup, protocol and verification instructions in Russian](README_RU.md).
Legacy `sequence =` and `otp =` formats remain available.

An OpenWrt 25.12 package recipe and SDK build script are included in
`packaging/openwrt` and `scripts/build-openwrt.py`. OpenWrt runs a native C
controller and packet daemon, a dedicated uhttpd HTTPS instance, procd and
firewall4/nftables. Settings and profiles use the standard UCI package
`/etc/config/knock-control`, with `uci commit` and init.d reload support.
It does not install Python. Schema-2 JSON configurations migrate automatically;
client credentials and the SQLite replay journal are preserved. Ordinary Linux installations
retain the Python controller and iptables/ipset.
See the OpenWrt section of README_RU.md for APK installation and QEMU verification.

### Browser ON/OFF without a management listener

Newly exported profiles advertise `ice_version: 1`. The browser extension/web app
uses WebRTC ICE connectivity checks to deliver an HMAC-SHA256 signed ON/OFF token
inside a STUN USERNAME. The daemon captures it with libpcap on the profile's base
UDP port: no UDP listener, STUN responder or reachable HTTPS API is required for
ON/OFF. HTTPS remains available for status, settings and the legacy browser mode.
The native bridge retains its TCP/UDP sequence transport.

Re-export and import the profile after updating the server. Select the transport
under connection settings; older profiles keep HTTPS until re-imported. The ICE
target must be a numeric IPv4 (a local override is provided for DNS profiles).
Public source discovery uses `stun:stun.cloudflare.com:3478`, or a configured STUN;
it receives no profile secret or signed command. A manual public IPv4 avoids STUN.
UDP and protected service traffic must leave through the same public IPv4.
WebRTC/UDP must be permitted by the browser and network. No automatic HTTPS fallback
is performed. Sending is unacknowledged; verify access through the protected service.
Nonces and per-IP command ordering persist in SQLite across daemon restarts.
An extension has its application files locally; the PWA needs prior HTTPS installation.
See the Russian guide for setup, protocol and current verification results.

Real Android APKs have also passed emulator tests on Android 15 / API 35 x86_64:
Chrome 124.0.6367.219 web app and Firefox 158.0.1 web app/temporary extension.
Checks cover real firewall ON/OFF with the HTTPS listener stopped, cached web-app
startup, idle expiry and replay rejection after restart. This does not establish
permanent Firefox installation or physical phone/iOS compatibility.
See the [Android lab instructions](doc/ANDROID_TESTING.md) and
[test report](doc/android-emulator-test-report.json).

### Named firewall rules

The same commands work on OpenWrt (native C/UCI/nftables) and Linux (iptables/ipset):

```sh
knock-control rule-set ssh_lan --type dnat --protocol tcp --ports 2222 --dest-ip 192.168.1.10 --dest-port 22
knock-control rule-set udp_range --type input --protocol udp --ports 11000-11100
knock-control rule-set ping --type input --protocol icmp
knock-control issue --name Phone --rules ssh_lan,ping --allowed-rules ssh_lan,ping,udp_range --out /root/phone.json --qr-out /root/phone.png
```

On OpenWrt each definition is a `config rule 'NAME'` section in
`/etc/config/knock-control`; profile lists `rules` and `allowed_rules` bind it to
an issued secret. Clients select only allowed names and cannot change targets.
`input` opens local services, `forward` permits routed traffic to `dest_ip`, and
`dnat` forwards to that host with optional single-port translation. Ranges keep
port numbers. ICMP defaults to echo-request; `--icmp-type any` selects all types.
ON/OFF and traffic idle expiry apply per source IP, including established NAT
flows. No SNAT is added; internal hosts need a return route. IPv6 is not supported.
See the Russian guide for full UCI examples, migration and verification.

### Motivation

Knock Control can act as a preconfigured emergency entrance (a controlled
"backdoor") when the usual access method, such as a VPN, is unavailable because
of a service failure, routing problem, client configuration or network restrictions.
An authorized client can temporarily reach sensitive SSH, RDP, administration or
other TCP/UDP services that are normally inaccessible from the public internet,
restore the primary access method, and remove its grant with OFF. Protected
service traffic refreshes only that source IP's idle timeout; otherwise the grant
expires automatically. The service retains its normal authentication.

Set up and test this path before an incident. It works independently of the VPN
as long as the server and the selected knock transport or HTTPS control API
remain reachable. The firewall supports the host's IPv4 services and routed/DNAT access to internal
hosts. Forwarding requires IP routing and a return route through this server;
services bound only to localhost require a proxy.

Two clients can import the same profile: with different public IPv4 addresses,
ON/OFF and idle expiry affect their own grants. Profile settings and revocation
are shared; changing settings resets all grants of that profile. Devices sharing
one public IPv4 behind NAT also share one grant. Issue separate credentials when
independent settings or revocation are required.


Copyright (c) 2004, Judd Vinet <jvinet@zeroflux.org>

### ABOUT  

This is a port-knocking server/client.  Port-knocking is a method where a
server can sniff one of its interfaces for a special "knock" sequence of
port-hits.  When detected, it will run a specified event bound to that port
knock sequence.  These port-hits need not be on open ports, since we use
libpcap to sniff the raw interface traffic.


### BUILDING

To build knockd, make sure you have libpcap and the autoconf tools
installed. Then run the following:

    $ autoreconf -fi
    $ ./configure --prefix=/usr/local
    $ make
    $ sudo make install


### EXAMPLE  

The example below could be used to run a strict (DENY policy) firewall that
can only be accessed after a successful knock sequence.

  1. Client sends four TCP SYN packets to Server, at the following ports:
     38281, 29374, 4921, 54918
  2. Server detects this and runs an iptables command to open port 22 to
     Client.
  3. Client connects to Server via SSH and does whatever it needs to do.
  4. Client sends four more TCP SYN packets to Server:  37281, 8529,
     40127, 10100
  5. Server detects this and runs another iptables command to close port
     22 to Client.

### EXAMPLE  WITH ONE TIME PASSWORD AND SRC IP PROTECTION
The legacy `otp =` mode below derives changing ports from a decimal time counter and optionally binds a suffix to the source IPv4. It is not RFC 6238 and does not provide complete protection against replay or an active on-path attacker. The new `totp =` mode described in README_RU.md uses standard authenticator codes plus a signed confirmation. The legacy configuration format is:

otp = AAgR%XXx30O$#, 45, 20000, on, tcp, udp, tcp

in this  section

- AAgR%XXx30O$# is a seed which is used to generate one time port numbers sequence
- 45 is otp_change_time. The time in secs of how often we  change our dynamic port numbers
- 20000 is a ports range starting point (unsigned short). This is a starting point of  256 numbers area, used for random port numbers generation. Usually is bigger then 1000. Each port number is generated by an algorythm in the range of 0-255 and then added to this number. So, in this examples a random port numbers within a range of 20000-20255 will be generated each time.
- on is ip_protection flag (boolean on/off). It specifies if we need additional ports generated based on mix of the key and the sender ip address to validate sender. Only in rear cases where the sender can't know for sure it's public IP address or if internet provider has several public IP addresses which are used on round-robin basis for providing internet access to its customers, this flag should be set to off. In these rear cases only time-based port generation might be used, which is less secure, but better than nothing. 
- tcp, udp, tcp - protocol sequence. These are the protocols used for every generated port sequence. The number of protocol names defines the number of port numbers derived from the seed. If ip_protection flag is set to on, additional random port numbers are generated based on src ip of a sender. The number and types of these additional ports are the same as the primary ones. In this examples 3 additional port numbers will be generated resulting in total 6 port numbers seqence of these protocols: tcp, udp, tcp, tcp, udp, tcp

`knockd.sh` now invokes the Python client for the new managed TOTP profile.
Building knockd requires libpcap and OpenSSL libcrypto development packages.
Use `scripts/build.sh` or the autotools build above.

### KNOCKING CLIENTS

The accompanying knock client is very basic.  If you want to do more advanced
knocks (eg, setting specific tcp flags) then you should take look at hping,
sendip or packit.

  - [hping](http://freshmeat.net/projects/hping/)
  - [sendip](http://freshmeat.net/projects/sendip/)
  - [packit](http://freshmeat.net/projects/packit/)


### OTHER IMPLEMENTATIONS  

Here are some other implementations of port-knocking:

  - [pasmal](http://sourceforge.net/projects/pasmal/)
  - [doorman](http://doorman.sourceforge.net/)

