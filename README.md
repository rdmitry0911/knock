# Knock Control 4

[Download v4.0.3](https://github.com/rdmitry0911/knock/releases/tag/v4.0.3): Mozilla-signed Firefox XPI, Chromium ZIP, Linux DEB/RPM, OpenWrt APKs and sources. [Linux packages](doc/LINUX_PACKAGES.md). [Russian guide](README_RU.md).

Knock Control provides a preconfigured emergency entrance (a controlled
"backdoor") when the usual access path, such as a VPN, fails. It temporarily
opens sensitive SSH, RDP, administration and other services that are normally
blocked from the public internet. Service authentication remains in place.
Configure and test this path before an incident; UDP/WebRTC and the server's
network path must remain reachable.

The browser client contains only **ON, OFF and local profile management**:
import, select and delete. Click its toolbar icon to open the popup. Desktop
imports JSON files/text; mobile clients also scan QR codes or import QR images.
Profile deletion removes the stored credential from this browser. Press OFF
first if you need immediate closure; deletion does not revoke the server's
credential or clear a remote grant. Server-side revocation remains an admin CLI
operation. A missing response is expected: the client reports that a knock was
sent, not that the firewall acknowledged it.

ON/OFF uses HMAC-signed WebRTC ICE checks captured by libpcap on a closed UDP
port. **No HTTPS API, port 8443, TLS certificate, management listener or local
helper is needed.** Closing the popup does not abort the extension's transmission.
STUN discovers the public IPv4 for each command; it receives no profile secret or
signed command. WebRTC/UDP must be available and use the same public source IPv4
as the protected service. Administrators may supply `ice_host`, `ice_source` and
`stun_server` in the imported JSON instead of the defaults.

The server generates credentials with their own rules and traffic-based idle
timeouts. Two addresses sharing one credential have independent ON/OFF grants;
traffic refreshes only its own address. Devices behind one public IPv4 share a
grant. Rules, timeouts and revocation are managed locally by the administrator,
through UCI on OpenWrt or the local controller/configuration on Linux. There are
no browser settings, server-status requests, HTTPS fallback or remote configuration
endpoints. Named rules support TCP/UDP ports and ranges, ICMP, forwarding and DNAT.
The standalone TCP/UDP CLI remains available.

OpenWrt uses native C, procd and firewall4/nftables. Configuration is
`/etc/config/knock-control`; no Python, dedicated uhttpd or web application is
installed. Linux uses the Python administrator CLI, systemd and iptables/ipset.
An upgrade stops/disables the retired API and removes its unit/CGI. Existing
credentials and replay journals are preserved; old ICE-enabled JSON/QR profiles
can be imported. New v3 profiles and `knock-control://import/` QR payloads contain
no management URL or certificate pin. Servers must support ICE; update a pre-ICE server before using this client.
Re-export a profile if its revision or target address is outdated.

The optional web client for mobile browsers without extensions is a **separate
static ZIP**. Host it on any trusted HTTPS static site, install/cache it, and
import a profile inside it. The knock server does not host that site. A new QR
is imported inside the client; it does not open a page on the knock server.

Ten packaged languages follow the browser language: English (default), Russian,
German, French, Spanish, Brazilian Portuguese, Simplified Chinese, Japanese,
Arabic (RTL) and Hindi. The icon comes from the owner's Mozilla profile.

See [installation](doc/BROWSER_INSTALLATION_RU.md), [v4 verification](doc/RELEASE_4.0.3.md)
and the Russian guide for server setup, local administration and migration.

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

