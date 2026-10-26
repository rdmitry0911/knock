# Split UDP/TCP access addresses (4.1.0)

A browser can send UDP from one public IPv4 while its HTTPS/SSH connections
reach a service from another, even without an intentionally configured VPN.
KNI1 authorizes the observed UDP source, so a successfully sent knock does not
make a different TCP source reachable. The client now discovers the access IPv4
through `https://api.ipify.org/?format=json`, with `https://ipv4.icanhazip.com/`
as fallback, independently of STUN's UDP source discovery. Discovery receives
no credentials, target hostname, authentication token or enrollment data.

If the addresses match, the existing KNI1 behavior is retained. Otherwise the
client sends a KNI2 authenticated STUN request and then a TCP SYN proof through
ordinary HTTPS HEAD connection attempts to closed ports in the profile's knock
range. No listener, TLS exception, native helper or additional extension host
permission is required. Expected connection failures are absorbed; there is
still no server acknowledgement. The success message identifies the access IP.

KNI2 is 165 ASCII characters, like KNI1:

| Offset | Length | Content |
|---|---|---|
| 0 | 4 | `KNI2` |
| 4 | 24 | Profile ID |
| 28 | 1 | `O` or `C` |
| 29 | 8 | Revision, hexadecimal |
| 37 | 8 | 30-second time counter, hexadecimal |
| 45 | 8 | Claimed TCP access IPv4, hexadecimal |
| 53 | 16 | Millisecond command timestamp, hexadecimal |
| 69 | 32 | Random nonce, hexadecimal |
| 101 | 64 | HMAC-SHA256, hexadecimal |

The HMAC covers `knock-control:ice:v2:PREFIX:UDP_SOURCE` (or `-` when source
binding was explicitly disabled), where PREFIX is the first 101 characters.
The claimed access address is covered by the HMAC. Only unicast IPv4 addresses
with first octet 1..223 are accepted. Packet revision/time checks remain in
force. The daemon authenticates against the actual observed UDP source.

An authenticated KNI2 request creates a bounded pending entry for 20 seconds;
it does not change firewall grants. Up to 128 such entries are held. Six unique
TCP destination ports are derived from the first six MAC bytes: offset = byte
modulo 255; increment modulo 255 to avoid prior offsets; port = base + 1 + offset.
The browser sends two ordered passes with short intervals. Only incoming SYNs
without ACK/RST, from the claimed access IP and addressed to this daemon's
configured target, advance the pending proof. Unrelated traffic does not reset
or extend its deadline. SYNs outside that profile's proof range are ignored;
an unexpected SYN inside it resets the sequence, while a retransmission of its
last matched SYN is ignored. This prevents a blind port sweep from manufacturing
the proof as a subsequence. TCP proof alone and authenticated UDP alone cannot grant
access in split mode. An incorrect or malicious IP-echo answer cannot authorize
another address without that address's corresponding TCP proof.

After a complete proof, the trusted controller rechecks the HMAC and revision,
reserves the nonce durably and orders commands by **access IPv4**, then adds or
removes that address's grant. A changed UDP route cannot make a late ON supersede
a newer OFF for the same access IP. Other access IPs remain independent. The
existing durable replay journal is retained on update; it is not renamed or
cleared. Capture/replay after daemon restart must not reopen a closed grant.

Profiles and secrets do not need reissuing. Both server and browser must be
updated for split mode. Old browsers remain compatible in same-source networks.
An optional, administrator-supplied JSON field `access_source` pins the access
IPv4 instead of querying discovery services; `ice_source` pins the UDP source.
Pinned values must be updated when their corresponding address changes. Leaving
them absent is recommended for roaming clients. QR/JSON import preserves both.

The regression environment uses isolated network namespaces with distinct NAT
addresses for TCP and UDP, real browser UI, the real packet daemon/controller
and kernel firewall grants. Its access-IP discovery value is supplied by the
fixture; live discovery availability/CORS is checked separately. The public-class
test addresses exist only inside those namespaces, which have no external
network interfaces. No production firewall or profile is modified by the tests.
