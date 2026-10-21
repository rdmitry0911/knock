"""Standalone raw TCP/UDP transport for the command-line client."""
import errno
import socket
import select
import time
from common import settings,confirmation,sequence

def transport_config(bundle):
    return {'host':bundle['knock_host'], 'public_ip':bundle['public_ip'],
            'settings':settings({**bundle['settings'],'secret':bundle['secret'],'profile_id':bundle['profile_id']})}


def knock(config, action, code=None):
    cfg = config['settings']
    if cfg['ip_protection'] and not config['public_ip']:
        raise ValueError('Specify the public IPv4 seen by this server')
    # Resolve once: all packets in a sequence must hit the SAME IPv4 address.
    address = socket.getaddrinfo(config['host'], None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    count = len(cfg['protocols'])
    duration = count * .25 + .5
    if duration >= cfg['period']:
        raise ValueError('OTP period is too short for this sequence')
    remaining = cfg['period'] - time.time() % cfg['period']
    if remaining < duration:
        time.sleep(remaining + .05)
    stamp = time.time()
    proof = confirmation(cfg, action, config['public_ip'], now=stamp, code=code)
    ports = sequence(cfg, action, config['public_ip'], now=stamp, code=code)
    for port, proto in ports:
        if proto == 'udp':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b'\x00', (address, port))
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setblocking(False)
                code = sock.connect_ex((address, port))
                if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.ECONNREFUSED):
                    raise OSError(code, 'TCP knock failed')
                # Give the kernel time to transmit the SYN, then close before retransmission.
                select.select([], [sock], [], .1)
        time.sleep(.15)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(proof, (address, cfg['base']))
    return {'ok': True, 'sent': len(ports) + 1, 'message': 'Sequence sent; receipt by the server is not confirmed.'}
