#!/usr/bin/python3
"""Boot disposable Debian QEMU VMs, install actual PVE 8/9, then test a DEB.

Requires official Debian genericcloud images, Proxmox repository keyrings,
QEMU/KVM, cloud-localds, SSH, Node/Playwright and the packaged web client.
All firewall and service changes happen inside the disposable VM.
Work directories contain test SSH keys and profiles; never publish them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import ssl
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--major', choices=('8', '9'), required=True)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--keyring', required=True, type=Path)
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--resume', action='store_true', help='Reuse this disposable PVE disk, repair interrupted setup and reset only its test credentials')
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    work.chmod(0o700)
    assert args.resume == (work / 'disk.qcow2').exists(), 'Use a fresh work directory or --resume for this test VM'
    major = args.major
    codename = 'bookworm' if major == '8' else 'trixie'
    hostname = 'knock-pve' + major
    ssh_port, https_port = port(), port()
    addresses = json.loads(run('ip', '-j', '-4', 'addr', 'show').stdout)
    bind = os.environ.get('ICE_VM_BIND') or next(a['local'] for link in addresses for a in link['addr_info'] if a['scope'] == 'global')
    key = work / 'id_ed25519'
    if not args.resume:
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
    config = {'hostname': hostname, 'fqdn': hostname + '.test', 'manage_etc_hosts': False,
              'disable_root': False, 'ssh_pwauth': False,
              'users': [{'name': 'root', 'ssh_authorized_keys': [key.with_suffix('.pub').read_text().strip()]}],
              'write_files': [{'path': '/etc/hosts', 'content': '127.0.0.1 localhost\n10.0.2.15 ' + hostname + '.test ' + hostname + '\n'}],
              'runcmd': [['sh', '-c', 'if command -v pveversion >/dev/null 2>&1; then systemctl start pve-cluster; printf "%s\\n" ' + shlex.quote(key.with_suffix('.pub').read_text().strip()) + ' >> /etc/pve/priv/authorized_keys; fi'],
                         ['touch', '/root/cloud-ready']]}
    (work / 'user-data').write_text('#cloud-config\n' + json.dumps(config))
    instance = hostname + ('-resume-' + str(time.time_ns()) if args.resume else '')
    (work / 'meta-data').write_text('instance-id: ' + instance + '\nlocal-hostname: ' + hostname + '\n')
    run('cloud-localds', str(work / 'seed.img'), str(work / 'user-data'), str(work / 'meta-data'))
    if not args.resume:
        run('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(args.image.resolve()), str(work / 'disk.qcow2'), '24G')
    ssh = ['ssh', '-i', str(key), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3',
           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=' + str(work / 'known_hosts'),
           '-p', str(ssh_port), 'root@127.0.0.1']

    def remote(command, *, check=True, timeout=120, input=None):
        result = subprocess.run([*ssh, command], text=True, capture_output=True, timeout=timeout, input=input)
        if check and result.returncode:
            raise RuntimeError('Guest command failed: ' + command + '\n' + result.stdout[-4000:] + result.stderr[-4000:])
        return result

    def shell(script, name, timeout=600):
        with (work / (name + '.log')).open('w') as log:
            result = subprocess.run([*ssh, 'bash -se'], input=script, text=True, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError(name + ' failed: ' + (work / (name + '.log')).read_text()[-5000:])

    def copy(source, target):
        run('scp', '-O', '-q', '-i', str(key), '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=' + str(work / 'known_hosts'), '-P', str(ssh_port), str(source), 'root@127.0.0.1:' + target)

    phases = []

    def record(phase, **details):
        value = {'phase': phase, 'result': 'PASS', **details}
        phases.append(value)
        print('PVE' + major + ': ' + json.dumps(value), flush=True)

    command = ['qemu-system-x86_64', '-name', hostname, '-enable-kvm', '-cpu', 'host', '-m', '4096', '-smp', '2',
               '-drive', 'file=' + str(work / 'disk.qcow2') + ',format=qcow2,if=virtio',
               '-drive', 'file=' + str(work / 'seed.img') + ',format=raw,if=virtio',
               '-display', 'none', '-serial', 'file:' + str(work / 'console.log'), '-monitor', 'none',
               '-qmp', 'unix:' + str(work / 'qmp.sock') + ',server=on,wait=off',
               '-netdev', f'user,id=wan,hostfwd=tcp:127.0.0.1:{ssh_port}-:22,hostfwd=tcp:{bind}:{https_port}-:8006',
               '-device', 'virtio-net-pci,netdev=wan,mac=52:54:00:09:00:0' + major]
    with (work / 'qemu.log').open('w') as log:
        vm = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        (work / 'pid').write_text(str(vm.pid))

        def ready(previous=None):
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if vm.poll() is not None:
                    raise RuntimeError('QEMU exited: ' + (work / 'qemu.log').read_text())
                result = remote('test -f /root/cloud-ready && cat /proc/sys/kernel/random/boot_id', check=False, timeout=5)
                if result.returncode == 0 and result.stdout.strip() and result.stdout.strip() != previous:
                    return result.stdout.strip()
                time.sleep(1)
            raise TimeoutError('VM SSH did not become ready: ' + (work / 'console.log').read_text(errors='replace')[-4000:])

        try:
            boot = ready()
            record('debian-boot', distribution=remote('cat /etc/os-release').stdout)
            copy(args.keyring, '/usr/share/keyrings/knock-test-proxmox.gpg')
            shell(f'''export DEBIAN_FRONTEND=noninteractive
printf 'grub-pc grub-pc/install_devices multiselect /dev/vda\\n' | debconf-set-selections
dpkg --configure -a
python3 - <<'PY'
from pathlib import Path
for path in Path('/etc/apt/sources.list.d').iterdir():
    if path.is_file() and 'enterprise.proxmox.com' in path.read_text():
        path.unlink()
PY
echo 'deb [signed-by=/usr/share/keyrings/knock-test-proxmox.gpg] http://download.proxmox.com/debian/pve {codename} pve-no-subscription' > /etc/apt/sources.list.d/pve-test.list
apt-get update
apt-get install -y proxmox-default-kernel proxmox-ve postfix open-iscsi
''', 'install-proxmox', timeout=1200)
            remote('systemctl reboot', check=False)
            boot = ready(boot)
            kernel = remote('uname -r').stdout.strip()
            assert kernel.endswith('-pve'), kernel
            version = remote('pveversion -v').stdout
            assert not remote('dpkg --audit').stdout.strip(), 'Incomplete PVE package configuration'
            assert 'pve-manager/' + major + '.' in remote('pveversion').stdout
            deadline = time.monotonic() + 60
            while remote('systemctl is-active pveproxy pvedaemon pve-cluster', check=False).returncode:
                assert time.monotonic() < deadline, 'PVE services did not start'
                time.sleep(1)
            record('proxmox-boot', kernel=kernel, pveversion=version)
            if args.resume:
                shell('systemctl disable --now knock-control.service knock-control-firewall.service || true\napt-get purge -y knock-control || true\nrm -rf /etc/knock-control /var/lib/knock-control\nrm -f /etc/pve/firewall/cluster.fw\nsystemctl restart pve-firewall\n', 'reset-test-fixture')
            copy(args.package, '/root/knock-control.deb')
            shell('export DEBIAN_FRONTEND=noninteractive\napt-get install -y /root/knock-control.deb\n', 'install-deb')
            assert remote('test ! -e /etc/knock-control/settings.json', check=False).returncode == 0
            assert remote('systemctl is-active knock-control.service', check=False).returncode != 0
            assert remote('test ! -e /usr/lib/knock-control/api.py', check=False).returncode == 0
            record('deb-install', sha256=hashlib.sha256(args.package.read_bytes()).hexdigest(),
                   dependencies=remote("dpkg-query -W -f='${binary:Package} ${Version} ${db:Status-Status}\\n' knock-control python3 iptables ipset 'libssl3*' 'libpcap0.8*'").stdout,
                   iptables=remote('iptables --version').stdout.strip())

            def ctl(*args):
                return json.loads(remote('/usr/sbin/knock-control ' + shlex.join(map(str, args))).stdout)

            interface = json.loads(remote('ip -j route show default').stdout)[0]['dev']
            assert ctl('init', '--public-host', bind, '--interface', interface)['ok']
            assert ctl('issue', '--name', 'PVE browser test', '--ports', '8006', '--idle-timeout', '10',
                       '--out', '/root/ice.json', '--qr-out', '/root/ice.png')['ok']
            bundle = json.loads(remote('cat /root/ice.json').stdout)
            ident, base = bundle['profile_id'], bundle['settings']['base']
            assert ctl('activate')['ok']
            remote('systemctl enable knock-control.service knock-control-firewall.service')
            remote('systemctl is-active knock-control.service knock-control-firewall.service')
            record('systemd-activation', checks=['Real systemd PID 1 starts packet daemon and firewall unit', 'CLI issues v3 JSON and PNG; no management API'])

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as allocation:
                allocation.bind((bind, 0))
                ice_port = allocation.getsockname()[1]
            with socket.socket(socket.AF_UNIX) as connection:
                connection.connect(str(work / 'qmp.sock'))
                stream = connection.makefile('rwb')
                json.loads(stream.readline())

                def qmp(execute, arguments=None):
                    stream.write((json.dumps({'execute': execute, **({'arguments': arguments} if arguments else {})}) + '\n').encode())
                    stream.flush()
                    while True:
                        response = json.loads(stream.readline())
                        if 'error' in response:
                            raise RuntimeError(str(response))
                        if 'return' in response:
                            return response['return']

                qmp('qmp_capabilities')
                assert not qmp('human-monitor-command', {'command-line': f'hostfwd_add wan udp:{bind}:{ice_port}-:{base}'})

            def granted():
                return remote('ipset test kc_' + ident + ' ' + bind, check=False).returncode == 0

            def reachable():
                # Accept only this disposable VM's self-signed PVE UI certificate.
                try:
                    with urllib.request.urlopen(f'https://{bind}:{https_port}/', context=ssl._create_unverified_context(), timeout=.8) as response:
                        return response.status == 200 and b'Proxmox' in response.read()
                except OSError:
                    return False

            def browsers(phase):
                for engine in ('chromium', 'firefox'):
                    browser = subprocess.Popen([os.environ.get('NODE_BINARY', 'node'), str(ROOT / 'tests/ice-vm-browser.mjs'), engine],
                                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                    try:
                        def send(action='open', token=None):
                            browser.stdin.write(json.dumps({'bundle': bundle, 'action': action, 'source': bind, 'host': bind, 'port': ice_port,
                                                            **({'token': token} if token else {})}) + '\n')
                            browser.stdin.flush()
                            line = browser.stdout.readline()
                            assert line, 'Browser transport exited'
                            return json.loads(line)['token']

                        assert not granted() and not reachable(), phase + ': PVE UI exposed before ON'
                        captured = send()
                        assert granted() and reachable(), phase + ': ' + engine + ' ON failed'
                        send('close')
                        assert not granted() and not reachable(), phase + ': ' + engine + ' OFF failed'
                        remote('systemctl restart knock-control.service')
                        send(token=captured)
                        assert not granted() and not reachable(), phase + ': replay opened access'
                    finally:
                        if browser.poll() is None:
                            browser.stdin.write('{"stop":true}\n')
                            browser.stdin.flush()
                            browser.stdin.close()
                            try:
                                browser.wait(timeout=15)
                            except subprocess.TimeoutExpired:
                                browser.terminate()
                                browser.wait(timeout=5)
                record(phase, checks=['Actual Chromium and Firefox ICE opens/closes real PVE HTTPS UI on 8006',
                                      'Captured ON remains rejected after daemon restart'])

            browsers('browser-on-off')
            shell("mkdir -p /etc/pve/firewall\nprintf '[OPTIONS]\\nenable: 1\\npolicy_in: ACCEPT\\npolicy_out: ACCEPT\\n' > /etc/pve/firewall/cluster.fw\nprintf '[OPTIONS]\\nenable: 1\\n' > /etc/pve/nodes/" + hostname + "/host.fw\nsystemctl restart pve-firewall\nsleep 5\n", 'enable-pve-firewall')
            status = remote('pve-firewall status').stdout.strip()
            assert 'enabled/running' in status, status
            remote('iptables -C INPUT -j PVEFW-INPUT')
            record('pve-firewall-enabled', status=status, checks=['Datacenter and node firewall enabled; PVEFW-INPUT hook present'])
            browsers('pve-firewall-on-off')
            before = remote('sha256sum /etc/knock-control/settings.json').stdout
            remote('systemctl reboot', check=False)
            boot = ready(boot)
            deadline = time.monotonic() + 60
            while remote('systemctl is-active knock-control.service knock-control-firewall.service pveproxy', check=False).returncode:
                assert time.monotonic() < deadline, 'Services did not autostart after reboot'
                time.sleep(1)
            assert before == remote('sha256sum /etc/knock-control/settings.json').stdout
            assert not granted() and not reachable(), 'Protected PVE UI exposed after reboot'
            browsers('post-reboot-on-off')
            record('reboot', checks=['PVE kernel and real systemd boot', 'Credentials unchanged; both units autostart', 'PVE UI blocked until fresh ON'])
            shell('export DEBIAN_FRONTEND=noninteractive\napt-get reinstall -y /root/knock-control.deb\n', 'reinstall-deb')
            assert before == remote('sha256sum /etc/knock-control/settings.json').stdout
            remote('systemctl is-active knock-control.service')
            record('reinstall', checks=['Native apt reinstall preserves credentials and restarts active unit'])
            report = {'result': 'PASS', 'tested_date': '2026-10-21', 'proxmox_major': major,
                      'package': args.package.name, 'sha256': hashlib.sha256(args.package.read_bytes()).hexdigest(),
                      'image': args.image.name, 'image_sha512': hashlib.sha512(args.image.read_bytes()).hexdigest(),
                      'proxmox_keyring_sha256': hashlib.sha256(args.keyring.read_bytes()).hexdigest(),
                      'virtualization': 'QEMU KVM, full VM with actual Proxmox kernel and services', 'phases': phases,
                      'scope': 'Knock server installed on nested Proxmox VE host; not a Debian-only guest or chroot',
                      'limitations': ['Single disposable node; no cluster or nested VM/container workload test',
                                      'Classic pve-firewall tested; alternative nftables Proxmox firewall not selected',
                                      'PVE UI certificate accepted only by the test probe; released clients have no HTTPS API']}
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
            print('PASS: ' + str(args.report), flush=True)
        except Exception:
            print(remote('systemctl --no-pager status knock-control.service knock-control-firewall.service pveproxy; journalctl -u knock-control -n 30 --no-pager; iptables-save', check=False).stdout[-10000:], flush=True)
            raise
        finally:
            vm.terminate()
            try:
                vm.wait(timeout=10)
            except subprocess.TimeoutExpired:
                vm.kill()
                vm.wait()


if __name__ == '__main__':
    main()
