"""Container entrypoint: kill switch first, then OpenVPN and the proxy."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import ovpn
import proxy

CONFIG = Path('/config')
READY = Path('/tmp/vpn-ready')
AUTH_FAILED = Path('/tmp/auth-failed')


def rule(*args, tool='iptables'):
    subprocess.run([tool, '-w', *args], check=True)


def firewall(remotes, protocol):
    """All rules apply only inside this container's network namespace."""
    route = subprocess.check_output(['ip', '-4', 'route', 'show', 'default'], text=True).split()
    gateway, uplink = route[route.index('via') + 1], route[route.index('dev') + 1]
    rule('-P', 'OUTPUT', 'DROP')
    rule('-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT')
    rule('-A', 'OUTPUT', '-o', 'tun0', '-j', 'ACCEPT')
    # Replies to clients of the published proxy port.
    rule('-A', 'OUTPUT', '-o', uplink, '-p', 'tcp', '--sport', '8080', '-m', 'conntrack', '--ctstate', 'ESTABLISHED', '-j', 'ACCEPT')
    for host, port in remotes:
        rule('-A', 'OUTPUT', '-o', uplink, '-p', protocol, '-d', host, '--dport', str(port), '-j', 'ACCEPT')
        # Pin VPN endpoints to the original gateway; reconnects cannot recurse into tun0.
        subprocess.run(['ip', 'route', 'replace', host + '/32', 'via', gateway, 'dev', uplink], check=True)
    try:
        ipv6_off = Path('/proc/sys/net/ipv6/conf/all/disable_ipv6').read_text().strip() == '1'
    except OSError:
        ipv6_off = True
    if not ipv6_off:
        rule('-P', 'OUTPUT', 'DROP', tool='ip6tables')


def main():
    try:
        proxy.Settings(os.environ)
        auth = CONFIG / 'auth.txt'
        # Hostname remotes are resolved here, before the kill switch; nothing else ever leaves outside the tunnel.
        text, remotes, protocol, dropped = ovpn.harden((CONFIG / 'client.ovpn').read_text(), auth if auth.exists() else None)
    except (OSError, ValueError, IndexError) as error:
        sys.exit(f'sidetunnel: {error}')
    if dropped:
        print('sidetunnel: ignored profile directives: ' + ', '.join(dropped), flush=True)
    firewall(remotes, protocol)
    for path, content in [('/tmp/client.ovpn', text),
                          ('/tmp/up.sh', "#!/bin/sh\nenv | sed -n 's/^foreign_option_[0-9]*=dhcp-option DNS //p' > /tmp/dns\ntouch /tmp/vpn-ready\n"),
                          ('/tmp/down.sh', '#!/bin/sh\nrm -f /tmp/vpn-ready\n')]:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as file:
            file.write(content)
    READY.unlink(missing_ok=True)
    AUTH_FAILED.unlink(missing_ok=True)
    # The hooks run through /bin/sh so they work on a noexec /tmp.
    vpn = subprocess.Popen(['openvpn', '--config', '/tmp/client.ovpn', '--script-security', '2',
                            '--up', '/bin/sh /tmp/up.sh', '--up-delay', '--up-restart', '--down', '/bin/sh /tmp/down.sh', '--down-pre'],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def forward():
        for line in vpn.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            if 'AUTH_FAILED' in line:
                AUTH_FAILED.touch()

    reader = threading.Thread(target=forward, daemon=True)
    reader.start()
    server = subprocess.Popen(['python3', '/app/proxy.py'])

    def stop(*signalled):
        READY.unlink(missing_ok=True)
        vpn.terminate()
        server.terminate()
        sys.exit(0 if signalled else 1)  # a dead child is a failure, a signal is not

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while vpn.poll() is None and server.poll() is None:
        time.sleep(0.5)
    reader.join(2)
    if AUTH_FAILED.exists():
        # Stay up without retrying: a restart policy re-sending rejected credentials can lock the VPN account.
        server.terminate()
        signal.pause()
    stop()


if __name__ == '__main__':
    main()
