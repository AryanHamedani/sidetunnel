"""Harden an OpenVPN client profile: keep connection settings, drop everything that runs code or reconfigures the host."""
import ipaddress
import shlex
import socket
import sys
from pathlib import Path

KEEP = {'client', 'persist-key', 'persist-tun', 'tls-client', 'remote-cert-tls', 'verify-x509-name', 'auth', 'cipher',
        'key-direction', 'tls-version-min', 'tls-cipher', 'remote-random', 'tun-mtu', 'mssfix', 'fragment', 'reneg-sec'}
BLOCKS = {'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2'}
# OpenVPN reads lines into a 256-byte buffer and would split a longer line into two.
MAX_LINE = 250
PROTOCOLS = {'udp': 'udp', 'udp4': 'udp', 'tcp': 'tcp', 'tcp4': 'tcp', 'tcp-client': 'tcp', 'tcp4-client': 'tcp'}


def lookup(host):
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)})


def harden(source, auth_file=None, resolve=lookup):
    """Return (profile text, [[ip, port]], 'udp' or 'tcp', dropped directive names)."""
    result, remotes, dropped, block = [], [], set(), None
    protocol, default_port = 'udp', 1194
    if '\0' in source:
        raise ValueError('Profile contains a NUL byte.')
    # Split exactly as OpenVPN does; any other line separator stays inside its line.
    for line in source.split('\n'):
        line = line.rstrip('\r')
        if len(line.encode()) > MAX_LINE:
            raise ValueError('Profile line is too long.')
        s = line.strip()
        if block:
            # OpenVPN ends a block at any line that starts with the closing tag, so no other line may start with "<".
            if s.startswith('<'):
                if s != f'</{block}>':
                    raise ValueError(f'Unexpected tag inside <{block}>.')
                block = None
            result.append(line)
            continue
        if s.startswith('<'):
            block = s[1:-1]
            if block not in BLOCKS:
                raise ValueError(f'Unsupported inline block: {block}')
            result.append(line)
            continue
        if not s or s.startswith(('#', ';')):
            continue
        fields = shlex.split(s)
        name = fields[0]
        if name == 'proto':
            if fields[1] not in PROTOCOLS:
                raise ValueError(f'Unsupported proto {fields[1]}: only UDP and TCP client profiles work.')
            protocol = PROTOCOLS[fields[1]]
        elif name in ('port', 'rport'):
            default_port = int(fields[1])
        elif name == 'remote':
            # shortcut: a per-remote protocol (fourth field) is ignored, add it when a profile mixes UDP and TCP remotes.
            remotes.append((fields[1], int(fields[2]) if len(fields) > 2 else None))
        elif name in KEEP:
            result.append(s)
        else:
            dropped.add(name)
    if block:
        raise ValueError(f'Inline block <{block}> is not closed.')
    endpoints = []
    for host, port in remotes:
        port = port or default_port
        if not 1 <= port <= 65535:
            raise ValueError('Invalid remote port')
        try:
            addresses = [str(ipaddress.IPv4Address(host))]
        except ValueError:
            addresses = resolve(host)
        endpoints += [[address, port] for address in addresses if [address, port] not in endpoints]
    # Profiles often list internal remotes beside the public one; they only delay the connection from outside.
    public = [e for e in endpoints if ipaddress.IPv4Address(e[0]).is_global]
    endpoints = public or endpoints
    if not endpoints:
        raise ValueError('Profile needs at least one IPv4 remote.')
    result.append('proto ' + ('udp' if protocol == 'udp' else 'tcp-client'))
    result += [f'remote {address} {port}' for address, port in endpoints]
    if auth_file:
        result.append(f'auth-user-pass {auth_file}')
    result += ['dev tun0', 'nobind', 'redirect-gateway def1', 'auth-nocache',
               # nointeract would resend rejected credentials forever and can lock the account.
               'auth-retry none', 'connect-retry-max 2', 'server-poll-timeout 10',
               'data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC', 'data-ciphers-fallback AES-256-CBC',
               'pull-filter ignore "route-ipv6"', 'pull-filter ignore "ifconfig-ipv6"', 'verb 3']
    return '\n'.join(result) + '\n', endpoints, protocol, sorted(dropped)


if __name__ == '__main__':
    # Validate a profile without connecting: prints what would be dropped, exits 1 with the reason if unusable.
    try:
        _, endpoints, protocol, dropped = harden(Path(sys.argv[1] if len(sys.argv) > 1 else '/config/client.ovpn').read_text())
    except (OSError, ValueError, IndexError) as error:
        sys.exit(f'sidetunnel: profile rejected: {error}')
    print(f'profile ok: {len(endpoints)} {protocol} remote(s); ignored directives: {", ".join(dropped) or "none"}')
