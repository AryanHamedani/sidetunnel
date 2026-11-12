"""HTTP CONNECT and SOCKS5 proxy on one port. Upstream sockets and DNS queries are pinned to the tunnel device."""
import asyncio
import base64
import fnmatch
import hmac
import ipaddress
import logging
import os
from pathlib import Path
import secrets
import socket
import struct

log = logging.getLogger('sidetunnel')
PUSHED_DNS = Path('/tmp/dns')


def socks_reply(code):
    return bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0])


# Per protocol: connection opened, destination not allowed, destination unreachable.
REPLIES = {
    'http': (b'HTTP/1.1 200 Connection Established\r\n\r\n',
             b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',
             b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'),
    'socks': (socks_reply(0), socks_reply(2), socks_reply(4)),
}


class Refused(Exception):
    """The destination is outside ALLOWED_HOSTS or ALLOWED_PORTS."""


class Settings:
    def __init__(self, env):
        hosts = [h.strip().lower().rstrip('.') for h in env.get('ALLOWED_HOSTS', '').split(',') if h.strip()]
        if not hosts:
            raise ValueError('Set ALLOWED_HOSTS to a comma-separated list of hosts, or to * to allow every host.')
        self.networks = [ipaddress.ip_network(h, strict=False) for h in hosts if '/' in h]
        self.patterns = [h for h in hosts if '/' not in h]
        self.ports = []
        for part in env.get('ALLOWED_PORTS', '80,443').split(','):
            low, _, high = part.strip().partition('-')
            if low == '*':
                self.ports.append((1, 65535))
            elif low:
                self.ports.append((int(low), int(high or low)))
        if not self.ports:
            raise ValueError('ALLOWED_PORTS is empty.')
        user, password_file = env.get('PROXY_USER', ''), env.get('PROXY_PASSWORD_FILE', '')
        if bool(user) != bool(password_file):
            raise ValueError('Set PROXY_USER and PROXY_PASSWORD_FILE together.')
        self.credentials = None
        if user:
            password = Path(password_file).read_text().rstrip('\r\n')
            if not password:
                raise ValueError('PROXY_PASSWORD_FILE is empty.')
            self.credentials = (user.encode(), password.encode())
        self.dns = [str(ipaddress.IPv4Address(s.strip())) for s in env.get('DNS_SERVERS', '').split(',') if s.strip()]
        self.log_level = env.get('LOG_LEVEL', 'info').upper()
        if self.log_level not in ('DEBUG', 'INFO', 'WARNING', 'ERROR'):
            raise ValueError('LOG_LEVEL must be debug, info, warning or error.')
        self.device = 'tun0'

    def allowed(self, host, port):
        host = host.lower().rstrip('.')
        if not any(low <= port <= high for low, high in self.ports):
            return False
        if any(fnmatch.fnmatchcase(host, pattern) for pattern in self.patterns):
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address in network for network in self.networks)


def dns_query(name, txid):
    labels = name.rstrip('.').encode('idna').split(b'.')
    question = b''.join(bytes([len(label)]) + label for label in labels) + b'\0'
    return struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 0) + question + struct.pack('>HH', 1, 1)


def dns_addresses(data, txid):
    """A records from the answer section of a DNS response; CNAME records in between are skipped."""
    ident, flags, questions, answers = struct.unpack_from('>HHHH', data)
    if ident != txid or not flags & 0x8000 or flags & 0x000F:
        raise OSError('DNS lookup failed')

    def skip_name(pos):
        while True:
            length = data[pos]
            if length >= 0xC0:
                return pos + 2
            if length == 0:
                return pos + 1
            pos += length + 1

    pos = 12
    for _ in range(questions):
        pos = skip_name(pos) + 4
    found = []
    for _ in range(answers):
        pos = skip_name(pos)
        rtype, _, _, length = struct.unpack_from('>HHIH', data, pos)
        pos += 10
        if rtype == 1 and length == 4:
            found.append(socket.inet_ntoa(data[pos:pos + 4]))
        pos += length
    return found


async def relay(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (ConnectionError, OSError):
        pass


class Proxy:
    dns_port = 53

    def __init__(self, settings):
        self.settings = settings

    def socket(self, kind):
        sock = socket.socket(socket.AF_INET, kind)
        if self.settings.device:
            # No route outside the tunnel can carry this socket, whatever the routing table says.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.settings.device.encode() + b'\0')
        sock.setblocking(False)
        return sock

    def dns_servers(self):
        if self.settings.dns:
            return self.settings.dns
        try:
            pushed = PUSHED_DNS.read_text().split()
        except OSError:
            pushed = []
        return pushed or ['1.1.1.1']

    async def resolve(self, host):
        try:
            return [str(ipaddress.IPv4Address(host))]
        except ValueError:
            pass
        loop = asyncio.get_running_loop()
        # shortcut: one UDP attempt per server, no cache and no TCP retry for truncated answers;
        # upgrade if lookups become slow or large record sets matter.
        for server in self.dns_servers():
            sock = self.socket(socket.SOCK_DGRAM)
            try:
                txid = secrets.randbelow(65536)
                await loop.sock_connect(sock, (server, self.dns_port))
                await loop.sock_sendall(sock, dns_query(host, txid))
                if found := dns_addresses(await asyncio.wait_for(loop.sock_recv(sock, 4096), 3), txid):
                    return found
            except (OSError, struct.error, IndexError):
                continue
            finally:
                sock.close()
        raise OSError(f'cannot resolve {host}')

    async def connect(self, host, port):
        if not self.settings.allowed(host, port):
            raise Refused
        loop = asyncio.get_running_loop()
        error = OSError('no address')
        for address in (await self.resolve(host))[:3]:
            sock = self.socket(socket.SOCK_STREAM)
            try:
                await asyncio.wait_for(loop.sock_connect(sock, (address, port)), 15)
                return await asyncio.open_connection(sock=sock)
            except BaseException as caught:
                sock.close()
                if not isinstance(caught, OSError):
                    raise
                error = caught
        raise error

    async def http(self, header, writer):
        lines = header.decode('latin-1').split('\r\n')
        method, target, _ = lines[0].split()
        if method != 'CONNECT':
            writer.write(b'HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Length: 0\r\n\r\n')
            return None
        if self.settings.credentials:
            fields = {key.strip().lower(): value.strip() for key, _, value in (line.partition(':') for line in lines[1:])}
            scheme, _, token = fields.get('proxy-authorization', '').partition(' ')
            expected = base64.b64encode(b':'.join(self.settings.credentials))
            if scheme.lower() != 'basic' or not hmac.compare_digest(token.strip().encode('latin-1'), expected):
                writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                             b'Proxy-Authenticate: Basic realm="sidetunnel"\r\nContent-Length: 0\r\n\r\n')
                return None
        host, _, port = target.rpartition(':')
        return host.strip('[]'), int(port)

    async def socks(self, reader, writer):
        async def field():
            return await reader.readexactly((await reader.readexactly(1))[0])

        method = 2 if self.settings.credentials else 0
        if method not in await field():
            writer.write(b'\x05\xff')
            return None
        writer.write(bytes([5, method]))
        if self.settings.credentials:
            await reader.readexactly(1)
            user, password = await field(), await field()
            expected_user, expected_password = self.settings.credentials
            ok = hmac.compare_digest(user, expected_user) & hmac.compare_digest(password, expected_password)
            writer.write(b'\x01' + (b'\x00' if ok else b'\x01'))
            if not ok:
                return None
        _, command, _, kind = await reader.readexactly(4)
        if kind == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif kind == 3:
            host = (await field()).decode('ascii')
        else:
            writer.write(socks_reply(8))
            return None
        port = struct.unpack('>H', await reader.readexactly(2))[0]
        if command != 1:
            writer.write(socks_reply(7))
            return None
        return host, port

    async def request(self, reader, writer):
        first = await reader.readexactly(1)
        if first == b'\x05':
            return 'socks', await self.socks(reader, writer)
        return 'http', await self.http(first + await reader.readuntil(b'\r\n\r\n'), writer)

    async def handle(self, reader, writer):
        upstream = None
        try:
            kind, target = await asyncio.wait_for(self.request(reader, writer), 20)
            if not target:
                return
            host, port = target
            opened, denied, unreachable = REPLIES[kind]
            try:
                upstream_reader, upstream = await self.connect(host, port)
            except Refused:
                log.info('denied %s:%d', host, port)
                writer.write(denied)
                return
            except OSError as error:
                log.info('failed %s:%d (%s)', host, port, error)
                writer.write(unreachable)
                return
            log.info('open %s:%d', host, port)
            writer.write(opened)
            await writer.drain()
            tasks = [asyncio.create_task(relay(reader, upstream)), asyncio.create_task(relay(upstream_reader, writer))]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, ValueError, EOFError, asyncio.LimitOverrunError, struct.error):
            pass  # malformed request or the client went away
        finally:
            if upstream:
                upstream.close()
            try:
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass


async def main():
    settings = Settings(os.environ)
    logging.basicConfig(level=settings.log_level, format='%(asctime)s proxy: %(message)s')
    if '*' in settings.patterns:
        log.warning('ALLOWED_HOSTS=*: whoever can reach this port can reach every host behind the VPN.')
    server = await asyncio.start_server(Proxy(settings).handle, '0.0.0.0', 8080, limit=16384)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
