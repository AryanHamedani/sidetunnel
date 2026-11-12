import asyncio
import base64
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import proxy  # noqa: E402


def settings(**env):
    made = proxy.Settings({'ALLOWED_HOSTS': '127.0.0.1', **env})
    made.device = None  # the test host has no tun0
    return made


class SettingsTests(unittest.TestCase):
    def test_allowed_hosts_is_required(self):
        for env in ({}, {'ALLOWED_HOSTS': ' , '}):
            with self.assertRaises(ValueError):
                proxy.Settings(env)

    def test_host_patterns_networks_and_ports(self):
        rules = proxy.Settings({'ALLOWED_HOSTS': 'api.example, *.corp.example,10.0.0.0/8', 'ALLOWED_PORTS': '443,8000-8100'})
        self.assertTrue(rules.allowed('API.example.', 443))
        self.assertTrue(rules.allowed('a.b.corp.example', 8050))
        self.assertTrue(rules.allowed('10.2.3.4', 443))
        self.assertFalse(rules.allowed('corp.example', 443))
        self.assertFalse(rules.allowed('api.example.evil', 443))
        self.assertFalse(rules.allowed('11.0.0.1', 443))
        self.assertFalse(rules.allowed('api.example', 22))

    def test_open_mode_is_explicit_and_default_ports_stay_narrow(self):
        rules = proxy.Settings({'ALLOWED_HOSTS': '*'})
        self.assertTrue(rules.allowed('anything.example', 80))
        self.assertFalse(rules.allowed('anything.example', 22))
        self.assertTrue(proxy.Settings({'ALLOWED_HOSTS': '*', 'ALLOWED_PORTS': '*'}).allowed('anything.example', 22))

    def test_invalid_options_fail_at_start(self):
        for env in ({'PROXY_USER': 'u'}, {'DNS_SERVERS': 'dns.example'}, {'LOG_LEVEL': 'loud'}, {'ALLOWED_PORTS': ''}):
            with self.assertRaises(ValueError):
                proxy.Settings({'ALLOWED_HOSTS': '*', **env})


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def echo(reader, writer):
            writer.write(b'echo:' + await reader.read(100))
            await writer.drain()
            writer.close()
        self.target = await asyncio.start_server(echo, '127.0.0.1', 0)
        self.target_port = self.target.sockets[0].getsockname()[1]
        self.servers = [self.target]

    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()

    async def start(self, **env):
        self.proxy = proxy.Proxy(settings(ALLOWED_PORTS=str(self.target_port), **env))
        server = await asyncio.start_server(self.proxy.handle, '127.0.0.1', 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def exchange(self, port, *messages):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        replies = []
        for message in messages:
            writer.write(message)
            await writer.drain()
            replies.append(await asyncio.wait_for(reader.read(4096), 5))
        writer.close()
        return replies

    def connect(self, host='127.0.0.1', port=None, extra=''):
        return f'CONNECT {host}:{port or self.target_port} HTTP/1.1\r\n{extra}\r\n'.encode()

    def socks_request(self, host=None, port=None):
        address = b'\x01' + socket.inet_aton('127.0.0.1') if host is None else b'\x03' + bytes([len(host)]) + host.encode()
        return b'\x05\x01\x00' + address + struct.pack('>H', port or self.target_port)

    async def test_http_connect_relays_an_allowed_destination(self):
        port = await self.start()
        opened, echoed = await self.exchange(port, self.connect(), b'ping')
        self.assertIn(b'200 Connection Established', opened)
        self.assertEqual(echoed, b'echo:ping')

    async def test_http_rejects_other_hosts_ports_and_methods(self):
        port = await self.start()
        self.assertIn(b'403 Forbidden', (await self.exchange(port, self.connect('other.example')))[0])
        self.assertIn(b'403 Forbidden', (await self.exchange(port, self.connect(port=1)))[0])
        self.assertIn(b'405 Method', (await self.exchange(port, b'GET http://127.0.0.1/ HTTP/1.1\r\n\r\n'))[0])

    async def test_http_authentication(self):
        with tempfile.NamedTemporaryFile('w') as secret:
            secret.write('s3cret\n')
            secret.flush()
            port = await self.start(PROXY_USER='user', PROXY_PASSWORD_FILE=secret.name)
        self.assertIn(b'407 Proxy Authentication', (await self.exchange(port, self.connect()))[0])
        wrong = 'Proxy-Authorization: Basic ' + base64.b64encode(b'user:nope').decode() + '\r\n'
        self.assertIn(b'407 Proxy Authentication', (await self.exchange(port, self.connect(extra=wrong)))[0])
        right = 'proxy-authorization: basic ' + base64.b64encode(b'user:s3cret').decode() + '\r\n'
        self.assertIn(b'200 Connection Established', (await self.exchange(port, self.connect(extra=right)))[0])

    async def test_socks5_relays_an_allowed_destination(self):
        port = await self.start()
        method, opened, echoed = await self.exchange(port, b'\x05\x01\x00', self.socks_request(), b'ping')
        self.assertEqual(method, b'\x05\x00')
        self.assertEqual(opened[:2], b'\x05\x00')
        self.assertEqual(echoed, b'echo:ping')

    async def test_socks5_resolves_names_itself_and_enforces_the_allowlist(self):
        port = await self.start(ALLOWED_HOSTS='inside.example')

        async def resolve(host):
            return ['127.0.0.1']
        self.proxy.resolve = resolve
        self.assertEqual((await self.exchange(port, b'\x05\x01\x00', self.socks_request('inside.example')))[1][:2], b'\x05\x00')
        self.assertEqual((await self.exchange(port, b'\x05\x01\x00', self.socks_request('other.example')))[1][:2], b'\x05\x02')
        # A client that resolved the name itself sends an address, which a name allowlist does not match.
        self.assertEqual((await self.exchange(port, b'\x05\x01\x00', self.socks_request()))[1][:2], b'\x05\x02')

    async def test_socks5_authentication(self):
        with tempfile.NamedTemporaryFile('w') as secret:
            secret.write('s3cret')
            secret.flush()
            port = await self.start(PROXY_USER='user', PROXY_PASSWORD_FILE=secret.name)
        self.assertEqual((await self.exchange(port, b'\x05\x01\x00'))[0], b'\x05\xff')
        self.assertEqual((await self.exchange(port, b'\x05\x02\x00\x02', b'\x01\x04user\x04nope'))[1], b'\x01\x01')
        replies = await self.exchange(port, b'\x05\x02\x00\x02', b'\x01\x04user\x06s3cret', self.socks_request())
        self.assertEqual(replies[1], b'\x01\x00')
        self.assertEqual(replies[2][:2], b'\x05\x00')

    async def test_resolver_follows_cname_and_falls_back_to_the_next_server(self):
        class Dns(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                question = data[12:]
                cname = b'\xc0\x0c' + struct.pack('>HHIH', 5, 1, 60, 4) + b'\x01x\xc0\x0c'
                a = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + socket.inet_aton('192.0.2.7')
                self.transport.sendto(data[:2] + struct.pack('>HHHHH', 0x8180, 1, 2, 0, 0) + question + cname + a, addr)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Dns, local_addr=('127.0.0.2', 0))
        try:
            resolver = proxy.Proxy(settings(DNS_SERVERS='127.0.0.1,127.0.0.2'))
            resolver.dns_port = transport.get_extra_info('sockname')[1]
            self.assertEqual(await resolver.resolve('name.example'), ['192.0.2.7'])
            self.assertEqual(await resolver.resolve('192.0.2.9'), ['192.0.2.9'])
        finally:
            transport.close()

    def test_dns_response_for_another_query_is_rejected(self):
        with self.assertRaises(OSError):
            proxy.dns_addresses(struct.pack('>HHHHHH', 2, 0x8180, 0, 0, 0, 0), 1)


if __name__ == '__main__':
    unittest.main()
