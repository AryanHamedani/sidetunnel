from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import ovpn  # noqa: E402


class HardenTests(unittest.TestCase):
    def test_keeps_keys_but_drops_scripts_and_internal_remote(self):
        source = 'client\nremote 10.0.0.1 1194\nremote 1.1.1.1 8443\nproto udp\nup /bad\nauth-user-pass old\n<key>\nSECRET\n</key>\n'
        text, remotes, protocol, dropped = ovpn.harden(source, '/config/auth.txt')
        self.assertIn('<key>\nSECRET\n</key>', text)
        self.assertNotIn('10.0.0.1', text)
        self.assertNotIn('/bad', text)
        self.assertNotIn('auth-user-pass old', text)
        self.assertIn('auth-user-pass /config/auth.txt', text)
        self.assertIn('auth-retry none', text)
        self.assertEqual(remotes, [['1.1.1.1', 8443]])
        self.assertEqual(protocol, 'udp')
        self.assertEqual(dropped, ['auth-user-pass', 'up'])

    def test_hardening_its_own_output_changes_nothing(self):
        once = ovpn.harden('client\nproto tcp\nremote 1.1.1.1 443\n<ca>\nCA\n</ca>\n', '/config/auth.txt')[0]
        self.assertEqual(ovpn.harden(once, '/config/auth.txt')[0], once)

    def test_without_credentials_no_auth_is_requested(self):
        self.assertNotIn('auth-user-pass', ovpn.harden('remote 1.1.1.1\n')[0])

    def test_tcp_spellings_and_default_port(self):
        text, remotes, protocol, _ = ovpn.harden('proto tcp\nremote 1.1.1.1\nport 443\n')
        self.assertIn('proto tcp-client', text)
        self.assertEqual((remotes, protocol), ([['1.1.1.1', 443]], 'tcp'))

    def test_hostname_remote_is_pinned_to_its_addresses(self):
        text, remotes, _, _ = ovpn.harden('remote vpn.example 1194\n', resolve=lambda host: ['1.1.1.1', '8.8.8.8'])
        self.assertEqual(remotes, [['1.1.1.1', 1194], ['8.8.8.8', 1194]])
        self.assertNotIn('vpn.example', text)

    def test_private_remote_is_used_when_it_is_the_only_one(self):
        self.assertEqual(ovpn.harden('remote 10.0.0.1 1194\n')[1], [['10.0.0.1', 1194]])

    def test_directives_cannot_hide_inside_a_block(self):
        # OpenVPN closes a block at a line that only starts with the closing tag, and splits lines at 255 bytes.
        for hidden in ('</key>x\nup /bin/evil\n', ' </key> \t x\nup /bin/evil\n', 'A' * 255 + '</key>\nup /bin/evil\n',
                       '<ca>\nup /bin/evil\n', 'A\0</key>\nup /bin/evil\n'):
            with self.assertRaises(ValueError, msg=repr(hidden[:20])):
                ovpn.harden('remote 1.1.1.1\n<key>\n' + hidden + '</key>\n')

    def test_other_line_separators_do_not_start_a_directive(self):
        text = ovpn.harden('remote 1.1.1.1\ncipher AES-256-GCM\x0bup /bin/evil\r\n')[0]
        self.assertNotIn('\nup ', text)

    def test_unusable_profiles_fail_explicitly(self):
        for source in ('proto tcp-server\nremote 1.1.1.1 443\n', 'client\n', 'remote 1.1.1.1\n<ca>\nCA\n',
                       'remote 1.1.1.1\n<script>\nx\n</script>\n', 'remote 1.1.1.1 70000\n'):
            with self.assertRaises(ValueError, msg=source):
                ovpn.harden(source)


if __name__ == '__main__':
    unittest.main()
