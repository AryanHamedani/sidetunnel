"""Docker checks of the entrypoint with a stub in place of OpenVPN; never uses a real VPN or credentials."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

IMAGE = os.environ.get('SIDETUNNEL_IMAGE', 'sidetunnel:dev')


def docker_run(root, stub, *extra, env=('ALLOWED_HOSTS=api.example',)):
    command = ['docker', 'run', '--cap-add=NET_ADMIN', '--read-only', '--tmpfs', '/tmp:noexec',
               '--mount', f'type=bind,src={root},dst=/config,readonly']
    if stub:
        command += ['--mount', f'type=bind,src={stub},dst=/usr/sbin/openvpn,readonly']
    for item in env:
        command += ['--env', item]
    return [*command, *extra, IMAGE]


@unittest.skipUnless(os.environ.get('RUN_DOCKER_TESTS') == '1', 'Set RUN_DOCKER_TESTS=1 to run Docker integration checks')
class ContainerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        os.chmod(self.root, 0o755)
        (self.root / 'client.ovpn').write_text('proto tcp-client\nremote 203.0.113.1 1194\nup /bad\n')

    def stub(self, content):
        path = self.root / 'openvpn'
        path.write_text(content)
        path.chmod(0o755)
        return path

    def test_kill_switch_and_hooks_work_on_readonly_noexec_filesystem(self):
        stub = self.stub('''#!/usr/bin/python3
import os, pathlib, shlex, subprocess, sys
args=sys.argv
rules=subprocess.check_output(['iptables','-S','OUTPUT'],text=True).splitlines()
assert rules[0]=='-P OUTPUT DROP', rules
assert '-p tcp' in next(line for line in rules if '203.0.113.1' in line)
profile=pathlib.Path(args[args.index('--config')+1]).read_text()
assert '/bad' not in profile and 'remote 203.0.113.1 1194' in profile, profile
env={**os.environ,'foreign_option_1':'dhcp-option DNS 10.8.0.1','foreign_option_2':'dhcp-option DOMAIN corp.example'}
subprocess.run(shlex.split(args[args.index('--up')+1]),check=True,env=env)
assert pathlib.Path('/tmp/vpn-ready').exists()
assert pathlib.Path('/tmp/dns').read_text()=='10.8.0.1\\n'
assert subprocess.run(['status'],capture_output=True,text=True).stdout in ('ready\\n','proxy-down\\n')
subprocess.run(shlex.split(args[args.index('--down')+1]),check=True)
assert subprocess.run(['status'],capture_output=True,text=True).stdout=='connecting\\n'
print('HOOKS_OK',flush=True)
''')
        result = subprocess.run(docker_run(self.root, stub, '--rm'), capture_output=True, text=True, timeout=30)
        self.assertIn('HOOKS_OK', result.stdout, result.stdout + result.stderr)
        self.assertIn('ignored profile directives: up', result.stdout)

    def test_refuses_to_start_without_an_explicit_allowlist(self):
        result = subprocess.run(docker_run(self.root, None, '--rm', env=()), capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ALLOWED_HOSTS', result.stderr)

    def test_profile_can_be_validated_without_connecting(self):
        command = docker_run(self.root, None, '--rm', '--entrypoint', 'python3', env=()) + ['/app/ovpn.py']
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('profile ok: 1 tcp remote(s); ignored directives: up', result.stdout)

    def test_rejected_credentials_are_not_retried(self):
        stub = self.stub('#!/bin/sh\necho "AUTH: Received control message: AUTH_FAILED"\nexit 1\n')
        name = 'sidetunnel-auth-test'
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
        subprocess.run(docker_run(self.root, stub, '-d', '--name', name, '--restart', 'unless-stopped'), check=True, capture_output=True)
        try:
            time.sleep(4)
            state = subprocess.check_output(['docker', 'inspect', name, '--format', '{{.State.Running}} {{.RestartCount}}'], text=True).split()
            self.assertEqual(state, ['true', '0'])
            status = subprocess.run(['docker', 'exec', name, 'status'], capture_output=True, text=True)
            self.assertEqual((status.returncode, status.stdout), (2, 'auth-failed\n'))
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


if __name__ == '__main__':
    unittest.main()
