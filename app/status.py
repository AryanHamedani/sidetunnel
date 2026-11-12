#!/usr/bin/env python3
"""Print the tunnel state and exit 0 (ready), 1 (not ready yet) or 2 (credentials rejected). Also the image HEALTHCHECK."""
import os
import socket
import sys

if os.path.exists('/tmp/auth-failed'):
    print('auth-failed')
    sys.exit(2)
if not os.path.exists('/tmp/vpn-ready'):
    print('connecting')
    sys.exit(1)
try:
    socket.create_connection(('127.0.0.1', 8080), 2).close()
except OSError:
    print('proxy-down')
    sys.exit(1)
print('ready')
