# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

First release, extracted from [kubectl-vpn](https://github.com/AryanHamedani/kubectl-vpn).

### Added

- OpenVPN client in a container with an always-on kill switch and upstream sockets bound to the tunnel.
- HTTP CONNECT and SOCKS5 on one port.
- `ALLOWED_HOSTS` (required; names, wildcards, addresses, CIDR ranges or `*`) and `ALLOWED_PORTS`.
- Optional proxy authentication with `PROXY_USER` and `PROXY_PASSWORD_FILE`.
- DNS resolution through the tunnel, using the servers the VPN pushes or `DNS_SERVERS`.
- Profile hardening inside the container, host names in `remote`, and `proto tcp` profiles.
- `status` command and image `HEALTHCHECK`.

[0.1.0]: https://github.com/AryanHamedani/sidetunnel/releases/tag/v0.1.0
