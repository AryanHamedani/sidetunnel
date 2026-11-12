# sidetunnel

A second VPN beside the one your machine is already on, used as a local proxy.

`sidetunnel` runs an OpenVPN client inside a container with its own network namespace and exposes it as an HTTP CONNECT and SOCKS5 proxy on a local port. Your machine's routes, DNS and existing VPN stay exactly as they are; only the applications you point at the proxy use the tunnel.

```text
browser, curl, kubectl → 127.0.0.1:8080 → container: proxy → OpenVPN tunnel → private network
everything else        → your normal network or VPN, unchanged
```

Typical uses: reaching a company network while your laptop stays on a personal VPN, opening one internal site in a browser through a proxy extension, or giving a single tool access to a second network.

## Quick start

You need Linux with Docker and `/dev/net/tun`, and an OpenVPN client profile.

```sh
mkdir -m 700 ~/.config/sidetunnel
cp /path/to/profile.ovpn ~/.config/sidetunnel/client.ovpn
# Only if the VPN asks for a username and password: line 1 username, line 2 password.
install -m 600 /dev/stdin ~/.config/sidetunnel/auth.txt

docker run -d --name sidetunnel --restart unless-stopped \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --read-only --tmpfs /tmp \
  -p 127.0.0.1:8080:8080 \
  -v ~/.config/sidetunnel:/config:ro \
  -e ALLOWED_HOSTS='intranet.example.com,*.corp.example.com' \
  ghcr.io/aryanhamedani/sidetunnel:0.1.0

docker exec sidetunnel status          # connecting, ready, auth-failed or proxy-down
curl -x http://127.0.0.1:8080 https://intranet.example.com/
curl --socks5-hostname 127.0.0.1:8080 https://intranet.example.com/
```

The same with Compose:

```yaml
services:
  sidetunnel:
    image: ghcr.io/aryanhamedani/sidetunnel:0.1.0
    restart: unless-stopped
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun]
    read_only: true
    tmpfs: [/tmp]
    ports: ['127.0.0.1:8080:8080']
    volumes: ['~/.config/sidetunnel:/config:ro']
    environment:
      ALLOWED_HOSTS: 'intranet.example.com,*.corp.example.com'
```

## Options

| Variable | Default | Meaning |
| --- | --- | --- |
| `ALLOWED_HOSTS` | none, required | Comma-separated destinations the proxy may connect to: host names, `*.example.com` wildcards, IPv4 addresses, CIDR ranges such as `10.0.0.0/8`, or `*` for every host. The container refuses to start without it. |
| `ALLOWED_PORTS` | `80,443` | Destination ports: single ports, ranges such as `8000-8100`, or `*`. |
| `PROXY_USER`, `PROXY_PASSWORD_FILE` | off | Require proxy authentication. The file holds the password, for example `/config/proxy-password`. HTTP uses Basic, SOCKS5 uses username/password (RFC 1929). |
| `DNS_SERVERS` | pushed by the VPN, else `1.1.1.1` | Comma-separated IPv4 resolvers. They are always queried through the tunnel. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warning` or `error`. At `info` each connection logs its destination and whether it was opened, denied or failed. |

Files in `/config` (mount it read-only):

| File | Purpose |
| --- | --- |
| `client.ovpn` | Your OpenVPN profile, required. |
| `auth.txt` | Username and password on two lines, only for VPNs that ask for them. |

The listen address is chosen by Docker's `-p`. Keep `127.0.0.1:` in front of the port unless you mean to share the proxy; see [Exposure](#exposure).

`*.example.com` matches subdomains at any depth but not `example.com` itself; list both if you need both.

## Using it from applications

- **Browsers**: use a proxy extension such as FoxyProxy with a rule per site. Either proxy type works: `HTTP` on `127.0.0.1:8080` carries `https://` sites, `SOCKS5` carries `http://` sites as well. With SOCKS5, turn on "proxy DNS" (remote DNS), otherwise the browser resolves names itself and a name-based allowlist will not match. Browsers do not support SOCKS5 authentication; use the HTTP type if you set `PROXY_USER`.
- **Command line**: `HTTPS_PROXY=http://127.0.0.1:8080` for most tools, or `ALL_PROXY=socks5h://127.0.0.1:8080`.
- **Kubernetes**: [kubectl-vpn](https://github.com/AryanHamedani/kubectl-vpn) wraps this image for `kubectl` and other kubeconfig clients.

Plain `http://` requests sent to the HTTP proxy type (a `GET http://…` instead of `CONNECT`) are answered with 405; use SOCKS5 for those.

## What it guarantees

- **Nothing on the host changes.** OpenVPN's routes and the firewall rules live in the container's network namespace. No host routes, DNS settings or firewall rules are touched, and the container does not use host networking or privileged mode (it needs `NET_ADMIN` and the TUN device inside its own namespace).
- **Kill switch, always on.** Before OpenVPN starts, the container's outbound policy becomes DROP. The only traffic allowed outside the tunnel is the VPN transport to the profile's endpoints and replies to proxy clients. IPv6 output is dropped.
- **No direct fallback.** Every upstream socket and every DNS query is bound to the tunnel device. If the tunnel is down, connections fail; they are never retried over the normal network.
- **DNS stays in the tunnel.** The proxy resolves names itself through the tunnel and does not use Docker's resolver. The one exception is a host name in the profile's `remote` line, which has to be resolved once, before the tunnel exists.
- **TLS is end to end.** The proxy relays bytes; it does not terminate or inspect TLS.
- **Rejected credentials are not retried.** If the VPN answers `AUTH_FAILED`, the container stays up idle and reports `auth-failed` instead of reconnecting, because repeated attempts can lock an account. Fix `auth.txt` and recreate the container.

## Exposure

Anyone who can reach the proxy port can reach whatever `ALLOWED_HOSTS` permits inside the VPN. So:

- Publish on `127.0.0.1` unless other machines must use the proxy. Other local users and processes on the same machine can still connect to it.
- Prefer a list of hosts over `*`. With `*`, also consider narrowing `ALLOWED_PORTS`.
- If you publish on another interface, set `PROXY_USER` and `PROXY_PASSWORD_FILE`. Proxy authentication is sent unencrypted, so treat it as a guard for a trusted network, not for the internet.

## The profile

The container does not run your profile as written. It keeps the connection settings (remotes, protocol, inline `ca`/`cert`/`key`/`tls-auth`/`tls-crypt`/`tls-crypt-v2`, cipher and TLS options, MTU options) and drops everything else, including `up`/`down` scripts, routes, `dev` and `auth-user-pass` paths. It then adds its own device, routing and retry settings. The names of dropped directives are logged at start.

To check a profile without connecting:

```sh
docker run --rm -v ~/.config/sidetunnel:/config:ro --entrypoint python3 \
  ghcr.io/aryanhamedani/sidetunnel:0.1.0 /app/ovpn.py
```

Limits in this release:

- OpenVPN only, over UDP or TCP, IPv4 only.
- Certificates and keys must be inline in the profile; external files are not read.
- Username/password is the only interactive credential; MFA prompts are not supported.
- When a profile lists public and private endpoint addresses, only the public ones are used.
- Profiles that depend on dropped directives (for example compression) may need adapting.

## Status and health

`docker exec sidetunnel status` prints one word and sets the exit code: `ready` (0), `connecting` or `proxy-down` (1), `auth-failed` (2). The same check is the image's `HEALTHCHECK`, so `docker ps` shows `healthy` once the tunnel is up. `docker logs sidetunnel` shows OpenVPN's output and the proxy's connection log; neither contains credentials.

After changing `client.ovpn`, `auth.txt` or any option, recreate the container.

## Development

```sh
python3 -m unittest discover -s tests -v          # unit tests, Python 3.11+
docker build -t sidetunnel:dev .
RUN_DOCKER_TESTS=1 python3 -m unittest discover -s tests -v   # plus entrypoint tests with a stub OpenVPN
tests/e2e.sh                                      # real tunnel to a throwaway OpenVPN server in Docker
```

No test uses a real VPN account. The code is Python standard library only.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

MIT. See [LICENSE](LICENSE).
