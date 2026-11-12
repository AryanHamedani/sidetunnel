#!/bin/sh
# End-to-end check against a throwaway OpenVPN server on a private Docker network.
# Usage: tests/e2e.sh [image]   (needs docker, openssl, curl; uses local port 18099)
set -eu
IMAGE=${1:-sidetunnel:dev}
NET=sidetunnel-e2e SERVER=sidetunnel-e2e-server CLIENT=sidetunnel-e2e-client PORT=18099
WORK=$(mktemp -d)
cleanup() {
  docker rm -f "$SERVER" "$CLIENT" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
cleanup; mkdir -p "$WORK/pki" "$WORK/config"; chmod 755 "$WORK" "$WORK/pki" "$WORK/config"

cd "$WORK/pki"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -subj /CN=e2e-ca -days 2 2>/dev/null
for role in server client; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $role.key -out $role.csr -subj /CN=$role 2>/dev/null
  printf 'extendedKeyUsage=%sAuth\nkeyUsage=digitalSignature,keyAgreement\n' $role > $role.ext
  openssl x509 -req -in $role.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $role.crt -days 2 -extfile $role.ext 2>/dev/null
done
chmod 644 ./*
{
  # The hostname remote, the script hook and the route must be resolved, dropped and overridden.
  printf 'client\ndev tun\nproto udp\nremote %s 1194\nremote-cert-tls server\nup /bin/false\nroute-nopull\n' "$SERVER"
  printf '<ca>\n%s\n</ca>\n<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n' "$(cat ca.crt)" "$(cat client.crt)" "$(cat client.key)"
} > "$WORK/config/client.ovpn"
cd /

docker network create "$NET" >/dev/null
docker run -d --name "$SERVER" --network "$NET" --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$WORK/pki:/pki:ro" --entrypoint sh "$IMAGE" -c \
  "python3 -m http.server 8000 -d /app & exec openvpn --dev tun --proto udp --port 1194 --topology subnet \
   --server 10.8.0.0 255.255.255.0 --ca /pki/ca.crt --cert /pki/server.crt --key /pki/server.key --dh none \
   --push 'dhcp-option DNS 10.8.0.1' --verb 3" >/dev/null
docker run -d --name "$CLIENT" --network "$NET" --cap-add NET_ADMIN --device /dev/net/tun --read-only --tmpfs /tmp \
  -p "127.0.0.1:$PORT:8080" -v "$WORK/config:/config:ro" -e ALLOWED_HOSTS=10.8.0.1 -e ALLOWED_PORTS=8000 "$IMAGE" >/dev/null

i=0
until [ "$(docker exec "$CLIENT" status 2>/dev/null)" = ready ]; do
  i=$((i + 1))
  [ $i -lt 60 ] || { docker logs "$CLIENT"; docker logs "$SERVER"; echo 'FAIL: tunnel did not come up'; exit 1; }
  sleep 1
done
fail() { echo "FAIL: $1"; docker logs --tail 30 "$CLIENT"; exit 1; }

curl -sf -m 10 -p -x "http://127.0.0.1:$PORT" http://10.8.0.1:8000/status.py | grep -q auth-failed || fail 'HTTP CONNECT through the tunnel'
curl -sf -m 10 --socks5-hostname "127.0.0.1:$PORT" http://10.8.0.1:8000/status.py | grep -q auth-failed || fail 'SOCKS5 through the tunnel'
[ "$(curl -s -m 10 -o /dev/null -w '%{http_connect}' -p -x "http://127.0.0.1:$PORT" http://10.8.0.2:8000/)" = 403 ] || fail 'host outside the allowlist was not refused'
[ "$(docker exec "$CLIENT" cat /tmp/dns)" = 10.8.0.1 ] || fail 'pushed DNS server was not recorded'
SERVER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVER")
# Kill switch: with the tunnel routes removed, nothing but the VPN transport may leave the container.
docker exec "$CLIENT" sh -c 'ip route del 0.0.0.0/1; ip route del 128.0.0.0/1'
if docker exec "$CLIENT" wget -q -T 3 -O /dev/null "http://$SERVER_IP:8000/"; then fail 'traffic left the container outside the tunnel'; fi
echo 'e2e ok'
