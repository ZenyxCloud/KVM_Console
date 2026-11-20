# Zenyx KVM Console

Public entry point for the noVNC and xterm.js consoles once the Proxmox nodes
are only reachable on the private network (VPN). It replaces the ModulesGarden
console proxy shipped in `ZenyxCloud/whmcs_proxmox` under `proxy/` (Lumen on PHP 7.4, MySQL, nginx with
`resolver 8.8.8.8`) with one static Go binary and no database.

It speaks the same API as that proxy, so **the WHMCS module needs no code
change**: it is declared in the module's existing *Console Proxy* settings.

```
Browser ── noVNC page served by WHMCS (VncConsole / Xtermjs packages)
   │
   │ wss://console.zenyx.cloud/auth/<token>/proxmox
   ▼
kvm-console (public HTTPS, leg on the VPN) ──wss──► PVE node :8006 vncwebsocket
   ▲
   │ POST /token (securityToken, URL, PVEAuthCookie, client ip)
WHMCS (already reaches the PVE API over the VPN)
```

1. The client opens the console in WHMCS. The module calls `vncproxy` (or
   `termproxy`) on the node **as the VM's Proxmox user**, then posts the
   websocket URL and that user's `PVEAuthCookie` to the gateway.
2. The gateway checks the caller (WHMCS_IPS + API key) and the target
   (https, allowed port, `/api2/json/nodes/<node>/(qemu|lxc)/<vmid>/vncwebsocket`,
   only `port` and `vncticket` in the query), stores it in memory and returns
   a random 32-character token, valid 60 s and **usable once**.
3. WHMCS renders noVNC with `wss://<gateway>/auth/<token>/proxmox` and the VNC
   ticket. The gateway checks the `Origin`, redeems the token, connects to the
   node (certificate verified, destination IP re-checked against
   `PVE_ALLOWED_NETWORKS` after DNS resolution) and relays frames both ways.

Nothing is written to disk; tickets and cookies are never logged.

## Run

```sh
cp example.env .env
openssl rand -hex 32
docker compose up -d
```

`ghcr.io/zenyxcloud/kvm-console` is built by `.github/workflows/ci.yml`
(`latest` from `main`, `X.Y.Z` and `X.Y` from a `vX.Y.Z` tag). The image is
private, distroless, non-root and runs read-only. Pull it on the VM with the
read-only ZenyxDeploy account:

```sh
docker login ghcr.io -u ZenyxDeploy
docker compose pull && docker compose up -d
```

The host needs a public HTTPS name (e.g. `console.zenyx.cloud`) and a route to the
nodes' port 8006 over the VPN. If the nodes are addressed by an internal DNS
name, the container must use the internal resolver.

Put it behind the existing reverse proxy (TLS, websockets, long timeouts) and
list that proxy in `TRUSTED_PROXIES`, or let it terminate TLS itself with
`TLS_CERT_FILE` / `TLS_KEY_FILE`. nginx example:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 12h;
    proxy_send_timeout 12h;
    proxy_buffering off;
}
```

Caddy needs nothing more than `reverse_proxy 127.0.0.1:8080`.

## Configuration

| Variable | Default | |
|---|---|---|
| `API_KEY` / `API_KEY_FILE` | — | Shared secret, ≥ 32 characters. Same value as the API key in WHMCS. |
| `WHMCS_IPS` | — | Addresses or CIDRs allowed to call `POST /token`. |
| `PVE_ALLOWED_NETWORKS` | — | CIDRs the gateway may connect to (the nodes' private network). |
| `PVE_ALLOWED_PORTS` | `8006` | Ports allowed on the nodes. |
| `PVE_CA_FILE` | system CAs | PEM bundle for the nodes' certificates, normally the cluster's `/etc/pve/pve-root-ca.pem`. |
| `PVE_TLS_INSECURE` | `false` | Skip certificate verification of the nodes. Last resort only. |
| `ALLOWED_ORIGINS` | — | Origins allowed to open a console, e.g. `https://my.zenyx.eu`. Empty accepts any origin (warning logged). |
| `TRUSTED_PROXIES` | — | Reverse proxies whose `X-Forwarded-For` is trusted. |
| `CLIENT_IP_VALIDATE` | `false` | Require the browser IP seen by the gateway to equal the one WHMCS saw. Breaks clients whose IPv4/IPv6 path differs. |
| `TOKEN_TTL` | `60` | Seconds before an unused token expires. |
| `SESSION_MAX_DURATION` | `12h` | A console session is closed after this. |
| `MAX_SESSIONS` / `MAX_SESSIONS_PER_IP` | `500` / `10` | Concurrent sessions. |
| `MAX_PENDING_TOKENS` | `10000` | Unredeemed tokens kept in memory. |
| `CLIENT_MESSAGE_LIMIT` | `4194304` | Largest message accepted from a browser (bytes). |
| `PING_INTERVAL` | `25s` | Websocket pings on both legs (keeps idle consoles open through proxies). |
| `PVE_DIAL_TIMEOUT` | `10s` | |
| `LISTEN_ADDR` | `:8080` | |
| `LOG_LEVEL` | `info` | JSON logs on stdout. |

The node certificates must name the address WHMCS uses for the server (IP or
hostname). After moving the nodes to private addresses, regenerate them with
`pvecm updatecerts --force` on each node, or set a hostname that the
certificates already contain.

## WHMCS

In the module's admin area, **Tools → Console Proxy** → *Create*: host
`console.zenyx.cloud`, API key = `API_KEY`. Then choose it in **Settings → Console
Proxy** (all nodes) or per node in **Cluster**. noVNC and xterm.js then go
through the gateway for clients and admins.

WHMCS verifies the gateway's certificate when the Proxmox server has *Secure*
enabled, so the public name needs a valid certificate.

## Not covered

- **SPICE** (`.vv` file, port 3128 on the node) is not proxied and stops
  working for private nodes.
- When no console proxy is selected for a node, the module still falls back to
  redirecting the browser to `https://<node>:8006/novnc/mgnovnc.html`, which
  cannot work for private nodes.

## Tests

```sh
go test -race ./...
```

The Go tests run the whole path against a fake Proxmox websocket (TLS,
cookie and ticket checks, subprotocol, 3 MiB frames, keepalive, close
propagation) and cover the refusals: replayed or expired token, foreign
origin, wrong key or caller, targets outside the allowlists (including a
hostname resolving elsewhere), untrusted certificate, IP binding, limits. 

`ZenyxCloud/whmcs_proxmox` keeps `tests/test-kvm-console-contract.php`, which
drives the module's own `ProxyService` against a built binary:

```sh
CGO_ENABLED=0 go build -o /tmp/kvm-console .
KVM_CONSOLE_BIN=/tmp/kvm-console php /path/to/whmcs_proxmox/tests/test-kvm-console-contract.php
```
