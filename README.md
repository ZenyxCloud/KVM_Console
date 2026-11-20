# Zenyx KVM Console

KVM Console relays WHMCS noVNC and xterm.js sessions to private Proxmox API
endpoints over the VPN. It keeps the existing WHMCS **Console Proxy** API and
stores pending tokens in memory. Token issuance and redemption must reach the
same gateway instance. A restart discards its pending tokens.

```text
WHMCS       ── HTTPS vncproxy or termproxy ──► Proxmox API endpoint
WHMCS       ── HTTPS POST /token ────────────► KVM Console
Browser     ── WSS /auth/<token>/proxmox ────► KVM Console
KVM Console ── WSS vncwebsocket over VPN ────► Proxmox API endpoint
```

1. WHMCS takes the endpoint from the Proxmox server assigned to the VPS and
   requests a console ticket as the VPS's Proxmox user. The VM's recorded
   node and VM ID are part of the API path. The gateway uses the host and
   port supplied by WHMCS for the WebSocket connection.
2. WHMCS sends the upstream WebSocket URL, the user's `PVEAuthCookie`, the
   browser IP it sees, and the configured server fingerprint when present
   to `POST /token`. The gateway checks the caller against `WHMCS_IPS` and
   `API_KEY` and validates the target URL. It returns a single-use token that
   expires after `TOKEN_TTL` (60 seconds by default). Proxmox controls the
   lifetime of its own ticket.
3. WHMCS serves the console page, which opens
   `wss://<gateway>/auth/<token>/proxmox`. The gateway applies its Origin and
   client IP settings, redeems the token, checks the destination IP and port
   after DNS resolution, and opens the upstream TLS connection before
   relaying the session.

Gateway logs include session metadata such as node, VM ID and client IP.
Reverse-proxy access logs can include the token in the WebSocket URL. Avoid
logging the request path for `/auth/` if those logs are retained.

## Deploy on Portainer

Use a Linux Docker Standalone endpoint with `/dev/net/tun` available.
The repository's `docker-compose.yml` starts KVM Console and the Pangolin
CLI machine client. Both use the host network so KVM Console can use the
Pangolin routes directly. Only the Pangolin container has `NET_ADMIN`. KVM
Console listens on `127.0.0.1:8080` for the host's HTTPS reverse proxy.

1. In Pangolin, use a site connector on a network that can reach Proxmox.
   Create a **private CIDR** resource for each dedicated Proxmox subnet.
   Allow TCP 8006, or the API ports configured in WHMCS. In **Clients →
   Machines**, create a machine client and grant it access to those resources.
2. In Portainer, add a Git repository stack using `docker-compose.yml` as
   the Compose path. In **Environment variables**, enter the values from
   `example.env`, or import a filled-out copy. Portainer writes those values
   to `stack.env`, which both services read. Keep the filled file out of Git.
3. Select a registry credential with pull access to
   `ghcr.io/zenyxcloud/kvm-console` if the package requires authentication.
   Enable GitOps updates for the branch you want Portainer to follow.

Start with these values and replace the examples with your own settings.

```dotenv
PANGOLIN_ENDPOINT=https://pangolin.example.com
CLIENT_ID=your-machine-client-id
CLIENT_SECRET=your-machine-client-secret
API_KEY=your-generated-hex-key
WHMCS_IPS=203.0.113.10
PVE_ALLOWED_NETWORKS=10.20.0.0/16
PVE_ALLOWED_PORTS=8006
ALLOWED_ORIGINS=https://my.zenyx.eu
TRUSTED_PROXIES=127.0.0.1/32
```

Generate `API_KEY` using `openssl rand -hex 32` and enter the same value in
the WHMCS Console Proxy settings. `WHMCS_IPS` is the WHMCS server's egress IP
as seen by the gateway after the reverse proxy. `PVE_ALLOWED_NETWORKS` must
cover the real private destination addresses granted in Pangolin.
`ALLOWED_ORIGINS` includes the public origins of the WHMCS client and admin
areas. Remove any old `PVE_CA_FILE` value from the Portainer stack when
switching to this Compose file. Set each private server's TLS fingerprint
in WHMCS.

The stack uses Pangolin's split tunnel and leaves DNS resolution to the
gateway host. Use real private Proxmox addresses or hostnames the gateway can
resolve to those addresses. Do not assign an exit node to this machine client.
WHMCS itself needs access to Proxmox to request the console ticket. If the
gateway host has an alternate route to the same addresses, verify that the
preferred route to them uses Pangolin.

After deployment, verify that the machine client is connected in Pangolin
and open a new WHMCS console. `/healthz` checks only the gateway process.

### Run from the command line

For a new deployment outside Portainer, copy `example.env` to `stack.env`,
fill it out, then start the same stack. Sign in to GHCR first if the image
requires authentication.

```sh
docker login ghcr.io -u ZenyxDeploy
docker compose pull
docker compose up -d
```

The image is built by `.github/workflows/ci.yml`. The `latest` tag follows
`main`. Versioned Docker tags are published from release tags.

### Public HTTPS endpoint

Point a reverse proxy on the host network at `127.0.0.1:8080` and enable
WebSocket upgrades. Set `TRUSTED_PROXIES` to the reverse proxy address used
for the connection. If the reverse proxy is containerized, it must be able
to reach the host loopback listener. For standalone deployments outside the
provided Compose stack, the gateway can terminate TLS with `TLS_CERT_FILE`
and `TLS_KEY_FILE`.

The following nginx location forwards HTTPS traffic to the Compose listener.

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

With Caddy on the same host, use `reverse_proxy 127.0.0.1:8080` and configure
`TRUSTED_PROXIES` as above.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `API_KEY` / `API_KEY_FILE` | — | Shared secret, ≥ 32 characters. Same value as the API key in WHMCS. |
| `WHMCS_IPS` | — | Addresses or CIDRs allowed to call `POST /token`. |
| `PVE_ALLOWED_NETWORKS` | — | Required destination CIDRs. Use the dedicated Proxmox VPN address pools. |
| `PVE_ALLOWED_PORTS` | `8006` | Ports allowed on the nodes. |
| `PVE_CA_FILE` | system CAs | For unpinned connections, a replacement trust store built from comma-separated PEM files or directories of `*.pem` / `*.crt` files. |
| `PVE_TLS_INSECURE` | `false` | Disables certificate verification for unpinned upstream connections when enabled. A supplied fingerprint is still verified. |
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
| `LISTEN_ADDR` | `:8080` | The supplied Compose sets this to `127.0.0.1:8080`. |
| `LOG_LEVEL` | `info` | JSON logs on stdout. |

## WHMCS and cluster changes

Use gateway and WHMCS module builds that both support fingerprints. Update the
gateway first. In the Proxmox addon, create a proxy under **Tools → Console
Proxy** with the gateway's HTTPS URL and shared `API_KEY`. Select it under
**Settings → Console Proxy** as the global default. **Cluster** can override
that choice for an individual node. Add the client and admin WHMCS origins
to `ALLOWED_ORIGINS`.

WHMCS verifies the public gateway's HTTPS certificate when saving the proxy
and when requesting a token. The save checks HTTPS with a HEAD request.
Open a console to check the API key and route. Browsers verify the gateway
certificate when they open the WebSocket.

For private Proxmox certificates, set **TLS Certificate Fingerprint
(SHA-256)** on the server entry used by the VPS in WHMCS. The authenticated
`POST /token` carries it as the optional `tlsFingerprint` field with 64
hexadecimal characters. The gateway verifies the exact leaf certificate and
its validity period. An invalid, expired or mismatched certificate fails the
upstream connection. When the field is omitted, the gateway uses normal
certificate and hostname verification with the system CAs by default.
A standalone gateway can use `PVE_CA_FILE` to load a custom trust store
at startup.

The gateway maintains no inventory of nodes or clusters.

| Change | Where to update it |
|---|---|
| Add or remove a node in an existing cluster, or move a VM | Keep the VPS's server and node current in WHMCS. The next console launch uses those records. |
| Add a Proxmox server, change the API endpoint, or replace its certificate | Update the server entry and fingerprint in WHMCS. Update private DNS if the endpoint's address changes. |
| Use a destination outside the configured VPN CIDRs or API ports | Update the gateway's route or allowlists as needed before issuing consoles to that destination. |

A change in WHMCS affects new console launches. Previously issued tokens
keep the URL and fingerprint received at issuance, with DNS resolved at
connection time. An open WebSocket stays on its existing connection.

When neither a node nor a global proxy is configured, WHMCS uses the
legacy Proxmox-hosted console page. A private endpoint then needs to be
reachable by the browser. If a saved node override points to a deleted proxy,
WHMCS tries the global selection. When that selection is unavailable,
the console reports a configuration error. SPICE uses its own native
connection and needs a reachable SPICE endpoint.

## Health check

`GET /healthz` returns HTTP 200 with `{"status":"ok"}` while the gateway is serving requests.

## Tests

```sh
go test -race ./...
```

The Go tests use simulated Proxmox WebSocket endpoints. They exercise
certificate fingerprints across two clusters without loading their CAs,
CA-based trust, token expiry and replay, destination allowlists, and
WebSocket frame relay. The PHP contract in `ZenyxCloud/whmcs_proxmox` checks
TLS and token issuance using the module's `ProxyService` and the built
gateway binary.

```sh
CGO_ENABLED=0 go build -o /tmp/kvm-console .
KVM_CONSOLE_BIN=/tmp/kvm-console php /path/to/whmcs_proxmox/tests/test-kvm-console-contract.php
```
