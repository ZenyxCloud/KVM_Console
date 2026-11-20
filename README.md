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

## Run

For a new deployment, copy `example.env` to `.env` and set the values for your
environment before starting the container. Generate the shared `API_KEY` with
`openssl rand -hex 32` and use the same value in WHMCS.

`ghcr.io/zenyxcloud/kvm-console` is built by `.github/workflows/ci.yml`
(`latest` from `main`, `X.Y.Z` and `X.Y` from a `vX.Y.Z` tag). The image is
private and distroless. It runs as a non-root user with a read-only
filesystem under Compose. Pull it on the VM with the read-only ZenyxDeploy
account.

```sh
docker login ghcr.io -u ZenyxDeploy
docker compose pull && docker compose up -d
```

The gateway needs a public HTTPS name and a route to the Proxmox API
endpoints over the VPN. The container's DNS resolver must resolve any private
hostnames used in WHMCS.

The supplied Compose file publishes port 8080 on the host's loopback interface.
Use a reverse proxy that supports WebSocket upgrades and list its source
address as seen by the gateway in `TRUSTED_PROXIES`. For standalone TLS
termination, set `TLS_CERT_FILE` and `TLS_KEY_FILE` to files the gateway can
read and expose its HTTPS listener to WHMCS and browsers.

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
| `LISTEN_ADDR` | `:8080` | |
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
certificate and hostname verification by default. `PVE_CA_FILE` is optional
for unpinned servers whose CA is outside the system trust store. The Compose
file mounts `./ca/` at `/etc/kvm-console/ca`, which can be set as
`PVE_CA_FILE`. Changes to that trust store take effect after a gateway restart.

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
