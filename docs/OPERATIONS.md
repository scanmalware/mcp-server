# Operations / Deployment Runbook

This document describes the current DigitalOcean deployment, how to connect to the droplet, how to redeploy, and where to find logs.

## Current deployment

- Domain: `mcp.scanmalware.com`
- Region: `fra1` (Frankfurt)
- Droplet size: `s-1vcpu-2gb`
- OS image: `debian-12-x64`
- Containers (Docker Compose plugin):
  - `mcp` (ScanMalware MCP server, streamable HTTP on port 8000)
  - `nginx` (frontend on 80/443, proxies `/mcp` to `mcp:8000`)
  - `proxy` (mitmproxy with ScanMalware destination checks + full HTTP logging)

## Connect to the DigitalOcean instance

This runbook is public, so it does not hardcode the droplet address or a key
path. Resolve them once per shell and reuse `mcpssh` in the commands below.

```bash
# Look the droplet up by tag rather than pinning its IP here.
export MCP_HOST="$(doctl compute droplet list --tag-name scanmalware-mcp \
  --format PublicIPv4 --no-header | head -1)"
export MCP_SSH_KEY="${MCP_SSH_KEY:-$HOME/.ssh/id_ed25519}"

# A function, not a variable: zsh does not word-split an unquoted "$VAR" used
# as a command, so stashing the whole ssh invocation in a variable breaks there.
# A function works in bash and zsh alike, and accepts heredocs.
mcpssh() { ssh -i "$MCP_SSH_KEY" "root@$MCP_HOST" "$@"; }

mcpssh 'hostname; uptime'
```

Nicer still, put it in `~/.ssh/config` (untracked) and just use `ssh scanmalware-mcp`:

```
Host scanmalware-mcp
  HostName <droplet-ip>
  User root
  IdentityFile ~/.ssh/id_ed25519
```

## Services and paths

- Repo checkout: `/opt/scanmalware-mcp`
- Compose file: `/opt/scanmalware-mcp/deploy/docker-compose.yml`
- Nginx config: `/opt/scanmalware-mcp/deploy/nginx/nginx.conf`
- Landing page: `/opt/scanmalware-mcp/deploy/nginx/html/index.html`
- mitmproxy addon: `/opt/scanmalware-mcp/deploy/mitmproxy/log_full.py`
- mitmproxy destination guard: `/opt/scanmalware-mcp/deploy/mitmproxy/restrict_hosts.py`
- mitmproxy state (CA): `/opt/scanmalware-mcp/deploy/mitmproxy/state`
- MCP source mount: `/opt/scanmalware-mcp/scanmalware_mcp` → `/app/scanmalware_mcp` (`PYTHONPATH=/app`)

## HTTPS / TLS

- TLS is terminated by Nginx using Let’s Encrypt certificates.
- Cert paths:
  - `/etc/letsencrypt/live/mcp.scanmalware.com/fullchain.pem`
  - `/etc/letsencrypt/live/mcp.scanmalware.com/privkey.pem`
- HSTS is enabled: `Strict-Transport-Security: max-age=31536000`.
- Cert renewal is handled by `certbot renew`. A deploy hook reloads nginx (container restart).
- Only `mcp.scanmalware.com` is served. The droplet IP is recycled and other
  domains (riskap.store, matos.re, coquesdetel.com and more) still resolve to
  it; they made up about half of all requests. Default servers now close
  those connections: port 80 returns 444, and port 443 refuses the TLS
  handshake for any other SNI name (`ssl_reject_handshake`) and returns 444 to
  a request with our SNI but another `Host`. ACME challenges for
  `mcp.scanmalware.com` are unaffected.

To renew manually:

```bash
certbot renew
```

## MCP endpoint

- MCP endpoint: `https://mcp.scanmalware.com/mcp`
- The HTTP transport expects `Accept: application/json, text/event-stream`. On
  POST, a header whose media ranges already cover both (`*/*`,
  `application/*, text/*`) or no `Accept` header at all is spelled out to that
  before the SDK checks it; until October 2026 those got 406. A header that
  excludes either type is still refused. GET is unchanged and needs
  `text/event-stream`, because an accepted GET opens a standing SSE stream.
- `submit_scan` does not call `/api/v1/csrf-token` (no CSRF token tool).

Minimal smoke test:

```bash
python - <<'PY'
import json
import httpx

URL = "https://mcp.scanmalware.com/mcp"
HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}

init_payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcp-smoke-test", "version": "0.1.0"},
    },
}


def extract_sse_data(text: str) -> dict:
    for line in text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: "):])
    raise ValueError("No SSE data line found")


with httpx.Client(timeout=10) as client:
    init_resp = client.post(URL, headers=HEADERS, json=init_payload)
    init_resp.raise_for_status()

    # The server runs stateless_http=True, so it returns no mcp-session-id.
    # Only send the header when one is present, so this works either way.
    session_id = init_resp.headers.get("mcp-session-id")

    init_message = extract_sse_data(init_resp.text)
    protocol_version = init_message["result"]["protocolVersion"]

    headers = {**HEADERS, "mcp-protocol-version": protocol_version}
    if session_id:
        headers["mcp-session-id"] = session_id

    client.post(URL, headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})

    tools_resp = client.post(
        URL,
        headers=headers,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    tools_resp.raise_for_status()
    tools_message = extract_sse_data(tools_resp.text)
    tool_names = [tool["name"] for tool in tools_message["result"]["tools"]]

print("protocol_version:", protocol_version)
print("session_id:", session_id or "(none - stateless)")
print("tool_count:", len(tool_names))
PY
```

## Transport mode (stateless)

The server is built with `stateless_http=True`, so:

- responses carry **no `mcp-session-id`** header, and clients must not require one;
- no per-session transport is retained, which is what keeps memory flat.

This was a deliberate change. With the old SDK, stateful mode never evicted entries from `_server_instances`,
so every session leaked a
`StreamableHTTPServerTransport` + `ServerSession` (~77 KB) for the life of the
process. MCP 1.30.0 adds session reclamation, but this server continues to use
stateless mode. Measured with the old SDK over 600 sessions: stateful grew ~41 MB and kept climbing,
stateless stayed flat at ~75 MB RSS. The server sends no server-initiated
notifications, so it gives up nothing it actually used.

## Client attribution in logs

`stateless_http=True` means the `initialize` params are not carried across
requests, so `client_name` and `client_version` are `null` on `mcp.tool.start`
events. Tool events therefore also log `user_agent`, taken from the HTTP header,
which does survive. Group tool usage by `user_agent`; the [popularity example below](#popularity-reporting-example)
does this already.

The client's own name and version are logged once per session instead, on the
`mcp.session.start` event (see [MCP logs](#mcp-logs)). Generic user agents hide
who is calling: in October 2026 `node` was mostly Glama, `undici` was
span-pipeline and the Glama inspector, and `python-requests` was the
agentstatus probe network.

The raw `mcp-http.log` still records full request headers either way.

## Dependency pinning

`mcp` is constrained to `>=1.30.0,<2`, with the production dependency graph
pinned by version and hash in `requirements.lock`. mcp 2.x renamed `FastMCP` to `MCPServer` and this
server does not import under it - a rebuild that picked up 2.x would produce a
container that crashes on startup. `httpx` is declared explicitly because mcp 2.x
switched to `httpx2`, so it can no longer be relied on transitively.

## Security maintenance

The 2026-10-02 maintenance release uses Docker Engine 29.8.2 from Docker's
signed Debian repository, Compose 5.5.1, containerd 2.3.6, runc 1.5.1,
Python 3.14.8, MCP 1.30.0, Nginx 1.30.5 and mitmproxy 12.2.3.
Host Debian security updates remain automatic. Container image
contents require a separate rebuild and deployment; restarting does not patch them.

Python and Nginx base images are pinned by digest. Each build applies available
OS package updates. MCP and proxy Python dependencies are installed from hashed
lock files, checked for consistency, and pip is removed from runtime images.
MCP still runs as UID 10001. Container names are explicit so certificate renewal
and log-rotation hooks remain valid with the Compose plugin.

Refresh the locks, then review the resulting versions and advisories:

```bash
uv pip compile pyproject.toml requirements-build.in --python-version 3.14 \
  --python-platform x86_64-unknown-linux-gnu --generate-hashes --upgrade \
  --output-file requirements.lock
uv pip compile deploy/mitmproxy/requirements.in --python-version 3.14 \
  --python-platform x86_64-unknown-linux-gnu --generate-hashes --upgrade \
  --output-file deploy/mitmproxy/requirements.lock
uv run --no-project --with pip-audit pip-audit --no-deps --disable-pip -r requirements.lock
uv run --no-project --with pip-audit pip-audit --no-deps --disable-pip -r deploy/mitmproxy/requirements.lock
```

The [GitHub security-maintenance workflow](../.github/workflows/security-maintenance.yml)
is active on `main`. It rebuilds images and runs dependency checks and tests on
pushes to `main`, pull requests, manual runs and the first of each month at
05:17 UTC. [Dependabot](../.github/dependabot.yml) checks base images and Python
dependencies weekly, and GitHub Actions monthly. Automated updates stay on
the tested Python 3.14, Nginx 1.30 and MCP 1.x release lines; release-line
migrations need a separate compatibility review. These checks do not deploy
to production.

Before a runtime upgrade or reboot, retain a droplet snapshot, the private
configuration/CA backup and previous images. Build and test candidates first.
After deployment, verify tools/list (128 tools), API requests, both proxy
protocol guards, direct-egress restrictions, certificate renewal and rotation.
The Docker startup drop-in reapplies egress restrictions before containers start.
Keep the previous snapshot until the new deployment has been observed healthy.

### Remaining upstream advisories

The MCP Python dependency lock has no known findings in the maintenance audit.
This is not a claim that all container OS packages are vulnerability-free:
Debian still lists findings without a released distribution fix.

mitmproxy 12.2.3 caps four libraries below available security fixes:

| Library | Locked version | Remaining scope / action |
| --- | --- | --- |
| cryptography | 48.0.1 | Certificate-verifier and PKCS7 advisories; follow the upstream compatibility update. |
| h2 | 4.3.0 | HTTP/2 is disabled in this deployment. |
| msgpack | 1.1.2 | Unpacker error handling; no untrusted flow archives are loaded by the service. |
| tornado | 6.5.5 | HTTP/websocket/UI advisories; mitmweb and Tornado server/client features are not enabled here. |

These remain open package findings. The audit step reports each match and uses
`deploy/mitmproxy/audit-baseline.json` to fail on new advisories, changed package
versions, or an overdue review (2026-11-02). Do not override upstream dependency bounds just to make the
audit green; test a compatible upstream release when one becomes available.
The proxy was rebuilt on current Python/OS packages and its compatible
cryptography, HPACK and ASN.1 updates were applied.

## Logs (persistent)

### MCP logs

Two files are persisted on the host and survive redeploys:

- Sanitized log: `/opt/scanmalware-mcp/logs/mcp/mcp.log`
  - Includes tool/resource start/end, args (sanitized), timing, client name/version, and IP fields.
- Full log (args + result): `/opt/scanmalware-mcp/logs/mcp/mcp-full.log`
  - Includes full tool args and full tool results (no redaction).

Rotation (defaults): 10 MiB max per file, 7 backups. Controlled by:
- `SCANMALWARE_LOG_FILE`, `SCANMALWARE_LOG_MAX_BYTES`, `SCANMALWARE_LOG_BACKUP_COUNT`
- `SCANMALWARE_FULL_LOG_FILE`, `SCANMALWARE_FULL_LOG_MAX_BYTES`, `SCANMALWARE_FULL_LOG_BACKUP_COUNT`

Process and session lifecycle events:

- `mcp.startup` fires **once per process**, when the shared ScanMalware HTTP
  client is built. It carries the resolved config (base URL, proxy, CA cert).
- `mcp.session.start` fires **once per session-opening request** on the
  streamable HTTP transport: `initialize`, or `server/discover` from clients
  that speak protocol 2026-07-28 (Claude.ai, recent Claude Code). It carries
  `method`, `protocol_version`, `client_name`, `client_version`, `user_agent`
  and the client IP fields. A 2026-07-28 client that falls back logs a
  `server/discover` followed by an `initialize`, so count `initialize` for
  sessions.
- `mcp.lifespan.enter` (DEBUG, not written at the default INFO level) fires
  for every HTTP request, because the SDK runs the lifespan per request under
  `stateless_http`.

Count sessions, and the clients behind them, for one log file:

```bash
grep '"mcp.session.start"' /opt/scanmalware-mcp/logs/mcp/mcp.log | grep -c '"method": "initialize"'
grep '"mcp.session.start"' /opt/scanmalware-mcp/logs/mcp/mcp.log \
  | grep -o '"client_name": "[^"]*"' | sort | uniq -c | sort -rn | head -20
```

Older logs count differently. Before the shared-client change (2026-09-10),
`mcp.startup` fired per session. From then until `mcp.session.start` was added
(October 2026), `mcp.session.open` fired at INFO for every HTTP request, not
per session: about 2.7k a day against about 680 `initialize` requests, so it
roughly tripled the apparent session count. A rising `mcp.startup` count in a
current log means the process is restarting.

Tool calls log `mcp.tool.start` and then exactly one of `mcp.tool.end`,
`mcp.tool.error` or `mcp.tool.cancelled`. The last means the client
disconnected or cancelled before the result, for example when a slow query
outlasted the client's own timeout; before October 2026 such calls left only
a start event.

### MCP raw HTTP logs

- Raw HTTP log: `/opt/scanmalware-mcp/logs/mcp/mcp-http.log`
  - Includes raw MCP HTTP request/response headers and bodies (base64) with per-request IDs.
  - Bodies are captured up to `SCANMALWARE_MCP_HTTP_LOG_MAX_BODY_BYTES` (default `1048576`, set to `0` for unlimited).

Rotation: 10 MiB max per file; 63 backups in Compose (about 640 MiB including
the active file), or 7 backups for the standalone server. Controlled by:
- `SCANMALWARE_MCP_HTTP_LOG_FILE`, `SCANMALWARE_MCP_HTTP_LOG_MAX_BYTES`, `SCANMALWARE_MCP_HTTP_LOG_BACKUP_COUNT`
- `SCANMALWARE_MCP_HTTP_LOG_MAX_BODY_BYTES`

### Nginx logs

- Access log: `/opt/scanmalware-mcp/logs/nginx/access.log`
- Error log: `/opt/scanmalware-mcp/logs/nginx/error.log`

The access log includes client IPs and MCP session IDs.

### mitmproxy logs

- Full HTTP log: `/opt/scanmalware-mcp/logs/mitmproxy/full.log`
  - JSON lines with full request/response headers and bodies (base64).
  - Bodies may be compressed (see `content-encoding` header).

### Rotation and retention

Docker stdout/stderr logs use the `json-file` driver with `max-size=10m`,
`max-file=5`, and compression for all three services. Recreate containers after
changing these settings; a restart does not apply new logging options. See the
[Docker logging documentation](https://docs.docker.com/engine/logging/drivers/json-file/).
Archive existing output with `docker logs --timestamps` before recreation if
it needs to be retained. Do not truncate Docker's internal log files.

Install the host rotation policy once on the standard `/opt/scanmalware-mcp`
deployment (the installer and policy assume the default `deploy_*_1` names):

```bash
apt-get update
apt-get install -y logrotate
bash /opt/scanmalware-mcp/deploy/logrotate/install.sh
```

The dedicated `scanmalware-logrotate.timer` checks hourly. Nginx access/error
logs and the proxy's `full.log` rotate daily or at 100 MiB, retaining 14 archives
per file with delayed compression. The active file can exceed 100 MiB between
checks; pre-existing oversized files remain in the archives until aged out.
The policy lives at `/etc/scanmalware-mcp/logrotate.conf` with its own state file,
outside the distribution's `/etc/logrotate.d` policy set.

Nginx receives `USR1` after a rename to reopen its logs. The proxy addon opens
and closes its file for each event and recreates it on the next write. Neither
uses `copytruncate`. See [Nginx log rotation](https://nginx.org/en/docs/control.html).

MCP application, full-result, and raw HTTP logs continue using Python rotation.
The Compose deployment retains 63 raw HTTP backups plus the active file at
10 MiB each (about 640 MiB, roughly a week at the observed traffic rate).
The standalone server and other MCP log streams retain their existing defaults.
Rotation limits are volume-based, so they do not guarantee a fixed history window.

Verify the installed configuration and timer:

```bash
logrotate --debug --state /dev/null /etc/scanmalware-mcp/logrotate.conf
systemctl list-timers scanmalware-logrotate.timer
systemctl status scanmalware-logrotate.service --no-pager
```

### Slow upstream queries

Five tools use `SCANMALWARE_SLOW_QUERY_TIMEOUT_S` (default 90 seconds), each
because measured latency exceeded or approached the normal 30-second timeout:

| Tool | Observed latency |
| --- | --- |
| `get_favicon_stats` | 57 s live aggregation |
| `search_ocr` | 24–30 s for successful searches |
| `get_jsfingerprint_similarity_counts` | ~31 s per call (2026-10-07) |
| `search_js_fingerprinter2_signature` | 57–65 s cold, 0.2 s once cached |
| `get_technology_stats` | 18 s median, 27 s max, three 30 s timeouts (week to 2026-10-08) |

Other tools continue using `SCANMALWARE_TIMEOUT_S`. A client with a shorter
timeout of its own may still give up first; that shows up as
`mcp.tool.cancelled` (14 of 35 `get_favicon_stats` calls between 2 and 8 October 2026).
These calls are not automatically retried, avoiding duplicate expensive queries.
This accommodates observed latency; database/query optimization belongs upstream.

The upstream library inventory identifies Next.js as `nextjs`. The display name
`next.js` at the end of the library route produces an HTML frontend 404, while
`nextjs` returns API JSON. `search_js_fingerprint_by_library` maps this specific
display-name alias to `nextjs` without changing its filters or pagination.

## Egress restriction (ScanMalware-only)

The MCP container is forced to use a local mitmproxy and is firewalled so it can only reach that proxy.
The proxy only allows traffic to `scanmalware.com` (and subdomains).

Components:
- `SCANMALWARE_PROXY_URL` is set to `http://172.28.0.11:3128` in `deploy/docker-compose.yml`.
- `deploy/mitmproxy/restrict_hosts.py` rejects other destinations before CONNECT
  or HTTP forwarding. Only ScanMalware hostnames on web ports are allowed.
- `connection_strategy=lazy` delays upstream connections until the checks run.
- `allow_hosts` is deliberately not used as access control: it only selects which
  TLS connections are intercepted; other connections can pass through.
- HTTP/2 and HTTP/3 are disabled; the API connection uses HTTP/1.1.
- Host firewall rules restrict the MCP container’s egress to the proxy IP.

Apply the firewall rules (idempotent):

```bash
mcpssh \
  "bash /opt/scanmalware-mcp/deploy/iptables/lock-egress.sh"
```

Install the Docker startup hook so the rules are applied before containers
restart, including after runtime upgrades:

```bash
mcpssh \
  "mkdir -p /etc/systemd/system/docker.service.d && \
   cp /opt/scanmalware-mcp/deploy/iptables/docker-egress.conf /etc/systemd/system/docker.service.d/scanmalware-egress.conf && \
   systemctl daemon-reload"
```

Verify egress is locked to the proxy:

```bash
mcpssh <<'SH'
docker exec -i deploy_mcp_1 python - <<'PY'
import httpx

try:
    httpx.get("https://1.1.1.1", timeout=3)
    print("direct: unexpected success")
except Exception as exc:
    print("direct: blocked", type(exc).__name__)

proxy = "http://172.28.0.11:3128"
verify = "/etc/scanmalware-certs/mitmproxy-ca-cert.pem"

try:
    resp = httpx.get(
        "https://scanmalware.com/api/v1/recent",
        params={"page": 1, "limit": 1},
        proxy=proxy,
        verify=verify,
        timeout=10,
    )
    print("proxy scanmalware:", resp.status_code)
except Exception as exc:
    print("proxy scanmalware: failed", exc)

try:
    resp = httpx.get("https://example.com", proxy=proxy, verify=verify, timeout=10)
    print("proxy example:", resp.status_code)
except Exception as exc:
    print("proxy example: blocked", type(exc).__name__)
PY
SH
```

## TLS inspection (mitmproxy)

mitmproxy is configured to intercept TLS so it can log full request/response data.
It generates a CA under `deploy/mitmproxy/state` and the MCP container trusts the
CA via `SCANMALWARE_CA_CERT`.

Generate the CA on the droplet and restart the stack:

Set up `mcpssh` using [Connect to the DigitalOcean instance](#connect-to-the-digitalocean-instance)
first. On a fresh host, provision the [Nginx TLS certificates](#https--tls) before
starting Nginx.

```bash
mcpssh <<'SH'
set -euo pipefail
cd /opt/scanmalware-mcp

mkdir -p deploy/mitmproxy/state logs/mitmproxy

docker compose -f deploy/docker-compose.yml up -d --build proxy

# Wait for CA generation.
for i in $(seq 1 20); do
  if [ -f deploy/mitmproxy/state/mitmproxy-ca-cert.pem ]; then
    break
  fi
  sleep 1
done

if [ ! -f deploy/mitmproxy/state/mitmproxy-ca-cert.pem ]; then
  echo "mitmproxy CA not found, check proxy logs"
  exit 1
fi

docker compose -f deploy/docker-compose.yml up -d --build mcp nginx
SH
```
The MCP container reads the CA from `/etc/scanmalware-certs/mitmproxy-ca-cert.pem`
via `SCANMALWARE_CA_CERT` so it trusts the bumped certificates.

## Popularity reporting (example)

```bash
mcpssh <<'SH'
python3 - <<'PY'
import json
from collections import Counter

log_path = '/opt/scanmalware-mcp/logs/mcp/mcp.log'

tool_counts = Counter()
client_pairs = Counter()
session_clients = Counter()

with open(log_path, 'r', encoding='utf-8') as fh:
    for line in fh:
        if 'scanmalware_mcp' not in line:
            continue
        start = line.find('{')
        if start == -1:
            continue
        try:
            data = json.loads(line[start:])
        except json.JSONDecodeError:
            continue
        # One per session, with the client's own name from initialize.
        if data.get('event') == 'mcp.session.start' and data.get('method') == 'initialize':
            session_clients[data.get('client_name') or '?'] += 1
        if data.get('event') == 'mcp.tool.start':
            tool = data.get('tool')
            if tool:
                tool_counts[tool] += 1
            # client_name/client_version are null under stateless_http: the
            # initialize params are not retained across requests. Group by the
            # User-Agent header instead, which is logged on every tool call.
            agent = data.get('user_agent')
            if agent:
                client_pairs[agent] += 1
            else:
                name = data.get('client_name')
                version = data.get('client_version')
                if name and version:
                    client_pairs[f"{name}/{version}"] += 1

print('top_tools:', tool_counts.most_common(10))
print('top_clients:', client_pairs.most_common(10))
print('sessions_by_client:', session_clients.most_common(10))
PY
SH
```

## Environment variables

Core:
- `SCANMALWARE_BASE_URL` (default `https://scanmalware.com`)
- `SCANMALWARE_TIMEOUT_S` (default `30`)
- `SCANMALWARE_SLOW_QUERY_TIMEOUT_S` (default `90`; the five slow aggregate and search tools listed under [Slow upstream queries](#slow-upstream-queries))
- `SCANMALWARE_MAX_DOWNLOAD_BYTES` (default `10485760`)
- `SCANMALWARE_ALLOW_HTTP` (default `false`)
- `SCANMALWARE_ALLOW_PRIVATE_TARGETS` (default `false`)
- `SCANMALWARE_BEARER_TOKEN` (optional; required for private scans)

MCP server:
- `MCP_TRANSPORT` (default `streamable-http`)
- `MCP_HOST` (default `0.0.0.0`)
- `MCP_PORT` (default `8000`)
- `MCP_AUTH_TOKEN` (optional)
- `MCP_RESOURCE_SERVER_URL` / `MCP_ISSUER_URL` (optional; used when `MCP_AUTH_TOKEN` is set)

Logging:
- `SCANMALWARE_LOG_LEVEL` (default `INFO`)
- `SCANMALWARE_LOG_FILE` (default `/var/log/scanmalware-mcp/mcp.log`)
- `SCANMALWARE_LOG_MAX_BYTES` (default `10485760`)
- `SCANMALWARE_LOG_BACKUP_COUNT` (default `7`)
- `SCANMALWARE_FULL_LOG_FILE` (default `/var/log/scanmalware-mcp/mcp-full.log`)
- `SCANMALWARE_FULL_LOG_MAX_BYTES` (default `10485760`)
- `SCANMALWARE_FULL_LOG_BACKUP_COUNT` (default `7`)
- `SCANMALWARE_MCP_HTTP_LOG_FILE` (default `/var/log/scanmalware-mcp/mcp-http.log`)
- `SCANMALWARE_MCP_HTTP_LOG_MAX_BYTES` (default `10485760`)
- `SCANMALWARE_MCP_HTTP_LOG_BACKUP_COUNT` (standalone default `7`; Compose default `63`)
- `SCANMALWARE_MCP_HTTP_LOG_MAX_BODY_BYTES` (default `1048576`, set `0` for unlimited)

Proxy:
- `SCANMALWARE_PROXY_URL` (unset for standalone use; Compose default `http://172.28.0.11:3128`)
- `SCANMALWARE_CA_CERT` (optional CA bundle; Compose default `/etc/scanmalware-certs/mitmproxy-ca-cert.pem`)

## Deploy / redeploy

In-place update on the existing droplet:

```bash
tar --exclude=.git --exclude=.venv --exclude=__pycache__ -czf /tmp/scanmalware-mcp.tar.gz -C . .
scp -i "$MCP_SSH_KEY" /tmp/scanmalware-mcp.tar.gz "root@$MCP_HOST:/tmp/"
mcpssh \
  "bash /opt/scanmalware-mcp/deploy/redeploy.sh /tmp/scanmalware-mcp.tar.gz"
```
The redeploy script stops containers before swapping files to avoid bind-mount inode issues.
If the script is not on the droplet yet, run the legacy tar + docker compose command once to install it.

Optional one-shot helper from the repo root:
```bash
./deploy/push-redeploy.sh "root@$MCP_HOST" "$MCP_SSH_KEY"
```

Rolling deploy (new droplet):
1) Create a new droplet (same region/size/OS)
2) Deploy the same bundle
3) Update DNS to new IP
4) Delete old droplet

## Create a new droplet (reference)

```bash
DROPLET_NAME=scanmalware-mcp-small
REGION=fra1
SIZE=s-1vcpu-2gb
IMAGE=debian-12-x64
SSH_KEYS=$(doctl compute ssh-key list --format ID --no-header | paste -sd, -)

doctl compute droplet create "$DROPLET_NAME" \
  --region "$REGION" \
  --size "$SIZE" \
  --image "$IMAGE" \
  --ssh-keys "$SSH_KEYS" \
  --tag-name scanmalware-mcp \
  --wait
```

Firewall:

```bash
doctl compute firewall create \
  --name scanmalware-mcp-fw \
  --inbound-rules "protocol:tcp,ports:22,address:0.0.0.0/0,address:::0/0" \
  --inbound-rules "protocol:tcp,ports:80,address:0.0.0.0/0,address:::0/0" \
  --inbound-rules "protocol:tcp,ports:443,address:0.0.0.0/0,address:::0/0" \
  --outbound-rules "protocol:icmp,ports:0,address:0.0.0.0/0,address:::0/0" \
  --outbound-rules "protocol:tcp,ports:0,address:0.0.0.0/0,address:::0/0" \
  --outbound-rules "protocol:udp,ports:0,address:0.0.0.0/0,address:::0/0" \
  --droplet-ids <droplet-id>
```

## Notes

- Auth-gated endpoints and `/modules/*` tools are removed from the MCP server.
- Upstream-disabled endpoints are excluded (e.g., `get_improvements`, `find_screenshot_duplicates`, `get_ai_stats`, `search_js_fingerprinter2_code_hash`, `search_js_segments_by_tlsh`).
- Some search tools require at least one filter and return a validation error if none are provided.
- Cloudflare proxying is disabled for `mcp.scanmalware.com`.
- The MCP server is public; set `MCP_AUTH_TOKEN` if you want to restrict access.
