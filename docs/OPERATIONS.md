# Operations / Deployment Runbook

This document describes the current DigitalOcean deployment, how to connect to the droplet, how to redeploy, and where to find logs.

## Current deployment

- Domain: `mcp.scanmalware.com`
- Public IP: `64.227.123.54`
- Region: `fra1` (Frankfurt)
- Droplet size: `s-1vcpu-2gb`
- OS image: `debian-12-x64`
- Containers (docker-compose):
  - `mcp` (ScanMalware MCP server, streamable HTTP on port 8000)
  - `nginx` (frontend on 80/443, proxies `/mcp` to `mcp:8000`)
  - `proxy` (mitmproxy with ScanMalware allowlist + full HTTP logging)

## Connect to the DigitalOcean instance

```bash
ssh -i ~/.ssh/id_ed25519 root@64.227.123.54
```

If you need to discover the droplet IP:

```bash
doctl compute droplet list --tag-name scanmalware-mcp
```

## Services and paths

- Repo checkout: `/opt/scanmalware-mcp`
- Compose file: `/opt/scanmalware-mcp/deploy/docker-compose.yml`
- Nginx config: `/opt/scanmalware-mcp/deploy/nginx/nginx.conf`
- Landing page: `/opt/scanmalware-mcp/deploy/nginx/html/index.html`
- mitmproxy addon: `/opt/scanmalware-mcp/deploy/mitmproxy/log_full.py`
- mitmproxy state (CA): `/opt/scanmalware-mcp/deploy/mitmproxy/state`
- MCP source mount: `/opt/scanmalware-mcp/scanmalware_mcp` → `/app/scanmalware_mcp` (`PYTHONPATH=/app`)

## HTTPS / TLS

- TLS is terminated by Nginx using Let’s Encrypt certificates.
- Cert paths:
  - `/etc/letsencrypt/live/mcp.scanmalware.com/fullchain.pem`
  - `/etc/letsencrypt/live/mcp.scanmalware.com/privkey.pem`
- HSTS is enabled: `Strict-Transport-Security: max-age=31536000`.
- Cert renewal is handled by `certbot renew`. A deploy hook reloads nginx (container restart).

To renew manually:

```bash
certbot renew
```

## MCP endpoint

- MCP endpoint: `https://mcp.scanmalware.com/mcp`
- The HTTP transport requires `Accept: application/json, text/event-stream`.
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

This was a deliberate change. In stateful mode the SDK's session manager never
evicts from `_server_instances`, so every session leaked a
`StreamableHTTPServerTransport` + `ServerSession` (~77 KB) for the life of the
process. Measured over 600 sessions: stateful grew ~41 MB and kept climbing,
stateless stayed flat at ~75 MB RSS. The server sends no server-initiated
notifications, so it gives up nothing it actually used.

## Dependency pinning

`mcp` is pinned `>=1.14.0,<2`. mcp 2.x renamed `FastMCP` to `MCPServer` and this
server does not import under it - a rebuild that picked up 2.x would produce a
container that crashes on startup. `httpx` is declared explicitly because mcp 2.x
switched to `httpx2`, so it can no longer be relied on transitively.

## Logs (persistent)

### MCP logs

Two files are persisted on the host and survive redeploys:

- Sanitized log: `/opt/scanmalware-mcp/logs/mcp/mcp.log`
  - Includes tool/resource start/end, args (sanitized), timing, client name/version, and IP fields.
- Full log (args + result): `/opt/scanmalware-mcp/logs/mcp/mcp-full.log`
  - Includes full tool args and full tool results (no redaction).

Rotation (defaults): 10MB max, 7 backups. Controlled by:
- `SCANMALWARE_LOG_FILE`, `SCANMALWARE_LOG_MAX_BYTES`, `SCANMALWARE_LOG_BACKUP_COUNT`
- `SCANMALWARE_FULL_LOG_FILE`, `SCANMALWARE_FULL_LOG_MAX_BYTES`, `SCANMALWARE_FULL_LOG_BACKUP_COUNT`

Two events describe process and session lifecycle:

- `mcp.startup` fires **once per process**, when the shared ScanMalware HTTP
  client is built. It carries the resolved config (base URL, proxy, CA cert).
- `mcp.session.open` fires **once per MCP session**.

Count sessions per day with `mcp.session.open`:

```bash
grep -c 'mcp.session.open' /opt/scanmalware-mcp/logs/mcp/mcp.log
```

Note: before the shared-client change, `mcp.startup` fired per session, so in
logs rotated out from before that change it is the session counter instead. A
rising `mcp.startup` count in a current log means the process is restarting.

### MCP raw HTTP logs

- Raw HTTP log: `/opt/scanmalware-mcp/logs/mcp/mcp-http.log`
  - Includes raw MCP HTTP request/response headers and bodies (base64) with per-request IDs.
  - Bodies are captured up to `SCANMALWARE_MCP_HTTP_LOG_MAX_BODY_BYTES` (default `1048576`, set to `0` for unlimited).

Rotation (defaults): 10MB max, 7 backups. Controlled by:
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

## Egress restriction (ScanMalware-only)

The MCP container is forced to use a local mitmproxy and is firewalled so it can only reach that proxy.
The proxy only allows traffic to `scanmalware.com` (and subdomains).

Components:
- `SCANMALWARE_PROXY_URL` is set to `http://172.28.0.11:3128` in `deploy/docker-compose.yml`.
- mitmproxy `--allow-hosts` is set to `(^|\\.)scanmalware\\.com:` to allow the domain and subdomains.
- Host firewall rules restrict the MCP container’s egress to the proxy IP.

Apply the firewall rules (idempotent):

```bash
ssh -i ~/.ssh/id_ed25519 root@64.227.123.54 \
  "bash /opt/scanmalware-mcp/deploy/iptables/lock-egress.sh"
```

Persist the rules across reboot:

```bash
ssh -i ~/.ssh/id_ed25519 root@64.227.123.54 \
  "iptables-save > /etc/iptables/rules.v4"
```

Verify egress is locked to the proxy:

```bash
ssh -i ~/.ssh/id_ed25519 root@64.227.123.54 <<'SH'
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

```bash
ssh -i ~/.ssh/id_ed25519 root@64.227.123.54 <<'SH'
set -euo pipefail
cd /opt/scanmalware-mcp

mkdir -p deploy/mitmproxy/state logs/mitmproxy

docker-compose -f deploy/docker-compose.yml up -d proxy

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

docker-compose -f deploy/docker-compose.yml up -d mcp nginx
SH
```
The MCP container reads the CA from `/etc/scanmalware-certs/mitmproxy-ca-cert.pem`
via `SCANMALWARE_CA_CERT` so it trusts the bumped certificates.

## Popularity reporting (example)

```bash
ssh -i ~/.ssh/id_ed25519 root@64.227.123.54 <<'SH'
python3 - <<'PY'
import json
from collections import Counter

log_path = '/opt/scanmalware-mcp/logs/mcp/mcp.log'

tool_counts = Counter()
client_pairs = Counter()

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
        if data.get('event') == 'mcp.tool.start':
            tool = data.get('tool')
            if tool:
                tool_counts[tool] += 1
            name = data.get('client_name')
            version = data.get('client_version')
            if name and version:
                client_pairs[f"{name}/{version}"] += 1

print('top_tools:', tool_counts.most_common(10))
print('top_clients:', client_pairs.most_common(10))
PY
SH
```

## Environment variables

Core:
- `SCANMALWARE_BASE_URL` (default `https://scanmalware.com`)
- `SCANMALWARE_TIMEOUT_S` (default `30`)
- `SCANMALWARE_MAX_DOWNLOAD_BYTES` (default `10485760`)
- `SCANMALWARE_ALLOW_HTTP` (default `false`)
- `SCANMALWARE_ALLOW_PRIVATE_TARGETS` (default `false`)

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
- `SCANMALWARE_MCP_HTTP_LOG_BACKUP_COUNT` (default `7`)
- `SCANMALWARE_MCP_HTTP_LOG_MAX_BODY_BYTES` (default `1048576`, set `0` for unlimited)

Proxy:
- `SCANMALWARE_PROXY_URL` (default `http://172.28.0.11:3128`)

## Deploy / redeploy

In-place update on the existing droplet:

```bash
tar --exclude=.git --exclude=.venv --exclude=__pycache__ -czf /tmp/scanmalware-mcp.tar.gz -C . .
scp -i ~/.ssh/id_ed25519 /tmp/scanmalware-mcp.tar.gz root@64.227.123.54:/tmp/
ssh -i ~/.ssh/id_ed25519 root@64.227.123.54 \
  "bash /opt/scanmalware-mcp/deploy/redeploy.sh /tmp/scanmalware-mcp.tar.gz"
```
The redeploy script stops containers before swapping files to avoid bind-mount inode issues.
If the script is not on the droplet yet, run the legacy tar + docker-compose command once to install it.

Optional one-shot helper from the repo root:
```bash
./deploy/push-redeploy.sh root@64.227.123.54 ~/.ssh/id_ed25519
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
