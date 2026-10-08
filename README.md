# scanmalware-mcp

Minimal Python MCP server that wraps the public ScanMalware.com API.

## Operations

See [the operations runbook](docs/OPERATIONS.md) for deployment, TLS, logging, security maintenance, and how to connect to the DigitalOcean droplet.

## Run locally (Streamable HTTP)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install .

export MCP_TRANSPORT=streamable-http
export MCP_HOST=127.0.0.1
export MCP_PORT=8000

scanmalware-mcp
```

## Run with Docker

```bash
docker build -t scanmalware-mcp .
docker run --rm -p 127.0.0.1:8000:8000 \
  -e MCP_TRANSPORT=streamable-http \
  -e MCP_HOST=0.0.0.0 \
  -e MCP_PORT=8000 \
  scanmalware-mcp
```

Optional: set `MCP_AUTH_TOKEN` to require `Authorization: Bearer <MCP_AUTH_TOKEN>` for HTTP transports.

Optional auth env vars (only needed for auth-gated endpoints):

- `SCANMALWARE_BEARER_TOKEN`

Other env vars:

- `SCANMALWARE_BASE_URL` (default: `https://scanmalware.com`)
- `SCANMALWARE_ALLOW_HTTP` (default: `false`)
- `SCANMALWARE_TIMEOUT_S` (default: `30`)
- `SCANMALWARE_SLOW_QUERY_TIMEOUT_S` (default: `90`; favicon and technology statistics, OCR text search, JS fingerprint similarity counts and behavioural signature search)
- `SCANMALWARE_MAX_DOWNLOAD_BYTES` (default: `10485760`)
- `SCANMALWARE_ALLOW_PRIVATE_TARGETS` (default: `false`)
- `SCANMALWARE_CA_CERT` (optional; path to a CA bundle for SSL bump)

MCP server security env vars:

- `MCP_AUTH_TOKEN` (if set, HTTP transports require `Authorization: Bearer <token>`)
- `MCP_RESOURCE_SERVER_URL` / `MCP_ISSUER_URL` (optional; only used when `MCP_AUTH_TOKEN` is set)

Transport note: the HTTP transports run stateless (`stateless_http=True`), so responses carry
no `mcp-session-id` header. Clients must not require one. This keeps per-session state -
and therefore memory - flat. Both MCP protocol generations are served: `initialize`
(2024-11-05 to 2025-11-25) and `server/discover` (2026-07-28). Requests use POST;
GET on `/mcp` returns 405 because the server offers no standalone SSE stream.

SSE transport: set `MCP_TRANSPORT=sse`, and optionally `MCP_SSE_MOUNT_PATH` to serve
it under a path prefix.

Tool note: `submit_scan` does not call `/api/v1/csrf-token`; there is no CSRF token tool.
Tool note: some upstream endpoints are disabled and excluded from the tool list (e.g., `get_improvements`, `find_screenshot_duplicates`, `get_ai_stats`, `search_js_fingerprinter2_code_hash`, `search_js_segments_by_tlsh`).
Filters: every search tool can be called with its defaults.
`search_js_fingerprint_patterns` applies `has_eval=true` when no pattern filter
is given, because the API requires one; `search_js_obfuscation` and
`search_js_malware_families` fall back to the API's own defaults. Score filters
use the API's scales and are checked before the request: the AI risk score is
0-10, AI confidence 0-100, JS obfuscation scores 0-1 and the runtime JS risk
score 0-100. OCR search requires at least three characters after trimming.
Library lookups use detected identifiers from `get_js_library_inventory`;
`search_js_fingerprint_by_library` accepts `Next.js` as an alias for the
detected identifier `nextjs`.

## Scan visibility

`submit_scan` requires `scan_type`; there is no default. A `public` scan puts the
target URL and scan results in ScanMalware's public feed, visible to other users
and search engines. Choose deliberately for client targets, confidential URLs,
and security engagements:

- `public`: publishes the scan. Use for these targets only with explicit approval to publish.
- `unlisted`: excluded from public listings, but accessible to anyone with the direct link.
- `private`: results are restricted to the authenticated ScanMalware account.
  Requires a valid `SCANMALWARE_BEARER_TOKEN` configured on the MCP server;
  `MCP_AUTH_TOKEN` only controls access to the MCP server and does not provide
  ScanMalware authentication.

If visibility has not already been specified for these targets, ask the user
to choose `unlisted` or `private` before submitting. If submission fails, do not
retry with a less restrictive visibility. These modes control scan visibility;
requests still go to ScanMalware and may be recorded in server logs (see
[the MCP privacy policy](PRIVACY.md)). ScanMalware documents the visibility
options in its [privacy policy](https://scanmalware.com/privacy).

## Example prompts

Phishing triage (submit → wait → summarize):
```text
Submit an unlisted scan for https://example-login-update.com, wait for completion, and
return status, risk_score, and the top indicators. If high risk, include the
AI analysis and screenshot resource.
```

Brand abuse monitoring:
```text
Search scans for "acme login" (limit 5). For each result, list scan_id,
status, risk_score, and URL. Highlight anything marked high risk.
```

TLS/certificate inspection:
```text
For scan_id 1234...abcd, fetch TLS details and the certificate PEM download.
Summarize issuer, subject, validity dates, and SANs; flag mismatches.
```

## Deploy to DigitalOcean (Debian + Docker + Nginx)

The deploy bundle lives in `deploy/` and runs three containers:

- `mcp` (this server, streamable HTTP on port 8000)
- `nginx` (frontend on ports 80/443; redirects HTTP to HTTPS and proxies `/mcp` to the MCP server)
- `proxy` (mitmproxy, checks ScanMalware destinations and logs upstream HTTP traffic)

### Prereqs

- `doctl` authenticated (`doctl auth init`)
- SSH key uploaded to DigitalOcean (used by `doctl compute droplet create`)
- DNS and Let's Encrypt certificates at the paths in [HTTPS / TLS](docs/OPERATIONS.md#https--tls) before starting Nginx

### Create a small droplet in Germany (Frankfurt)

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

### Firewall (public HTTP/HTTPS + SSH)

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

### Install Docker + compose on the droplet

Install Docker Engine and the Compose plugin from the [official Docker apt repository](https://docs.docker.com/engine/install/debian/). Use `docker compose`; the old Python `docker-compose` client is incompatible with current Docker Engine.

See [the operations runbook](docs/OPERATIONS.md#security-maintenance) for pinned builds and maintenance checks.

### Upload and run

```bash
# Package exactly one commit; a tar of the working tree also picks up untracked
# files (.tools/, caches, egg-info) and uncommitted edits.
git archive --format=tar.gz -o /tmp/scanmalware-mcp.tar.gz origin/main
scp -i /path/to/key /tmp/scanmalware-mcp.tar.gz root@<droplet-ip>:/tmp/
ssh -i /path/to/key root@<droplet-ip> \
  "mkdir -p /opt/scanmalware-mcp && tar -xzf /tmp/scanmalware-mcp.tar.gz -C /opt/scanmalware-mcp"
```

On a fresh host, follow [TLS inspection](docs/OPERATIONS.md#tls-inspection-mitmproxy)
to build the proxy and generate its CA before starting MCP and Nginx. Install
the [egress rules and Docker startup hook](docs/OPERATIONS.md#egress-restriction-scanmalware-only)
and [log rotation](docs/OPERATIONS.md#rotation-and-retention) as part of host setup.

### Verify

```bash
curl -I https://mcp.scanmalware.com/
curl -sS -o /dev/null -w '%{http_code}\n' https://mcp.scanmalware.com/mcp
```

`/` should return 200 from Nginx. `/mcp` returns 405 on GET, which is expected: the server offers no standalone SSE stream, so MCP requests use POST.

### Smoke test (MCP initialize + tools/list)

```bash
python - <<'PY'
import json
import httpx

URL = "https://mcp.scanmalware.com/mcp"
HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}

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

with httpx.Client(timeout=10) as client:
    init_resp = client.post(URL, headers=HEADERS, json=init_payload)
    init_resp.raise_for_status()
    # Stateless deployments return no session header.
    session_id = init_resp.headers.get("mcp-session-id")

    def extract_sse_data(text: str) -> dict:
        for line in text.splitlines():
            if line.startswith("data: "):
                return json.loads(line[len("data: "):])
        raise ValueError("No SSE data line found")

    init_message = extract_sse_data(init_resp.text)
    protocol_version = init_message["result"]["protocolVersion"]

    headers = {**HEADERS, "mcp-protocol-version": protocol_version}
    if session_id:
        headers["mcp-session-id"] = session_id

    # Send initialized notification
    client.post(
        URL,
        headers=headers,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )

    tools_resp = client.post(
        URL,
        headers=headers,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    tools_resp.raise_for_status()
    tools_message = extract_sse_data(tools_resp.text)
    tool_names = [tool["name"] for tool in tools_message["result"]["tools"]]

print("protocol_version:", protocol_version)
print("tool_count:", len(tool_names))
print("tools:", ", ".join(tool_names))
PY
```

### Redeploy / new deploys

Two common flows:

1) In-place update (same droplet)
```bash
# Package exactly one commit; a tar of the working tree also picks up untracked
# files (.tools/, caches, egg-info) and uncommitted edits.
git archive --format=tar.gz -o /tmp/scanmalware-mcp.tar.gz origin/main
scp -i /path/to/key /tmp/scanmalware-mcp.tar.gz root@<droplet-ip>:/tmp/
ssh -i /path/to/key root@<droplet-ip> \
  "bash /opt/scanmalware-mcp/deploy/redeploy.sh /tmp/scanmalware-mcp.tar.gz"
```
The redeploy script stops all three containers, replaces the files, and rebuilds
and restarts every image (`docker compose up -d --build`), preserving the mitmproxy
CA. It deletes files on the droplet that are not in git (everything outside `logs/`). If the script is not on the droplet yet, run the legacy tar + docker compose
command once to install it.

Optional one-shot helper from the repo root (it packs the working tree, including
uncommitted changes, rather than a commit):
```bash
./deploy/push-redeploy.sh root@<droplet-ip> /path/to/key
```

To update only the MCP server with a few seconds of downtime, see
[Updating only the MCP server](docs/OPERATIONS.md#updating-only-the-mcp-server).

2) Rolling deploy (new droplet)
- Create a new droplet (steps above)
- Deploy the same bundle
- Switch DNS to the new IP
- Destroy the old droplet when ready

```bash
doctl compute droplet delete <old-droplet-id> --force
```
