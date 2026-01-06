# scanmalware-mcp

Minimal Python MCP server that wraps the public ScanMalware.com API.

## Operations

See `docs/OPERATIONS.md` for deployment, TLS, logging, and how to connect to the DigitalOcean droplet.

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
docker run --rm -p 127.0.0.1:8000:8000 \\
  -e MCP_TRANSPORT=streamable-http \\
  -e MCP_HOST=0.0.0.0 \\
  -e MCP_PORT=8000 \\
  scanmalware-mcp
```

Optional: set `MCP_AUTH_TOKEN` to require `Authorization: Bearer <MCP_AUTH_TOKEN>` for HTTP transports.

Optional auth env vars (only needed for auth-gated endpoints):

- `SCANMALWARE_BEARER_TOKEN`

Other env vars:

- `SCANMALWARE_BASE_URL` (default: `https://scanmalware.com`)
- `SCANMALWARE_ALLOW_HTTP` (default: `false`)
- `SCANMALWARE_TIMEOUT_S` (default: `30`)
- `SCANMALWARE_MAX_DOWNLOAD_BYTES` (default: `10485760`)
- `SCANMALWARE_ALLOW_PRIVATE_TARGETS` (default: `false`)
- `SCANMALWARE_CA_CERT` (optional; path to a CA bundle for SSL bump)

MCP server security env vars:

- `MCP_AUTH_TOKEN` (if set, HTTP transports require `Authorization: Bearer <token>`)
- `MCP_RESOURCE_SERVER_URL` / `MCP_ISSUER_URL` (optional; only used when `MCP_AUTH_TOKEN` is set)

Tool note: `submit_scan` supports `csrf=true` to fetch a CSRF token internally; there is no separate `get_csrf_token` tool.

## Example prompts

Phishing triage (submit → wait → summarize):
```text
Submit a scan for https://example-login-update.com, wait for completion, and
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

The deploy bundle lives in `deploy/` and runs two containers:
- `mcp` (this server, streamable HTTP on port 8000)
- `nginx` (frontend on port 80; proxies `/mcp` to the MCP server)

### Prereqs

- `doctl` authenticated (`doctl auth init`)
- SSH key uploaded to DigitalOcean (used by `doctl compute droplet create`)

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

```bash
ssh -i /path/to/key root@<droplet-ip> \
  "apt-get update -y && apt-get install -y docker.io docker-compose"
```

### Upload and run

```bash
tar --exclude=.git --exclude=.venv --exclude=__pycache__ -czf /tmp/scanmalware-mcp.tar.gz -C . .
scp -i /path/to/key /tmp/scanmalware-mcp.tar.gz root@<droplet-ip>:/tmp/
ssh -i /path/to/key root@<droplet-ip> \
  "mkdir -p /opt/scanmalware-mcp && tar -xzf /tmp/scanmalware-mcp.tar.gz -C /opt/scanmalware-mcp"
ssh -i /path/to/key root@<droplet-ip> \
  "cd /opt/scanmalware-mcp && docker-compose -f deploy/docker-compose.yml up -d --build"
```

### Verify

```bash
curl -I https://mcp.scanmalware.com/
curl -I https://mcp.scanmalware.com/mcp
```

`/` should return 200 from Nginx. `/mcp` returns 406 on GET without MCP Accept headers, which is expected.

### Smoke test (MCP initialize + tools/list)

```bash
python - <<'PY'
import json
import httpx

URL = "http://<droplet-ip>/mcp"
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
    session_id = init_resp.headers.get("mcp-session-id")

    def extract_sse_data(text: str) -> dict:
        for line in text.splitlines():
            if line.startswith("data: "):
                return json.loads(line[len("data: "):])
        raise ValueError("No SSE data line found")

    init_message = extract_sse_data(init_resp.text)
    protocol_version = init_message["result"]["protocolVersion"]

    # Send initialized notification
    client.post(
        URL,
        headers={
            **HEADERS,
            "mcp-session-id": session_id,
            "mcp-protocol-version": protocol_version,
        },
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )

    tools_resp = client.post(
        URL,
        headers={
            **HEADERS,
            "mcp-session-id": session_id,
            "mcp-protocol-version": protocol_version,
        },
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
tar --exclude=.git --exclude=.venv --exclude=__pycache__ -czf /tmp/scanmalware-mcp.tar.gz -C . .
scp -i /path/to/key /tmp/scanmalware-mcp.tar.gz root@<droplet-ip>:/tmp/
ssh -i /path/to/key root@<droplet-ip> \
  "bash /opt/scanmalware-mcp/deploy/redeploy.sh /tmp/scanmalware-mcp.tar.gz"
```
The redeploy script stops containers before swapping files to avoid bind-mount inode issues.
If the script is not on the droplet yet, run the legacy tar + docker-compose command once to install it.

Optional one-shot helper from the repo root:
```bash
./deploy/push-redeploy.sh root@<droplet-ip> /path/to/key
```

2) Rolling deploy (new droplet)
- Create a new droplet (steps above)
- Deploy the same bundle
- Switch DNS to the new IP
- Destroy the old droplet when ready

```bash
doctl compute droplet delete <old-droplet-id> --force
```
