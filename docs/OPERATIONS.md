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
- Egress firewall: `/opt/scanmalware-mcp/deploy/iptables/lock-egress.sh` (rules in the `DOCKER-USER` chain)
- Audit rules: `/etc/audit/rules.d/scanmalware-mcp.rules` (from `deploy/audit/`), log in `/var/log/audit/`
- Security check: `/opt/scanmalware-mcp/deploy/security/security_check.py` (see [Security monitoring](#security-monitoring))
- Files served but not in git, such as the `demo/` directory under the html root,
  live only on the droplet; a [full redeploy](#full-redeploy) deletes them.

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
- POST must accept both `application/json` and `text/event-stream`. Since the
  mcp 2.x migration, wildcard ranges such as `*/*` or `application/*, text/*`
  count; mcp 1.30 wanted the literal types and answered those with 406 (about
  1,200 POSTs a week by October 2026). A missing `Accept` header, or one that
  excludes either type, still gets 406.
- GET on `/mcp` answers **405** (`Allow: POST`): the server sends no
  server-initiated messages, so it offers no standalone SSE stream. mcp 2.x
  would otherwise accept `*/*` on GET and hold the stream open until the client
  left, so every browser or health check that fetched `/mcp` pinned a
  connection.
- Both protocol generations are served: `initialize` with 2024-11-05 to
  2025-11-25, and `server/discover` plus per-request `_meta` with 2026-07-28
  (Claude.ai and recent Claude Code). mcp 1.30 answered the latter with 400
  "Unsupported protocol version" and the clients fell back to `initialize`.
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
process. MCP 1.30.0 added session reclamation and 2.x caps stateful sessions
(30 minutes idle, 10,000 at most), but this server continues to use stateless
mode. Measured with the old SDK over 600 sessions: stateful grew ~41 MB and kept climbing,
stateless stayed flat at ~75 MB RSS; under mcp 2.3.0 RSS stayed flat (81 → 76 MB)
over 8,000 mixed requests. The server sends no server-initiated notifications,
so it gives up nothing it actually used.

Under mcp 2.x `stateless_http` is no longer a constructor argument: it is passed
to `run()` and `streamable_http_app()`, which default to stateful. The server
class keeps it as a property and passes it on, so do not call the SDK's app
factories directly. It also sets `subscriptions=False`; otherwise 2.x advertises
`listChanged` to 2026-07-28 clients, and each one that subscribes holds an SSE
stream open.

## Client attribution in logs

`stateless_http=True` means a 2025-protocol client's `initialize` params are
not carried across requests, so `client_name` and `client_version` are `null`
on its `mcp.tool.start` events. 2026-07-28 clients repeat their client info in
every request's `_meta`, so their tool events do carry it. Tool events also log
`user_agent`, taken from the HTTP header, which is always present. Group tool
usage by `user_agent`; the [popularity example below](#popularity-reporting-example)
does this already.

The client's own name and version are logged once per session instead, on the
`mcp.session.start` event (see [MCP logs](#mcp-logs)). Generic user agents hide
who is calling: in October 2026 `node` was mostly Glama, `undici` was
span-pipeline and the Glama inspector, and `python-requests` was the
agentstatus probe network.

The raw `mcp-http.log` still records full request headers either way.

## Dependency pinning

`mcp` is constrained to `>=2.3.0,<3`, with the production dependency graph
pinned by version and hash in `requirements.lock`. The server moved from 1.30.0
to 2.3.0 in October 2026 to serve the 2026-07-28 protocol. That port had three
traps that do not show up as import errors:

- 2.x shows the client only the text of `ToolError`/`ResourceError`; any other
  exception becomes a bare "Error executing tool". The logging wrapper converts
  `ValueError`/`RuntimeError` (argument checks and ScanMalware API errors), so
  the model still sees why a call failed.
- `host`, `port` and `stateless_http` moved from the constructor to `run()` and
  the app factories (see [Transport mode](#transport-mode-stateless)).
- Pydantic models use snake_case attributes (`client_info`, not `clientInfo`);
  the wire format is unchanged.

The 1.30 → 2.3 change left `tools/list` byte-identical for all 128 tools, along
with resources, templates and prompts. `serverInfo.version` now reports the
package version rather than the SDK's. `httpx` is declared explicitly because
mcp 2.x uses `httpx2` internally, so it cannot be relied on transitively.
Dependabot still ignores major `mcp` updates: 3.x will need its own port.

## Security maintenance

The 2026-10-02 maintenance release uses Docker Engine 29.8.2 from Docker's
signed Debian repository, Compose 5.5.1, containerd 2.3.6, runc 1.5.1,
Python 3.14.8, MCP 1.30.0 (2.3.0 since the October 2026 migration), Nginx 1.30.5 and mitmproxy 12.2.3.
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
the tested Python 3.14, Nginx 1.30 and MCP 2.x release lines; release-line
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

- Sanitized log: `/opt/scanmalware-mcp/logs/mcp/mcp.log` (about three months in Compose)
  - Includes session starts (client name/version, protocol version), tool/resource
    start/end/error/cancelled, args (sanitized), timing, user agent and IP fields.
  - Every event of a call carries its `call_id`. The end, error and cancelled
    events also list the call's `upstream` requests as sent (`GET /api/v1/... 200`,
    polling collapsed to one entry with a count), so this log alone shows which
    API paths a crafted argument reached.
  - Scan tools (`submit_scan`, `get_scan_summary`, `wait_for_scan`,
    `get_scan_result`) add an `mcp.scan.outcome` event: scan ID, submitted and
    final URL, visibility, status, redirect count, risk. If the final URL or a
    redirect lands on a private, loopback or link-local address, an
    `mcp.scan.internal_target` WARNING follows. See [Security monitoring](#security-monitoring).
- Full log (args + result): `/opt/scanmalware-mcp/logs/mcp/mcp-full.log` (about two weeks in Compose)
  - Includes full tool args and full tool results (no redaction).

Rotation: 10 MiB max per file; Compose keeps 30 backups of `mcp.log` and 48 of
`mcp-full.log`, the standalone server 7 of each. Controlled by:
- `SCANMALWARE_LOG_FILE`, `SCANMALWARE_LOG_MAX_BYTES`, `SCANMALWARE_LOG_BACKUP_COUNT`
- `SCANMALWARE_FULL_LOG_FILE`, `SCANMALWARE_FULL_LOG_MAX_BYTES`, `SCANMALWARE_FULL_LOG_BACKUP_COUNT`

Process and session lifecycle events:

- `mcp.startup` fires **once per process**, when the shared ScanMalware HTTP
  client is built. It carries the resolved config (base URL, proxy, CA cert).
- `mcp.session.start` fires **once per session-opening request** on the
  streamable HTTP transport: `initialize`, or `server/discover` from clients
  that speak protocol 2026-07-28 (Claude.ai, recent Claude Code). It carries
  `method`, `protocol_version`, `client_name`, `client_version`, `user_agent`
  and the client IP fields. Sessions are the `initialize` events (2025
  protocol clients) plus the `server/discover` events (2026-07-28 clients).
  Discovery is optional in 2026-07-28, so treat the second number as a lower
  bound.
- `mcp.lifespan.enter` (DEBUG, not written at the default INFO level) fires
  when the SDK enters the server lifespan: once per process for streamable HTTP
  under mcp 2.x, once per connection for SSE. Under mcp 1.30 it ran for every
  HTTP request.

Count sessions, and the clients behind them, for one log file:

```bash
grep '"mcp.session.start"' /opt/scanmalware-mcp/logs/mcp/mcp.log | grep -o '"method": "[^"]*"' | sort | uniq -c
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

Rotation: 10 MiB max per file; 112 backups in Compose (about 1.1 GiB, two weeks
at ~79 MB a day in October 2026), or 7 backups for the standalone server. Controlled by:
- `SCANMALWARE_MCP_HTTP_LOG_FILE`, `SCANMALWARE_MCP_HTTP_LOG_MAX_BYTES`, `SCANMALWARE_MCP_HTTP_LOG_BACKUP_COUNT`
- `SCANMALWARE_MCP_HTTP_LOG_MAX_BODY_BYTES`

### Nginx logs

- Access log: `/opt/scanmalware-mcp/logs/nginx/access.log`
- Error log: `/opt/scanmalware-mcp/logs/nginx/error.log`

The access log includes client IPs, the Host header and TLS details. Its
`mcp_session` field is always `-`: the server is stateless and issues no
`mcp-session-id`. Requests for other domains are closed by the default servers
(444, or a refused TLS handshake, which is logged only in the error log).

### mitmproxy logs

- Full HTTP log: `/opt/scanmalware-mcp/logs/mitmproxy/full.log`
  - JSON lines with full request/response headers and bodies (base64).
  - Bodies may be compressed (see `content-encoding` header).
  - Each upstream request carries the MCP call's `X-MCP-Call-ID` header, which
    matches `call_id` in `mcp.log`.
  - Every refused destination is a `proxy.blocked` line (method, host, port,
    client). Until October 2026 only refused plain-HTTP requests appeared; a
    refused HTTPS `CONNECT` left no trace.

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

MCP application, full-result, and raw HTTP logs continue using Python rotation,
10 MiB per file. The Compose deployment keeps, at October 2026 rates:

| Log | Backups | Size | Covers about |
| --- | --- | --- | --- |
| `mcp.log` | 30 | ~310 MiB | three months |
| `mcp-full.log` | 48 | ~490 MiB | two weeks (was two days with 7) |
| `mcp-http.log` | 112 | ~1.1 GiB | two weeks (was one with 63) |

Nginx and the proxy keep 14 daily archives (above). The standalone server keeps
7 backups of each MCP log. Rotation limits are volume-based, so they do not
guarantee a fixed history window.

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
| `search_js_runtime_by_signature` | 57–65 s cold, 0.2 s once cached |
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
  Anything else it sends is logged (rate-limited) before being dropped; see
  [Security monitoring](#security-monitoring).

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

## Security monitoring

The goal is to tell, after the fact, whether an attack worked. An October 2026
review found the request side well logged but the outcome side short-lived, and
code execution inside the container invisible. What each layer now shows:

| Question | Where to look |
| --- | --- |
| What did a client send, and did the call fail? | `mcp.log`: `mcp.tool.start` args, then end/error/cancelled (three months) |
| Which API paths did that call reach? | `upstream` on the end/error event; full exchanges in the proxy log via `X-MCP-Call-ID` = `call_id` |
| Did a scan end on an internal address? | `mcp.scan.internal_target` WARNING in `mcp.log` |
| What did the client get back? | `mcp-full.log` and `mcp-http.log` (two weeks) |
| Did code in the container try to reach anything else? | `proxy.blocked` in the proxy log; firewall drops in the kernel log |
| Did anything run in the container, or change on the host? | auditd (below) |
| Who logged in to the host? | `journalctl -u ssh` |

### Firewall drop log

`deploy/iptables/lock-egress.sh` logs, at most 6 a minute, every packet from
the MCP container that is not going to the proxy, just before dropping it. The
server never sends such packets, so any entry means code in the container is
trying another way out:

```bash
journalctl -k -g scanmalware-mcp-egress-drop --since today
```

### Process and change auditing (auditd)

`deploy/audit/scanmalware-mcp.rules` records:

- `scanmalware_mcp_exec`: programs started by UID 10001, the MCP container's
  user. The server never starts programs, so apart from the entrypoint
  (`/usr/local/bin/scanmalware-mcp`) when the container starts, every hit is a
  `docker exec` or code execution in the container.
- `scanmalware_deploy_change`, `scanmalware_code_change`: writes under `deploy/`
  and `scanmalware_mcp/`. Deploys appear here too; that is the audit trail.
- `ssh_authorized_keys`, `sshd_config`, `docker_config`: ways to keep access.

Install once (check `free -m` first; the droplet has 2 GB and no swap):

```bash
mcpssh "bash /opt/scanmalware-mcp/deploy/audit/install.sh"
# --input-logs: without a terminal (ssh with a command, cron, timers) ausearch
# reads records from stdin instead of the audit log and waits or finds nothing.
mcpssh "ausearch --input-logs -i -k scanmalware_mcp_exec --uid 10001 --start today"
```

### Container hardening

The `mcp` container runs with a read-only root filesystem, a small
`noexec` `/tmp`, no Linux capabilities and `no-new-privileges`. It reads its
code and writes only to the logs bind mount, so none of this changes its
behaviour, but code running in it cannot modify the image, run files it drops
in `/tmp`, or gain privileges.

### Security check (on demand)

`deploy/security/security_check.py` reads the last `--hours` (default 24) of all
of the above and prints findings, most serious first. It is not scheduled and
writes nothing; run it when you want to know whether anything got through:

```bash
mcpssh "python3 /opt/scanmalware-mcp/deploy/security/security_check.py --hours 24"
```

- HIGH: a scan reached an internal host; the proxy or firewall refused
  container traffic; a program ran as the container user; root's SSH keys or the
  SSH config changed; audit rules were removed or auditing switched off; a
  container was killed for running out of memory.
- MEDIUM: injection-style tool arguments (by client); a successful upstream
  request for an encoded or dot path segment; nginx serving a 2xx for a path
  other than the landing page, `/mcp`, `/.well-known/` or `/demo/`.
- INFO: counts of calls, errors, cancellations and sessions by client;
  restarts; audit rule loads; deploy changes; SSH logins (any source address is
  allowed) and failed attempts.

A `docker exec` into `deploy_mcp_1` runs as UID 10001 and is reported as HIGH,
like code execution in the container would be.

### Decided against (October 2026)

- Copying logs off the droplet: they stay on the host, so someone with root
  could erase them.
- Scheduled reports or alerts: run the check above instead.
- An SSH source allowlist: logins are key-only and allowed from any address.

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
        # One per session (initialize, or server/discover from 2026-07-28
        # clients), with the client's own name.
        if data.get('event') == 'mcp.session.start':
            session_clients[data.get('client_name') or '?'] += 1
        if data.get('event') == 'mcp.tool.start':
            tool = data.get('tool')
            if tool:
                tool_counts[tool] += 1
            # client_name/client_version are null for 2025-protocol clients
            # under stateless_http: their initialize params are not retained.
            # Group by the User-Agent header, which is logged on every tool call.
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
- `MCP_SSE_MOUNT_PATH` (optional; path prefix for `MCP_TRANSPORT=sse`)

Logging:
- `SCANMALWARE_LOG_LEVEL` (default `INFO`; `MCP_LOG_LEVEL` is read as a fallback)
- `SCANMALWARE_LOG_FILE` (unset: console only; Compose `/var/log/scanmalware-mcp/mcp.log`)
- `SCANMALWARE_LOG_MAX_BYTES` (default `10485760`)
- `SCANMALWARE_LOG_BACKUP_COUNT` (standalone default `7`; Compose default `30`)
- `SCANMALWARE_FULL_LOG_FILE` (unset: no full log; Compose `/var/log/scanmalware-mcp/mcp-full.log`)
- `SCANMALWARE_FULL_LOG_MAX_BYTES` (default `10485760`)
- `SCANMALWARE_FULL_LOG_BACKUP_COUNT` (standalone default `7`; Compose default `48`)
- `SCANMALWARE_MCP_HTTP_LOG_FILE` (unset: no raw HTTP log; Compose `/var/log/scanmalware-mcp/mcp-http.log`)
- `SCANMALWARE_MCP_HTTP_LOG_MAX_BYTES` (default `10485760`)
- `SCANMALWARE_MCP_HTTP_LOG_BACKUP_COUNT` (standalone default `7`; Compose default `112`)
- `SCANMALWARE_MCP_HTTP_LOG_MAX_BODY_BYTES` (default `1048576`, set `0` for unlimited)

Proxy:
- `SCANMALWARE_PROXY_URL` (unset for standalone use; Compose default `http://172.28.0.11:3128`)
- `SCANMALWARE_CA_CERT` (optional CA bundle; Compose default `/etc/scanmalware-certs/mitmproxy-ca-cert.pem`)

## Deploy / redeploy

Deploy a commit that is on `main`, packaged with `git archive`. A tar of the
working tree also ships untracked files (`.tools/`, caches, egg-info) and
uncommitted edits, and prod then matches no commit.

### Full redeploy

```bash
git archive --format=tar.gz -o /tmp/scanmalware-mcp.tar.gz origin/main
scp -i "$MCP_SSH_KEY" /tmp/scanmalware-mcp.tar.gz "root@$MCP_HOST:/tmp/"
mcpssh \
  "bash /opt/scanmalware-mcp/deploy/redeploy.sh /tmp/scanmalware-mcp.tar.gz"
```

The redeploy script stops all three containers (avoiding bind-mount inode
issues), replaces everything under `/opt/scanmalware-mcp` except `logs/` while
preserving the mitmproxy CA, then rebuilds and starts every image
(`docker compose up -d --build`). Every service is down for the length of the
rebuild. Files on the droplet that are not in git are deleted, for example
anything put in the html root's `demo/` directory: copy them back afterwards, or
use the MCP-only update below. If the script is not on the droplet yet, run the legacy tar + docker
compose command once to install it.

Optional one-shot helper from the repo root. It packs the working tree,
uncommitted changes included, rather than a commit:

```bash
./deploy/push-redeploy.sh "root@$MCP_HOST" "$MCP_SSH_KEY"
```

### Code and image must match

`scanmalware_mcp/` is bind-mounted over the image (`PYTHONPATH=/app`): the
running code comes from `/opt/scanmalware-mcp/scanmalware_mcp`, its
dependencies from the image. Copying `server.py` and restarting `deploy_mcp_1`
is enough only when `requirements.lock` is unchanged. When the lock changes,
rebuild the image. For example, `server.py` from before 2d124a3 (the move to
mcp 2.3.0) fails to import on the current image, and newer code fails on an
older image.

### Updating only the MCP server

This rebuilds and recreates only `deploy_mcp_1`, leaving Nginx and the proxy
running. It was used for 2d124a3 on 2026-10-08, with about 5 seconds of
downtime. Upload the bundle as in [Full redeploy](#full-redeploy), then:

```bash
mcpssh <<'SH'
set -euo pipefail
free -m                          # build only with a few hundred MB available
cd /opt/scanmalware-mcp
REV=<short commit id>
B="/root/deploy-backup-$(date +%F)-pre-$REV"
mkdir -p "$B"
tar -cf "$B/files.tar" scanmalware_mcp pyproject.toml requirements.lock deploy/nginx/nginx.conf
# Compose runs the image tagged security-20261002; keep the current one for rollback.
docker tag scanmalware-mcp:security-20261002 "scanmalware-mcp:rollback-pre-$REV"

# Build from a staged copy, so the live tree is untouched until the image exists.
rm -rf "/tmp/deploy-$REV" && mkdir "/tmp/deploy-$REV"
tar -xzf /tmp/scanmalware-mcp.tar.gz -C "/tmp/deploy-$REV"
(cd "/tmp/deploy-$REV" && nice docker build -q -t scanmalware-mcp:security-20261002 .)

# cp writes into existing files, keeping nginx.conf's inode: it is a single-file
# bind mount, and a replaced file would be invisible to the running container.
inode=$(stat -c %i deploy/nginx/nginx.conf)
cp -a "/tmp/deploy-$REV/." .
[ "$inode" = "$(stat -c %i deploy/nginx/nginx.conf)" ] || echo "nginx.conf inode changed: restart nginx"

docker compose -f deploy/docker-compose.yml up -d --no-deps mcp
docker exec deploy_nginx_1 nginx -t && docker exec deploy_nginx_1 nginx -s reload
grep '"mcp.startup"' logs/mcp/mcp.log | tail -1   # expect "ca_cert_loaded": true
SH
```

Then run the [smoke test](#mcp-endpoint) and the [egress check](#egress-restriction-scanmalware-only).

Proxy addon changes (`deploy/mitmproxy/*.py`, bind-mounted single files) need no
restart: written in place as above, mitmproxy reloads the script by itself
(`docker logs deploy_proxy_1` shows "Loading script"), as it did on 2026-10-08.

Rollback, using the backup and tag made above:

```bash
mcpssh <<'SH'
set -euo pipefail
cd /opt/scanmalware-mcp
REV=<short commit id>
docker tag "scanmalware-mcp:rollback-pre-$REV" scanmalware-mcp:security-20261002
inode=$(stat -c %i deploy/nginx/nginx.conf)
# GNU tar on the droplet writes into existing files, keeping the inode.
tar -xf "/root/deploy-backup-<date>-pre-$REV/files.tar"
docker compose -f deploy/docker-compose.yml up -d --no-deps mcp
if [ "$inode" = "$(stat -c %i deploy/nginx/nginx.conf)" ]; then
  docker exec deploy_nginx_1 nginx -t && docker exec deploy_nginx_1 nginx -s reload
else
  docker compose -f deploy/docker-compose.yml restart nginx
fi
SH
```

### Rolling deploy (new droplet)

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
- Every search tool works with its defaults; `search_js_fingerprint_patterns` applies `has_eval=true` when given no filter, because the API requires one.
- Cloudflare proxying is disabled for `mcp.scanmalware.com`.
- The MCP server is public; set `MCP_AUTH_TOKEN` if you want to restrict access.
