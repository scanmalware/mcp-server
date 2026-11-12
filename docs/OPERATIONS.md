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
  - `proxy` (mitmproxy with ScanMalware destination checks and bounded HTTP body logging)

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
- Landing page: `/opt/scanmalware-mcp/deploy/nginx/html/index.html` (English, at `/`) and
  `html/{en,sv,es,zh-cn}/index.html`, generated: edit `deploy/nginx/landing/template.html` and
  `strings.json`, run `python3 deploy/nginx/landing/build.py`, commit the result
  (`tests/maintenance/test_landing_page.py` fails on a stale page). nginx sends `/` to the
  browser's language (`map $landing_lang`); `robots.txt` and `sitemap.xml` come from the same
  build; light/dark follows `html/theme.js`, the same
  script as status.scanmalware.com. The html directory is mounted, so a file copy is live
  without a restart; an `nginx.conf` change needs `nginx -t` and a reload.
- mitmproxy addon: `/opt/scanmalware-mcp/deploy/mitmproxy/log_full.py`
- mitmproxy destination guard: `/opt/scanmalware-mcp/deploy/mitmproxy/restrict_hosts.py`
- mitmproxy state (CA): `/opt/scanmalware-mcp/deploy/mitmproxy/state`
- MCP source mount: `/opt/scanmalware-mcp/scanmalware_mcp` → `/app/scanmalware_mcp` (`PYTHONPATH=/app`)
- Egress firewall: `/opt/scanmalware-mcp/deploy/iptables/lock-egress.sh` (rules in the `DOCKER-USER` chain)
- Audit rules: `/etc/audit/rules.d/scanmalware-mcp.rules` (from `deploy/audit/`), log in `/var/log/audit/`
- Security check: `/opt/scanmalware-mcp/deploy/security/security_check.py` (see [Security monitoring](#security-monitoring))
- Log archive (one year, zstd): `/var/log/scanmalware-mcp-archive` (see [Long-term archive](#long-term-archive))
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

The 2026-11-07 maintenance release uses Docker Engine 29.9.3 from Docker's
signed Debian repository, Compose 5.7.0, containerd 2.4.2, Debian kernel 6.1.0-54,
Python 3.14.10, MCP 2.3.0, Nginx 1.30.6 and mitmproxy 12.3.1. It applies Docker
29.9.3's security fixes (including BuildKit 0.34.2, used for the on-host image
builds), Python 3.14.10 (tarfile CVE-2026-114583, ssl CVE-2026-115557), apt 3.0.4
in the Debian-based images (CVE-2026-109518) and libexpat 2.10.0 in the Nginx
image, from Alpine's refreshed `nginx:1.30.6-alpine`. The 2026-10-29 release
before it ran Docker Engine 29.9.2, Compose 5.6.1 and Python 3.14.9, and followed
the Brotli decoder flaw (CVE-2026-111497) and the Nginx 1.30.6 security fixes.
Host Debian security updates remain automatic, but packages from Docker's
repository and kernel reboots do not happen by themselves. Container image
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

For a security-only release, `--upgrade-package <name>` in place of `--upgrade`
limits the MCP lock to the affected packages (2026-10-29: certifi, setuptools,
pip; 2026-11-07: pip). A full refresh can move Pydantic, which generates the published tool
schemas, and the directory reviews rescan any change to tools/list.

The [GitHub security-maintenance workflow](../.github/workflows/security-maintenance.yml)
is active on `main`. It rebuilds images and runs dependency checks and tests on
pushes to `main`, pull requests, manual runs and the first of each month at
05:17 UTC. [Dependabot](../.github/dependabot.yml) checks base images and Python
dependencies weekly, and GitHub Actions monthly. Automated updates stay on
the tested Python 3.14, Nginx 1.30 and MCP 2.x release lines; release-line
migrations need a separate compatibility review. These checks do not deploy
to production.

CI validates the repository's actual nginx configuration with a disposable TLS
certificate and a local `mcp` hostname mapping (`bash deploy/check_nginx.sh nginx-check`).
It also runs a loopback-only proxy streaming fixture, response/deadline regression
tests, and redeploy tests using a Docker stub. No test submits a live scan.

Before a runtime upgrade or reboot, retain a droplet snapshot, the private
configuration/CA backup and previous images. Build and test candidates first.
After deployment, verify tools/list (145 tools), API requests, both proxy
protocol guards, direct-egress restrictions, certificate renewal and rotation.
The Docker startup drop-in reapplies egress restrictions before containers start.
Keep the previous snapshot until the new deployment has been observed healthy.

Docker's packages come from Docker's repository, which unattended-upgrades
does not cover, so upgrade them by hand (`apt-get install --only-upgrade
docker-ce docker-ce-cli docker-compose-plugin containerd.io`). The daemon restart
stops every container. Both times so far (2026-10-29 and 2026-11-07) dockerd
brought back `mcp` and `proxy` but left `deploy_nginx_1` `Exited (0)`, despite
`restart: unless-stopped`, and the site stayed down until it was started by hand.
Straight after the upgrade, run `docker ps -a`, `docker start` any `deploy_*`
container that is not up, and check that `/mcp` answers 405.

To check the running or freshly built images for vulnerable packages without
running anything in them, copy their package databases out and scan them
locally. `docker exec` would show up as a HIGH finding in the
[security check](#security-check-on-demand); `docker cp` from a running
container, or from one made with `docker create`, runs nothing. Trivy needs
`/etc/debian_version` to recognise the Debian images.

```bash
mcpssh <<'SH' | tar -xzf -
set -e
cd /tmp && rm -rf rfs && mkdir rfs
for c in mcp proxy nginx; do
  id=$(docker create "scanmalware-$c:security-20261107")
  mkdir -p "rfs/$c/etc" "rfs/$c/var/lib/dpkg" "rfs/$c/lib/apk/db" "rfs/$c/usr/local/lib"
  docker cp -L "$id:/etc/os-release" "rfs/$c/etc/os-release"
  docker cp -L "$id:/etc/debian_version" "rfs/$c/etc/" 2>/dev/null || true
  docker cp "$id:/var/lib/dpkg/status" "rfs/$c/var/lib/dpkg/" 2>/dev/null || true
  docker cp "$id:/lib/apk/db/installed" "rfs/$c/lib/apk/db/" 2>/dev/null || true
  docker cp "$id:/usr/local/lib/python3.14" "rfs/$c/usr/local/lib/" 2>/dev/null || true
  docker rm -f "$id" >/dev/null
done
find rfs \( -name status -o -name installed -o -name os-release -o -name debian_version \
  -o -path '*.dist-info/METADATA' \) -print0 | tar --null -czf - -T -
rm -rf rfs
SH
for c in mcp proxy nginx; do trivy rootfs --quiet --scanners vuln --severity HIGH,CRITICAL "rfs/$c"; done
```

### Remaining upstream advisories

The MCP Python dependency lock has no known findings in the maintenance audit.
This is not a claim that all container OS packages are vulnerability-free:
Debian still lists findings without a released distribution fix.

mitmproxy 12.3.1 caps one library below available security fixes:

| Library | Locked version | Remaining scope / action |
| --- | --- | --- |
| tornado | 6.5.10 | Header line folding, chunked-body and RedirectHandler advisories, fixed in 6.6; mitmdump runs no Tornado server or client, and mitmweb is not enabled here. |

These remain open package findings. The audit step reports each match and uses
`deploy/mitmproxy/audit-baseline.json` to fail on new advisories, changed package
versions, or an overdue review (2026-12-01). Do not override upstream dependency bounds just to make the
audit green; test a compatible upstream release when one becomes available.
mitmproxy 12.3.1 lifted the earlier caps on cryptography (now 50.0.2), h2 (4.4.1)
and Brotli (1.2.1), and no longer depends on msgpack.

CVE-2026-111497 (Brotli decoder, October 2026) is fixed in every copy on the
droplet: the host's `libbrotli1` carries Debian's fix (`1.0.9-2+deb12u1`,
installed automatically on 2026-10-23), the proxy runs Brotli 1.2.1, and the
Nginx image's `brotli-libs` (used by freetype and curl, not by Nginx) is
`1.2.1-r0`. The MCP image has no Brotli decoder, and httpx there only offers
gzip and deflate. Before the fix, the proxy's exposure was already small: it
logs raw bodies without decoding them, and scanmalware.com sent no Brotli.

## Logs (persistent)

### MCP logs

Two files are persisted on the host and survive redeploys:

- Sanitized log: `/opt/scanmalware-mcp/logs/mcp/mcp.log` (about five months on disk; a year in the [archive](#long-term-archive))
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
- Full log (args + result): `/opt/scanmalware-mcp/logs/mcp/mcp-full.log` (about two and a half weeks on disk; a year in the archive)
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
  - Authorization, Proxy-Authorization, Cookie, Set-Cookie and X-API-Key header
    values are redacted in both directions. URL/body contents can still be sensitive.
  - Bodies are captured up to `SCANMALWARE_MCP_HTTP_LOG_MAX_BODY_BYTES` (default `1048576`, set to `0` for unlimited).

Rotation: 10 MiB max per file; 112 backups in Compose (about 1.1 GiB), or 7
backups for the standalone server. That held ten days at ~115 MB a day in
mid-October 2026, but only about two days at ~530 MB a day by November, when
Claude Code connections grew about 40-fold; the [archive](#long-term-archive)
keeps a year. Controlled by:
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

- HTTP log: `/opt/scanmalware-mcp/logs/mitmproxy/full.log`
  - JSON lines with request/response metadata and redacted sensitive headers.
  - Buffered bodies include at most `MITMPROXY_LOG_MAX_BODY_BYTES` (default 64 KiB)
    as base64, plus original `length`, `captured` and `truncated` fields. `0` omits
    body bytes. Bodies may be compressed (see `content-encoding`).
  - Responses above `MITMPROXY_STREAM_LARGE_BODIES` (default `1m`) are streamed
    with `store_streamed_bodies=false`: the body is not retained or logged.
    This lets metadata-only NetLog requests close after headers without first
    buffering the whole file. The proxy also rejects bodies above
    `MITMPROXY_BODY_SIZE_LIMIT` (default `64m`); raise that limit deliberately if
    metadata is needed for larger artifacts. Application limits still apply.
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
10 MiB per file. On disk the Compose deployment keeps, at the volume measured on
2026-11-07 (oldest entry per file set, read on the droplet):

| Log | Backups | Size | Covers about on disk |
| --- | --- | --- | --- |
| `mcp.log` | 30 | ~310 MiB | five months (~5 days per file; logging began 2026-06-13, so it is not full yet) |
| `mcp-full.log` | 48 | ~490 MiB | two and a half weeks |
| `mcp-http.log` | 112 | ~1.1 GiB | two days (ten in mid-October, before Claude Code connections grew) |

Nginx and the proxy keep 14 daily archives (above), and auditd five 8 MB files
(about nine days). The standalone server keeps 7 backups of each MCP log.
Rotation limits are volume-based, so on its own the disk copy guarantees no
fixed history window; the archive below does.

Verify the installed configuration and timer:

```bash
logrotate --debug --state /dev/null /etc/scanmalware-mcp/logrotate.conf
systemctl list-timers scanmalware-logrotate.timer
systemctl status scanmalware-logrotate.service --no-pager
```

### Long-term archive

Every rotated log is also kept for **one year** in
`/var/log/scanmalware-mcp-archive`, zstd-compressed:

| Group | Source (rotated files only) |
| --- | --- |
| `mcp/` | `mcp.log`, `mcp-full.log`, `mcp-http.log` |
| `nginx/` | `access.log`, `error.log` |
| `mitmproxy/` | `full.log` |
| `audit/` | `/var/log/audit/audit.log` |

`scanmalware-log-archive.timer` runs
[`archive_logs.py`](../deploy/logrotate/archive_logs.py) (installed as
`/usr/local/sbin/scanmalware-archive-logs`) every ten minutes. It copies each
rotated file once, never a live one, into `<group>/<year>/<month>/` under a
name built from the file's first line, such as
`mcp-http.log.20261107T104813Z.<hash>.zst`. That name does not change when a
later rotation renames the file or logrotate gzips it, so each segment is stored
exactly once. Archives whose first entry is older than 365 days are deleted
(`--retention-days` changes this). The job never modifies the source logs.

The archive is root-owned (`root:adm`, mode 0750), outside the release tree, so
no redeploy touches it, and outside every container mount, so code in a
container cannot alter it. It is not copied off the host (see
[Decided against](#decided-against-october-2026)), and nothing under it, or
under `logs/`, belongs in git. `.gitignore` excludes log, archive and capture
files, and
[`tests/maintenance/test_repo_hygiene.py`](../tests/maintenance/test_repo_hygiene.py)
fails CI if a tracked file has a log-like path or contains log lines or a
private key.

zstd at level 10 shrinks the raw HTTP log about 100-fold, because the same
large `tools/list` responses repeat, and the full log about eightfold. At the
November 2026 volume a year takes roughly 2 GB for `mcp-http.log`, 1.2 GB for
`mcp-full.log`, 1.5 GB for the proxy, 1.2 GB for audit and 0.4 GB for Nginx: about
6–7 GB in total, with 38 GB free. The job prints a warning to its journal when
less than 10% of the disk is free.

The journal (SSH logins, firewall drops) is not archived: journald keeps it
under its default size cap, 4 GB, and it held ten months (2.2 GB, back to
January 2026) on 2026-11-07.

Install with the [host rotation policy](#rotation-and-retention) (`install.sh`
also needs `zstd`). Its first run archives every backup already on disk. Read the
archive with the zstd tools:

```bash
systemctl list-timers scanmalware-log-archive.timer
journalctl -u scanmalware-log-archive --since today   # archived=N bytes_in=... pruned=N
du -sh /var/log/scanmalware-mcp-archive/*
zstdgrep '"proxy.blocked"' /var/log/scanmalware-mcp-archive/mitmproxy/2026/11/*.zst
zstdcat /var/log/scanmalware-mcp-archive/mcp/2026/11/mcp.log.*.zst | grep '"mcp.scan.internal_target"'
```

### Response and polling budgets

Successful binary resources and JSON responses are read as streams with separate
10 MiB decoded limits. Chunked or compressed responses count decoded bytes;
`Content-Length` is not trusted as the only size check. Error bodies are sampled
up to 16 KiB, marked when truncated, and keep the original HTTP status so retry
and missing-artifact handling still work. Limits are configurable with the three
`SCANMALWARE_MAX_*_BYTES` variables below; all must be positive.

`wait_for_scan` applies a wall-clock deadline to requests, retries and sleeps.
It accepts finite `timeout_s` in `(0, 3600]` and `poll_interval_s` in `[0.1, 60]`.
Retryable errors back off up to 60 seconds and honor `Retry-After`; the overall
deadline can interrupt that delay. On timeout the last successful summary is
returned, or an empty summary and `status: "unknown"` if no poll succeeded.
Ordinary API tools, including writes, are not automatically retried.

### Slow upstream queries

Ten tools use `SCANMALWARE_SLOW_QUERY_TIMEOUT_S` (default 90 seconds). The first
five were moved there because measured latency exceeded or approached the normal
30-second timeout; the SMQL and CT-by-IP tools (2026-11-12) because the upstream
documents long-running queries:

| Tool | Observed latency |
| --- | --- |
| `get_favicon_stats` | 57 s live aggregation |
| `search_ocr` | 24–30 s for successful searches |
| `get_jsfingerprint_similarity_counts` | ~31 s per call (2026-10-07) |
| `search_js_runtime_by_signature` | 57–65 s cold, 0.2 s once cached |
| `get_technology_stats` | 18 s median, 27 s max, three 30 s timeouts (week to 2026-10-08) |
| `search_smql` | 7.6 s for a wildcard filter, 0.1–0.8 s otherwise (2026-11-12) |
| `get_smql_facets`, `count_smql_queries` | 0.1–0.3 s; the API gives counts a longer budget on request |
| `search_smql_domains` | 0.1–2.3 s; a wildcard over every CT log runs a minute or more and answers 202 meanwhile |
| `get_ct_root_domains_by_ip` | 6.2 s, right after a 503 `back_pressure` (2026-11-12) |

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
| What did a client send, and did the call fail? | `mcp.log`: `mcp.tool.start` args, then end/error/cancelled (five months on disk, a year in the [archive](#long-term-archive)) |
| Which API paths did that call reach? | `upstream` on the end/error event; full exchanges in the proxy log via `X-MCP-Call-ID` = `call_id` |
| Did a scan end on an internal address? | `mcp.scan.internal_target` WARNING in `mcp.log` |
| What did the client get back? | `mcp-full.log` (two and a half weeks on disk) and `mcp-http.log` (two days on disk); both a year in the archive |
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

mitmproxy intercepts TLS for destination enforcement and bounded traffic logging.
It generates a CA under `deploy/mitmproxy/state` and the MCP container trusts the
CA via `SCANMALWARE_CA_CERT`.

Compose waits for the proxy listener and CA certificate before starting MCP,
then waits for MCP's local `/mcp` response before starting nginx. Health probes
use local sockets only; they do not submit scans or call the upstream API.

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
- `SCANMALWARE_MAX_JSON_BYTES` (default `10485760`; decoded successful JSON bodies)
- `SCANMALWARE_MAX_ERROR_BYTES` (default `16384`; decoded error sample, marked when truncated)
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

The redeploy script extracts into a sibling staging directory, preserves `.env`,
`deploy/.env` and the mitmproxy CA, validates Compose and builds all images while
the old stack runs. It then stops the containers, swaps releases (so bind mounts
use the new inodes), moves the existing logs into the new tree, and starts with
`--no-build --wait`. The default readiness budget is 120 seconds; override with
`DEPLOY_WAIT_TIMEOUT_S`. Only the final switch needs downtime.

A build failure leaves the running release in place and restores any retagged
images. A startup/readiness failure restores the old files, settings and image
tags and attempts to restart the old stack. If recovery itself fails, the script
prints the protected backup/staging paths for manual recovery and leaves them
intact. It never deletes logs. A sibling `.deploy-lock` directory prevents
overlapping runs; after a killed process, confirm no deploy is running before
removing a stale lock. Keep enough disk space for staging and previous images.

For persistent configuration outside the release tree, use an absolute path:

```bash
DEPLOY_ENV_FILE=/etc/scanmalware-mcp.env bash deploy/redeploy.sh /tmp/scanmalware-mcp.tar.gz
```

That file is passed explicitly to every Compose invocation. Without an override,
the script uses `deploy/.env`, then root `.env`, if present; both local files are
preserved. Existing operator files take precedence over archive copies. The
service remains public when no auth variables are configured.

Other untracked files, such as an html `demo/` directory, are removed after a
successful release; the [security release](#security-release-all-three-images)
and MCP-only procedures below keep them. If the new script is not yet installed on the droplet, copy
`deploy/redeploy.sh` there before invoking it; running the older script still
uses its older deployment behavior.

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
# Compose runs the image tagged security-20261107; keep the current one for rollback.
docker tag scanmalware-mcp:security-20261107 "scanmalware-mcp:rollback-pre-$REV"

# Build from a staged copy, so the live tree is untouched until the image exists.
rm -rf "/tmp/deploy-$REV" && mkdir "/tmp/deploy-$REV"
tar -xzf /tmp/scanmalware-mcp.tar.gz -C "/tmp/deploy-$REV"
(cd "/tmp/deploy-$REV" && nice docker build -q -t scanmalware-mcp:security-20261107 .)

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
docker tag "scanmalware-mcp:rollback-pre-$REV" scanmalware-mcp:security-20261107
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

### Publishing to the MCP registry

`server.json` is the entry at registry.modelcontextprotocol.io (`com.scanmalware.mcp/scanmalware-mcp`).
The registry refuses a version it already has, so bump the version in `server.json`,
`pyproject.toml` and `scanmalware_mcp/__init__.py` together (a test checks they agree) and
deploy before publishing. Ownership of the `com.scanmalware.mcp` namespace is proven over HTTP:
the droplet serves the public key at `https://mcp.scanmalware.com/.well-known/mcp-registry-auth`
(`v=MCPv1; k=ecdsap384; p=...`), and the matching ECDSA P-384 private key stays off the
droplet and out of git, with the maintainer.

```bash
cd "$(mktemp -d)" && git -C /path/to/mcp-server show origin/main:server.json > server.json
/path/to/mcp-server/.tools/mcp-publisher login http --domain mcp.scanmalware.com \
  --algorithm ecdsap384 --private-key "<hex of the 48-byte private scalar>"
/path/to/mcp-server/.tools/mcp-publisher publish
rm -f ~/.mcp_publisher_token   # the login token the publisher leaves behind
```

Check the result: `curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=scanmalware'`
must list the new version with `isLatest: true`. The hosted remote declares no headers: the server
needs no key, and a declared secret header (0.2.1 had `Authorization: Bearer <token>`) makes
registry-driven installers ask for one. The `icons` entry points at
`https://mcp.scanmalware.com/icon.png` (`deploy/nginx/html/icon.png`, 512 x 512).

### Security release (all three images)

Used for the 2026-10-29 and 2026-11-07 releases: all three images are rebuilt
under a new tag while the old stack keeps serving, then swapped in. Total
downtime was about 15 seconds, the time the new MCP process takes to start;
untracked files such as `demo/` survive. The compose file on `main` names the
new tag, for example `security-20261107`.

1. Take a droplet snapshot, check `free -m`, and save a copy of the live
   `tools/list` to compare afterwards. If Docker's packages need upgrading, do
   that now, as described in [Security maintenance](#security-maintenance),
   so the images are built with the patched BuildKit.
2. Check the droplet still matches the commit it runs. Another session may have
   hot-copied a file; the copy step below would overwrite it.

   ```bash
   OLD=<commit prod runs>
   rm -rf /tmp/old && mkdir /tmp/old && git archive "$OLD" | tar -xf - -C /tmp/old
   (cd /tmp/old && find . -type f -exec md5 -r {} + | sort -k2) > /tmp/old.md5
   mcpssh 'cd /opt/scanmalware-mcp && find . -type f ! -path "./logs/*" \
     ! -path "./deploy/mitmproxy/state/*" -exec md5sum {} + | sort -k2' > /tmp/live.md5
   diff <(awk '{print $1, $2}' /tmp/old.md5) <(awk '{print $1, $2}' /tmp/live.md5)
   ```

   Expect only the untracked `demo/` video and `state/.gitkeep` to differ.
3. Upload `git archive` of `main` as in [Full redeploy](#full-redeploy), then
   back up and build:

   ```bash
   mcpssh <<'SH'
   set -euo pipefail
   REV=<short commit id>; TAG=security-<yyyymmdd>
   B="/root/deploy-backup-$(date +%F)-pre-$REV"; mkdir -p "$B"
   (cd /opt/scanmalware-mcp && tar -cf "$B/files.tar" --exclude=./logs .)
   rm -rf "/tmp/deploy-$REV" && mkdir "/tmp/deploy-$REV"
   tar -xzf /tmp/scanmalware-mcp.tar.gz -C "/tmp/deploy-$REV"
   cd "/tmp/deploy-$REV"
   nice docker build -q -t "scanmalware-mcp:$TAG" .
   nice docker build -q -t "scanmalware-proxy:$TAG" deploy/mitmproxy
   nice docker build -q -t "scanmalware-nginx:$TAG" deploy/nginx
   SH
   ```

4. Optionally scan the new images with the `docker cp` method in
   [Security maintenance](#security-maintenance) before swapping.
5. Swap. `cp -a` keeps `nginx.conf`'s inode and does not delete untracked
   files. `--no-build` makes Compose use the images just built.

   ```bash
   mcpssh <<'SH'
   set -euo pipefail
   REV=<short commit id>; cd /opt/scanmalware-mcp
   inode=$(stat -c %i deploy/nginx/nginx.conf)
   cp -a "/tmp/deploy-$REV/." .
   [ "$inode" = "$(stat -c %i deploy/nginx/nginx.conf)" ] || echo "nginx.conf inode changed: restart nginx"
   docker compose -f deploy/docker-compose.yml up -d --no-build
   sleep 20; docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}' | grep deploy_
   grep '"mcp.startup"' logs/mcp/mcp.log | tail -1   # expect "ca_cert_loaded": true
   SH
   ```

6. Verify: `/mcp` answers 405, `tools/list` is byte-identical to step 1, one
   real tool call succeeds, the [egress check](#egress-restriction-scanmalware-only)
   passes (it produces four expected HIGH findings), and
   `security_check.py --hours 1` shows nothing else.

Rollback: set the previous tag in `deploy/docker-compose.yml` (or restore
`files.tar`) and run `docker compose -f deploy/docker-compose.yml up -d --no-build`.
Keep the previous images and snapshot for a few days, then delete them.

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
- Not every public endpoint is a tool. Excluded: account, follow and submission endpoints that need a logged-in user; legacy aliases of an exposed endpoint; Atom feeds, sitemaps and health pings. `/ai/stats`, `/screenshot/duplicates`, `/js-segments/search/tlsh/{hash}` and `/js-fingerprinter2/search/code-hash/{hash}` were excluded while disabled upstream and answer again since November 2026; they are candidates to add.
- Every search tool works with its defaults; `search_js_fingerprint_patterns` applies `has_eval=true` when given no filter, because the API requires one.
- Cloudflare proxying is disabled for `mcp.scanmalware.com`.
- The MCP server is public; set `MCP_AUTH_TOKEN` if you want to restrict access.
