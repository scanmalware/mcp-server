# AGENTS.md

This repo will contain a Python **Model Context Protocol (MCP)** server that exposes the **ScanMalware.com** API as tools/resources for an MCP client.

## API source of truth

- OpenAPI spec: `https://scanmalware.com/openapi.json`
- Base URL (OpenAPI omits `servers`): `https://scanmalware.com`
- API prefix: `/api/v1`
- OpenAPI currently lists ~146 paths / ~147 operations; many response schemas are `{}` (treat as untyped JSON and verify with live calls).

Practical note: some endpoints return **binary** despite the OpenAPI describing JSON:
- `GET /api/v1/screenshot/{scan_id}` returns PNG bytes.
- `GET /api/v1/tls/{scan_id}/certificate/download` returns PEM (`application/x-pem-file`).
- Other “download” style endpoints may be binary (verify with `curl -D - -o /dev/null ...`).

## Authentication

Most endpoints are public (no auth in OpenAPI). Auth-gated endpoints in the spec:

- **Bearer (`HTTPBearer`)**
  - `GET /api/v1/auth/profile`
  - `GET /api/v1/auth/admin`
  - `GET /api/v1/auth/analyst`
- **Optional bearer (`OptionalHTTPBearer`)**
  - `GET /api/v1/auth/test-optional`
- **HTTP Basic (`HTTPBasic`)** (Module Monitoring)
  - `GET /api/v1/modules/health`
  - `GET /api/v1/modules/stats`
  - `GET /api/v1/modules/failures`
  - `GET /api/v1/modules/stuck`
  - `GET /api/v1/modules/chains`
  - `GET /api/v1/modules/scan/{scan_id}`
  - `GET /api/v1/modules/percentiles/{module_name}`
  - `POST /api/v1/modules/admin/change-password`

Recommended env vars (never hardcode secrets):

- `SCANMALWARE_BASE_URL` (default: `https://scanmalware.com`)
- `SCANMALWARE_BEARER_TOKEN` (optional; only needed for auth endpoints)
- `SCANMALWARE_BASIC_USER` / `SCANMALWARE_BASIC_PASSWORD` (optional; only needed for `/modules/*`)

## Core scan workflow (API-level)

1. `POST /api/v1/scan` with JSON body:
   - `url` (required)
   - `scan_type` (default `"public"`)
   - `options` (object, optional)
   - Optional headers: `User-Agent`
2. Poll for completion:
   - `GET /api/v1/scan/{scan_id}/summary` (compact; includes `status`, `risk_score`, counts)
   - and/or `GET /api/v1/result/{scan_id}/progress`
3. Fetch details:
   - `GET /api/v1/result/{scan_id}`
   - plus specialized endpoints (`/ai/{scan_id}`, `/tls/{scan_id}`, `/technologies/by-scan/{scan_id}`, etc.)

## MCP tool design (recommended)

Keep the exposed tool surface area curated (the API is large):

- Prefer a small set of high-signal tools (submit → wait → summarize → fetch details).
- For list/search endpoints, always expose `page`/`limit` where available (OpenAPI often caps `limit` at 100).
- Avoid returning megabytes of raw JSON unless explicitly requested; provide “summary” tools that distill key fields (status/verdict/risk score/interesting indicators) while still offering raw endpoints when needed.
- For binary endpoints (PNG/PEM/etc.), expose as **MCP Resources** with correct `mimeType` and either:
  - base64 data (small payloads), or
  - a server-side cached blob + resource URI (preferred for large payloads).

Suggested initial tool set (public-only MVP):

- `submit_scan(url, scan_type="public", options=None, user_agent=None)`
- `wait_for_scan(scan_id, timeout_s=..., poll_interval_s=...)`
- `get_scan_summary(scan_id)`
- `get_scan_result(scan_id)`
- `get_recent_scans(page=1, limit=20)`
- `search_scans(...)` (wrap `GET /api/v1/search`)
- `get_ai_analysis(scan_id)` (wrap `GET /api/v1/ai/{scan_id}`)
- `get_screenshot(scan_id)` (resource; wraps `GET /api/v1/screenshot/{scan_id}`)
- `download_certificate(scan_id)` (resource; wraps `GET /api/v1/tls/{scan_id}/certificate/download`)

Safety default (recommended): do not implement any behavior that fetches the target URL yourself; only forward to ScanMalware. Consider optionally rejecting obvious private/loopback targets (RFC1918, `localhost`) unless explicitly enabled.

## Python MCP server options (evaluation)

### Option A: Official `mcp` Python SDK (recommended)

- Package: `mcp` (repo: `https://github.com/modelcontextprotocol/python-sdk`)
- Pros:
  - Reference SDK; best MCP compatibility.
  - Multiple transports available (stdio, SSE, streamable HTTP, websocket, ASGI transport helpers).
  - Includes `mcp.server.fastmcp` for ergonomic tool/resource definitions while staying “official”.
- Cons:
  - Auto-generating a tool per OpenAPI operation can create an unwieldy server; curate or group tools.

Recommendation: use `mcp.server.fastmcp.FastMCP` for a curated tool set, and run it in Docker via an HTTP-capable transport (or stdio for local use).

### Option B: `fastmcp`

- Package: `fastmcp` (repo: `https://github.com/jlowin/fastmcp`, docs: `https://gofastmcp.com`)
- Pros:
  - High-level, Pythonic ergonomics for tools/resources.
  - Good DX for rapidly iterating on an MCP server.
- Cons:
  - Additional dependency outside the official SDK; validate transport support and client compatibility for your deployment target.

### Option C: Manual MCP implementation (not recommended)

- Implement JSON-RPC + MCP messages directly over stdio/HTTP.
- Pros: full control.
- Cons: highest risk of protocol drift and subtle compatibility bugs; only do this if the SDKs cannot satisfy a hard requirement.

## Docker guidance (server must run in a container)

- Prefer `python:3.14-slim` and a non-root user.
- No secrets in the image; configure via env vars.
- Pick one transport for the MVP:
  - **HTTP** (container-friendly): run under an ASGI server and expose a port.
  - **stdio** (local-friendly): run the MCP process as the container entrypoint and connect via `docker run -i`.
- Use explicit HTTP timeouts/retries and handle `429`/`5xx` gracefully.

## Implementation conventions (when code is added)

- Use async I/O; prefer `httpx` (async client) and structured error handling.
- Add typing everywhere; only model stable request/response shapes (e.g., `ScanRequest`, `ScanResponse`) and keep the rest as `dict` until proven stable (OpenAPI has many `{}` schemas).
- Keep dependencies minimal; document all required env vars and example usage.
