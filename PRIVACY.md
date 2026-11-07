Privacy Policy
Last updated: 2026-11-07

This Privacy Policy describes how the ScanMalware MCP server ("Service")
collects, uses, and shares information when you access or use the Service.

Overview
- The Service is an MCP server that forwards scan requests to ScanMalware.com.
- The Service does not fetch target URLs directly; it calls the ScanMalware API.

Information We Collect
- Request data: URLs, scan_id values, and other tool parameters you submit.
- Connection data: IP address, user agent, the MCP client name and version your
  client reports when it connects, and timestamps. The Service issues no MCP
  session IDs.
- Logs: tool names and arguments (long values shortened), durations, status
  codes, the ScanMalware API paths each call requested, and scan outcomes
  (submitted and final URL, visibility, status, risk). Full logs add complete
  arguments and results. Raw HTTP logs may include request and response headers
  and bodies. Authorization, Proxy-Authorization, Cookie, Set-Cookie and X-API-Key
  header values are redacted. Secrets embedded in URLs or bodies may still be logged.
- Proxy data: mitmproxy logs include upstream request/response metadata and
  bounded body samples (base64 encoded). Large responses are streamed without
  retaining their bodies. The same sensitive header values are redacted.

How We Use Information
- Provide and operate the Service.
- Troubleshoot errors and improve reliability.
- Monitor for abuse and maintain security.
- Produce aggregated usage metrics.

Sharing
- With ScanMalware.com: requests are forwarded to ScanMalware for processing.
- With infrastructure providers: hosting and logging services used to operate
  the Service.
- We do not sell personal data.

Retention
- Logs, including raw HTTP and proxy logs, are kept for up to one year so abuse
  and security incidents can be investigated after the fact. Recent logs rotate
  by size and date; each rotated log is then kept in a compressed archive on the
  same server and deleted automatically once its first entry is a year old.
- Logs stay on the server. They are not published, and are not part of the
  public source repository.
- See [the operations runbook](docs/OPERATIONS.md#long-term-archive) for current
  settings.

Security
- TLS is used for public access.
- Optional MCP authentication can be enabled via MCP_AUTH_TOKEN.
- Access logs and raw logs may contain sensitive inputs; avoid submitting
  secrets or personal data you do not want stored in logs.

Your Choices
- Do not submit sensitive or confidential data through the Service.
- If you have questions or requests about data handling, contact us.

Contact
- Contact form: https://scanmalware.com/contact
- GitHub issues: https://github.com/scanmalware/mcp-server/issues
