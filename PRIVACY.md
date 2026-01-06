Privacy Policy
Last updated: 2026-01-06

This Privacy Policy describes how the ScanMalware MCP server ("Service")
collects, uses, and shares information when you access or use the Service.

Overview
- The Service is an MCP server that forwards scan requests to ScanMalware.com.
- The Service does not fetch target URLs directly; it calls the ScanMalware API.

Information We Collect
- Request data: URLs, scan_id values, and other tool parameters you submit.
- Connection data: IP address, user agent, MCP session ID, and timestamps.
- Logs: tool names, durations, status codes, and (in full logs) arguments and
  results. Raw HTTP logs may include request and response headers and bodies.
  If you send Authorization headers, those values may be captured in raw logs.
- Proxy data: mitmproxy logs include upstream requests and responses to
  ScanMalware.com (including response bodies, usually base64 encoded).

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
- Logs are retained based on size-based rotation settings. Defaults are
  configured via environment variables and typically keep multiple backups.
  See docs/OPERATIONS.md for current defaults.

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
