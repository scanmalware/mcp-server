#!/usr/bin/env bash
set -euo pipefail

CHAIN=DOCKER-USER
MCP_IP=${MCP_IP:-172.28.0.10}
PROXY_IP=${PROXY_IP:-172.28.0.11}
PROXY_PORT=${PROXY_PORT:-3128}

# This script also runs before Docker starts, including on the first boot.
if ! iptables -S "$CHAIN" >/dev/null 2>&1; then
  iptables -N "$CHAIN"
fi

add_rule() {
  local rule=("$@")
  if ! iptables -C "$CHAIN" "${rule[@]}" >/dev/null 2>&1; then
    iptables -I "$CHAIN" 1 "${rule[@]}"
  fi
}

# Insert in reverse order so final chain order is:
# 1) ESTABLISHED/RELATED
# 2) MCP -> proxy allow
# 3) MCP -> any: log (rate-limited)
# 4) MCP -> any drop
add_rule -s "$MCP_IP" -j DROP
add_rule -s "$MCP_IP" -d "$PROXY_IP" -p tcp --dport "$PROXY_PORT" -j ACCEPT
add_rule -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# The MCP server only ever talks to the proxy, so anything reaching the DROP is
# code in the container trying to get out another way, and was silently
# discarded. Log it to the kernel log (journalctl -k), placed immediately before
# the DROP: add_rule inserts at the top, which on an existing chain would log the
# allowed traffic too. Rate-limited so a flood cannot fill the journal.
LOG_RULE=(-s "$MCP_IP" -m limit --limit 6/min --limit-burst 10 -j LOG --log-prefix "scanmalware-mcp-egress-drop: " --log-level 4)
if ! iptables -C "$CHAIN" "${LOG_RULE[@]}" >/dev/null 2>&1; then
  drop_line=$(iptables -L "$CHAIN" --line-numbers -n | awk -v ip="$MCP_IP" '$2 == "DROP" && $5 == ip { print $1; exit }')
  iptables -I "$CHAIN" "$drop_line" "${LOG_RULE[@]}"
fi

iptables -S "$CHAIN" | sed -n '1,10p'
