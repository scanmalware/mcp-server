#!/usr/bin/env bash
set -euo pipefail

CHAIN=DOCKER-USER
MCP_IP=${MCP_IP:-172.28.0.10}
PROXY_IP=${PROXY_IP:-172.28.0.11}
PROXY_PORT=${PROXY_PORT:-3128}

add_rule() {
  local rule=("$@")
  if ! iptables -C "$CHAIN" "${rule[@]}" >/dev/null 2>&1; then
    iptables -I "$CHAIN" 1 "${rule[@]}"
  fi
}

# Insert in reverse order so final chain order is:
# 1) ESTABLISHED/RELATED
# 2) MCP -> proxy allow
# 3) MCP -> any drop
add_rule -s "$MCP_IP" -j DROP
add_rule -s "$MCP_IP" -d "$PROXY_IP" -p tcp --dport "$PROXY_PORT" -j ACCEPT
add_rule -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -S "$CHAIN" | sed -n '1,10p'
