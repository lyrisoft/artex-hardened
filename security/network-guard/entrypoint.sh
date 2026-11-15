#!/bin/sh
# Firewall administered by a separate container sharing the ARTEX network namespace.
# ARTEX is never granted CAP_NET_ADMIN or the Docker socket.
set -eu
: "${ARTEX_TARGET_CIDRS:?Explicit ARTEX_TARGET_CIDRS required (comma separated IPv4 CIDRs)}"
# Reject malformed input before modifying packet filters.
python3 - <<'PY'
import ipaddress, os
raw=os.environ["ARTEX_TARGET_CIDRS"]
parts=[v.strip() for v in raw.split(",")]
if not parts or any(not p for p in parts):
    raise SystemExit("Invalid empty CIDR entry")
for p in parts:
    n=ipaddress.ip_network(p, strict=False)
    if n.version != 4: raise SystemExit("Only IPv4 is supported: "+p)
    if n.prefixlen == 0: raise SystemExit("0.0.0.0/0 is not an acceptable testing scope")
    if n.is_multicast or n.is_unspecified:
        raise SystemExit("Invalid destination range: "+p)
print("Validated explicit destination allowlist")
PY
# Database IP is pinned in Compose. Do not enable Docker DNS simply to resolve PostgreSQL.
PG_IP="${ARTEX_PG_IP:?Set pinned ARTEX_PG_IP}"
test -n "$PG_IP"
# Install fail-closed rules (avoid a window with unrestricted OUTPUT).
iptables -P OUTPUT DROP
ip6tables -P OUTPUT DROP
iptables -F OUTPUT
ip6tables -F OUTPUT
iptables -A OUTPUT -o lo -d 127.0.0.1/32 -j ACCEPT
ip6tables -A OUTPUT -o lo -d ::1/128 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d "$PG_IP/32" -p tcp --dport 5432 -j ACCEPT
OLDIFS="$IFS"; IFS=,
for cidr in $ARTEX_TARGET_CIDRS; do
  cidr="$(echo "$cidr" | tr -d '[:space:]')"
  iptables -A OUTPUT -d "$cidr" -j ACCEPT
done
IFS="$OLDIFS"
# Optional Docker DNS allowance. WARNING: DNS can be used as a covert channel.
# Off by default; approved domains should use a trusted restrictive DNS resolver.
if [ "${ARTEX_ALLOW_DNS:-0}" = 1 ]; then
  iptables -A OUTPUT -d 127.0.0.11 -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -d 127.0.0.11 -p tcp --dport 53 -j ACCEPT
fi
iptables -A OUTPUT -m limit --limit 10/min -j LOG --log-prefix "ARTEX_EGRESS_BLOCK " --log-level 4
ip6tables -A OUTPUT -m limit --limit 10/min -j LOG --log-prefix "ARTEX_IPV6_BLOCK " --log-level 4
touch /run/network-guard-ready
echo "ARTEX egress guard active; database-only + explicitly approved IPv4 CIDRs. DNS enabled=${ARTEX_ALLOW_DNS:-0}"
exec tail -f /dev/null
