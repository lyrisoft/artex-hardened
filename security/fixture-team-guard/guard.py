#!/usr/bin/env python3
"""Disposable CI fixture for exact endpoint egress; not a production runner.

The caller must start this only in a fresh container network namespace and wait
for readiness before attaching any test process. This fixture cannot prove that
its input was independently approved, that an address is synthetic, or that a
host/daemon is isolated. It is not used by the application.
"""

import ipaddress
import json
import os
import signal
import subprocess
import sys

_PRIVATE = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_IPTABLES = "iptables"
_IP6TABLES = "ip6tables"
_SAFE_COMMAND_ENV = {"PATH": "/usr/sbin:/sbin:/usr/bin:/bin", "LANG": "C"}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def parse_endpoints(raw):
    """Accept bounded, unique private IPv4/TCP endpoint pairs only."""
    if not isinstance(raw, str):
        raise ValueError("invalid endpoint document")
    try:
        if len(raw.encode("utf-8")) > 8192:
            raise ValueError("invalid endpoint document")
        items = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise ValueError("invalid endpoint document") from exc
    if not isinstance(items, list) or not 1 <= len(items) <= 32:
        raise ValueError("invalid endpoint count")
    result = []
    seen = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"address", "port"}:
            raise ValueError("invalid endpoint fields")
        address, port = item["address"], item["port"]
        if not isinstance(address, str) or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("invalid endpoint")
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("invalid endpoint") from exc
        if not isinstance(ip, ipaddress.IPv4Address) or str(ip) != address or not any(ip in net for net in _PRIVATE):
            raise ValueError("invalid endpoint")
        pair = (address, port)
        if pair in seen:
            raise ValueError("duplicate endpoint")
        seen.add(pair)
        result.append(pair)
    return result


def _run(binary, *arguments):
    subprocess.run((binary, *arguments), check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, env=_SAFE_COMMAND_ENV)


def main():
    if os.environ.get("ARTEX_FIXTURE_GUARD_ACK") != "DISPOSABLE_NETWORK_NAMESPACE_ONLY":
        raise SystemExit("fixture guard requires a disposable network namespace acknowledgement")
    # Default deny is installed before parsing. An error prevents the readiness
    # marker and the CI driver never attaches a process to this namespace.
    for binary in (_IPTABLES, _IP6TABLES):
        for chain in ("OUTPUT", "INPUT", "FORWARD"):
            _run(binary, "-P", chain, "DROP")
        for chain in ("OUTPUT", "INPUT", "FORWARD"):
            _run(binary, "-F", chain)
    endpoints = parse_endpoints(os.environ.get("ARTEX_FIXTURE_ENDPOINTS", ""))
    for address, port in endpoints:
        _run(_IPTABLES, "-A", "OUTPUT", "-d", address + "/32", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
        _run(_IPTABLES, "-A", "INPUT", "-s", address + "/32", "-p", "tcp", "--sport", str(port),
             "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
    with open("/run/fixture-team-guard-ready", "x", encoding="ascii") as ready:
        ready.write("ready\n")
    print("fixture endpoint guard ready", flush=True)
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit(0))
    while True:
        signal.pause()


if __name__ == "__main__":
    main()
