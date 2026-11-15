#!/usr/bin/env python3
"""Fail closed on important ARTEX Compose runtime guardrails; prints no secrets."""
import json
import subprocess
import sys

def main():
    if len(sys.argv) != 1:
        raise SystemExit("Usage: docker compose config --format json | python3 scripts/check-compose-security.py")
    try:
        doc = json.load(sys.stdin)
    except Exception as e:
        raise SystemExit(f"Cannot parse Compose JSON: {e}")
    services = doc.get("services", {})
    a = services.get("artex")
    if not isinstance(a, dict):
        raise SystemExit("Missing artex service")
    errors = []
    if a.get("privileged", False):
        errors.append("privileged container")
    if a.get("network_mode") == "host":
        errors.append("host networking")
    if a.get("pid") == "host":
        errors.append("host PID namespace")
    if a.get("pids_limit") != 256:
        errors.append("PID limit is not 256")
    if a.get("init") is not True:
        errors.append("init process is not enabled")
    if "no-new-privileges:true" not in (a.get("security_opt") or []):
        errors.append("no-new-privileges is missing")
    for port in a.get("ports", []):
        if isinstance(port, dict):
            if port.get("host_ip") not in ("127.0.0.1", "::1"):
                errors.append("non-loopback port binding")
        else:
            errors.append("unrecognized/unsafe port mapping")
    for volume in a.get("volumes", []):
        if isinstance(volume, dict) and (
            volume.get("source") in ("/", "/var/run/docker.sock")
            or volume.get("target") == "/var/run/docker.sock"
        ):
            errors.append("dangerous host mount")
    env = a.get("environment", {})
    if not isinstance(env, dict):
        errors.append("environment not a mapping")
    else:
        if str(env.get("ARTEX_UPDATE_CHECK", "")).lower() not in ("0", "false", "off", "no", ""):
            errors.append("update check is enabled")
        if str(env.get("ARTEX_UNTRUSTED_BOUNDARY", "")).lower() in ("0", "false", "off", "no"):
            errors.append("prompt-injection boundary is disabled")
    if errors:
        for item in errors:
            print(f"FAIL: {item}", file=sys.stderr)
        raise SystemExit(1)
    print("PASS: ARTEX Compose baseline (not a comprehensive sandbox or egress test)")

if __name__ == "__main__":
    main()
