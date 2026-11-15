#!/usr/bin/env python3
"""Run on the Docker host, outside ARTEX, to retain tamper-evident event history.

docker events only includes lifecycle metadata. Execution activity must also be
exported from ARTEX itself and forwarded to an independent SIEM.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT=Path(os.getenv("ARTEX_AUDIT_DIR", "/var/log/artex-hardened"))
PROJECT=os.getenv("ARTEX_COMPOSE_PROJECT", "artex-hardened")
ROOT.mkdir(parents=True,exist_ok=True)
os.chmod(ROOT,0o700)
path=ROOT/"docker-events.jsonl"
previous="0"*64
if path.exists():
    for line in path.open(encoding="utf-8"):
        try: previous=json.loads(line)["digest"]
        except (ValueError,KeyError): raise SystemExit("Corrupt audit chain; preserve file for investigation")
f=os.open(str(path),os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)
cmd=["docker","events","--filter","type=container","--filter",f"label=com.docker.compose.project={PROJECT}","--format","{{json .}}"]
with os.fdopen(f,"a",encoding="utf-8", buffering=1) as out:
    with subprocess.Popen(cmd,stdout=subprocess.PIPE,text=True) as proc:
        for line in proc.stdout:
            try:
                event=json.loads(line)
                attrs=event.get("Actor",{}).get("Attributes",{})
                item={"time_ns":event.get("timeNano"),"type":event.get("Type"),"action":event.get("Action"),
                    "container_id":event.get("id"),"service":attrs.get("com.docker.compose.service"),
                    "prev":previous,"received_at":time.time_ns()}
                canonical=json.dumps(item,sort_keys=True,separators=(",",":"))
                previous=hashlib.sha256(canonical.encode()).hexdigest()
                out.write(json.dumps({**item,"digest":previous},sort_keys=True)+"\n")
            except (ValueError,KeyError) as exc:
                print(f"audit capture error: {exc}",file=sys.stderr)
        if proc.wait() != 0:
            raise SystemExit("docker events ended unexpectedly")
