#!/usr/bin/env python3
"""Validate rendered Compose deployment without echoing secrets."""
import json
import sys
c=json.load(sys.stdin)
svc=c["services"]
a,g=svc["artex"],svc["network-guard"]
problems=[]
if a.get("network_mode") != "service:network-guard": problems.append("not sharing guarded network namespace")
if "NET_ADMIN" in a.get("cap_add",[]): problems.append("ARTEX has network-admin capability")
if a.get("cap_drop") != ["ALL"]: problems.append("ARTEX does not drop all capabilities")
if g.get("cap_add") != ["NET_ADMIN"]: problems.append("guard capability mismatch")
if a.get("privileged",False): problems.append("ARTEX is privileged")
if a.get("ports"): problems.append("ARTEX publishes ports directly")
for p in g.get("ports",[]):
    if p.get("host_ip") != "127.0.0.1": problems.append("management port exposed externally")
for v in a.get("volumes",[]):
    src=v.get("source","")
    if src in ("/","/var/run/docker.sock") or v.get("target") == "/var/run/docker.sock": problems.append("dangerous mount")
if "llm-broker" in svc:
    b=svc["llm-broker"]
    if b.get("ports"): problems.append("model broker exposed publicly")
    if b.get("read_only") is not True: problems.append("broker must have read-only filesystem")
    if any(s.get("source")=="openai_api_key" for s in a.get("secrets",[])): problems.append("ARTEX can mount cloud secret")
if problems:
    raise SystemExit("; ".join(problems))
print("PASS: contained Compose structural checks (live packet filtering still requires testing)")
