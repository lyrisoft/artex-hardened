FROM alpine:3.21
RUN apk add --no-cache iptables ip6tables python3
COPY security/fixture-team-guard/guard.py /fixture-team-guard.py
ENTRYPOINT ["python3", "-B", "/fixture-team-guard.py"]
