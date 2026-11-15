FROM alpine:3.21
RUN apk add --no-cache iptables ip6tables conntrack-tools python3
COPY security/network-guard/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
