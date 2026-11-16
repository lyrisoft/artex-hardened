# Disposable CI fixture only; not the production ARTEX executor image.
FROM alpine:3.21
RUN apk add --no-cache bash curl nmap
USER 65532:65532
ENTRYPOINT ["/bin/bash"]
