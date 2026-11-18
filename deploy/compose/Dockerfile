# SPDX-License-Identifier: BUSL-1.1
ARG POSTGRES_IMAGE=docker.io/library/postgres:16.16-alpine@sha256:81e77a4833487b8132fe4b00bedd39dc3f74b8641e387f19312a48f7de218c2e
FROM ${POSTGRES_IMAGE} AS trust

FROM scratch
COPY --chmod=0644 --from=trust /etc/ssl/certs/ca-certificates.crt /ca-certificates.crt
ENV SSL_CERT_FILE=/ca-certificates.crt
COPY --chmod=0755 cratectld cratectl /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cratectld"]
