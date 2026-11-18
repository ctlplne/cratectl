# SPDX-License-Identifier: BUSL-1.1
ARG POSTGRES_IMAGE=postgres:16.15-alpine
FROM ${POSTGRES_IMAGE} AS trust

FROM scratch
COPY --chmod=0644 --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0755 cratectld cratectl /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cratectld"]
