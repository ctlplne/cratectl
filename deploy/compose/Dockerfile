# SPDX-License-Identifier: BUSL-1.1
ARG POSTGRES_IMAGE=postgres:16.15-alpine
FROM ${POSTGRES_IMAGE} AS trust

FROM scratch
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY cratectld cratectl /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cratectld"]
