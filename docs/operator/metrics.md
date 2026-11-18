# Read cratectl process metrics

The registry can expose Prometheus text metrics at `GET /metrics` on its
configured TLS listener. Configure a separate private metrics credential
for the deployment operator who scrapes the process.

```sh
(umask 077; openssl rand -hex 32 > "$METRICS_CREDENTIAL")
cratectld serve --config "$RUNTIME" --metrics-token-file "$METRICS_CREDENTIAL"
```

The private runtime JSON can also specify the credential's absolute path in
`metrics_token_file`. Restart the registry when replacing the file. Configure
the scraper to use verified TLS and the bearer credential file. The endpoint
requires this dedicated credential even when a caller already administers
a tenant.

```yaml
scrape_configs:
  - job_name: cratectl
    scheme: https
    metrics_path: /metrics
    authorization:
      credentials_file: /private/cratectl/metrics.token
    tls_config:
      ca_file: /private/cratectl/ca.crt
    static_configs:
      - targets: ['localhost:38443']
```

The metrics cover request outcomes, a request-duration histogram, active
handlers, body bytes read and written by the application, and transfer
admission use, capacity, and saturation refusals. The label sets are fixed.
They identify protocol groups and broad HTTP outcomes. The counters reset
with the registry process. Body totals reflect application I/O, and audit
or delivery receipts establish what a receiver actually obtained.

These are deployment-level metrics. Queue fairness, cache diagnostics,
feed health, replication and projection lag, and OpenTelemetry
qualification remain separate observability work.
