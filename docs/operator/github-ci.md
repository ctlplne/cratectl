# GitHub CI

The public repository runs GitHub Actions on fresh Ubuntu 24.04 x86-64 and ARM64
machines, plus a macOS ARM64 machine for build, unit, race, lint and console
reproduction. Both Linux architectures also run real PostgreSQL integration and
stock-client journeys. The registry listens only on the owned loopback port 38443; the
disposable PostgreSQL service uses port 35432. The service is recreated for every
job. CI does not connect to an operator or customer database.

The native job installs checked ORAS 1.3.6 and Maven 3.10.0 archives, Python 3.14,
Java 21, Node 26 and the exact Go version from `go.mod`. It runs the existing
`make integration` gate, the generic/npm/PyPI/Maven/OCI compatibility driver, and
the native lifecycle driver. On x86-64 it also runs all Chromium console workflows
and automated accessibility checks. These are real clients and a real registry;
their exact versions and results are visible in the job logs. The ARM64 browser
journey remains a separate gate until Chromium on that runner is qualified.

The scoped security job runs Go source and binary vulnerability checks plus
Gitleaks on the current tree and full reachable history. The source job runs the
web dependency audit. The existing `make security` and `make packaging` gates
still fail until their complete campaigns exist. A green CI run does not declare
full product, release, platform or legal readiness. The capability and journey
ledgers retain the remaining scope.

Pull requests run with a read-only GitHub token and no repository secrets. The
ephemeral PostgreSQL service uses local trust authentication solely inside its
GitHub-hosted runner. Generated credentials and all fixture data stay in ignored
`.private/` and `.cache/`; the workflow does not upload them. The retained local
macOS ARM qualification is separate from GitHub's Linux ARM64 and x86-64 results.
