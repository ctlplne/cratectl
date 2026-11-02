# GitHub CI

The public repository runs GitHub Actions on fresh Ubuntu 24.04 x86-64 and ARM64
machines, plus a macOS ARM64 machine for build, unit, race, lint and console
reproduction. A separate bounded fuzz job exercises every checked-in Go fuzz
target on all three native architectures; this is a smoke budget, not a full
fuzz campaign. Both Linux architectures also run real PostgreSQL integration and
stock-client journeys. The registry listens only on the owned loopback port 38443; the
disposable PostgreSQL service uses port 35432. The service is recreated for every
job. CI does not connect to an operator or customer database.

The native job installs checked ORAS 1.3.6 and Maven 3.10.0 archives, Python 3.14,
Java 21, Node 26 and the exact Go version from `go.mod`. It runs
`make integration` and `make integration-race` against the disposable database,
then generic/npm/PyPI/Maven/OCI compatibility and native lifecycle drivers.
It also runs fresh-database TLS installation, durable
job and lease recovery, filesystem inventory and integrity sweeps, and legal-hold
matter journeys on both Linux architectures. On x86-64 it runs all Chromium console
workflows and automated accessibility checks. These are real clients and a real registry;
their exact versions and results are visible in the job logs. The ARM64 browser
journey remains a separate gate until Chromium on that runner is qualified.

The scoped security job runs Go source and binary vulnerability checks plus
Gitleaks on the current tree and full reachable history. The source job runs the
web dependency audit. Synthetic credential-rule fixtures verify Gitleaks exceptions
in directory and Git history modes. The existing `make security` and `make packaging` gates
still fail until their complete campaigns exist. A green CI run does not declare
full product, release, platform or legal readiness. The capability and journey
ledgers retain the remaining scope.

Pull requests run with a read-only GitHub token and no repository secrets. The
ephemeral PostgreSQL service uses local trust authentication solely inside its
GitHub-hosted runner. Generated credentials and all fixture data stay in ignored
`.private/` and `.cache/`; the workflow does not upload that raw state. The retained
local macOS ARM qualification is separate from GitHub's Linux ARM64 and x86-64 results.
Each security/native job uploads only a bounded CI summary of generated evidence
fields for 30 days. Native binary records include reviewed paths, SHA-256 and
clean embedded Git/OS/architecture identity; unknown paths or mismatched builds
fail the exporter. Raw reports, browser traces and private command logs stay
on the disposable runner.

The [qualification placement plan](../qualification/github-actions-plan.md) lists
the next drivers, required real services and native hosts, and the limits of each
CI result. It is updated with the capability and journey ledgers as work grows.

`Controlled upgrade qualification` uses separate native Linux x86-64 and ARM64
runners on relevant `main` pushes, manual dispatch and Mondays at 08:17 UTC.
It rebuilds the ten pinned historical sources from
`docs/qualification/upgrade-baselines.json`, rejects dirty or cross-built
artifacts, and runs legacy adoption, schema 2–10 lifecycle upgrades, repair,
recurring integrity and retention upgrades against disposable PostgreSQL.
Both native jobs passed on `1678ed5`; see
`evidence/2026-11-02/github-controlled-upgrades-checkpoint.json` for the exact
run, binary identities, assertions and limits.
The retained local primary is outside this workflow.

`Focused browser regression` is a separate native x86 GitHub workflow for
console defect replay. On relevant UI/driver changes or manual
dispatch, it defaults to `--workflow repair` five times with independent fresh
databases. Each selected run must pass its single workflow with zero skips or
flaky results; the first failure stops the gate and prints safe locations.
The default console gate still requires all 14 workflows. Early diagnostic
labels were unreliable because source snippets were searched as error text.
The corrected diagnostic reads headers and explicit phases; the browser harness
now reads displayed repair IDs and job rows instead of navigation-sensitive
Chromium response bodies. See
`evidence/2026-11-02/github-repair-diagnostic-correction.json`. Live replay remains
required; the unsupported product focus change was reverted.

The `20a71c1` full run passed repair but failed retention approval while reading
a Chromium response body after the dialog closed. See
`evidence/2026-11-02/github-ci-20a71c1-failure.json`. Retention now verifies the
browser POST/status and dialog closure, then identifies exactly one newly
admitted run through the independent API client. The existing cancellation,
revocation, recovery, byte and zero-Axe assertions remain required. Manual
dispatch with `workflow=retention` replays that complete journey five times on
independent fresh databases. It has a separate concurrency group so it cannot
cancel the repair campaign. Both focused campaigns and full main/upgrades must
pass on one exact next candidate. Failed runs retain bounded browser counts too.
