# Operator console

Open `/console/` at the installation's configured HTTPS address. The Go registry
serves the bundled interface and management APIs together. No Node process, CDN,
external fonts or vendor service is needed to use it. First initialize the
installation and trust its CA as described in [native installation](native-install.md).

Choose `admin.token` from your private installation directory or paste an expiring
tenant credential. A reader or writer credential works within its current role
and repository grants. A worker credential cannot connect. The console keeps the
credential in this tab's memory; reloading, disconnecting or receiving an
unauthorized response clears it. It creates no authentication cookie and stores
no credential in browser storage or URLs. Keep the installation address trusted:
the browser necessarily gives that installation the supplied credential.

Create a hosted repository for publication, a proxy for an approved upstream, or
a group over existing repositories of the same format. The format selector shows
only adapters supported by the server. Proxy setup accepts a configured private
credential reference, never its value. More advanced source configuration remains
available through the API. Restricted repositories require actor grants as well
as an appropriate credential role.

Review is enabled by default. Use **Client setup** to copy an endpoint or native
configuration template, supply a scoped reader/writer credential privately, and
publish with the package's ordinary client. The templates contain placeholders,
not this tab's credential. In **Packages**, inspect the exact path and SHA-256
before choosing **Allow** or **Deny**. Allowing a digest changes availability; it
does not establish malware, vulnerability, license or signature approval. Current
server policy governs every download, including after the displayed observation
was fetched.

Every mutation retains its serialized request and idempotency key while awaiting
confirmation. If the connection fails, **Retry same request** asks the server to
confirm that original operation. **Edit as a new request** creates a different
operation; first check the current state if the original response was lost.
A job admission means pending work. Open **Jobs** to inspect its recorded progress,
errors and observations; cancellation and retry remain subject to server checks.

**Storage** can admit filesystem inventory, preview/start a referenced integrity
sweep and preview/reconcile expired transfer leases. Inventory layout coverage,
SHA-256 verification, missing bytes, unsupported paths and read errors are separate
observations. These screens do not approve content security or authorize deletion.
**Audit** reads the tenant's authoritative event journal. **Export this page**
exports only the loaded page; it is not a full-history export or chain verification.

Fetch times describe observations, which are labelled stale after one minute.
Refresh to request current data. A service error may retain an explicitly older
observation; a permission denial clears the affected resource data. Disconnect
before changing tenants. In-flight requests abort, and late responses cannot
populate the next tenant's workspace.

Jobs, inventory, sweep observations and audit use their available server cursors.
Repository and package-reference lists still have a legacy server bound (normally
1,000 rows before visibility filtering). They may omit records even when fewer
are visible. Local filtering and previous/next loaded rows search only that
bounded response. Complete management pagination remains required.

Keyboard users can use **Skip to content**, open dialogs, focus the first form
field, close with Escape and return to the initiating control. Layouts support
narrow screens and reduced-motion preferences. Qualification records name the
actual browser, tested states, keyboard actions and automated accessibility rules;
full WCAG conformance and assistive-technology/native-browser coverage remain open.

## Building and verifying the embedded assets

A normal `make build` checks committed source/asset hashes and builds the Go
binaries without Node. To modify the interface, install the exact pinned frontend
dependencies with `npm --prefix web ci --ignore-scripts`, run `make console`, review
both source and generated `internal/consoleui/dist` files, then run `make console-check`
for a byte-for-byte rebuild comparison. Bundled dependency notices are served at
`/console/third-party-notices.txt`. Keep the lockfile and `web/build-manifest.json`
with source changes.

The real browser fixture runs through `scripts/dev.py` with
`scripts/conformance_console.py`; `--require-clean-build` checks both binary source
identities. It uses an empty owned PostgreSQL database, a registry and worker,
stock npm and pinned Chromium. Its loopback HTTP development profile does not
qualify browser CA deployment or production PKI. Credential files and raw browser
reports stay in ignored `.private/`; public evidence contains only scoped results.
