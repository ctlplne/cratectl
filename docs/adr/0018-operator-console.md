# Embedded operator console

The basic console uses React, TypeScript and Vite and calls the same authenticated
management APIs as the CLI. A current-identity endpoint returns the tenant, actor,
role, client-visible authority and actually supported adapters. It rechecks the
credential through the normal transaction path. No browser route bypasses store
authorization, policy, idempotency or worker fences.

Production assets are bundled locally and embedded in the Go service. The source,
lockfile, generated assets and dependency notices are retained together. Serving
the console requires no Node process, external font, CDN, analytics or entitlement
service. A same-origin content policy permits only packaged scripts/styles and
API connections. Static HTML contains no deployment credentials or tenant data.

An operator chooses a token file or pastes an expiring credential. The token is
kept in tab memory, excluded from URLs/browser storage/logging, and cleared on
disconnect or unauthorized response. Requests abort on session/navigation changes;
late responses cannot populate another tenant's view. Backend enforcement remains
authoritative. A displayed policy observation has a fetch time and can become
stale; actual serving still uses current policy.

Mutations preview their affected repository, digest or job. An uncertain response
retains the original request bytes/key for explicit retry. Inspection admission
is pending work, not successful inspection or security approval. Read errors and
denied states have recovery actions. Every list states its scope: jobs, storage
and audit use available cursors; repository/artifact management lists now use bounded server search and encrypted
continuation cursors as specified in [the pagination decision](0019-management-pagination.md).
Complete native indexes and every management workflow remain separate obligations.

The visual grammar references the studio's warm paper surfaces, light navigation,
system typography, restrained borders and clear status labels. Keyboard focus,
native dialogs, labels, status announcements, reduced motion and responsive
layouts are tested in a real browser. Automated accessibility checks supplement
keyboard and visual review; they do not establish the full WCAG campaign.

Pinned dependencies are resolved from the official npm registry. Framework and
test contracts follow [React](https://react.dev/versions),
[Vite](https://vite.dev/guide/) and
[Playwright](https://playwright.dev/docs/test-configuration). [Playwright browser selection](https://playwright.dev/docs/browsers) documents the
full Chromium channel used for these checks. In this environment the separate
headless shell stalls in axe color-contrast even on minimal controls. Full Chromium
completes the same current axe rules: a good control passes, and a seeded bad control
reports contrast, label, button-name, image-alt and target-size violations. No CSP
relaxation or accessibility rule exclusion is used. This is an observed runner
difference; its underlying platform cause is not established.

The console adds no
new runtime database, protocol adapter or server-side package execution.
