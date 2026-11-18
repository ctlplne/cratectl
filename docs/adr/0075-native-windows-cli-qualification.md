# 0075: Qualify Windows private configuration on native GitHub hosts

Status: native x64 and ARM64 verified at `a0e646d` for the profile below.

Windows ACL, NTFS, reparse-point and sharing behavior must run on Windows. The
existing POSIX process helper cannot establish those outcomes. Add two independent
GitHub-hosted jobs on `windows-2025` x64 and `windows-11-arm` ARM64. Fail-fast is
disabled and running jobs are never cancelled by a later push. Only owner main
source runs this profile, with a read-only token and checkout credentials disabled.
Disable automatic CRLF conversion before checkout so working source hashes equal
the original Git blobs. The jobs build the actual native CLI and a Go qualifier
with the pinned Go1.27.4 SDK. No Python interpreter or x86 emulation is needed for
the ARM64 qualification.

The qualifier checks actual runtime and SDK platform, clean checkout and embedded
CLI/driver source revision, modification flag, package and Go version. It records
three executable hashes and twenty-three exact source hashes. Five managed commands
check Git revision/cleanliness, native SDK host and target, and two noncached test
suites.
The fifteen required functions include ten configuration controls and five driver
controls. The configuration tests cover the Windows handle reader, pure ACL
policy, read budgets and concurrent first-writer behavior. The actual CLI tests
read private input over an owned TLS management stand-in on `127.0.0.1:38443`
and write a protected npm configuration, with refusal of an existing output and
a broad source credential.

Each command gets a fresh unnamed Windows Job Object with kill-on-close. The
process is assigned to that job by the process-creation attribute and starts
suspended. Observe exactly one active process before resuming its initial thread.
Only explicit standard handles are inherited. Bound argument/environment bytes,
output to8MiB and execution to four minutes. On every return, terminate only the
owned job and observe zero active processes; join the output reader and retain
bounded partial failure bytes. Never enumerate or signal unrelated PIDs. Native
controls prove exact output, overflow refusal and cancellation of a real observed
descendant through its owned job; the descendant is observed through a process
handle, not killed by PID.

Decode bounded Go test JSON events. Require one run/pass for each exact selected
top-level function and a final package pass. Any failed/skipped subtest, unknown
function, incomplete/duplicate/out-of-order/trailing stream or exceeded budget
refuses. The profile cannot convert a missing native fixture capability into a
skip. The fixture-helper function is invoked as a child only and is never counted
as profile proof.

Upload one closed safe report per successful job, retained14days. It contains
fixed identities, hashes, the exact sorted function names and explicit scope
flags, without raw test output, user SIDs, private paths or credential values.
Both upload steps enable hidden files for their exact paths under `.cache`.
Windows creates npm configuration and failure output with a protected owner
DACL before the first write. Failed writes attempt removal through the same file
handle. Failure output is bounded to 8 MiB. Seal the first observation with the
existing public diagnostic recipient
using OpenSSL CMS AES-256-GCM/RSA-OAEP-SHA256. Retain only ciphertext and closed
hash/absence metadata for30days. Failed/unavailable encryption has no plaintext
fallback and cannot erase the first failure. Diagnostic encryption is not proof
of a successful test or a signing service.

The read-only campaign verifier adds the two exact native job/step/platform and
artifact-member contracts. A separate closed validator binds all source hashes
to candidate Git bytes without executing artifact code. Unknown/private fields,
missing/reordered function coverage, dirty/cross-built executable identities,
wrong runner/run/candidate, skipped steps and unsupported broad claims refuse.
Adding the workflow and validator closes22 files rather than20. The original
78a5983 whole acceptance and2a0268c's completed failed strict campaign are retained
before publishing this boundary; historical results are never upgraded by it.

The first-attempt `a0e646d` workflow completed both native jobs. Both reports bind
all 23 source files and the original CI identities. Each job ran the private
configuration, npm configuration output, scoped CLI request and owned process
controls. [Native evidence](../../evidence/2026-11-18/github-a0e646d-windows-native.json)

Windows server operation, server-issued credential creation and bootstrap,
collection directory locks, disconnected installation and the other GOAL
requirements stay open.
No primary/customer/sibling service or selected local binary is changed.

References: [GitHub standard native runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[process creation attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[initial suspended-thread resume](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread),
and [public Microsoft SDK attribute definitions](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WinBase.h).
