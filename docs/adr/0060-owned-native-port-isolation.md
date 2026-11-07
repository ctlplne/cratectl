# 0060: Reserve owned CI ports and retain bind-state diagnostics

Date: 2026-11-07. State: implementation/qualification in progress.

Preserve DEFECT0136: exactbadb85b x86 full race suite fails in the original OCI
signed-delivery test when127.0.0.1:38443 is already in use. No socket/process
state was captured. Its actual owner/cause is unknown; no timeout/data race was
reported. ARM full main succeeds. Named Go success does not accept this campaign.

The selected fixed ports overlap Linux's usual automatic client-port range.
Reserve only35432/38443 before running native integration in disposable
GitHub-hosted Linux. Read/merge the inherited ip_local_reserved_ports set rather
than replacing it; verify preservation and both required reservations afterward.
Do not change local macOS, customer/sibling services, ephemeral range, test
assertions, ports, time budgets or source/service permission semantics. Never
kill an unidentified process or retry a failed bind as a substitute for evidence.

Qualify the kernel behavior in two fresh owned child network namespaces: with a
declared one-port automatic range, an unreserved automatic client connection
occupies38443 and prevents its listener; with reservation, that automatic
allocation refuses and both explicit35432/38443 listeners still bind. Namespace
and root/GitHub-host/platform guards prevent changing the parent range. These
controlled kernel cases do not identify the original failed socket's owner.

For future native conformance bind failures, retain bounded counts of matching
Linux TCP states without remote addresses, PIDs, tokens or full process tables.
A later live listener versus connection/TIME_WAIT observation narrows diagnosis;
the original missing observation remains missing. Full original274PG/96Go
normal/race,57fuzz/19main151 and every actually selected profile remain required.

Official kernel contracts checked2026-11-07:

- [Reserved ports exclude automatic allocation and preserve explicit binds](https://docs.kernel.org/networking/ip-sysctl.html#ip-variables).
- [Bounded TCP table interpretation](https://docs.kernel.org/networking/proc_net_tcp.html).

No schema/primary/release/package/image/credential/customer/sibling change.
Full450capabilities/41families/later GOAL4.1 scope and readiness gates stay open.
