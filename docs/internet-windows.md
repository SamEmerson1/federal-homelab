# Internet access log

The lab segment has no route to the internet. When a host needs patches or packages, its virtual
adapter is moved to NAT for that task and moved back afterwards. Each window is recorded here.

| Date | Host | Purpose | Duration | Returned to LABNET |
|---|---|---|---|---|
|2026-09-19|RHEL01|Fetched scan script|~14 min|Yes|
|2026-09-19|RHEL01|Installed 18 packages required by the STIG remediation|~13 min|Yes|
|2026-09-20|DC01|Windows Update check; Defender platform and signature updates|15 min|Yes|
|2026-09-20|WS01|Patching attempt; aborted after filesystem corruption, VM reverted to pre-patch snapshot|~2 h (18:5x–20:4x)|Yes|

Windows opened during the initial build, before this log was started, were not individually
recorded.
