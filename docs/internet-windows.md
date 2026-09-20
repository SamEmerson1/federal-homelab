# Internet access log

The lab segment has no route to the internet. When a host needs patches or packages, its virtual
adapter is moved to NAT for that task and moved back afterwards. Each window is recorded here.

| Date | Host | Purpose | Duration | Returned to LABNET |
|---|---|---|---|---|
|2026-09-19|RHEL01|Fetched scan script|~14 min|Yes|
|2026-09-19|RHEL01|Installed 18 packages required by the STIG remediation|—|Yes|

Windows opened during the initial build, before this log was started, were not individually
recorded.
