# Internet access log

The lab segment has no route to the internet. When a host needs patches or packages, its virtual
adapter is moved to NAT for that task and moved back afterwards. Each window is recorded here.

| Date | Host | Purpose | Duration | Returned to LABNET |
|---|---|---|---|---|
|2026-09-19|RHEL01|Fetched scan script|~14 min|Yes|
|2026-09-19|RHEL01|Installed 18 packages required by the STIG remediation|~13 min|Yes|
|2026-09-20|DC01|Windows Update check; Defender platform and signature updates|15 min|Yes|
|2026-09-20|WS01|Patching attempt; aborted after filesystem corruption, VM reverted to pre-patch snapshot|~2 h (18:5x–20:4x)|Yes|
|2026-09-20|WS01|Windows cumulative KB5129195, .NET, Defender, and Store app updates after snapshot revert|~20 min|Yes|

Windows opened during the initial build, before this log was started, were not individually
recorded.

## Transfers made without opening a window

Recorded because the absence of a window is itself the decision, and an isolation claim is only
meaningful if the exceptions are enumerated.

**2026-09-22 — DoD PKI certificates, WS01.** The InstallRoot 5.6 package was downloaded on the
physical host and transferred into the segment rather than attaching WS01 to NAT. Before execution
the file was checked two ways: its SHA-256 was compared against the hash computed on the host to
confirm it crossed intact, and its Authenticode signature was checked to confirm DISA published it.

The signature initially reported `UnknownError — a certificate chain processed, but terminated in a
root certificate which is not trusted`, because the certificate that validates the installer is
issued by the same DoD PKI the installer exists to install. After the roots were in place the
identical file returned `Valid`, which confirms the installation succeeded by a different mechanism
than counting certificates in a store.

This is the preferred pattern for introducing software to an isolated enclave: acquire outside,
verify, transfer, verify again. It replaces a network exception with a file-integrity check.
