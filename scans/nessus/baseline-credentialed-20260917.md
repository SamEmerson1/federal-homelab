# Nessus credentialed baseline — 2026-09-17

**Tool:** Tenable Nessus Essentials Plus (education license, 20 IPs)
**Scanner:** KALI01, 10.10.10.50
**Policy:** Basic Network Scan
**Severity base:** CVSS v3.0
**Duration:** 29 minutes
**Authentication:** `Auth: Pass` on all four hosts

## Credentials used

| Target | Method | Account | Escalation |
|---|---|---|---|
| DC01, WS01 | Windows SMB | domain administrator | — |
| RHEL01 | SSH password | `rheladmin` | sudo to root |
| SIEM01 | SSH password | `siemadmin` | sudo to root |

Scan options enabled Remote Registry and administrative shares for the duration of the scan only;
both are disabled again when the scan completes.

## Results

| IP | Host | Uncredentialed | Credentialed |
|---|---|---|---|
| 10.10.10.10 | DC01 | 58 | 229 |
| 10.10.10.20 | SIEM01 | 5 | 37 |
| 10.10.10.30 | RHEL01 | 22 | 53 |
| 10.10.10.40 | WS01 | 20 | 233 |

**Unique vulnerabilities:** 85 (uncredentialed: 32)
**Remediation actions identified:** 9

WS01 severity breakdown: 21 critical, 32 high, 5 medium, 175 informational.

| Severity | Count |
|---|---|
| Critical | — |
| High | — |
| Medium | — |

## Notes

**Credentialed vs uncredentialed.** Roughly 4× the unique findings from the same hosts on the same
network in 7 additional minutes. Uncredentialed scanning enumerates what a service exposes;
credentialed scanning reads installed package versions and local configuration, which is where
missing patches appear. This is why credentialed scanning is the standard in operational
vulnerability management programs.

**Scanning access vs hardening.** The Remote Registry and administrative share access this scan
requires is access that STIG hardening restricts. Applying the STIG GPO package is expected to
break credentialed Windows scanning, and re-establishing it will require a documented exception for
the scanner. That tension is recorded rather than worked around.

**Environment issue during first attempt.** An initial run returned only 3 of 4 hosts. WS01's
default Windows power plan suspended the VM mid-scan (System event 42 → 107), and SIEM01 was
powered off. Idle sleep was disabled on all hosts and the scan was re-run from scratch; only the
complete run is recorded here.

**Licensing limitation.** Nessus Essentials Plus does not support data export, so evidence is
captured as rendered PDF/HTML reports rather than raw `.nessus` files. It also does not include
compliance checks or audit files — all STIG compliance figures in this repository come from
OpenSCAP and SCC, never from Nessus.

## Evidence

`baseline-credentialed-20260917.html`
