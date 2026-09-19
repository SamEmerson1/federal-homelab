# Nessus uncredentialed baseline — 2026-09-17

**Tool:** Tenable Nessus Essentials Plus (education license, 20 IPs)
**Scanner:** KALI01, 10.10.10.50
**Policy:** Basic Network Scan
**Severity base:** CVSS v3.0
**Credentials:** none — `Auth: Fail` on all hosts is the intended result
**Duration:** 22 minutes

## Targets

| IP | Host | Findings |
|---|---|---|
| 10.10.10.10 | DC01 | 58 |
| 10.10.10.20 | SIEM01 | 5 |
| 10.10.10.30 | RHEL01 | 22 |
| 10.10.10.40 | WS01 | 20 |

**Unique vulnerabilities across all hosts:** 32, overwhelmingly informational.

KALI01 is excluded — it is the scanner.

## Notes

**Host discovery.** Windows Firewall blocks ICMP by default. The scan's default discovery settings
include TCP and ARP alongside ICMP, so all four hosts responded without firewall changes.

**Isolation confirmed by scan failure.** Two scan notes record DNS resolution failures for
`r.nessus.org`, the external callback host Nessus uses for its Log4Shell check. The lab segment has
no route out, so those plugins could not run. This is evidence the segmentation is real, and a
genuine limitation: vulnerability checks requiring outbound callbacks cannot be evaluated in this
environment.

**Purpose.** This scan establishes the external attacker's view — open ports, service banners,
certificate detail — as a comparison point for the credentialed scan. It is not a substitute for it.

## Evidence

`baseline-uncredentialed-20260917.html`
