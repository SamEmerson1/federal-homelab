# Federal-Aligned Security Lab

An isolated virtual enterprise network built to practice the security controls used in federal and
defense-contractor environments: DISA STIG hardening, SCAP compliance scanning, credentialed
vulnerability assessment, centralized logging with ATT&CK-mapped detections, and NIST 800-53
control documentation.

Five virtual machines, a Windows domain, a SIEM, an attack platform, and a documented set of
findings.

---

## Environment

| Host | OS | Role |
|---|---|---|
| **DC01** | Windows Server 2025 | Active Directory Domain Services, DNS, Group Policy |
| **WS01** | Windows 11 Pro | Domain-joined workstation, Sysmon telemetry, attack simulation target |
| **RHEL01** | Rocky Linux 9 | STIG hardening target, OpenSCAP scanning |
| **SIEM01** | Rocky Linux 9 | Splunk indexer, centralized log collection |
| **KALI01** | Kali Linux | Vulnerability scanner, attack platform |

All hosts sit on an isolated virtual network segment with no route to the physical host or any
production network. Internet access is temporary and deliberate — attached only for patching, then
removed.

![Network topology](screenshots/network-topology.png)

See [`docs/architecture.md`](docs/architecture.md) for addressing and isolation design, and
[`docs/network-diagram.md`](docs/network-diagram.md) for the full topology.

---

## Stack

| Function | Tool |
|---|---|
| Directory services | Active Directory Domain Services, DNS, Group Policy |
| Linux compliance scanning | OpenSCAP with `scap-security-guide` (DISA STIG profile) |
| Windows compliance scanning | SCAP Compliance Checker (SCC), DISA STIG Viewer |
| Windows hardening | DISA STIG Group Policy Objects |
| Vulnerability assessment | Tenable Nessus — credentialed and uncredentialed scanning |
| Endpoint telemetry | Sysmon |
| Log aggregation | Splunk Enterprise with Universal Forwarders |
| Detection engineering | SPL searches mapped to MITRE ATT&CK |
| Adversary emulation | Atomic Red Team |
| Control documentation | NIST SP 800-53 Rev. 5, RMF artifacts |
| Virtualization | VMware Workstation Pro |

---

## Compliance hardening

Baseline scan, remediation, rescan. Findings that were not remediated are tracked in the
[POA&M](docs/poam.md) with a written justification.

| Target | Benchmark | Tool | Before | After |
|---|---|---|---|---|
| RHEL01 | DISA STIG for RHEL 9 | OpenSCAP | — | — |
| WS01 | Microsoft Windows 11 STIG | SCC | — | — |

![OpenSCAP compliance report](screenshots/openscap-report.png)

Linux remediation uses OpenSCAP-generated fix scripts, reviewed and applied in stages. Windows
remediation uses the DISA STIG GPO package imported into Active Directory and linked to a scoped
organizational unit.

![STIG GPO applied](screenshots/stig-gpo-applied.png)

---

## Vulnerability assessment

Credentialed Nessus scans against the domain and Linux hosts, remediation of critical and high
findings, then verification rescans.

| Scan | Critical | High | Medium |
|---|---|---|---|
| Baseline (credentialed) | — | — | — |
| Post-remediation | — | — | — |
| Remaining, tracked in POA&M | — | — | — |

![Nessus scan results](screenshots/nessus-results.png)

Sanitized reports are in [`scans/`](scans/).

---

## Detection engineering

Windows Security, PowerShell, and Sysmon logs forward from DC01 and WS01 into Splunk. Each
detection is written against a stated hypothesis, then validated by executing the corresponding
Atomic Red Team test and confirming the search fires on real telemetry.

| Technique | ATT&CK ID | Log source | Detection |
|---|---|---|---|
| PowerShell | T1059.001 | Sysmon EID 1, PowerShell 4104 | — |
| Create Account: Local Account | T1136.001 | Security 4720, 4732 | [`T1136.001`](detections/T1136.001-local-account-creation.md) |
| Scheduled Task/Job | T1053.005 | Security 4698, Sysmon EID 1 | — |
| Abuse Elevation Control: UAC Bypass | T1548.002 | Sysmon EID 1, 13 | — |
| Clear Windows Event Logs | T1070.001 | Security 1102, System 104 | — |

![Splunk detection firing](screenshots/splunk-detection.png)

Each detection documents the hypothesis, the SPL, expected false positives, analyst response steps,
and what it does not catch. Full set in [`detections/`](detections/).

![Splunk dashboard](screenshots/splunk-dashboard.png)

---

## Documentation

| Artifact | Contents |
|---|---|
| [`docs/ssp-lite.md`](docs/ssp-lite.md) | System Security Plan — NIST 800-53 Rev. 5 control implementation statements across AC, AU, CM, IA, RA, SC, and SI |
| [`docs/poam.md`](docs/poam.md) | Plan of Action and Milestones — unremediated findings with severity, control mapping, and remediation plan |
| [`docs/architecture.md`](docs/architecture.md) | Environment design, isolation model, addressing |
| [`docs/network-diagram.md`](docs/network-diagram.md) | Topology and data flows |

---

## Repository

```
federal-security-lab/
├── docs/           architecture, network diagram, SSP, POA&M
├── configs/        Sysmon config, Splunk inputs/outputs, GPO notes
├── scans/          OpenSCAP, SCC, and Nessus results (sanitized)
├── detections/     SPL searches with ATT&CK mapping
├── scripts/        scan automation
└── screenshots/    walkthrough evidence
```

---

## Notes

A personal training environment, not an accredited system. Compliance percentages describe lab
virtual machines. STIG and SCAP content is published by DISA; this repository contains only results
generated against it.

AI assistance (Claude, Anthropic) was used for planning, drafting documentation, and reviewing
configurations. All scanning, hardening, and detection validation was performed by me in this
environment, and every figure above traces to a scan output committed to `scans/`.
