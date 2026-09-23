# Federal-Aligned Security Lab

An isolated virtual enterprise network built to practice the security controls used in federal and
defense-contractor environments: DISA STIG hardening, SCAP compliance scanning, credentialed
vulnerability assessment, centralized logging with ATT&CK-mapped detections, and NIST 800-53
control documentation.

Five virtual machines, a Windows domain, an attack platform, and a documented set of findings.

![RHEL01 Warning](screenshots/rhel01-warning.png)

---

## Environment

| Host | OS | Role |
|---|---|---|
| **DC01** | Windows Server 2025 Standard | Active Directory Domain Services, DNS, Group Policy |
| **WS01** | Windows 11 Pro (25H2) | Domain-joined workstation, SCC scanning host; Sysmon and attack simulation planned |
| **RHEL01** | Rocky Linux 9.8 | STIG hardening target, OpenSCAP scanning |
| **SIEM01** | Rocky Linux 9.8 | Log collection host; Splunk deployment planned |
| **KALI01** | Kali Linux | Vulnerability scanner, attack platform |

All hosts sit on an isolated virtual network segment with no route to the physical host or any
production network. Internet access is temporary and deliberate — attached only for patching, then
removed.

```mermaid
graph TB
    subgraph LABNET["Isolated segment · 10.10.10.0/24 · no route to host or local network"]
        DC01["DC01<br/>Windows Server 2025<br/>10.10.10.10<br/>AD DS · DNS · Group Policy"]
        SIEM01["SIEM01<br/>Rocky Linux 9<br/>10.10.10.20<br/>Splunk (planned) · :9997 :8000"]
        RHEL01["RHEL01<br/>Rocky Linux 9<br/>10.10.10.30<br/>OpenSCAP STIG target"]
        WS01["WS01<br/>Windows 11 Pro<br/>10.10.10.40<br/>SCC · Sysmon + ART (planned)"]
        KALI01["KALI01<br/>Kali Linux<br/>10.10.10.50<br/>Nessus scanner"]
    end

    WS01 -->|"domain join · Group Policy"| DC01
    WS01 -.->|"planned: Sysmon + Windows event logs :9997"| SIEM01
    DC01 -.->|"planned: Security + Directory Service logs :9997"| SIEM01
    KALI01 -->|"credentialed scan"| DC01
    KALI01 -->|"credentialed scan"| WS01
    KALI01 -->|"credentialed scan"| RHEL01
    KALI01 -->|"credentialed scan"| SIEM01

    classDef win fill:#1f3a5f,stroke:#4a7ab8,color:#ffffff
    classDef lin fill:#1f4f3a,stroke:#4ab887,color:#ffffff
    classDef atk fill:#5f1f2a,stroke:#b84a5f,color:#ffffff
    class DC01,WS01 win
    class SIEM01,RHEL01 lin
    class KALI01 atk
```

See [`docs/architecture.md`](docs/architecture.md) for addressing and isolation design, and
[`docs/network-diagram.md`](docs/network-diagram.md) for the full topology.

### Active Directory

Single-forest domain `lab.local` on DC01, with WS01 joined and placed in a dedicated
Workstations OU so hardening policy can be scoped away from the domain controller.

![Domain controller health](screenshots/ad-dcdiag.png)

![OU structure](screenshots/ad-ou-structure.png)

![WS01 moved to Workstations OU](screenshots/ad-ws01-ou.png)

---

## Stack

| Function | Tool | Status |
|---|---|---|
| Directory services | Active Directory Domain Services, DNS, Group Policy | In use |
| Linux compliance scanning | OpenSCAP with `scap-security-guide` (DISA STIG profile) | In use |
| Windows compliance scanning | SCAP Compliance Checker (SCC) 5.15 | In use |
| Vulnerability assessment | Tenable Nessus — credentialed and uncredentialed scanning | In use |
| Virtualization | VMware Workstation Pro | In use |
| Linux hardening | OpenSCAP-generated remediation, applied in reviewed stages | In use |
| Windows hardening | DISA STIG Group Policy Objects, scoped by OU with loopback processing | In use |
| Full-disk encryption | BitLocker, TPM + PIN pre-boot authentication, recovery keys escrowed to AD | In use |
| Password policy | Domain baseline plus fine-grained policy for privileged accounts | In use |
| Endpoint telemetry | Sysmon | Planned |
| Log aggregation | Splunk Enterprise with Universal Forwarders | Planned |
| Detection engineering | SPL searches mapped to MITRE ATT&CK | Planned |
| Adversary emulation | Atomic Red Team | Planned |
| Control documentation | NIST SP 800-53 Rev. 5, RMF artifacts | Planned |

---

## Compliance hardening

Baseline scan, remediation, rescan, against DISA STIG benchmarks.

| Target | Benchmark | Tool | Before | After |
|---|---|---|---|---|
| RHEL01 | DISA STIG for RHEL 9 | OpenSCAP 1.3.14 | 44.9% | **95.4%** |
| WS01 | Microsoft Windows 11 STIG V2R10 | SCC 5.15 | 38.84% | **97.11%** |
| DC01 | Microsoft Windows Server 2025 STIG V1R1 | SCC 5.15 | 42.74% | Deferred — [POA&M](docs/poam.md) |

Baseline rule counts, all scans run against the MAC-2 Sensitive profile:

| Target | Pass | Fail | N/A | Not checked | CAT I fail | CAT II fail | CAT III fail |
|---|---|---|---|---|---|---|---|
| RHEL01 | 167 | 258 | 42 | 10 | 11 | 224 | 20 |
| WS01 | 94 | 148 | 5 | 10 | 13 | 127 | 8 |
| DC01 | 103 | 138 | 21 | 29 | 11 | 119 | 8 |

After remediation, same benchmark, profile, and scoring method:

| Target | Pass | Fail | N/A | Not checked | CAT I fail | CAT II fail | CAT III fail |
|---|---|---|---|---|---|---|---|
| RHEL01 | 410 | 17 | 40 | 10 | 1 | 11 | 5 |
| WS01 | 235 | 7 | 5 | 10 | 1 | 6 | 0 |

**RHEL01:** 258 failed rules reduced to 17, applied in five reviewed stages with a snapshot and a
login test between each. Method, deviations, and a conflict found inside the benchmark content:
[`docs/rhel01-remediation.md`](docs/rhel01-remediation.md).

**WS01:** 148 failed rules reduced to 7, including 12 of 13 CAT I findings, using DISA's published
Group Policy Objects scoped to a Workstations OU with supplemental policy for the gaps the package
leaves open. The work surfaced three defects in the published GPO package — contradictory BitLocker
startup options, an omitted recovery-escrow policy that leaves an encrypted host unrecoverable, and
two releases of drift behind the benchmark being scanned against:
[`docs/ws01-stig-gpo.md`](docs/ws01-stig-gpo.md).

Every remaining failure on both hosts has a stated reason and carries into the
[POA&M](docs/poam.md).

![OpenSCAP compliance report](screenshots/openscap-report.png)

![OpenSCAP compliance report (post hardened)](screenshots/openscap-report-hardened.png)

![SCC compliance report](screenshots/scc-report.png)

![SCC compliance report (post hardened)](screenshots/post-hardenings-scc.png)

### Scan scope

SIEM01 and KALI01 are excluded from compliance scanning — SIEM01 as the monitoring platform,
KALI01 as the assessment platform. WS01 runs Windows 11 Pro, so the one STIG rule requiring an
Enterprise-only feature (Credential Guard) cannot be satisfied. Rationale for all three in
[`docs/architecture.md`](docs/architecture.md).

**DC01 is assessed but not remediated in this phase.** It is the sole domain controller, with no
replication partner. The Server 2025 STIG's authentication controls — LDAP and SMB signing, NTLM
restrictions, Kerberos encryption types — alter the authentication path every other host depends on,
including the scanner service account and the administrative access used to perform the remediation.
Applying them without a second domain controller and a per-dependency rollback plan exceeds the risk
tolerance for this phase, so the baseline stands and the deferral is recorded with its reasoning in
the [POA&M](docs/poam.md).

---

## Vulnerability assessment

Nessus scans from KALI01 against all four non-scanner hosts. An uncredentialed baseline was taken
first to establish the external view, then a credentialed scan with domain and SSH credentials.

| Scan | Hosts | Unique plugins | Finding instances | Duration |
|---|---|---|---|---|
| Uncredentialed baseline | 4 | 40 | 70 | 22 min |
| Credentialed baseline | 4 | 244 | 421 | 29 min |
| Credentialed, post-patch | 4 | 187 | 378 | — |

| Host | Uncredentialed | Credentialed | Critical | High | Medium | Low |
|---|---|---|---|---|---|---|
| DC01 | 30 | 143 | 0 | 3 | 0 | 0 |
| WS01 | 12 | 186 | 21 | 32 | 5 | 1 |
| RHEL01 | 23 | 54 | 0 | 0 | 0 | 1 |
| SIEM01 | 5 | 38 | 0 | 0 | 0 | 1 |
| **Total** | **70** | **421** | **21** | **35** | **5** | **3** |

Credentialed scanning returned 6× the findings from the same hosts on the same network. An
uncredentialed scan enumerates open ports and service banners, but cannot read installed package
versions or local configuration, which is where missing patches live.

WS01 carries every critical finding and 32 of 35 highs. The Rocky Linux hosts, patched during their
build, returned no critical, high, or medium findings.

| Severity | Baseline (credentialed) | Post-patch | Remaining in POA&M |
|---|---|---|---|
| Critical | 21 | **0** | — |
| High | 35 | **0** | — |
| Medium | 5 | **0** | — |
| Low | 3 | **0** | — |

All 64 actionable findings were closed: 57 by patching WS01 and DC01, 4 by specific configuration
fixes (WinVerifyTrust certificate padding check on both Windows hosts, the Intel BHI speculative
execution mitigation, and a pending-reboot completion), 2 by blocking ICMP timestamp requests on the
Linux hosts, and 1 by updating Defender signatures. Details in
[`scans/nessus/post-patch-credentialed-20260921.md`](scans/nessus/post-patch-credentialed-20260921.md).

![Nessus scan results](screenshots/nessus-results.png)

![Post patch credentialed results](screenshots/postpatch-nessus-scan.png)

Scanning used a dedicated `svc-nessus` domain account rather than a Domain Admin, since the Windows
11 STIG denies privileged domain accounts logon rights on workstations. Remote Registry was enabled
only for the scan window and disabled afterwards.

Full reports are in [`scans/`](scans/).

---

## Detection engineering
**Status:** in progress — Splunk deployment pending.

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

---

## Documentation

| Artifact | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Environment design, isolation model, addressing, scan scope |
| [`docs/network-diagram.md`](docs/network-diagram.md) | Topology and data flows |
| [`docs/internet-windows.md`](docs/internet-windows.md) | Log of temporary internet access for patching |
| [`docs/rhel01-remediation.md`](docs/rhel01-remediation.md) | RHEL01 STIG remediation: staging, deviations, and open items |
| [`docs/ws01-stig-gpo.md`](docs/ws01-stig-gpo.md) | WS01 STIG remediation: GPO import and scoping, package defects, BitLocker, VBS |
| [`docs/poam.md`](docs/poam.md) | Plan of Action and Milestones — every open finding with its reason and closure path |

---

## Repository

```
federal-homelab/
├── docs/           architecture, remediation method, POA&M
├── scans/          OpenSCAP, SCC, and Nessus results
├── detections/     SPL searches with ATT&CK mapping
├── scripts/        scan automation
└── screenshots/    walkthrough evidence
```

---

## Notes

A personal training environment, not an accredited system. Compliance percentages describe lab
virtual machines. STIG and SCAP content is published by DISA and NIWC Atlantic; this repository
contains only results generated against it.

AI assistance (Claude, Anthropic) was used for planning, drafting documentation, and reviewing
configurations. All scanning, hardening, and detection validation was performed by me in this
environment, and every figure above traces to a scan output committed to `scans/`.
