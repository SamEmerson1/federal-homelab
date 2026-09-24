# Architecture

## Design goals

- An enterprise-shaped environment: a Windows domain with a joined workstation, Linux servers, and a separate attack platform.
- Complete isolation from any production or personal network, so adversary emulation can run safely.
- Tooling that matches what is actually deployed in federal and defense-contractor environments, not consumer equivalents.

## Virtual machine inventory

| VM | OS | RAM | vCPU | Disk | Address | Role |
|---|---|---|---|---|---|---|
| DC01 | Windows Server 2025 Standard | 4 GB | 2 | 60 GB thin | 10.10.10.10 | AD DS, DNS, Group Policy, STIG GPO distribution |
| SIEM01 | Rocky Linux 9 (minimal) | 6 GB | 2 | 80 GB thin | 10.10.10.20 | Splunk Enterprise — indexer and search head |
| RHEL01 | Rocky Linux 9 (minimal) | 2 GB | 2 | 40 GB thin | 10.10.10.30 | OpenSCAP STIG hardening target |
| WS01 | Windows 11 Pro | 4 GB | 2 | 80 GB thin | 10.10.10.40 | Domain client, SCC scanning host; Splunk forwarder, Sysmon, Atomic Red Team target |
| KALI01 | Kali Linux | 4 GB | 2 | 60 GB thin | 10.10.10.50 | Nessus scanner, attack platform |

Rocky Linux was chosen for both Linux hosts because it is binary compatible with Red Hat
Enterprise Linux, which is what the RHEL 9 DISA STIG targets and what most federal Linux estates
run.

WS01 additionally exposes CPU virtualization extensions and an IOMMU to the guest. The STIG requires
virtualization-based security, which runs inside Hyper-V's hypervisor; without nested virtualization
the policy applies but the feature reports as configured and not running. SIEM01 ran at 2 GB during
the hardening phase to leave memory for that overhead, and was raised to 6 GB for Splunk, whose
key-value store and search processes do not fit in 2 GB.

## Network design

A single flat lab subnet on a private virtual switch with no host-side adapter. This matters: a
host-only network still exposes an adapter on the physical machine, and a bridged network places
lab VMs directly on the local LAN. Neither is acceptable when the environment is deliberately
running adversary techniques.

| Setting | Value |
|---|---|
| Subnet | 10.10.10.0/24 |
| Domain | `lab.local` |
| DNS | 10.10.10.10 (DC01) for all hosts. SIEM01 and RHEL01 are not domain-joined, so their A records are static |
| DHCP | Disabled — static addressing keeps scan targets stable |
| Default gateway | None |

### Isolation boundary

| Path | State |
|---|---|
| Lab to physical host | Closed |
| Lab to local network | Closed |
| Lab to internet | Closed by default; opened temporarily for patching, then removed |
| Clipboard, drag-and-drop | Disabled on the workstation |
| Shared folders | Used only to move verified installers into the segment; each transfer is recorded in [`internet-windows.md`](internet-windows.md) |
| USB passthrough | Disabled |

Every temporary internet window is recorded with the date, host, purpose, and duration in
[`internet-windows.md`](internet-windows.md). "Isolated,
with these documented exceptions" is a defensible statement; "isolated" with an undocumented
network adapter is not.

### Adversary emulation containment

Atomic Red Team executes only on WS01. It is never run against the domain controller or outside
the lab segment, and the workstation is snapshotted immediately before each session so any
persistence that survives cleanup can be rolled back.

## Tool-to-capability mapping

| Federal capability | Tool in this lab | Operational equivalent |
|---|---|---|
| SCAP compliance scanning | OpenSCAP, SCAP Compliance Checker | SCC is the DoD standard scanning tool |
| Vulnerability management | Tenable Nessus | ACAS is built on Tenable |
| Configuration hardening | DISA STIG GPOs, OpenSCAP remediation | Same published content used in DoD environments |
| Continuous monitoring | Splunk with Universal Forwarders | Widely deployed across DoD |
| Threat detection | SPL detections mapped to MITRE ATT&CK | SOC detection engineering |
| Control documentation | System Security Plan, POA&M | RMF artifacts under NIST SP 800-37 and 800-53 |

## Assessment scope

Two assessment tracks run against this environment: SCAP compliance scanning against DISA STIG
benchmarks, and network vulnerability scanning with Nessus.

| Host | Compliance scan | Vulnerability scan |
|---|---|---|
| DC01 | SCC — Windows Server 2025 STIG | Yes |
| WS01 | SCC — Windows 11 STIG | Yes |
| RHEL01 | OpenSCAP — RHEL 9 STIG | Yes |
| SIEM01 | Excluded | Yes |
| KALI01 | Excluded | Scanner |

SCAP scanners read local registry, policy, and filesystem state, so they run locally on each target
rather than remotely. Nessus scans across the network from KALI01, because it assesses exposed
services and patch levels rather than local configuration.

### Remediation scope

Assessment scope and remediation scope are not the same thing. A host can be assessed and its
baseline published without being remediated, and saying so is more useful than leaving the column
blank.

| Host | Assessed | Remediated |
|---|---|---|
| RHEL01 | Yes | Yes — OpenSCAP, staged |
| WS01 | Yes | Yes — DISA STIG GPOs |
| DC01 | Yes | **Deferred** |

DC01 is the only domain controller in this environment. The Windows Server 2025 STIG's
authentication controls — LDAP signing and channel binding, SMB signing, NTLM restrictions, and
Kerberos encryption-type constraints — change the authentication path that every other host depends
on: the workstation's secure channel, the scanner service account, time synchronisation for the
Linux hosts, and the administrative access used to apply and roll back the policy itself. With no
replication partner to fail over to, a policy change that breaks authentication also removes the
means of fixing it.

Remediation is therefore deferred until a second domain controller exists, and is recorded in the
[POA&M](poam.md) with its reasoning rather than treated as incomplete work. The scanning-account
design already reflects the same constraint: credentialed scans use a purpose-built domain account
rather than a Domain Admin, because the workstation STIG denies privileged domain accounts every
logon type.

### Exclusions

**SIEM01** is the monitoring platform. Applying the STIG baseline would conflict with Splunk's port
and service-account requirements during detection development. Excluded from compliance scanning;
still included in vulnerability scanning.

That exclusion was made before SIEM01 held anything. It now stores WS01's security audit records,
which makes it the most sensitive host in the lab rather than a support system: whoever controls it
can read or delete the evidence of activity on every host that forwards to it (AU-9). The exclusion
stands, and the risk it carries is recorded in the [POA&M](poam.md) as ENV-002 instead of being
treated as a scope decision.

**KALI01** is the assessment platform, not a target. It is Debian-based, no DISA STIG exists for it,
and hardening an attack platform is self-defeating.

### Windows 11 Pro limitation

WS01 runs Windows 11 Pro rather than Enterprise. Microsoft's published Enterprise evaluation image
was past its expiration date on download and enforced hourly shutdowns, so Pro was substituted.

One STIG requirement depends on an Enterprise-only feature: `V-253370, Credential Guard must be
running`, a CAT I failure in the WS01 baseline. Microsoft does not support Credential Guard on Pro,
so it has no remediation path and is recorded in the POA&M as a risk-accepted item with the reason
stated, rather than counted as a remediation failure.

Other controls often assumed to be Enterprise-only are available on Pro and were treated as normal
remediation items. BitLocker, backed by the VM's virtual TPM, is enabled with TPM + PIN pre-boot
authentication and recovery keys escrowed to Active Directory. Virtualization-based security and
HVCI both run, once the hypervisor feature is present and the VM exposes CPU virtualization
extensions — Credential Guard is the only one of the three that the edition actually gates.
AppLocker is likewise supported on all Windows 11 editions since KB5024351.

### What produces which number

Compliance percentages come from OpenSCAP and SCC only. The Nessus license tier in use includes no
compliance checks or audit files, so no STIG figure in this repository derives from Nessus output.

---

## SCAP content and tooling provenance

A compliance percentage is only meaningful alongside the benchmark revision it was measured
against. Every scan in `scans/` records its tool version, benchmark version, and profile.

| Component | Source | Version |
|---|---|---|
| SCAP Compliance Checker | DoD Cyber Exchange (`cyber.mil/stigs/SCAP`) | 5.15 |
| Windows 11 STIG SCAP benchmark | Bundled DISA content, SCC 5.15 | V2R10 / 002.010.018 |
| Windows Server 2025 STIG SCAP benchmark | Bundled DISA content, SCC 5.15 | V1R1 / 001.001.001 |
| RHEL 9 STIG content | `scap-security-guide`, Rocky Linux 9 repositories | 0.1.82 |
| OpenSCAP scanner | Rocky Linux 9 repositories | 1.3.14 |

The SCC installer was verified against the published SHA-256 checksum before transfer into the lab.
The Windows SCAP content carries a DoD PKI digital signature, which SCC validated at scan time —
both baseline reports record signature status VALID.

NIWC Atlantic maintains public mirrors of SCC releases and SCAP content on GitHub
(`niwc-atlantic/scap-scc` and `niwc-atlantic/scap-content-library`) as an alternative to the
CAC-gated Cyber Exchange portal.

### Profile selection

All Windows scans use the **MAC-2 Sensitive** profile. MAC is DoD's Mission Assurance Category:
MAC-1 Classified applies to systems handling classified data, MAC-2 Sensitive to systems handling
sensitive but unclassified data, MAC-3 Public to administrative systems. MAC-2 matches what these
hosts represent. Post-remediation scans use the same profile, since a before/after comparison across
different profiles would be meaningless.

### Manual questions

The NIWC-enhanced SCAP content includes checks that cannot be automated — organizational policy and
physical security questions. These are left unanswered and reported as Not Checked. Compliance
scores reflect automated checks only, and SCC annotates this on each report.

