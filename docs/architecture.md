# Architecture

## Design goals

- An enterprise-shaped environment: a Windows domain with a joined workstation, Linux servers, and a separate attack platform.
- Complete isolation from any production or personal network, so adversary emulation can run safely.
- Tooling that matches what is actually deployed in federal and defense-contractor environments, not consumer equivalents.

## Virtual machine inventory

| VM | OS | RAM | vCPU | Disk | Address | Role |
|---|---|---|---|---|---|---|
| DC01 | Windows Server 2025 Standard | 4 GB | 2 | 60 GB thin | 10.10.10.10 | AD DS, DNS, Group Policy, STIG GPO distribution |
| SIEM01 | Rocky Linux 9 (minimal) | 6 GB | 2 | 80 GB thin | 10.10.10.20 | Splunk indexer and search head |
| RHEL01 | Rocky Linux 9 (minimal) | 2 GB | 2 | 40 GB thin | 10.10.10.30 | OpenSCAP STIG hardening target |
| WS01 | Windows 11 Enterprise | 4 GB | 2 | 80 GB thin | 10.10.10.40 | Domain client, Sysmon, Atomic Red Team target, SCC scanning host |
| KALI01 | Kali Linux | 4 GB | 2 | 60 GB thin | 10.10.10.50 | Nessus scanner, attack platform |

Rocky Linux was chosen for both Linux hosts because it is binary compatible with Red Hat
Enterprise Linux, which is what the RHEL 9 DISA STIG targets and what most federal Linux estates
run.

## Network design

A single flat lab subnet on a private virtual switch with no host-side adapter. This matters: a
host-only network still exposes an adapter on the physical machine, and a bridged network places
lab VMs directly on the local LAN. Neither is acceptable when the environment is deliberately
running adversary techniques.

| Setting | Value |
|---|---|
| Subnet | 10.10.10.0/24 |
| Domain | `lab.local` |
| DNS | 10.10.10.10 (DC01) for all hosts |
| DHCP | Disabled — static addressing keeps scan targets stable |
| Default gateway | None |

### Isolation boundary

| Path | State |
|---|---|
| Lab to physical host | Closed |
| Lab to local network | Closed |
| Lab to internet | Closed by default; opened temporarily for patching, then removed |
| Clipboard, drag-and-drop, shared folders | Disabled on the workstation and attack platform |
| USB passthrough | Disabled |

Every temporary internet window is recorded with the date, host, purpose, and duration. "Isolated,
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

## Scope boundaries

Compliance percentages come from OpenSCAP and SCC. Nessus is used for vulnerability assessment
only — the license tier in use does not include compliance auditing or audit files, so no STIG
percentage in this repository is derived from Nessus output.
