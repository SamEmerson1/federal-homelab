# Nessus credentialed rescan after patching — 2026-09-21

**Tool:** Tenable Nessus Essentials Plus (education license, 20 IPs)
**Scanner:** KALI01, 10.10.10.50
**Policy:** Basic Network Scan — same policy, targets, and plugin feed as the 09-17 baseline
**Severity base:** CVSS v3.0
**Authentication:** `Valid Credentials Provided` on all four hosts (plugin 141118)

## Results

| IP | Host | Critical | High | Medium | Low | Info | Total |
|---|---|---|---|---|---|---|---|
| 10.10.10.10 | DC01 | 0 | 0 | 0 | 0 | 140 | 140 |
| 10.10.10.20 | SIEM01 | 0 | 0 | 0 | 0 | 53 | 53 |
| 10.10.10.30 | RHEL01 | 0 | 0 | 0 | 0 | 55 | 55 |
| 10.10.10.40 | WS01 | 0 | 0 | 0 | 0 | 130 | 130 |
| | **Total** | **0** | **0** | **0** | **0** | **378** | **378** |

## Change against the baseline

| Severity | Baseline 09-17 | Post-patch 09-21 | Closed |
|---|---|---|---|
| Critical | 21 | 0 | 21 |
| High | 35 | 0 | 35 |
| Medium | 5 | 0 | 5 |
| Low | 3 | 0 | 3 |
| **Actionable total** | **64** | **0** | **64** |

Informational findings rose from 357 to 378 as patched components exposed more detail to the
credentialed checks.

## What closed what

| Finding group | Host | Closed by |
|---|---|---|
| 21 critical, 30 high, 5 medium, 1 low | WS01 | Windows cumulative KB5129195 (25H2 26200.9457), .NET, Defender platform and signatures, and Store/`winget` application updates |
| 1 high (Defender signature age) | DC01 | Signature update to a current version |
| 2 high — WinVerifyTrust signature validation, CVE-2013-3900 | DC01, WS01 | `EnableCertPaddingCheck` registry value set in both the native and WOW6432Node paths |
| 1 high — Windows Update reboot required | WS01 | Reboot completing pending servicing operations |
| 1 medium — Intel BHI speculative execution, CVE-2022-0001 | WS01 | `FeatureSettingsOverride` / `FeatureSettingsOverrideMask` per Microsoft KB4073119 |
| 2 low — ICMP timestamp disclosure | RHEL01, SIEM01 | firewalld ICMP block, not patching |

Four of the nine remaining findings after patching were configuration issues rather than missing
patches, and each needed a specific fix. Patching alone would have left them open.

## Scope and limitations

- **The plugin feed is deliberately frozen** at the baseline's version. KALI01 has had no internet
  access since. This keeps the comparison attributable to patching and configuration rather than to
  new plugins, and it means CVEs published after that feed date were not evaluated.
- **Zero findings is not the same as secure.** This measures what Nessus checks: missing patches and
  exposed services. Configuration compliance is measured separately against the DISA STIGs, where
  WS01 still sits at its 38.84% baseline.
- **No compliance checks.** The Nessus license tier includes no audit files, so no STIG figure in
  this repository comes from Nessus.
- **Plugins requiring outbound callbacks cannot run** in an isolated segment, as recorded in the
  uncredentialed baseline.
- This scan was taken **before** the Windows STIG GPO is applied. Hardening is expected to break
  credentialed scanning, which is tracked as a documented scanner exception.

## Scanner access used

| Item | State during the scan | Afterwards |
|---|---|---|
| `RemoteRegistry` (DC01, WS01) | Manual, started by Nessus | Stopped and set back to Disabled |
| Administrative shares | Enabled for the scan | — |
| Windows credential | `LAB\svc-nessus`, a domain account in `BUILTIN\Administrators` on DC01 and in the local Administrators group on WS01 by Group Policy — **not** a Domain Admin | Retained |
| SSH credentials | `rheladmin` (10.10.10.30), `siemadmin` (10.10.10.20), both escalating with sudo | Retained |

The scan account was moved off `LAB\Administrator` before this scan. The Windows 11 STIG denies
highly privileged domain accounts network, remote desktop, and local logon on workstations, so a
Domain Admin credential stops working once the GPO is applied. A dedicated account avoids granting
an exception to that rule later.

## Evidence

[Full Nessus report](https://samemerson1.github.io/federal-homelab/scans/nessus/post-patch-credentialed-20260921.html)
