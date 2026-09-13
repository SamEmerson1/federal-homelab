# System Security Plan (Lite)

**System name:** Federal-Aligned Security Lab
**System owner:** *(your name — decide whether this file is public before filling this in)*
**Categorization:** Low / Low / Low (training system, no real data) — see FIPS 199 rationale below
**Control baseline:** NIST SP 800-53 Rev. 5, tailored Low baseline
**Version:** 0.1
**Last updated:**

> This is a training artifact modeled on a real SSP. It is not an accredited system and carries no
> authorization to operate. Its purpose is to demonstrate familiarity with RMF documentation.

---

## 1. System description

Two to three paragraphs: purpose, boundary, components, users, data types.
Reference `docs/architecture.md` rather than repeating the VM table.

## 2. System boundary

| In boundary | Out of boundary |
|---|---|
| DC01, WS01, RHEL01, SIEM01, KALI01 and the `LABNET` virtual switch | The physical host OS and its daily-use applications |
| VMware virtual hardware and virtual networking | The home LAN and internet |
| Splunk, Sysmon, Nessus, OpenSCAP, SCC | Vendor cloud services |

## 3. FIPS 199 categorization

| Objective | Impact | Rationale |
|---|---|---|
| Confidentiality | Low | No real or production data. Synthetic accounts only. |
| Integrity | Low | Loss of integrity affects training outcomes only; VMs are rebuildable from snapshots. |
| Availability | Low | No availability requirement. |

**Overall: Low.** In a real package this drives baseline selection under FIPS 200.

## 4. RMF step traceability

| RMF step | What in this lab satisfies it | Artifact |
|---|---|---|
| 1 — Categorize | FIPS 199 table above | this file, §3 |
| 2 — Select | Tailored Low baseline, controls in §6 | this file, §6 |
| 3 — Implement | VM build, GPO application, OpenSCAP remediation | `configs/` |
| 4 — Assess | OpenSCAP, SCC, and Nessus scan results | `scans/` |
| 5 — Authorize | Residual risk accepted and tracked | `docs/poam.md` |
| 6 — Monitor | Splunk log aggregation, dashboards, recurring scans | `detections/`, `configs/splunk/` |

## 5. Control implementation summary

| Family | Controls documented | Assessment source |
|---|---|---|
| AC — Access Control | `__` | GPO, AD configuration, SCC |
| AU — Audit and Accountability | `__` | Sysmon, Splunk, SCC |
| CM — Configuration Management | `__` | STIG GPO, OpenSCAP, snapshots |
| IA — Identification and Authentication | `__` | AD password policy, SCC |
| RA — Risk Assessment | `__` | Nessus, OpenSCAP |
| SI — System and Information Integrity | `__` | Sysmon, detections, patching |
| **Total** | `__` | |

## 6. Control implementation statements

Each statement must describe something actually built and cite the evidence file. A statement that
could have been written before the lab existed is not a control implementation — it is a
paraphrase of the control text.

### Template

```
### <CONTROL-ID> — <Control Name>

**Control statement (paraphrased):**

**Implementation status:** Implemented | Partially implemented | Planned | Not applicable

**Responsible component:** DC01 | WS01 | RHEL01 | SIEM01 | KALI01 | LABNET

**How it is implemented:**

**Assessment method:** Examine | Interview | Test

**Evidence:** `scans/...` or `configs/...` or `screenshots/...`

**Residual gap (if any):** → POA&M item #
```

---

### AC-2 — Account Management

**Implementation status:**
**Responsible component:** DC01
**How it is implemented:**
**Assessment method:**
**Evidence:**
**Residual gap:**

### AC-6 — Least Privilege

### AC-7 — Unsuccessful Logon Attempts

### AC-17 — Remote Access

### AU-2 — Event Logging

### AU-3 — Content of Audit Records

### AU-6 — Audit Record Review, Analysis, and Reporting

### AU-9 — Protection of Audit Information

### AU-12 — Audit Record Generation

### CM-2 — Baseline Configuration

### CM-6 — Configuration Settings

### CM-7 — Least Functionality

### IA-2 — Identification and Authentication (Organizational Users)

### IA-5 — Authenticator Management

### RA-5 — Vulnerability Monitoring and Scanning

### SC-7 — Boundary Protection

### SI-2 — Flaw Remediation

### SI-4 — System Monitoring

### SI-7 — Software, Firmware, and Information Integrity

---

## 7. Notes on tailoring

Record which controls were marked Not Applicable and why. In a real package, an unexplained N/A is
the first thing an assessor challenges. Example: PE-family physical controls are inherited from the
host environment and outside this boundary.

## 8. References

- NIST SP 800-53 Rev. 5 — Security and Privacy Controls
- NIST SP 800-37 Rev. 2 — Risk Management Framework
- NIST SP 800-53A Rev. 5 — Assessment Procedures
- FIPS 199 / FIPS 200
- DISA STIGs for Windows 11, Windows Server, and RHEL 9
